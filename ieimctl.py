#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ieim.audit.file_audit_log import FileAuditLogger
from ieim.audit.verify import verify_audit_logs
from ieim.config import load_config
from ieim.hitl.review_store import FileReviewStore
from ieim.hitl.service import HitlService
from ieim.identity.config_select import select_config_path_for_message
from ieim.ops.load_test import run_load_test
from ieim.ops.retention import load_retention_config, run_raw_retention
from ieim.pipeline.p6_reprocess import ReprocessRunner
from ieim.route.evaluator import evaluate_routing
from ieim.route.ruleset import load_routing_ruleset
from ieim.runtime.config import validate_config_file


def _require_dict(obj: Any, *, path: str) -> dict[str, Any]:
    if not isinstance(obj, dict):
        raise ValueError(f"{path} must be an object")
    return obj


def _require_list(obj: Any, *, path: str) -> list[Any]:
    if not isinstance(obj, list):
        raise ValueError(f"{path} must be a list")
    return list(obj)


def _lint_condition(cond: dict[str, Any], *, path: str) -> list[str]:
    errors: list[str] = []
    supported_keys = {
        "risk_flags_any",
        "risk_flags_not_any",
        "primary_intent_in",
        "primary_intent_not_in",
        "identity_status_in",
        "product_line_in",
        "any",
        "all",
    }
    unknown = set(cond.keys()) - supported_keys
    if unknown:
        errors.append(f"{path}: unsupported keys: {sorted(unknown)}")

    for k in ("any", "all"):
        if k in cond:
            try:
                branches = _require_list(cond[k], path=f"{path}.{k}")
            except Exception as e:
                errors.append(f"{path}.{k}: {e}")
                continue
            for idx, branch in enumerate(branches):
                try:
                    branch_obj = _require_dict(branch, path=f"{path}.{k}[{idx}]")
                except Exception as e:
                    errors.append(f"{path}.{k}[{idx}]: {e}")
                    continue
                errors.extend(_lint_condition(branch_obj, path=f"{path}.{k}[{idx}]"))
    return errors


def cmd_rules_lint(args: argparse.Namespace) -> int:
    repo_root = Path(__file__).resolve().parent
    ruleset = load_routing_ruleset(repo_root=repo_root, ruleset_path=args.ruleset_path)

    errors: list[str] = []

    seen_rule_ids: set[str] = set()
    for idx, rule in enumerate(ruleset.rules):
        rule_id = rule.get("rule_id")
        if not isinstance(rule_id, str) or not rule_id:
            errors.append(f"rules[{idx}].rule_id: missing")
        elif rule_id in seen_rule_ids:
            errors.append(f"rules[{idx}].rule_id: duplicate {rule_id}")
        else:
            seen_rule_ids.add(rule_id)

        prio = rule.get("priority")
        if not isinstance(prio, int):
            errors.append(f"rules[{idx}].priority: must be integer")

        when = rule.get("when")
        if not isinstance(when, dict):
            errors.append(f"rules[{idx}].when: must be object")
        else:
            errors.extend(_lint_condition(when, path=f"rules[{idx}].when"))

        then = rule.get("then")
        if not isinstance(then, dict):
            errors.append(f"rules[{idx}].then: must be object")
        else:
            for field in ("queue_id", "sla_id", "priority", "actions", "fail_closed"):
                if field not in then:
                    errors.append(f"rules[{idx}].then.{field}: missing")

    fallback = ruleset.fallback
    if "queue_id" not in fallback or "sla_id" not in fallback or "priority" not in fallback:
        errors.append("fallback: missing queue_id/sla_id/priority")

    if errors:
        print("RULES_LINT_FAILED")
        for e in errors[:200]:
            print(e)
        return 1

    print("RULES_LINT_OK")
    return 0


def cmd_rules_simulate(args: argparse.Namespace) -> int:
    repo_root = Path(__file__).resolve().parent
    nm_dir = repo_root / args.normalized_dir
    gold_dir = repo_root / args.gold_dir

    failures = 0
    total = 0

    for nm_path in sorted(nm_dir.glob("*.json")):
        total += 1
        nm = json.loads(nm_path.read_text(encoding="utf-8"))
        msg_id = str(nm.get("message_id") or nm_path.stem)

        cfg = load_config(
            path=select_config_path_for_message(repo_root=repo_root, normalized_message=nm)
        )

        identity = json.loads((gold_dir / f"{msg_id}.identity.json").read_text(encoding="utf-8"))
        cls = json.loads((gold_dir / f"{msg_id}.classification.json").read_text(encoding="utf-8"))
        expected = json.loads((gold_dir / f"{msg_id}.routing.json").read_text(encoding="utf-8"))

        actual = evaluate_routing(
            repo_root=repo_root,
            config=cfg,
            normalized_message=nm,
            identity_result=identity,
            classification_result=cls,
        ).decision

        if actual != expected:
            failures += 1
            print(f"SIM_MISMATCH: {msg_id}")
            if failures >= 20:
                break

    if failures:
        print(f"RULES_SIMULATE_FAILED: {failures}/{total}")
        return 1

    print(f"RULES_SIMULATE_OK: {total}")
    return 0


def _resolve_repo_path(repo_root: Path, path: str) -> Path:
    p = Path(path)
    return p if p.is_absolute() else (repo_root / p)


def _run_python_script(*, repo_root: Path, script_rel: str) -> int:
    script = repo_root / script_rel
    if not script.exists():
        print(f"PACK_VERIFY_FAILED: missing {script_rel}")
        return 60

    try:
        cp = subprocess.run([sys.executable, str(script)], cwd=str(repo_root), check=False)
    except Exception as e:
        print(f"PACK_VERIFY_FAILED: failed to run {script_rel}: {e}")
        return 40

    return int(cp.returncode)


def cmd_audit_verify(args: argparse.Namespace) -> int:
    repo_root = Path(__file__).resolve().parent
    audit_dir = _resolve_repo_path(repo_root, args.audit_dir)
    schema_path = repo_root / "schemas" / "audit_event.schema.json"

    if not audit_dir.exists():
        print(f"AUDIT_VERIFY_FAILED: missing audit dir: {audit_dir}")
        return 10

    result = verify_audit_logs(audit_dir=audit_dir, schema_path=schema_path)
    if result.files_checked == 0:
        print(f"AUDIT_VERIFY_FAILED: no audit logs found in: {audit_dir}")
        return 10

    if not result.ok:
        print("AUDIT_VERIFY_FAILED")
        for err in result.errors[:200]:
            print(err)
        return 60

    print(f"AUDIT_VERIFY_OK: files={result.files_checked} events={result.events_checked}")
    return 0


def _load_crm_mapping(path: Path) -> dict[str, list[str]]:
    obj = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(obj, dict):
        raise ValueError("CRM mapping must be a JSON object")
    out: dict[str, list[str]] = {}
    for k, v in obj.items():
        if not isinstance(k, str) or not k:
            raise ValueError("CRM mapping keys must be non-empty strings")
        if not isinstance(v, list) or not all(isinstance(it, str) for it in v):
            raise ValueError(f"CRM mapping values must be list[str] for key: {k}")
        out[k] = list(v)
    return out


def cmd_reprocess(args: argparse.Namespace) -> int:
    repo_root = Path(__file__).resolve().parent

    crm_mapping: dict[str, list[str]] = {}
    if args.crm_mapping is not None:
        crm_path = _resolve_repo_path(repo_root, args.crm_mapping)
        crm_mapping = _load_crm_mapping(crm_path)

    history_dir = None
    if args.history_dir is not None:
        history_dir = _resolve_repo_path(repo_root, args.history_dir)

    runner = ReprocessRunner(
        repo_root=repo_root,
        normalized_dir=_resolve_repo_path(repo_root, args.normalized_dir),
        attachments_dir=_resolve_repo_path(repo_root, args.attachments_dir),
        out_dir=_resolve_repo_path(repo_root, args.out_dir),
        message_id=args.message_id,
        crm_mapping=crm_mapping,
        history_dir=history_dir,
    )

    report = runner.run()
    status = str(report.get("status") or "")
    print(f"REPROCESS_STATUS: {status}")
    if status == "OK":
        return 0
    if status == "REVIEW_REQUIRED":
        return 30
    return 60


def cmd_pack_verify(args: argparse.Namespace) -> int:
    repo_root = Path(__file__).resolve().parent

    scripts = [
        "scripts/check_placeholders.py",
        "scripts/check_single_definition_rule.py",
        "scripts/validate_schemas.py",
        "scripts/check_label_consistency.py",
        "scripts/check_manifest_completeness.py",
    ]
    for script in scripts:
        rc = _run_python_script(repo_root=repo_root, script_rel=script)
        if rc != 0:
            print(f"PACK_VERIFY_FAILED: {script}: rc={rc}")
            return int(rc)

    print("PACK_VERIFY_OK")
    return 0


def cmd_config_validate(args: argparse.Namespace) -> int:
    repo_root = Path(__file__).resolve().parent
    cfg_path = _resolve_repo_path(repo_root, args.config)
    try:
        validate_config_file(path=cfg_path)
    except Exception as e:
        print(f"CONFIG_VALIDATE_FAILED: {e}")
        return 60
    print("CONFIG_VALIDATE_OK")
    return 0


def _next_demo_run_dir(*, base_dir: Path) -> Path:
    base_dir.mkdir(parents=True, exist_ok=True)
    max_n = 0
    for p in base_dir.iterdir():
        if not p.is_dir():
            continue
        name = p.name
        if not name.startswith("run_"):
            continue
        suffix = name[len("run_") :]
        if suffix.isdigit():
            max_n = max(max_n, int(suffix))
    out = base_dir / f"run_{max_n + 1:03d}"
    out.mkdir(parents=True, exist_ok=False)
    return out


def cmd_demo_run(args: argparse.Namespace) -> int:
    repo_root = Path(__file__).resolve().parent
    cfg_path = _resolve_repo_path(repo_root, args.config)
    samples_dir = _resolve_repo_path(repo_root, args.samples)
    out_base_dir = _resolve_repo_path(repo_root, args.out_dir)

    try:
        validate_config_file(path=cfg_path)
    except Exception as e:
        print(f"DEMO_RUN_FAILED: invalid config: {e}")
        return 10

    normalized_dir = samples_dir / "emails"
    attachments_dir = samples_dir / "attachments"

    if not normalized_dir.exists():
        print(f"DEMO_RUN_FAILED: missing samples emails dir: {normalized_dir}")
        return 10
    if not attachments_dir.exists():
        print(f"DEMO_RUN_FAILED: missing samples attachments dir: {attachments_dir}")
        return 10

    try:
        run_dir = _next_demo_run_dir(base_dir=out_base_dir)
    except Exception as e:
        print(f"DEMO_RUN_FAILED: failed to create output dir: {e}")
        return 60

    crm_mapping: dict[str, list[str]] = {}
    if args.crm_mapping is not None:
        try:
            crm_mapping = _load_crm_mapping(_resolve_repo_path(repo_root, args.crm_mapping))
        except Exception as e:
            print(f"DEMO_RUN_FAILED: invalid --crm-mapping: {e}")
            return 10

    from ieim.case_adapter.adapter import InMemoryCaseAdapter
    from ieim.identity.adapters import InMemoryCRMAdapter, InMemoryClaimsAdapter, InMemoryPolicyAdapter
    from ieim.pipeline.p3_identity_resolution import IdentityResolutionRunner
    from ieim.pipeline.p4_classify_extract import ClassifyExtractRunner
    from ieim.pipeline.p5_case_adapter import CaseAdapterRunner
    from ieim.pipeline.p5_routing import RoutingRunner
    from ieim.pipeline.p7_hitl import HitlReviewItemsRunner

    audit_logger = FileAuditLogger(base_dir=run_dir)

    policy_adapter = InMemoryPolicyAdapter(valid_policy_numbers=None)
    claims_adapter = InMemoryClaimsAdapter(valid_claim_numbers=None)
    crm_adapter = InMemoryCRMAdapter(email_to_policy_numbers=dict(crm_mapping))

    try:
        identity_results = IdentityResolutionRunner(
            repo_root=repo_root,
            normalized_dir=normalized_dir,
            attachments_dir=attachments_dir,
            identity_out_dir=run_dir / "identity",
            drafts_out_dir=run_dir / "drafts",
            policy_adapter=policy_adapter,
            claims_adapter=claims_adapter,
            crm_adapter=crm_adapter,
            audit_logger=audit_logger,
            config_path_override=cfg_path,
        ).run()

        classify_extract_results = ClassifyExtractRunner(
            repo_root=repo_root,
            normalized_dir=normalized_dir,
            attachments_dir=attachments_dir,
            classification_out_dir=run_dir / "classification",
            extraction_out_dir=run_dir / "extraction",
            audit_logger=audit_logger,
            config_path_override=cfg_path,
        ).run()

        routing_results = RoutingRunner(
            repo_root=repo_root,
            normalized_dir=normalized_dir,
            identity_dir=run_dir / "identity",
            classification_dir=run_dir / "classification",
            routing_out_dir=run_dir / "routing",
            audit_logger=audit_logger,
            config_path_override=cfg_path,
        ).run()

        case_results = CaseAdapterRunner(
            repo_root=repo_root,
            normalized_dir=normalized_dir,
            attachments_dir=attachments_dir,
            routing_dir=run_dir / "routing",
            drafts_dir=run_dir / "drafts",
            case_out_dir=run_dir / "case",
            adapter=InMemoryCaseAdapter(),
            audit_logger=audit_logger,
        ).run()

        hitl_results = HitlReviewItemsRunner(
            repo_root=repo_root,
            normalized_dir=normalized_dir,
            attachments_dir=attachments_dir,
            identity_dir=run_dir / "identity",
            classification_dir=run_dir / "classification",
            extraction_dir=run_dir / "extraction",
            routing_dir=run_dir / "routing",
            drafts_dir=run_dir / "drafts",
            hitl_out_dir=run_dir / "hitl",
            audit_logger=audit_logger,
        ).run()
    except Exception as e:
        print(f"DEMO_RUN_FAILED: pipeline error: {type(e).__name__}: {e}")
        return 60

    schema_path = repo_root / "schemas" / "audit_event.schema.json"
    audit_dir = run_dir / "audit"
    audit_result = verify_audit_logs(audit_dir=audit_dir, schema_path=schema_path)
    if audit_result.files_checked == 0:
        print(f"DEMO_RUN_FAILED: no audit logs found in: {audit_dir}")
        return 60
    if not audit_result.ok:
        print("DEMO_RUN_FAILED: audit verify failed")
        for err in audit_result.errors[:200]:
            print(err)
        return 60

    print(
        "DEMO_RUN_OK:"
        f" out_dir={run_dir.as_posix()}"
        f" identity={len(identity_results)}"
        f" classify_extract={len(classify_extract_results)}"
        f" routing={len(routing_results)}"
        f" case={len(case_results)}"
        f" hitl={len(hitl_results)}"
        f" audit_files={audit_result.files_checked}"
        f" audit_events={audit_result.events_checked}"
    )
    return 0


def cmd_ingest_simulate(args: argparse.Namespace) -> int:
    repo_root = Path(__file__).resolve().parent
    samples_dir = _resolve_repo_path(repo_root, args.samples)
    out_dir = _resolve_repo_path(repo_root, args.out_dir)
    adapter_name = str(args.adapter or "").strip().lower()

    raw_mime_dir = samples_dir / "raw_mime"
    attachments_dir = samples_dir / "attachments"
    if not raw_mime_dir.exists():
        print(f"INGEST_SIMULATE_FAILED: missing samples raw_mime dir: {raw_mime_dir}")
        return 10
    if not attachments_dir.exists():
        print(f"INGEST_SIMULATE_FAILED: missing samples attachments dir: {attachments_dir}")
        return 10

    if adapter_name != "filesystem":
        print(f"INGEST_SIMULATE_FAILED: unsupported adapter: {adapter_name}")
        return 10

    from datetime import timedelta

    import jsonschema

    from ieim.attachments.av import Sha256MappingAVScanner
    from ieim.attachments.stage import AttachmentStage
    from ieim.audit.file_audit_log import FileAuditLogger
    from ieim.audit.verify import verify_audit_logs
    from ieim.ingest.filesystem_adapter import FilesystemMailIngestAdapter
    from ieim.pipeline.p1_ingest_normalize import IngestNormalizeRunner
    from ieim.raw_store import FileRawStore

    av_map: dict[str, str] = {}
    for meta_path in sorted(attachments_dir.glob("*.meta.json")):
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        if isinstance(meta, dict) and isinstance(meta.get("sha256"), str) and isinstance(meta.get("av_status"), str):
            av_map[meta["sha256"]] = meta["av_status"]

    adapter = FilesystemMailIngestAdapter(raw_mime_dir=raw_mime_dir, attachments_dir=attachments_dir)
    store = FileRawStore(base_dir=out_dir)
    audit_logger = FileAuditLogger(base_dir=out_dir)

    attachment_stage = AttachmentStage(
        adapter=adapter,
        raw_store=store,
        derived_store=store,
        av_scanner=Sha256MappingAVScanner(av_map, default_status="FAILED"),
        attachments_out_dir=out_dir / "attachments",
    )

    nm_schema = json.loads((repo_root / "schemas" / "normalized_message.schema.json").read_text("utf-8"))
    nm_validator = jsonschema.Draft202012Validator(nm_schema)

    runner = IngestNormalizeRunner(
        adapter=adapter,
        ingestion_source="M365_GRAPH",
        raw_store=store,
        state_dir=out_dir / "state",
        normalized_out_dir=out_dir / "emails",
        audit_logger=audit_logger,
        attachment_stage=attachment_stage,
        ingested_at_from_received_at=lambda received_at: received_at + timedelta(minutes=5),
    )

    try:
        produced = runner.run_once(limit=int(args.limit))
    except Exception as e:
        print(f"INGEST_SIMULATE_FAILED: pipeline error: {type(e).__name__}: {e}")
        return 60

    for nm in produced:
        nm_validator.validate(nm)

    audit_dir = out_dir / "audit"
    audit_schema_path = repo_root / "schemas" / "audit_event.schema.json"
    audit_result = verify_audit_logs(audit_dir=audit_dir, schema_path=audit_schema_path)
    if audit_result.files_checked == 0:
        print(f"INGEST_SIMULATE_FAILED: no audit logs found in: {audit_dir}")
        return 60
    if not audit_result.ok:
        print("INGEST_SIMULATE_FAILED: audit verify failed")
        for err in audit_result.errors[:200]:
            print(err)
        return 60

    print(
        "INGEST_SIMULATE_OK:"
        f" out_dir={out_dir.as_posix()}"
        f" produced={len(produced)}"
        f" audit_files={audit_result.files_checked}"
        f" audit_events={audit_result.events_checked}"
    )
    return 0


def cmd_case_simulate(args: argparse.Namespace) -> int:
    repo_root = Path(__file__).resolve().parent
    samples_dir = _resolve_repo_path(repo_root, args.samples)
    normalized_dir = samples_dir / "emails"
    attachments_dir = samples_dir / "attachments"
    adapter_name = str(args.adapter or "").strip().lower()

    if not normalized_dir.exists():
        print(f"CASE_SIMULATE_FAILED: missing samples emails dir: {normalized_dir}")
        return 10
    if not attachments_dir.exists():
        print(f"CASE_SIMULATE_FAILED: missing samples attachments dir: {attachments_dir}")
        return 10

    if adapter_name != "servicenow":
        print(f"CASE_SIMULATE_FAILED: unsupported adapter: {adapter_name}")
        return 10

    cfg_path = _resolve_repo_path(repo_root, args.config)
    try:
        validate_config_file(path=cfg_path)
    except Exception as e:
        print(f"CASE_SIMULATE_FAILED: invalid config: {e}")
        return 10

    out_base_dir = _resolve_repo_path(repo_root, args.out_dir)
    try:
        run_dir = _next_demo_run_dir(base_dir=out_base_dir)
    except Exception as e:
        print(f"CASE_SIMULATE_FAILED: failed to create output dir: {e}")
        return 60

    from ieim.audit.file_audit_log import FileAuditLogger
    from ieim.audit.verify import verify_audit_logs
    from ieim.case_adapter.servicenow_adapter import (
        ServiceNowIncidentAdapterConfig,
        ServiceNowIncidentCaseAdapter,
    )
    from ieim.case_adapter.servicenow_mock import ServiceNowMockServer, ServiceNowMockState
    from ieim.identity.adapters import InMemoryCRMAdapter, InMemoryClaimsAdapter, InMemoryPolicyAdapter
    from ieim.pipeline.p3_identity_resolution import IdentityResolutionRunner
    from ieim.pipeline.p4_classify_extract import ClassifyExtractRunner
    from ieim.pipeline.p5_case_adapter import CaseAdapterRunner
    from ieim.pipeline.p5_routing import RoutingRunner

    audit_logger = FileAuditLogger(base_dir=run_dir)

    policy_adapter = InMemoryPolicyAdapter(valid_policy_numbers=None)
    claims_adapter = InMemoryClaimsAdapter(valid_claim_numbers=None)
    crm_adapter = InMemoryCRMAdapter(email_to_policy_numbers={})

    try:
        _ = IdentityResolutionRunner(
            repo_root=repo_root,
            normalized_dir=normalized_dir,
            attachments_dir=attachments_dir,
            identity_out_dir=run_dir / "identity",
            drafts_out_dir=run_dir / "drafts",
            policy_adapter=policy_adapter,
            claims_adapter=claims_adapter,
            crm_adapter=crm_adapter,
            audit_logger=audit_logger,
            config_path_override=cfg_path,
        ).run()

        _ = ClassifyExtractRunner(
            repo_root=repo_root,
            normalized_dir=normalized_dir,
            attachments_dir=attachments_dir,
            classification_out_dir=run_dir / "classification",
            extraction_out_dir=run_dir / "extraction",
            audit_logger=audit_logger,
            config_path_override=cfg_path,
        ).run()

        routing_results = RoutingRunner(
            repo_root=repo_root,
            normalized_dir=normalized_dir,
            identity_dir=run_dir / "identity",
            classification_dir=run_dir / "classification",
            routing_out_dir=run_dir / "routing",
            audit_logger=audit_logger,
            config_path_override=cfg_path,
        ).run()
    except Exception as e:
        print(f"CASE_SIMULATE_FAILED: upstream pipeline error: {type(e).__name__}: {e}")
        return 60

    import uuid

    queue_ids: set[str] = set()
    for r in routing_results:
        qid = r.get("queue_id")
        if isinstance(qid, str) and qid:
            queue_ids.add(qid)
    group_map = {qid: str(uuid.uuid5(uuid.NAMESPACE_URL, f"sn_group:{qid}")) for qid in sorted(queue_ids)}

    def get_bytes(uri: str) -> bytes:
        p = Path(uri)
        path = p if p.is_absolute() else (repo_root / p)
        return path.read_bytes()

    sn_state = ServiceNowMockState(sys_users_by_email={"broker@example.broker": str(uuid.uuid4())})

    with ServiceNowMockServer(state=sn_state) as sn:
        if sn.base_url is None:
            print("CASE_SIMULATE_FAILED: mock ServiceNow did not start")
            return 60

        adapter = ServiceNowIncidentCaseAdapter(
            config=ServiceNowIncidentAdapterConfig(
                instance_url=sn.base_url,
                client_id="client_id",
                client_secret="client_secret",
                assignment_group_by_queue_id=group_map,
                get_bytes=get_bytes,
                attach_stage_outputs=True,
            )
        )

        try:
            results1 = CaseAdapterRunner(
                repo_root=repo_root,
                normalized_dir=normalized_dir,
                attachments_dir=attachments_dir,
                identity_dir=run_dir / "identity",
                classification_dir=run_dir / "classification",
                extraction_dir=run_dir / "extraction",
                routing_dir=run_dir / "routing",
                drafts_dir=run_dir / "drafts",
                case_out_dir=run_dir / "case",
                adapter=adapter,
                audit_logger=audit_logger,
            ).run()
        except Exception as e:
            print(f"CASE_SIMULATE_FAILED: case pipeline error: {type(e).__name__}: {e}")
            return 60

        incidents_before = sn_state.incident_count()
        attachments_before = sn_state.attachment_count()

        try:
            _ = CaseAdapterRunner(
                repo_root=repo_root,
                normalized_dir=normalized_dir,
                attachments_dir=attachments_dir,
                identity_dir=run_dir / "identity",
                classification_dir=run_dir / "classification",
                extraction_dir=run_dir / "extraction",
                routing_dir=run_dir / "routing",
                drafts_dir=run_dir / "drafts",
                case_out_dir=run_dir / "case",
                adapter=adapter,
                audit_logger=audit_logger,
            ).run()
        except Exception as e:
            print(f"CASE_SIMULATE_FAILED: case re-run error: {type(e).__name__}: {e}")
            return 60

        if sn_state.incident_count() != incidents_before:
            print("CASE_SIMULATE_FAILED: idempotency violation (incident count changed on replay)")
            return 60
        if sn_state.attachment_count() != attachments_before:
            print("CASE_SIMULATE_FAILED: idempotency violation (attachments changed on replay)")
            return 60

        created = len([r for r in results1 if r.get("status") == "CREATED"])
        if created <= 0 or sn_state.attachment_count() <= 0:
            print("CASE_SIMULATE_FAILED: expected at least one created case with attachments")
            return 60

    audit_dir = run_dir / "audit"
    schema_path = repo_root / "schemas" / "audit_event.schema.json"
    audit_result = verify_audit_logs(audit_dir=audit_dir, schema_path=schema_path)
    if audit_result.files_checked == 0 or not audit_result.ok:
        print("CASE_SIMULATE_FAILED: audit verify failed")
        for err in audit_result.errors[:200]:
            print(err)
        return 60

    print(
        "CASE_SIMULATE_OK:"
        f" out_dir={run_dir.as_posix()}"
        f" cases_created={created}"
        f" incidents={sn_state.incident_count()}"
        f" attachments={sn_state.attachment_count()}"
        f" audit_files={audit_result.files_checked}"
        f" audit_events={audit_result.events_checked}"
    )
    return 0


def _load_corrections(path: Path) -> list[dict[str, Any]]:
    obj = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(obj, dict) and "corrections" in obj:
        obj = obj["corrections"]
    if not isinstance(obj, list) or not all(isinstance(it, dict) for it in obj):
        raise ValueError("corrections JSON must be a list[object] or {corrections: list[object]}")
    return [dict(it) for it in obj]


def cmd_hitl_list(args: argparse.Namespace) -> int:
    repo_root = Path(__file__).resolve().parent
    hitl_dir = _resolve_repo_path(repo_root, args.hitl_dir)

    items = FileReviewStore(base_dir=hitl_dir).list_queue(queue_id=args.queue_id)
    for it in items:
        rid = str(it.get("review_item_id") or "")
        mid = str(it.get("message_id") or "")
        status = str(it.get("status") or "")
        print(f"{rid} {mid} {status}")
    print(f"HITL_LIST_OK: {len(items)}")
    return 0


def cmd_hitl_submit_correction(args: argparse.Namespace) -> int:
    repo_root = Path(__file__).resolve().parent
    hitl_dir = _resolve_repo_path(repo_root, args.hitl_dir)

    store = FileReviewStore(base_dir=hitl_dir)
    review_path = store.find_path(review_item_id=args.review_item_id)
    if review_path is None:
        print(f"HITL_SUBMIT_FAILED: review item not found: {args.review_item_id}")
        return 10

    try:
        corrections = _load_corrections(_resolve_repo_path(repo_root, args.corrections_json))
    except Exception as e:
        print(f"HITL_SUBMIT_FAILED: invalid corrections JSON: {e}")
        return 10

    audit_logger = None
    if args.audit_base_dir is not None:
        audit_logger = FileAuditLogger(base_dir=_resolve_repo_path(repo_root, args.audit_base_dir))

    service = HitlService(repo_root=repo_root, hitl_dir=hitl_dir, audit_logger=audit_logger)
    out = service.submit_correction(
        review_item_path=review_path,
        actor_id=args.actor_id,
        corrections=corrections,
        note=args.note,
    )
    print(f"HITL_SUBMIT_OK: {out.as_posix()}")
    return 0


def _parse_rfc3339(dt: str) -> datetime:
    if dt.endswith("Z"):
        dt = dt[:-1] + "+00:00"
    return datetime.fromisoformat(dt)


def cmd_retention_run(args: argparse.Namespace) -> int:
    repo_root = Path(__file__).resolve().parent
    base_dir = _resolve_repo_path(repo_root, args.base_dir)
    normalized_dir = _resolve_repo_path(repo_root, args.normalized_dir)
    attachments_dir = _resolve_repo_path(repo_root, args.attachments_dir)

    derived_base_dir = None
    if args.derived_base_dir is not None:
        derived_base_dir = _resolve_repo_path(repo_root, args.derived_base_dir)

    now = datetime.now(timezone.utc).replace(microsecond=0)
    if args.now is not None:
        try:
            now = _parse_rfc3339(args.now)
        except Exception as e:
            print(f"RETENTION_RUN_FAILED: invalid --now: {e}")
            return 10

    try:
        retention = load_retention_config(path=_resolve_repo_path(repo_root, args.config))
    except RuntimeError as e:
        print(f"RETENTION_RUN_FAILED: {e}")
        return 40
    except Exception as e:
        print(f"RETENTION_RUN_FAILED: invalid config: {e}")
        return 10

    report_path = None
    if args.report_path is not None:
        report_path = _resolve_repo_path(repo_root, args.report_path)

    try:
        report = run_raw_retention(
            base_dir=base_dir,
            derived_base_dir=derived_base_dir,
            normalized_dir=normalized_dir,
            attachments_dir=attachments_dir,
            raw_days=retention.raw_days,
            now=now,
            dry_run=not args.apply,
            report_path=report_path,
        )
    except Exception as e:
        print(f"RETENTION_RUN_FAILED: {e}")
        return 60

    if report_path is not None:
        print(f"RETENTION_RUN_OK: {report_path.as_posix()}")
    else:
        print(json.dumps(report.to_dict(), ensure_ascii=False, sort_keys=True))
        print("RETENTION_RUN_OK")
    return 0


def cmd_loadtest_run(args: argparse.Namespace) -> int:
    repo_root = Path(__file__).resolve().parent

    crm_mapping: dict[str, list[str]] = {}
    if args.crm_mapping is not None:
        try:
            crm_mapping = _load_crm_mapping(_resolve_repo_path(repo_root, args.crm_mapping))
        except Exception as e:
            print(f"LOADTEST_FAILED: invalid --crm-mapping: {e}")
            return 10

    cfg_path = None
    if args.config is not None:
        cfg_path = _resolve_repo_path(repo_root, args.config)

    try:
        report = run_load_test(
            repo_root=repo_root,
            normalized_dir=_resolve_repo_path(repo_root, args.normalized_dir),
            attachments_dir=_resolve_repo_path(repo_root, args.attachments_dir),
            iterations=int(args.iterations),
            config_path=cfg_path,
            crm_mapping=crm_mapping,
        )
    except Exception as e:
        print(f"LOADTEST_FAILED: {e}")
        return 60

    if args.report_path is not None:
        out_path = _resolve_repo_path(repo_root, args.report_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            json.dumps(report.to_dict(), indent=2, ensure_ascii=False, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(f"LOADTEST_OK: {out_path.as_posix()}")
        return 0

    print(json.dumps(report.to_dict(), ensure_ascii=False, sort_keys=True))
    print("LOADTEST_OK")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ieimctl")
    sub = parser.add_subparsers(dest="command", required=True)

    pack = sub.add_parser("pack")
    pack_sub = pack.add_subparsers(dest="pack_command", required=True)

    pack_verify = pack_sub.add_parser("verify")
    pack_verify.set_defaults(func=cmd_pack_verify)

    config = sub.add_parser("config")
    config_sub = config.add_subparsers(dest="config_command", required=True)

    cfg_validate = config_sub.add_parser("validate")
    cfg_validate.add_argument("--config", default="configs/dev.yaml", help="Config file (repo-relative).")
    cfg_validate.set_defaults(func=cmd_config_validate)

    demo = sub.add_parser("demo")
    demo_sub = demo.add_subparsers(dest="demo_command", required=True)

    demo_run = demo_sub.add_parser("run")
    demo_run.add_argument("--config", default="configs/dev.yaml", help="Config file (repo-relative).")
    demo_run.add_argument(
        "--samples",
        default="data/samples",
        help="Sample corpus base directory (repo-relative unless absolute).",
    )
    demo_run.add_argument(
        "--out-dir",
        default="out/demo",
        help="Output base directory for demo runs (repo-relative unless absolute).",
    )
    demo_run.add_argument(
        "--crm-mapping",
        default=None,
        help="Optional JSON file mapping sender email to policy numbers.",
    )
    demo_run.set_defaults(func=cmd_demo_run)

    ingest = sub.add_parser("ingest")
    ingest_sub = ingest.add_subparsers(dest="ingest_command", required=True)

    ingest_simulate = ingest_sub.add_parser("simulate")
    ingest_simulate.add_argument(
        "--adapter",
        default="filesystem",
        help="Ingest adapter (supported: filesystem).",
    )
    ingest_simulate.add_argument(
        "--samples",
        default="data/samples",
        help="Sample corpus base directory (repo-relative unless absolute).",
    )
    ingest_simulate.add_argument(
        "--out-dir",
        default="out/ingest_sim",
        help="Output base directory (repo-relative unless absolute).",
    )
    ingest_simulate.add_argument("--limit", default=500, help="Max messages per run.")
    ingest_simulate.set_defaults(func=cmd_ingest_simulate)

    case = sub.add_parser("case")
    case_sub = case.add_subparsers(dest="case_command", required=True)

    case_simulate = case_sub.add_parser("simulate")
    case_simulate.add_argument(
        "--adapter",
        default="servicenow",
        help="Case adapter (supported: servicenow).",
    )
    case_simulate.add_argument(
        "--samples",
        default="data/samples",
        help="Sample corpus base directory (repo-relative unless absolute).",
    )
    case_simulate.add_argument(
        "--out-dir",
        default="out/case_sim",
        help="Output base directory (repo-relative unless absolute).",
    )
    case_simulate.add_argument("--config", default="configs/dev.yaml", help="Config file (repo-relative).")
    case_simulate.set_defaults(func=cmd_case_simulate)

    rules = sub.add_parser("rules")
    rules_sub = rules.add_subparsers(dest="rules_command", required=True)

    lint = rules_sub.add_parser("lint")
    lint.add_argument(
        "--ruleset-path",
        default="configs/routing_tables/routing_rules_v1.4.1.json",
        help="Path to routing ruleset JSON (repo-relative).",
    )
    lint.set_defaults(func=cmd_rules_lint)

    sim = rules_sub.add_parser("simulate")
    sim.add_argument("--normalized-dir", default="data/samples/emails")
    sim.add_argument("--gold-dir", default="data/samples/gold")
    sim.set_defaults(func=cmd_rules_simulate)

    audit = sub.add_parser("audit")
    audit_sub = audit.add_subparsers(dest="audit_command", required=True)

    verify = audit_sub.add_parser("verify")
    verify.add_argument(
        "--audit-dir",
        default="audit",
        help="Audit directory (repo-relative unless absolute).",
    )
    verify.set_defaults(func=cmd_audit_verify)

    reprocess = sub.add_parser("reprocess")
    reprocess.add_argument("--message-id", required=True)
    reprocess.add_argument("--normalized-dir", default="data/samples/emails")
    reprocess.add_argument("--attachments-dir", default="data/samples/attachments")
    reprocess.add_argument("--out-dir", required=True)
    reprocess.add_argument(
        "--history-dir",
        default=None,
        help="Optional directory with historical outputs (e.g., data/samples/gold).",
    )
    reprocess.add_argument(
        "--crm-mapping",
        default=None,
        help="Optional JSON file mapping sender email to policy numbers.",
    )
    reprocess.set_defaults(func=cmd_reprocess)

    hitl = sub.add_parser("hitl")
    hitl_sub = hitl.add_subparsers(dest="hitl_command", required=True)

    hitl_list = hitl_sub.add_parser("list")
    hitl_list.add_argument("--hitl-dir", default="hitl", help="HITL base directory.")
    hitl_list.add_argument("--queue-id", required=True, help="Queue id to list (canonical).")
    hitl_list.set_defaults(func=cmd_hitl_list)

    hitl_submit = hitl_sub.add_parser("submit-correction")
    hitl_submit.add_argument("--hitl-dir", default="hitl", help="HITL base directory.")
    hitl_submit.add_argument("--review-item-id", required=True, help="Review item id.")
    hitl_submit.add_argument("--actor-id", required=True, help="Reviewer identifier.")
    hitl_submit.add_argument("--corrections-json", required=True, help="Path to corrections JSON file.")
    hitl_submit.add_argument("--note", default=None, help="Optional free-text note.")
    hitl_submit.add_argument(
        "--audit-base-dir",
        default=None,
        help="Optional base directory to append audit events (creates <base>/audit).",
    )
    hitl_submit.set_defaults(func=cmd_hitl_submit_correction)

    retention = sub.add_parser("retention")
    retention_sub = retention.add_subparsers(dest="retention_command", required=True)

    retention_run = retention_sub.add_parser("run")
    retention_run.add_argument("--config", default="configs/prod.yaml", help="Config file (repo-relative).")
    retention_run.add_argument("--base-dir", required=True, help="Base dir containing raw_store/ for deletion.")
    retention_run.add_argument(
        "--derived-base-dir",
        default=None,
        help="Optional base dir for derived_store (defaults to --base-dir).",
    )
    retention_run.add_argument(
        "--normalized-dir",
        required=True,
        help="Directory with NormalizedMessage JSON files (repo-relative unless absolute).",
    )
    retention_run.add_argument(
        "--attachments-dir",
        required=True,
        help="Directory with AttachmentArtifact JSON files (repo-relative unless absolute).",
    )
    retention_run.add_argument(
        "--apply",
        action="store_true",
        help="Apply deletions (default is dry-run).",
    )
    retention_run.add_argument(
        "--now",
        default=None,
        help="Optional RFC3339 timestamp to use as 'now' (e.g., 2026-01-18T00:00:00Z).",
    )
    retention_run.add_argument(
        "--report-path",
        default=None,
        help="Optional path to write a JSON report (repo-relative unless absolute).",
    )
    retention_run.set_defaults(func=cmd_retention_run)

    loadtest = sub.add_parser("loadtest")
    loadtest_sub = loadtest.add_subparsers(dest="loadtest_command", required=True)

    loadtest_run = loadtest_sub.add_parser("run")
    loadtest_run.add_argument("--normalized-dir", default="data/samples/emails")
    loadtest_run.add_argument("--attachments-dir", default="data/samples/attachments")
    loadtest_run.add_argument("--iterations", default=1, type=int)
    loadtest_run.add_argument(
        "--config",
        default=None,
        help="Optional config file to apply to all messages (repo-relative unless absolute).",
    )
    loadtest_run.add_argument(
        "--crm-mapping",
        default=None,
        help="Optional JSON file mapping sender email to policy numbers.",
    )
    loadtest_run.add_argument(
        "--report-path",
        default=None,
        help="Optional path to write a JSON report (repo-relative unless absolute).",
    )
    loadtest_run.set_defaults(func=cmd_loadtest_run)

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
