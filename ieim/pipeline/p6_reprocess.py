from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

from ieim.audit.file_audit_log import ArtifactRef, FileAuditLogger, build_audit_event
from ieim.classify.classifier import DeterministicClassifier
from ieim.config import IEIMConfig, load_config
from ieim.extract.extractor import DeterministicExtractor
from ieim.identity.adapters import InMemoryCRMAdapter, InMemoryClaimsAdapter, InMemoryPolicyAdapter
from ieim.identity.config import load_identity_config
from ieim.identity.config_select import select_config_path_for_message
from ieim.identity.resolver import IdentityResolver
from ieim.observability.file_observability_log import FileObservabilityLogger, build_observability_event
from ieim.raw_store import sha256_prefixed
from ieim.route.evaluator import evaluate_routing


def _parse_rfc3339(dt: str) -> datetime:
    if dt.endswith("Z"):
        dt = dt[:-1] + "+00:00"
    return datetime.fromisoformat(dt)


def _write_bytes_immutably(*, path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        existing = path.read_bytes()
        if existing != data:
            raise RuntimeError(f"immutability violation: existing content mismatch: {path}")
        return
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(data)
    tmp.replace(path)


def _write_text_immutably(*, path: Path, text: str) -> None:
    _write_bytes_immutably(path=path, data=text.encode("utf-8"))


def _load_attachments(*, attachments_dir: Path, nm: dict) -> list[dict]:
    out: list[dict] = []
    for att_id in nm.get("attachment_ids") or []:
        artifact_path = attachments_dir / f"{att_id}.artifact.json"
        if not artifact_path.exists():
            raise FileNotFoundError(f"missing attachment artifact: {artifact_path}")
        out.append(json.loads(artifact_path.read_text(encoding="utf-8")))
    return out


def _load_attachment_texts_c14n(*, repo_root: Path, attachments: list[dict]) -> list[str]:
    out: list[str] = []
    for artifact in attachments:
        if artifact.get("av_status") != "CLEAN":
            continue
        uri = artifact.get("extracted_text_uri")
        if not isinstance(uri, str) or not uri:
            continue
        text_path = (repo_root / uri).resolve()
        if not text_path.exists():
            raise FileNotFoundError(f"missing extracted text: {text_path}")
        text = text_path.read_text(encoding="utf-8")
        out.append(text.lower())
    return out


def _verify_raw_mime(*, repo_root: Path, nm: dict) -> Optional[str]:
    uri = nm.get("raw_mime_uri")
    expected_sha = nm.get("raw_mime_sha256")
    if not isinstance(uri, str) or not uri:
        return "missing raw_mime_uri"
    if not isinstance(expected_sha, str) or not expected_sha:
        return "missing raw_mime_sha256"
    path = (repo_root / uri).resolve()
    if not path.exists():
        return f"missing raw mime file: {path}"
    actual = sha256_prefixed(path.read_bytes())
    if actual != expected_sha:
        return f"raw mime sha256 mismatch: {actual} != {expected_sha}"
    return None


def _verify_attachment_texts(*, repo_root: Path, attachments: list[dict]) -> list[str]:
    errors: list[str] = []
    for artifact in attachments:
        uri = artifact.get("extracted_text_uri")
        expected_sha = artifact.get("extracted_text_sha256")
        if uri is None:
            continue
        if not isinstance(uri, str) or not uri:
            errors.append("invalid extracted_text_uri")
            continue
        if expected_sha is None:
            continue
        if not isinstance(expected_sha, str) or not expected_sha:
            errors.append(f"{uri}: invalid extracted_text_sha256")
            continue
        path = (repo_root / uri).resolve()
        if not path.exists():
            errors.append(f"{uri}: missing extracted text file")
            continue
        actual = sha256_prefixed(path.read_bytes())
        if actual != expected_sha:
            errors.append(f"{uri}: sha256 mismatch: {actual} != {expected_sha}")
    return errors


def _load_history_decision_hashes(*, history_dir: Path, message_id: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for suffix, key in [
        ("identity.json", "IDENTITY"),
        ("classification.json", "CLASSIFY"),
        ("routing.json", "ROUTE"),
    ]:
        path = history_dir / f"{message_id}.{suffix}"
        if not path.exists():
            raise FileNotFoundError(f"missing history output: {path}")
        obj = json.loads(path.read_text(encoding="utf-8"))
        dh = obj.get("decision_hash")
        if not isinstance(dh, str) or not dh:
            raise ValueError(f"missing decision_hash in {path}")
        out[key] = dh
    return out


@dataclass
class ReprocessRunner:
    repo_root: Path
    normalized_dir: Path
    attachments_dir: Path
    out_dir: Path
    message_id: str
    crm_mapping: dict[str, list[str]]
    history_dir: Optional[Path] = None

    def _load_config(self, *, nm: dict) -> IEIMConfig:
        config_path = select_config_path_for_message(repo_root=self.repo_root, normalized_message=nm)
        return load_config(path=config_path)

    def run(self) -> dict:
        t_total0 = time.perf_counter()
        nm_path = self.normalized_dir / f"{self.message_id}.json"
        if not nm_path.exists():
            raise FileNotFoundError(f"missing normalized message: {nm_path}")
        nm_bytes = nm_path.read_bytes()
        nm = json.loads(nm_bytes.decode("utf-8"))

        if str(nm.get("message_id") or "") != self.message_id:
            raise ValueError(f"message_id mismatch in {nm_path}")

        attachments = _load_attachments(attachments_dir=self.attachments_dir, nm=nm)

        raw_mime_error = _verify_raw_mime(repo_root=self.repo_root, nm=nm)
        attachment_text_errors = _verify_attachment_texts(repo_root=self.repo_root, attachments=attachments)

        reprocess_run_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"reprocess:{self.message_id}:{nm.get('run_id')}"))
        run_dir = self.out_dir / "reprocess" / self.message_id / reprocess_run_id
        audit_logger = FileAuditLogger(base_dir=run_dir)
        obs_logger = FileObservabilityLogger(base_dir=run_dir)

        nm_reprocess = dict(nm)
        nm_reprocess["run_id"] = reprocess_run_id
        nm_reprocess_bytes = (
            json.dumps(nm_reprocess, indent=2, ensure_ascii=False, sort_keys=True).encode("utf-8") + b"\n"
        )
        nm_out_path = run_dir / "normalized" / f"{self.message_id}.json"
        _write_bytes_immutably(path=nm_out_path, data=nm_reprocess_bytes)

        created_at_dt = _parse_rfc3339(str(nm.get("ingested_at") or "1970-01-01T00:00:00Z"))
        nm_ref = ArtifactRef(
            schema_id=str(nm_reprocess.get("schema_id") or ""),
            uri=nm_out_path.name,
            sha256=sha256_prefixed(nm_reprocess_bytes),
        )

        report: dict = {
            "message_id": self.message_id,
            "historical_run_id": str(nm.get("run_id") or ""),
            "reprocess_run_id": reprocess_run_id,
            "artifact_verification": {
                "raw_mime_error": raw_mime_error,
                "attachment_text_errors": attachment_text_errors,
            },
            "decision_hash_comparison": None,
            "status": None,
        }

        if raw_mime_error is not None or attachment_text_errors:
            report["status"] = "REVIEW_REQUIRED"
            report_path = run_dir / "reprocess_report.json"
            report_bytes = (
                json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True).encode("utf-8") + b"\n"
            )
            _write_bytes_immutably(path=report_path, data=report_bytes)

            obs_logger.append(
                build_observability_event(
                    event_type="STAGE_COMPLETE",
                    stage="REPROCESS",
                    message_id=self.message_id,
                    run_id=reprocess_run_id,
                    occurred_at=created_at_dt,
                    duration_ms=int((time.perf_counter() - t_total0) * 1000),
                    status="REVIEW_REQUIRED",
                    fields={},
                )
            )

            event = build_audit_event(
                message_id=self.message_id,
                run_id=reprocess_run_id,
                stage="REPROCESS",
                actor_type="JOB",
                created_at=created_at_dt,
                input_ref=nm_ref,
                output_ref=ArtifactRef(
                    schema_id="REPROCESS_REPORT",
                    uri=report_path.name,
                    sha256=sha256_prefixed(report_bytes),
                ),
                decision_hash=None,
                config_ref=None,
                rules_ref=None,
                model_info=None,
                evidence=[],
            )
            audit_logger.append(event)
            return report

        # Identity
        id_config_path = select_config_path_for_message(repo_root=self.repo_root, normalized_message=nm_reprocess)
        id_cfg = load_identity_config(path=id_config_path)
        resolver = IdentityResolver(
            config=id_cfg,
            policy_adapter=InMemoryPolicyAdapter(),
            claims_adapter=InMemoryClaimsAdapter(),
            crm_adapter=InMemoryCRMAdapter(self.crm_mapping),
        )

        attachment_texts_c14n = _load_attachment_texts_c14n(repo_root=self.repo_root, attachments=attachments)
        t_id0 = time.perf_counter()
        identity, request_info, evidence = resolver.resolve(
            normalized_message=nm_reprocess, attachment_texts_c14n=attachment_texts_c14n
        )
        id_ms = int((time.perf_counter() - t_id0) * 1000)

        identity_path = run_dir / "identity" / f"{self.message_id}.identity.json"
        identity_bytes = (
            json.dumps(identity, indent=2, ensure_ascii=False, sort_keys=True).encode("utf-8") + b"\n"
        )
        _write_bytes_immutably(path=identity_path, data=identity_bytes)

        if request_info is not None:
            draft_path = run_dir / "drafts" / f"{self.message_id}.request_info.md"
            _write_text_immutably(path=draft_path, text=request_info)

        audit_logger.append(
            build_audit_event(
                message_id=self.message_id,
                run_id=reprocess_run_id,
                stage="IDENTITY",
                actor_type="JOB",
                created_at=created_at_dt,
                input_ref=nm_ref,
                output_ref=ArtifactRef(
                    schema_id=str(identity.get("schema_id") or ""),
                    uri=identity_path.name,
                    sha256=sha256_prefixed(identity_bytes),
                ),
                decision_hash=str(identity["decision_hash"]),
                config_ref={"config_path": id_cfg.config_path, "config_sha256": id_cfg.config_sha256},
                rules_ref=None,
                model_info=None,
                evidence=evidence,
            )
        )
        obs_logger.append(
            build_observability_event(
                event_type="STAGE_COMPLETE",
                stage="IDENTITY",
                message_id=self.message_id,
                run_id=reprocess_run_id,
                occurred_at=created_at_dt,
                duration_ms=id_ms,
                status="OK",
                fields={"identity_status": str(identity.get("status") or "")},
            )
        )

        # Classify + Extract
        cfg = self._load_config(nm=nm_reprocess)
        classifier = DeterministicClassifier(config=cfg)
        t_cls0 = time.perf_counter()
        cls = classifier.classify(normalized_message=nm_reprocess, attachments=attachments)
        cls_ms = int((time.perf_counter() - t_cls0) * 1000)
        t_ex0 = time.perf_counter()
        extraction = DeterministicExtractor(config=cfg).extract(
            normalized_message=nm_reprocess, attachments=attachments
        )
        ex_ms = int((time.perf_counter() - t_ex0) * 1000)

        cls_path = run_dir / "classification" / f"{self.message_id}.classification.json"
        cls_bytes = (
            json.dumps(cls.result, indent=2, ensure_ascii=False, sort_keys=True).encode("utf-8") + b"\n"
        )
        _write_bytes_immutably(path=cls_path, data=cls_bytes)

        ex_path = run_dir / "extraction" / f"{self.message_id}.extraction.json"
        ex_bytes = (
            json.dumps(extraction, indent=2, ensure_ascii=False, sort_keys=True).encode("utf-8") + b"\n"
        )
        _write_bytes_immutably(path=ex_path, data=ex_bytes)

        cls_ref = ArtifactRef(
            schema_id=str(cls.result.get("schema_id") or ""),
            uri=cls_path.name,
            sha256=sha256_prefixed(cls_bytes),
        )
        audit_logger.append(
            build_audit_event(
                message_id=self.message_id,
                run_id=reprocess_run_id,
                stage="CLASSIFY",
                actor_type="JOB",
                created_at=created_at_dt,
                input_ref=nm_ref,
                output_ref=cls_ref,
                decision_hash=str(cls.result["decision_hash"]),
                config_ref={"config_path": cfg.config_path, "config_sha256": cfg.config_sha256},
                rules_ref=cls.rules_ref,
                model_info=None,
                evidence=[],
            )
        )
        obs_logger.append(
            build_observability_event(
                event_type="STAGE_COMPLETE",
                stage="CLASSIFY",
                message_id=self.message_id,
                run_id=reprocess_run_id,
                occurred_at=created_at_dt,
                duration_ms=cls_ms,
                status="OK",
                fields={"primary_intent": str(cls.result.get("primary_intent", {}).get("label") or "")},
            )
        )

        ex_ref = ArtifactRef(
            schema_id=str(extraction.get("schema_id") or ""),
            uri=ex_path.name,
            sha256=sha256_prefixed(ex_bytes),
        )
        audit_logger.append(
            build_audit_event(
                message_id=self.message_id,
                run_id=reprocess_run_id,
                stage="EXTRACT",
                actor_type="JOB",
                created_at=created_at_dt,
                input_ref=cls_ref,
                output_ref=ex_ref,
                decision_hash=None,
                config_ref={"config_path": cfg.config_path, "config_sha256": cfg.config_sha256},
                rules_ref=None,
                model_info=None,
                evidence=[],
            )
        )
        obs_logger.append(
            build_observability_event(
                event_type="STAGE_COMPLETE",
                stage="EXTRACT",
                message_id=self.message_id,
                run_id=reprocess_run_id,
                occurred_at=created_at_dt,
                duration_ms=ex_ms,
                status="OK",
                fields={"entity_count": len(extraction.get("entities") or [])},
            )
        )

        # Route
        t_route0 = time.perf_counter()
        route_result = evaluate_routing(
            repo_root=self.repo_root,
            config=cfg,
            normalized_message=nm_reprocess,
            identity_result=identity,
            classification_result=cls.result,
        )
        route_ms = int((time.perf_counter() - t_route0) * 1000)
        routing = route_result.decision

        routing_path = run_dir / "routing" / f"{self.message_id}.routing.json"
        routing_bytes = (
            json.dumps(routing, indent=2, ensure_ascii=False, sort_keys=True).encode("utf-8") + b"\n"
        )
        _write_bytes_immutably(path=routing_path, data=routing_bytes)

        routing_ref = ArtifactRef(
            schema_id=str(routing.get("schema_id") or ""),
            uri=routing_path.name,
            sha256=sha256_prefixed(routing_bytes),
        )
        audit_logger.append(
            build_audit_event(
                message_id=self.message_id,
                run_id=reprocess_run_id,
                stage="ROUTE",
                actor_type="JOB",
                created_at=created_at_dt,
                input_ref=cls_ref,
                output_ref=routing_ref,
                decision_hash=str(routing["decision_hash"]),
                config_ref={"config_path": cfg.config_path, "config_sha256": cfg.config_sha256},
                rules_ref=route_result.rules_ref,
                model_info=None,
                evidence=[],
            )
        )
        obs_logger.append(
            build_observability_event(
                event_type="STAGE_COMPLETE",
                stage="ROUTE",
                message_id=self.message_id,
                run_id=reprocess_run_id,
                occurred_at=created_at_dt,
                duration_ms=route_ms,
                status="OK",
                fields={"queue_id": str(routing.get("queue_id") or "")},
            )
        )

        comparison = None
        if self.history_dir is not None:
            hist = _load_history_decision_hashes(history_dir=self.history_dir, message_id=self.message_id)
            comparison = {
                "IDENTITY": {
                    "historical": hist["IDENTITY"],
                    "reprocess": identity["decision_hash"],
                    "match": hist["IDENTITY"] == identity["decision_hash"],
                },
                "CLASSIFY": {
                    "historical": hist["CLASSIFY"],
                    "reprocess": cls.result["decision_hash"],
                    "match": hist["CLASSIFY"] == cls.result["decision_hash"],
                },
                "ROUTE": {
                    "historical": hist["ROUTE"],
                    "reprocess": routing["decision_hash"],
                    "match": hist["ROUTE"] == routing["decision_hash"],
                },
            }
            report["decision_hash_comparison"] = comparison
            report["status"] = "OK" if all(v["match"] for v in comparison.values()) else "MISMATCH"
        else:
            report["status"] = "OK"

        report_path = run_dir / "reprocess_report.json"
        report_bytes = (
            json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True).encode("utf-8") + b"\n"
        )
        _write_bytes_immutably(path=report_path, data=report_bytes)

        audit_logger.append(
            build_audit_event(
                message_id=self.message_id,
                run_id=reprocess_run_id,
                stage="REPROCESS",
                actor_type="JOB",
                created_at=created_at_dt,
                input_ref=routing_ref,
                output_ref=ArtifactRef(
                    schema_id="REPROCESS_REPORT",
                    uri=report_path.name,
                    sha256=sha256_prefixed(report_bytes),
                ),
                decision_hash=None,
                config_ref=None,
                rules_ref=None,
                model_info=None,
                evidence=[],
            )
        )
        obs_logger.append(
            build_observability_event(
                event_type="STAGE_COMPLETE",
                stage="REPROCESS",
                message_id=self.message_id,
                run_id=reprocess_run_id,
                occurred_at=created_at_dt,
                duration_ms=int((time.perf_counter() - t_total0) * 1000),
                status=str(report.get("status") or ""),
                fields={},
            )
        )

        return report
