from __future__ import annotations

import json
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

from ieim.audit.file_audit_log import ArtifactRef, FileAuditLogger, build_audit_event
from ieim.case_adapter.adapter import CaseAdapter
from ieim.case_adapter.stage import CaseStage
from ieim.observability.file_observability_log import FileObservabilityLogger, build_observability_event
from ieim.raw_store import sha256_prefixed


def _parse_rfc3339(dt: str) -> datetime:
    if dt.endswith("Z"):
        dt = dt[:-1] + "+00:00"
    return datetime.fromisoformat(dt)


def _load_attachments(*, attachments_dir: Path, nm: dict) -> list[dict]:
    artifacts: list[dict] = []
    for att_id in nm.get("attachment_ids") or []:
        path = attachments_dir / f"{att_id}.artifact.json"
        if not path.exists():
            continue
        artifacts.append(json.loads(path.read_text(encoding="utf-8")))

    artifacts.sort(
        key=lambda a: (
            str(a.get("sha256") or ""),
            str(a.get("filename") or ""),
            str(a.get("attachment_id") or ""),
        )
    )
    return artifacts


def _load_optional_text(*, path: Path) -> Optional[str]:
    if not path.exists():
        return None
    return path.read_text(encoding="utf-8")


@dataclass
class CaseAdapterRunner:
    repo_root: Path
    normalized_dir: Path
    attachments_dir: Path
    routing_dir: Path
    drafts_dir: Path
    case_out_dir: Path
    adapter: CaseAdapter
    audit_logger: Optional[FileAuditLogger] = None
    obs_logger: Optional[FileObservabilityLogger] = None
    identity_dir: Optional[Path] = None
    classification_dir: Optional[Path] = None
    extraction_dir: Optional[Path] = None

    def run(self) -> list[dict]:
        produced: list[dict] = []
        self.case_out_dir.mkdir(parents=True, exist_ok=True)

        stage = CaseStage(adapter=self.adapter)

        for nm_path in sorted(self.normalized_dir.glob("*.json")):
            nm_bytes = nm_path.read_bytes()
            nm = json.loads(nm_bytes.decode("utf-8"))
            message_id = str(nm["message_id"])
            run_id = str(nm["run_id"])

            routing_path = self.routing_dir / f"{message_id}.routing.json"
            if not routing_path.exists():
                raise FileNotFoundError(f"missing routing decision: {routing_path}")
            routing_bytes = routing_path.read_bytes()
            routing = json.loads(routing_bytes.decode("utf-8"))

            attachments = _load_attachments(attachments_dir=self.attachments_dir, nm=nm)

            request_info_draft = _load_optional_text(
                path=self.drafts_dir / f"{message_id}.request_info.md"
            )
            reply_draft = _load_optional_text(path=self.drafts_dir / f"{message_id}.reply.md")

            identity = None
            classification = None
            extraction = None

            if self.identity_dir is not None:
                identity_path = self.identity_dir / f"{message_id}.identity.json"
                if identity_path.exists():
                    identity = json.loads(identity_path.read_text(encoding="utf-8"))

            if self.classification_dir is not None:
                cls_path = self.classification_dir / f"{message_id}.classification.json"
                if cls_path.exists():
                    classification = json.loads(cls_path.read_text(encoding="utf-8"))

            if self.extraction_dir is not None:
                ext_path = self.extraction_dir / f"{message_id}.extraction.json"
                if ext_path.exists():
                    extraction = json.loads(ext_path.read_text(encoding="utf-8"))

            audit_chain_head_sha256 = None
            if self.audit_logger is not None:
                audit_path = self.audit_logger.base_dir / "audit" / message_id / f"{run_id}.jsonl"
                if audit_path.exists():
                    events = []
                    for line in audit_path.read_text(encoding="utf-8").splitlines():
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            ev = json.loads(line)
                        except Exception:
                            continue
                        if isinstance(ev, dict):
                            events.append(ev)

                    if events:
                        first_case_idx = None
                        for idx, ev in enumerate(events):
                            if str(ev.get("stage") or "") == "CASE":
                                first_case_idx = idx
                                break
                        head_ev = None
                        if first_case_idx is None:
                            head_ev = events[-1]
                        elif first_case_idx > 0:
                            head_ev = events[first_case_idx - 1]

                        if head_ev is not None:
                            h = head_ev.get("event_hash")
                            if isinstance(h, str) and h:
                                audit_chain_head_sha256 = h

            status = "SKIPPED"
            case_id = None
            blocked = False
            failure_queue_id: Optional[str] = None
            error_type: Optional[str] = None
            error_message: Optional[str] = None

            t0 = time.perf_counter()
            try:
                result = stage.apply(
                    normalized_message=nm,
                    routing_decision=routing,
                    attachments=attachments,
                    identity_result=identity,
                    classification_result=classification,
                    extraction_result=extraction,
                    audit_chain_head_sha256=audit_chain_head_sha256,
                    request_info_draft=request_info_draft,
                    reply_draft=reply_draft,
                )
                case_id = result.case_id
                blocked = result.blocked
                if blocked:
                    status = "BLOCKED"
                elif case_id is not None:
                    status = "CREATED"
            except Exception as e:
                status = "FAILED"
                failure_queue_id = "QUEUE_CASE_CREATE_FAILURE_REVIEW"
                error_type = type(e).__name__
                error_message = str(e)
            dur_ms = int((time.perf_counter() - t0) * 1000)

            out = {
                "message_id": message_id,
                "run_id": run_id,
                "status": status,
                "case_id": case_id,
                "blocked": blocked,
                "failure_queue_id": failure_queue_id,
                "error_type": error_type,
                "error_message": error_message,
                "routing": {
                    "queue_id": str(routing.get("queue_id") or ""),
                    "sla_id": str(routing.get("sla_id") or ""),
                    "actions": list(routing.get("actions") or []),
                    "rule_id": str(routing.get("rule_id") or ""),
                    "rule_version": str(routing.get("rule_version") or ""),
                    "fail_closed": bool(routing.get("fail_closed") or False),
                    "fail_closed_reason": routing.get("fail_closed_reason"),
                },
            }

            out_path = self.case_out_dir / f"{message_id}.case.json"
            out_bytes = (
                json.dumps(out, indent=2, ensure_ascii=False, sort_keys=True).encode("utf-8") + b"\n"
            )
            tmp = out_path.with_suffix(out_path.suffix + ".tmp")
            tmp.write_bytes(out_bytes)
            tmp.replace(out_path)

            if self.obs_logger is not None:
                created_at_dt = _parse_rfc3339(str(nm["ingested_at"]))
                self.obs_logger.append(
                    build_observability_event(
                        event_type="STAGE_COMPLETE",
                        stage="CASE",
                        message_id=message_id,
                        run_id=run_id,
                        occurred_at=created_at_dt,
                        duration_ms=dur_ms,
                        status=status,
                        fields={"case_id": case_id or "", "blocked": blocked},
                    )
                )

            if self.audit_logger is not None:
                created_at_dt = _parse_rfc3339(str(nm["ingested_at"]))
                input_ref = ArtifactRef(
                    schema_id=str(routing["schema_id"]),
                    uri=routing_path.name,
                    sha256=sha256_prefixed(routing_bytes),
                )
                output_ref = ArtifactRef(
                    schema_id="CASE_RESULT",
                    uri=out_path.name,
                    sha256=sha256_prefixed(out_bytes),
                )
                evidence = []
                if error_type is not None and error_message is not None:
                    snippet = f"{error_type}: {error_message}"
                    if len(snippet) > 400:
                        snippet = snippet[:400]
                    evidence = [
                        {
                            "source": "CASE_ADAPTER_ERROR",
                            "start": 0,
                            "end": 0,
                            "snippet_redacted": snippet,
                            "snippet_sha256": sha256_prefixed(snippet.encode("utf-8")),
                        }
                    ]
                event = build_audit_event(
                    message_id=message_id,
                    run_id=run_id,
                    stage="CASE",
                    actor_type="SYSTEM",
                    created_at=created_at_dt,
                    input_ref=input_ref,
                    output_ref=output_ref,
                    decision_hash=None,
                    config_ref=None,
                    rules_ref=None,
                    model_info=None,
                    evidence=evidence,
                )
                self.audit_logger.append(event)

            produced.append(out)

        return produced
