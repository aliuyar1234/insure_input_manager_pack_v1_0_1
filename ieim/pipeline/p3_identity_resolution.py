from __future__ import annotations

import json
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

from ieim.audit.file_audit_log import ArtifactRef, FileAuditLogger, build_audit_event
from ieim.identity.adapters import CRMAdapter, ClaimsAdapter, PolicyAdapter
from ieim.identity.config import load_identity_config
from ieim.identity.config_select import select_config_path_for_message
from ieim.identity.resolver import IdentityResolver
from ieim.observability.file_observability_log import FileObservabilityLogger, build_observability_event
from ieim.raw_store import sha256_prefixed


def _parse_rfc3339(dt: str) -> datetime:
    if dt.endswith("Z"):
        dt = dt[:-1] + "+00:00"
    return datetime.fromisoformat(dt)


def _load_attachment_texts_c14n(*, repo_root: Path, attachments_dir: Path, nm: dict) -> list[str]:
    out: list[str] = []
    for att_id in nm.get("attachment_ids") or []:
        artifact_path = attachments_dir / f"{att_id}.artifact.json"
        if not artifact_path.exists():
            continue
        artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
        if artifact.get("av_status") != "CLEAN":
            continue
        uri = artifact.get("extracted_text_uri")
        if not isinstance(uri, str) or not uri:
            continue
        text_path = (repo_root / uri).resolve()
        if not text_path.exists():
            continue
        text = text_path.read_text(encoding="utf-8")
        out.append(text.lower())
    return out


@dataclass
class IdentityResolutionRunner:
    repo_root: Path
    normalized_dir: Path
    attachments_dir: Path
    identity_out_dir: Path
    drafts_out_dir: Path
    policy_adapter: PolicyAdapter
    claims_adapter: ClaimsAdapter
    crm_adapter: CRMAdapter
    audit_logger: Optional[FileAuditLogger] = None
    obs_logger: Optional[FileObservabilityLogger] = None
    config_path_override: Optional[Path] = None

    def run(self) -> list[dict]:
        produced: list[dict] = []
        self.identity_out_dir.mkdir(parents=True, exist_ok=True)
        self.drafts_out_dir.mkdir(parents=True, exist_ok=True)

        for nm_path in sorted(self.normalized_dir.glob("*.json")):
            nm_bytes = nm_path.read_bytes()
            nm = json.loads(nm_bytes.decode("utf-8"))

            config_path = self.config_path_override or select_config_path_for_message(
                repo_root=self.repo_root, normalized_message=nm
            )
            config = load_identity_config(path=config_path)

            attachment_texts_c14n = _load_attachment_texts_c14n(
                repo_root=self.repo_root, attachments_dir=self.attachments_dir, nm=nm
            )
            resolver = IdentityResolver(
                config=config,
                policy_adapter=self.policy_adapter,
                claims_adapter=self.claims_adapter,
                crm_adapter=self.crm_adapter,
            )
            t0 = time.perf_counter()
            result, request_info, evidence = resolver.resolve(
                normalized_message=nm, attachment_texts_c14n=attachment_texts_c14n
            )
            dur_ms = int((time.perf_counter() - t0) * 1000)

            out_path = self.identity_out_dir / f"{result['message_id']}.identity.json"
            out_bytes = (
                json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True).encode("utf-8")
                + b"\n"
            )
            tmp = out_path.with_suffix(out_path.suffix + ".tmp")
            tmp.write_bytes(out_bytes)
            tmp.replace(out_path)

            if request_info is not None:
                draft_path = self.drafts_out_dir / f"{result['message_id']}.request_info.md"
                draft_path.write_text(request_info, encoding="utf-8")

            if self.obs_logger is not None:
                created_at_dt = _parse_rfc3339(str(nm["ingested_at"]))
                self.obs_logger.append(
                    build_observability_event(
                        event_type="STAGE_COMPLETE",
                        stage="IDENTITY",
                        message_id=str(nm["message_id"]),
                        run_id=str(nm["run_id"]),
                        occurred_at=created_at_dt,
                        duration_ms=dur_ms,
                        status="OK",
                        fields={"identity_status": str(result.get("status") or "")},
                    )
                )

            if self.audit_logger is not None:
                created_at_dt = _parse_rfc3339(str(nm["ingested_at"]))
                input_ref = ArtifactRef(
                    schema_id=str(nm["schema_id"]),
                    uri=nm_path.name,
                    sha256=sha256_prefixed(nm_bytes),
                )
                output_ref = ArtifactRef(
                    schema_id=str(result["schema_id"]),
                    uri=out_path.name,
                    sha256=sha256_prefixed(out_bytes),
                )
                event = build_audit_event(
                    message_id=str(nm["message_id"]),
                    run_id=str(nm["run_id"]),
                    stage="IDENTITY",
                    actor_type="SYSTEM",
                    created_at=created_at_dt,
                    input_ref=input_ref,
                    output_ref=output_ref,
                    decision_hash=str(result["decision_hash"]),
                    config_ref={
                        "config_path": config.config_path,
                        "config_sha256": config.config_sha256,
                    },
                    evidence=evidence,
                )
                self.audit_logger.append(event)

            produced.append(result)

        return produced
