from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from ieim.audit.file_audit_log import ArtifactRef, FileAuditLogger, build_audit_event
from ieim.attachments.stage import AttachmentStage
from ieim.ingest.adapter import MailIngestAdapter
from ieim.ingest.cursor_store import CursorState, read_cursor, write_cursor
from ieim.normalize.normalized_message import build_normalized_message
from ieim.observability.file_observability_log import FileObservabilityLogger, build_observability_event
from ieim.raw_store import FileRawStore, sha256_prefixed


@dataclass(frozen=True)
class DedupeState:
    processed_raw_mime_sha256: set[str]


def read_dedupe_state(path: Path) -> DedupeState:
    if not path.exists():
        return DedupeState(processed_raw_mime_sha256=set())
    obj = json.loads(path.read_text(encoding="utf-8"))
    values = obj.get("processed_raw_mime_sha256", [])
    if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
        raise ValueError("invalid dedupe state")
    return DedupeState(processed_raw_mime_sha256=set(values))


def write_dedupe_state(path: Path, state: DedupeState) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    obj = {"processed_raw_mime_sha256": sorted(state.processed_raw_mime_sha256)}
    tmp.write_text(json.dumps(obj, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)


@dataclass
class IngestNormalizeRunner:
    adapter: MailIngestAdapter
    ingestion_source: str
    raw_store: FileRawStore
    state_dir: Path
    normalized_out_dir: Path
    audit_logger: Optional[FileAuditLogger] = None
    obs_logger: Optional[FileObservabilityLogger] = None
    attachment_stage: Optional[AttachmentStage] = None
    ingested_at_from_received_at: Optional[Callable[[datetime], datetime]] = None

    def _cursor_path(self) -> Path:
        return self.state_dir / "ingest_cursor.json"

    def _dedupe_path(self) -> Path:
        return self.state_dir / "dedupe_state.json"

    def _derive_message_id(self, *, source_message_id: str) -> str:
        try:
            uuid.UUID(source_message_id)
            return source_message_id
        except Exception:
            return str(
                uuid.uuid5(
                    uuid.NAMESPACE_URL, f"{self.ingestion_source}:{source_message_id}"
                )
            )

    def run_once(self, *, limit: int) -> list[dict]:
        cursor_state: CursorState = read_cursor(self._cursor_path())
        dedupe = read_dedupe_state(self._dedupe_path())

        refs, new_cursor = self.adapter.list_message_refs(
            cursor=cursor_state.cursor, limit=limit
        )

        produced: list[dict] = []

        for ref in refs:
            t_ingest0 = time.perf_counter()
            raw_mime = self.adapter.fetch_raw_mime(ref)
            raw_sha = sha256_prefixed(raw_mime)
            if raw_sha in dedupe.processed_raw_mime_sha256:
                continue

            put = self.raw_store.put_bytes(kind="mime", data=raw_mime, file_extension=".eml")
            ingest_ms = int((time.perf_counter() - t_ingest0) * 1000)

            message_id = self._derive_message_id(source_message_id=ref.source_message_id)
            run_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"run:{message_id}:{raw_sha}"))
            received_at = self.adapter.get_received_at(ref)
            now = (
                datetime.now(timezone.utc).replace(microsecond=0)
                if self.ingested_at_from_received_at is None
                else self.ingested_at_from_received_at(received_at).replace(microsecond=0)
            )

            processed_attachments = []
            attachment_ids = []
            if self.attachment_stage is not None:
                t_att0 = time.perf_counter()
                processed_attachments = self.attachment_stage.process_message(
                    message_id=message_id, source_ref=ref, created_at=now
                )
                att_ms = int((time.perf_counter() - t_att0) * 1000)
                attachment_ids = [p.attachment_id for p in processed_attachments]
                if self.obs_logger is not None:
                    self.obs_logger.append(
                        build_observability_event(
                            event_type="STAGE_COMPLETE",
                            stage="ATTACHMENTS",
                            message_id=message_id,
                            run_id=run_id,
                            occurred_at=now,
                            duration_ms=att_ms,
                            status="OK",
                            fields={"attachment_count": len(processed_attachments)},
                        )
                    )

            if self.obs_logger is not None:
                self.obs_logger.append(
                    build_observability_event(
                        event_type="STAGE_COMPLETE",
                        stage="INGEST",
                        message_id=message_id,
                        run_id=run_id,
                        occurred_at=now,
                        duration_ms=ingest_ms,
                        status="OK",
                        fields={"ingestion_source": self.ingestion_source},
                    )
                )

            t_norm0 = time.perf_counter()
            nm = build_normalized_message(
                raw_mime=raw_mime,
                message_id=message_id,
                run_id=run_id,
                ingested_at=now,
                received_at=received_at,
                ingestion_source=self.ingestion_source,
                raw_mime_uri=put.uri,
                raw_mime_sha256=put.sha256,
                attachment_ids=attachment_ids,
            )
            norm_ms = int((time.perf_counter() - t_norm0) * 1000)

            self.normalized_out_dir.mkdir(parents=True, exist_ok=True)
            out_path = self.normalized_out_dir / f"{message_id}.json"
            if out_path.exists():
                dedupe.processed_raw_mime_sha256.add(raw_sha)
                continue
            tmp = out_path.with_suffix(out_path.suffix + ".tmp")
            out_bytes = (
                json.dumps(nm, indent=2, ensure_ascii=False, sort_keys=True).encode("utf-8")
                + b"\n"
            )
            tmp.write_bytes(out_bytes)
            tmp.replace(out_path)

            if self.obs_logger is not None:
                self.obs_logger.append(
                    build_observability_event(
                        event_type="STAGE_COMPLETE",
                        stage="NORMALIZE",
                        message_id=message_id,
                        run_id=run_id,
                        occurred_at=now,
                        duration_ms=norm_ms,
                        status="OK",
                        fields={"normalized_bytes": len(out_bytes)},
                    )
                )

            if self.audit_logger is not None:
                raw_ref = ArtifactRef(schema_id="RAW_MIME", uri=put.uri, sha256=put.sha256)
                nm_ref = ArtifactRef(
                    schema_id=str(nm["schema_id"]),
                    uri=out_path.name,
                    sha256=sha256_prefixed(out_bytes),
                )

                ingest_event = build_audit_event(
                    message_id=message_id,
                    run_id=run_id,
                    stage="INGEST",
                    actor_type="SYSTEM",
                    created_at=now,
                    input_ref=raw_ref,
                    output_ref=raw_ref,
                    decision_hash=None,
                )
                self.audit_logger.append(ingest_event)

                normalize_event = build_audit_event(
                    message_id=message_id,
                    run_id=run_id,
                    stage="NORMALIZE",
                    actor_type="SYSTEM",
                    created_at=now,
                    input_ref=raw_ref,
                    output_ref=nm_ref,
                    decision_hash=None,
                )
                self.audit_logger.append(normalize_event)

                for p in processed_attachments:
                    event = build_audit_event(
                        message_id=message_id,
                        run_id=run_id,
                        stage="ATTACHMENTS",
                        actor_type="SYSTEM",
                        created_at=now,
                        input_ref=p.raw_ref,
                        output_ref=p.artifact_ref,
                        decision_hash=None,
                    )
                    self.audit_logger.append(event)

            dedupe.processed_raw_mime_sha256.add(raw_sha)
            produced.append(nm)

        write_dedupe_state(self._dedupe_path(), dedupe)
        write_cursor(self._cursor_path(), CursorState(cursor=new_cursor))
        return produced
