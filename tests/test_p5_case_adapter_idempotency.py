import json
import tempfile
import unittest
from pathlib import Path
from typing import Optional

import jsonschema

from ieim.audit.file_audit_log import FileAuditLogger
from ieim.case_adapter.adapter import CaseAdapter, InMemoryCaseAdapter
from ieim.case_adapter.stage import CaseStage
from ieim.pipeline.p5_case_adapter import CaseAdapterRunner


class _FailingCaseAdapter(CaseAdapter):
    def create_case(self, *, idempotency_key: str, queue_id: str, title: str, context: Optional[dict] = None) -> str:
        raise RuntimeError("case backend unavailable")

    def update_case(self, *, idempotency_key: str, case_id: str, title: Optional[str] = None) -> None:
        raise RuntimeError("case backend unavailable")

    def attach_artifact(self, *, idempotency_key: str, case_id: str, artifact: dict) -> None:
        raise RuntimeError("case backend unavailable")

    def add_note(self, *, idempotency_key: str, case_id: str, note: str) -> None:
        raise RuntimeError("case backend unavailable")

    def add_draft_message(self, *, idempotency_key: str, case_id: str, draft: str) -> None:
        raise RuntimeError("case backend unavailable")


class TestP5CaseAdapterIdempotency(unittest.TestCase):
    def test_case_stage_idempotent_create_attach_and_drafts(self) -> None:
        adapter = InMemoryCaseAdapter()
        stage = CaseStage(adapter=adapter)

        nm = {
            "message_id": "11111111-1111-1111-1111-111111111111",
            "message_fingerprint": "sha256:" + ("1" * 64),
            "raw_mime_uri": "raw_store/mime/sample.eml",
            "raw_mime_sha256": "sha256:" + ("2" * 64),
            "subject": "Hello",
        }
        routing = {
            "actions": [
                "CREATE_CASE",
                "ATTACH_ORIGINAL_EMAIL",
                "ATTACH_ALL_FILES",
                "ADD_REQUEST_INFO_DRAFT",
                "ADD_REPLY_DRAFT",
            ],
            "queue_id": "QUEUE_POLICY_SERVICE",
            "rule_id": "ROUTE_TEST",
            "rule_version": "1.0.0",
        }
        attachments = [
            {
                "attachment_id": "att-1",
                "extracted_text_uri": "data/samples/attachments/att-1.txt",
                "sha256": "sha256:" + ("3" * 64),
            },
            {
                "attachment_id": "att-2",
                "extracted_text_uri": "data/samples/attachments/att-2.txt",
                "sha256": "sha256:" + ("4" * 64),
            },
        ]

        r1 = stage.apply(
            normalized_message=nm,
            routing_decision=routing,
            attachments=attachments,
            request_info_draft="REQUEST",
            reply_draft="REPLY",
        )
        r2 = stage.apply(
            normalized_message=nm,
            routing_decision=routing,
            attachments=attachments,
            request_info_draft="REQUEST",
            reply_draft="REPLY",
        )

        self.assertFalse(r1.blocked)
        self.assertEqual(r1.case_id, r2.case_id)
        self.assertIsNotNone(r1.case_id)

        case = adapter.get_case(r1.case_id or "")
        self.assertEqual(len(case.artifacts), 3)
        self.assertEqual(len(case.drafts), 2)
        self.assertEqual(sorted(case.drafts), ["REPLY", "REQUEST"])

        attachment_ids = {a.get("attachment_id") for a in case.artifacts if a.get("kind") == "ATTACHMENT"}
        self.assertEqual(attachment_ids, {"att-1", "att-2"})

    def test_block_case_create_prevents_creation(self) -> None:
        adapter = InMemoryCaseAdapter()
        stage = CaseStage(adapter=adapter)

        nm = {
            "message_fingerprint": "sha256:" + ("a" * 64),
            "raw_mime_uri": "raw_store/mime/sample.eml",
            "raw_mime_sha256": "sha256:" + ("b" * 64),
            "subject": "Hello",
        }
        routing = {
            "actions": ["BLOCK_CASE_CREATE", "CREATE_CASE", "ATTACH_ORIGINAL_EMAIL"],
            "queue_id": "QUEUE_SECURITY_REVIEW",
            "rule_id": "ROUTE_SECURITY_MALWARE",
            "rule_version": "1.0.0",
        }
        res = stage.apply(
            normalized_message=nm,
            routing_decision=routing,
            attachments=[],
        )
        self.assertTrue(res.blocked)
        self.assertIsNone(res.case_id)
        self.assertEqual(len(adapter._cases), 0)

    def test_missing_required_draft_fails_closed_without_side_effects(self) -> None:
        adapter = InMemoryCaseAdapter()
        stage = CaseStage(adapter=adapter)

        nm = {
            "message_fingerprint": "sha256:" + ("c" * 64),
            "raw_mime_uri": "raw_store/mime/sample.eml",
            "raw_mime_sha256": "sha256:" + ("d" * 64),
            "subject": "Hello",
        }
        routing = {
            "actions": ["CREATE_CASE", "ADD_REQUEST_INFO_DRAFT"],
            "queue_id": "QUEUE_IDENTITY_REVIEW",
            "rule_id": "ROUTE_IDENTITY_UNCERTAIN_REVIEW",
            "rule_version": "1.0.0",
        }

        with self.assertRaises(ValueError):
            stage.apply(
                normalized_message=nm,
                routing_decision=routing,
                attachments=[],
                request_info_draft=None,
            )

        self.assertEqual(len(adapter._cases), 0)

    def _event_hash(self, event: dict) -> str:
        event_no_hash = {k: v for k, v in event.items() if k != "event_hash"}
        encoded = json.dumps(event_no_hash, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
            "utf-8"
        )
        import hashlib

        return "sha256:" + hashlib.sha256(encoded).hexdigest()

    def test_case_adapter_runner_emits_audit_on_failure(self) -> None:
        root = Path(__file__).resolve().parents[1]
        audit_schema = json.loads((root / "schemas" / "audit_event.schema.json").read_text("utf-8"))
        audit_validator = jsonschema.Draft202012Validator(audit_schema)

        with tempfile.TemporaryDirectory() as td:
            base = Path(td)

            normalized_dir = base / "normalized"
            attachments_dir = base / "attachments"
            routing_dir = base / "routing"
            drafts_dir = base / "drafts"
            case_out_dir = base / "case"
            normalized_dir.mkdir(parents=True, exist_ok=True)
            attachments_dir.mkdir(parents=True, exist_ok=True)
            routing_dir.mkdir(parents=True, exist_ok=True)
            drafts_dir.mkdir(parents=True, exist_ok=True)

            message_id = "11111111-1111-1111-1111-111111111111"
            run_id = "22222222-2222-2222-2222-222222222222"

            nm = {
                "message_id": message_id,
                "run_id": run_id,
                "ingested_at": "2020-01-01T00:00:00Z",
                "attachment_ids": [],
                "message_fingerprint": "sha256:" + ("e" * 64),
                "raw_mime_uri": "raw_store/mime/sample.eml",
                "raw_mime_sha256": "sha256:" + ("f" * 64),
                "subject": "Hello",
            }
            (normalized_dir / f"{message_id}.json").write_text(json.dumps(nm), encoding="utf-8")

            routing = {
                "schema_id": "urn:ieim:schema:routing-decision:1.0.0",
                "queue_id": "QUEUE_POLICY_SERVICE",
                "sla_id": "SLA_1BD",
                "actions": ["CREATE_CASE"],
                "rule_id": "ROUTE_TEST",
                "rule_version": "1.0.0",
                "fail_closed": False,
                "fail_closed_reason": None,
            }
            (routing_dir / f"{message_id}.routing.json").write_text(json.dumps(routing), encoding="utf-8")

            audit_logger = FileAuditLogger(base_dir=base)
            runner = CaseAdapterRunner(
                repo_root=root,
                normalized_dir=normalized_dir,
                attachments_dir=attachments_dir,
                routing_dir=routing_dir,
                drafts_dir=drafts_dir,
                case_out_dir=case_out_dir,
                adapter=_FailingCaseAdapter(),
                audit_logger=audit_logger,
            )

            produced = runner.run()
            self.assertEqual(len(produced), 1)
            self.assertEqual(produced[0]["status"], "FAILED")
            self.assertEqual(produced[0]["failure_queue_id"], "QUEUE_CASE_CREATE_FAILURE_REVIEW")
            self.assertEqual(produced[0]["error_type"], "RuntimeError")

            audit_path = base / "audit" / message_id / f"{run_id}.jsonl"
            self.assertTrue(audit_path.exists())
            lines = [ln for ln in audit_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
            self.assertEqual(len(lines), 1)
            event = json.loads(lines[0])
            audit_validator.validate(event)
            self.assertEqual(event["stage"], "CASE")
            self.assertIsNone(event["decision_hash"])
            self.assertEqual(event["event_hash"], self._event_hash(event))


if __name__ == "__main__":
    unittest.main()
