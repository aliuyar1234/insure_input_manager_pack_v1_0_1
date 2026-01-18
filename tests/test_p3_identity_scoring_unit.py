import unittest
from dataclasses import replace
from decimal import Decimal
from pathlib import Path

from ieim.identity.adapters import InMemoryCRMAdapter, InMemoryClaimsAdapter, InMemoryPolicyAdapter
from ieim.identity.config import IdentityThresholds, load_identity_config
from ieim.identity.resolver import IdentityResolver


class TestP3IdentityScoringUnit(unittest.TestCase):
    def test_near_tie_margin_triggers_review(self) -> None:
        root = Path(__file__).resolve().parents[1]
        base_cfg = load_identity_config(path=root / "configs" / "prod.yaml")
        thresholds = IdentityThresholds(
            confirmed_min_score=base_cfg.thresholds.confirmed_min_score,
            confirmed_min_margin=Decimal("0.20"),
            probable_min_score=base_cfg.thresholds.probable_min_score,
            probable_min_margin=Decimal("0.12"),
        )
        cfg = replace(base_cfg, thresholds=thresholds)

        resolver = IdentityResolver(
            config=cfg,
            policy_adapter=InMemoryPolicyAdapter(),
            claims_adapter=InMemoryClaimsAdapter(),
            crm_adapter=InMemoryCRMAdapter({}),
        )

        nm = {
            "schema_id": "urn:ieim:schema:normalized-message:1.0.0",
            "schema_version": "1.0.0",
            "message_id": "00000000-0000-0000-0000-000000000001",
            "run_id": "00000000-0000-0000-0000-000000000002",
            "ingested_at": "2026-01-17T08:00:00Z",
            "raw_mime_sha256": "sha256:" + ("0" * 64),
            "from_email": "kunde@example.test",
            "to_emails": ["service@example.insure"],
            "subject_c14n": "nachreichung clm-2025-9911 polizzennr 45-1234567",
            "body_text_c14n": "polizzennr 45-1234567",
            "language": "de",
            "message_fingerprint": "sha256:" + ("1" * 64),
        }

        result, _draft, _evidence = resolver.resolve(normalized_message=nm, attachment_texts_c14n=[])

        self.assertEqual(result["status"], "IDENTITY_NEEDS_REVIEW")
        self.assertIsNone(result["selected_candidate"])
        self.assertEqual([c["rank"] for c in result["top_k"]], [1, 2])


if __name__ == "__main__":
    unittest.main()
