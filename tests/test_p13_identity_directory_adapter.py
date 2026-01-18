import unittest
from pathlib import Path

from ieim.identity.config import load_identity_config
from ieim.identity.identity_directory_adapters import (
    IdentityDirectoryClaimsAdapter,
    IdentityDirectoryCRMAdapter,
    IdentityDirectoryPolicyAdapter,
)
from ieim.identity.identity_directory_client import (
    IdentityDirectoryClient,
    IdentityDirectoryClientConfig,
    IdentityDirectoryDependencyError,
)
from ieim.identity.identity_directory_mock import IdentityDirectoryMockServer, IdentityDirectoryMockState
from ieim.identity.resolver import IdentityResolver


class TestP13IdentityDirectoryAdapter(unittest.TestCase):
    def test_client_search_contract_and_auth(self) -> None:
        state = IdentityDirectoryMockState(
            token="TEST_TOKEN",
            mode="OK",
            candidates=[
                {
                    "entity_type": "POLICY",
                    "entity_id": "POL-2024-00012345",
                    "source_system": "policy_core",
                    "attributes": {"policy_number": "POL-2024-00012345"},
                    "relationships": {},
                    "matched_signals": [],
                }
            ],
        )

        with IdentityDirectoryMockServer(state=state) as server:
            self.assertIsNotNone(server.base_url)
            client = IdentityDirectoryClient(
                config=IdentityDirectoryClientConfig(
                    base_url=str(server.base_url),
                    token_provider=lambda: "TEST_TOKEN",
                )
            )
            req = {
                "request_id": "req_1",
                "top_k": 10,
                "allowed_entity_types": ["POLICY"],
                "signals": {"policy_number": "45-1234567"},
                "options": {"include_relationships": True},
            }
            resp = client.search(request=req)
            self.assertIn("candidates", resp)
            self.assertIsNotNone(state.last_search_request)
            self.assertEqual(state.last_search_request.get("request_id"), "req_1")

    def test_dependency_error_fails_closed_to_review(self) -> None:
        state = IdentityDirectoryMockState(token="TEST_TOKEN", mode="503", candidates=[])

        with IdentityDirectoryMockServer(state=state) as server:
            client = IdentityDirectoryClient(
                config=IdentityDirectoryClientConfig(
                    base_url=str(server.base_url),
                    token_provider=lambda: "TEST_TOKEN",
                )
            )

            policy_adapter = IdentityDirectoryPolicyAdapter(client=client)
            claims_adapter = IdentityDirectoryClaimsAdapter(client=client)
            crm_adapter = IdentityDirectoryCRMAdapter(client=client)

            root = Path(__file__).resolve().parents[1]
            cfg = load_identity_config(path=root / "configs" / "dev.yaml")
            resolver = IdentityResolver(
                config=cfg,
                policy_adapter=policy_adapter,
                claims_adapter=claims_adapter,
                crm_adapter=crm_adapter,
            )

            nm = {
                "schema_id": "urn:ieim:schema:normalized-message:1.0.0",
                "schema_version": "1.0.0",
                "message_id": "00000000-0000-0000-0000-000000000101",
                "run_id": "00000000-0000-0000-0000-000000000102",
                "ingested_at": "2026-01-17T08:00:00Z",
                "raw_mime_sha256": "sha256:" + ("0" * 64),
                "from_email": "kunde@example.test",
                "to_emails": ["service@example.insure"],
                "subject_c14n": "polizzennr 45-1234567",
                "body_text_c14n": "polizzennr 45-1234567",
                "language": "de",
                "message_fingerprint": "sha256:" + ("1" * 64),
            }

            result, _draft, evidence = resolver.resolve(normalized_message=nm, attachment_texts_c14n=[])
            self.assertEqual(result["status"], "IDENTITY_NEEDS_REVIEW")
            self.assertGreaterEqual(len(evidence), 1)
            self.assertEqual(evidence[0].get("source"), "DEPENDENCY_ID_DIR")

            with self.assertRaises(IdentityDirectoryDependencyError):
                client.search(
                    request={
                        "request_id": "req_2",
                        "top_k": 10,
                        "allowed_entity_types": ["POLICY"],
                        "signals": {"policy_number": "45-1234567"},
                        "options": {"include_relationships": True},
                    }
                )


if __name__ == "__main__":
    unittest.main()

