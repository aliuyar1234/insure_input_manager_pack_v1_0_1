from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from typing import Optional

from ieim.identity.adapters import CRMAdapter, ClaimsAdapter, ClaimRecord, PolicyAdapter, PolicyRecord
from ieim.identity.identity_directory_client import IdentityDirectoryClient, IdentityDirectoryError


class IdentityDirectoryAmbiguousResultError(IdentityDirectoryError):
    pass


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _request_id(*, kind: str, value: str) -> str:
    h = _sha256_hex(value)
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"ieim:id_dir:{kind}:{h}"))


def _extract_candidates(obj: dict) -> list[dict]:
    candidates = obj.get("candidates")
    if not isinstance(candidates, list):
        return []
    return [c for c in candidates if isinstance(c, dict)]


@dataclass(frozen=True)
class IdentityDirectoryPolicyAdapter(PolicyAdapter):
    client: IdentityDirectoryClient
    top_k: int = 10

    def lookup_by_policy_number(self, *, policy_number: str) -> Optional[PolicyRecord]:
        req = {
            "request_id": _request_id(kind="policy_number", value=policy_number),
            "top_k": int(self.top_k),
            "allowed_entity_types": ["POLICY"],
            "signals": {"policy_number": policy_number},
            "options": {"include_relationships": True},
        }
        obj = self.client.search(request=req)
        candidates = _extract_candidates(obj)
        matches = []
        for c in candidates:
            if c.get("entity_type") != "POLICY":
                continue
            entity_id = c.get("entity_id")
            if isinstance(entity_id, str) and entity_id:
                matches.append(entity_id)
        matches = sorted(set(matches))
        if not matches:
            return None
        if len(matches) > 1:
            raise IdentityDirectoryAmbiguousResultError("multiple POLICY candidates returned for policy_number")
        return PolicyRecord(policy_id=matches[0], is_active=True)


@dataclass(frozen=True)
class IdentityDirectoryClaimsAdapter(ClaimsAdapter):
    client: IdentityDirectoryClient
    top_k: int = 10

    def lookup_by_claim_number(self, *, claim_number: str) -> Optional[ClaimRecord]:
        req = {
            "request_id": _request_id(kind="claim_number", value=claim_number),
            "top_k": int(self.top_k),
            "allowed_entity_types": ["CLAIM"],
            "signals": {"claim_number": claim_number},
            "options": {"include_relationships": True},
        }
        obj = self.client.search(request=req)
        candidates = _extract_candidates(obj)
        matches = []
        for c in candidates:
            if c.get("entity_type") != "CLAIM":
                continue
            entity_id = c.get("entity_id")
            if isinstance(entity_id, str) and entity_id:
                matches.append(entity_id)
        matches = sorted(set(matches))
        if not matches:
            return None
        if len(matches) > 1:
            raise IdentityDirectoryAmbiguousResultError("multiple CLAIM candidates returned for claim_number")
        return ClaimRecord(claim_id=matches[0], is_open=True)


@dataclass(frozen=True)
class IdentityDirectoryCRMAdapter(CRMAdapter):
    client: IdentityDirectoryClient
    top_k: int = 10

    def policy_numbers_for_sender_email(self, *, email: str) -> list[str]:
        req = {
            "request_id": _request_id(kind="email", value=email),
            "top_k": int(self.top_k),
            "allowed_entity_types": ["POLICY"],
            "signals": {"email": email},
            "options": {"include_relationships": True},
        }
        obj = self.client.search(request=req)
        candidates = _extract_candidates(obj)
        policy_numbers: set[str] = set()
        for c in candidates:
            if c.get("entity_type") != "POLICY":
                continue
            attrs = c.get("attributes") if isinstance(c.get("attributes"), dict) else {}
            pn = attrs.get("policy_number")
            if isinstance(pn, str) and pn:
                policy_numbers.add(pn)
        return sorted(policy_numbers)

