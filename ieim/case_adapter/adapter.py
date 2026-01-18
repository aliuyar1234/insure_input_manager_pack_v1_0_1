from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class CaseRecord:
    case_id: str
    queue_id: str
    artifacts: list[dict] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    drafts: list[str] = field(default_factory=list)


class CaseAdapter:
    def create_case(
        self,
        *,
        idempotency_key: str,
        queue_id: str,
        title: str,
        context: Optional[dict] = None,
    ) -> str:
        raise NotImplementedError

    def update_case(self, *, idempotency_key: str, case_id: str, title: Optional[str] = None) -> None:
        raise NotImplementedError

    def attach_artifact(self, *, idempotency_key: str, case_id: str, artifact: dict) -> None:
        raise NotImplementedError

    def add_note(self, *, idempotency_key: str, case_id: str, note: str) -> None:
        raise NotImplementedError

    def add_draft_message(self, *, idempotency_key: str, case_id: str, draft: str) -> None:
        raise NotImplementedError


class InMemoryCaseAdapter(CaseAdapter):
    """Idempotent in-memory adapter for tests and local demos."""

    def __init__(self) -> None:
        self._idempotency_index: dict[str, str] = {}
        self._cases: dict[str, CaseRecord] = {}
        self._applied_keys: set[str] = set()

    def get_case(self, case_id: str) -> CaseRecord:
        return self._cases[case_id]

    def create_case(
        self,
        *,
        idempotency_key: str,
        queue_id: str,
        title: str,
        context: Optional[dict] = None,
    ) -> str:
        existing = self._idempotency_index.get(idempotency_key)
        if existing is not None:
            return existing

        case_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"case:{idempotency_key}"))
        self._cases[case_id] = CaseRecord(case_id=case_id, queue_id=queue_id)
        self._cases[case_id].notes.append(f"TITLE: {title}")
        self._idempotency_index[idempotency_key] = case_id
        return case_id

    def update_case(self, *, idempotency_key: str, case_id: str, title: Optional[str] = None) -> None:
        if idempotency_key in self._applied_keys:
            return
        self._applied_keys.add(idempotency_key)

        case = self._cases[case_id]
        if title is not None:
            case.notes.append(f"TITLE_UPDATE: {title}")

    def attach_artifact(self, *, idempotency_key: str, case_id: str, artifact: dict) -> None:
        if idempotency_key in self._applied_keys:
            return
        self._applied_keys.add(idempotency_key)
        self._cases[case_id].artifacts.append(dict(artifact))

    def add_note(self, *, idempotency_key: str, case_id: str, note: str) -> None:
        if idempotency_key in self._applied_keys:
            return
        self._applied_keys.add(idempotency_key)
        self._cases[case_id].notes.append(note)

    def add_draft_message(self, *, idempotency_key: str, case_id: str, draft: str) -> None:
        if idempotency_key in self._applied_keys:
            return
        self._applied_keys.add(idempotency_key)
        self._cases[case_id].drafts.append(draft)
