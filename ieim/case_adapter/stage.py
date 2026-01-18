from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ieim.case_adapter.adapter import CaseAdapter
from ieim.case_adapter.idempotency import build_idempotency_key


def _best_ref_from_extraction(*, extraction_result: Optional[dict], message_id: str) -> str:
    if extraction_result is not None:
        entities = extraction_result.get("entities") or []
        if isinstance(entities, list):
            for target in ("ENT_CLAIM_NUMBER", "ENT_POLICY_NUMBER"):
                for ent in entities:
                    if not isinstance(ent, dict):
                        continue
                    if ent.get("entity_type") != target:
                        continue
                    for field in ("value_redacted", "value", "value_sha256"):
                        v = ent.get(field)
                        if isinstance(v, str) and v:
                            return v
    return message_id


def _case_title(
    *,
    normalized_message: dict,
    classification_result: Optional[dict],
    extraction_result: Optional[dict],
) -> str:
    message_id = str(normalized_message.get("message_id") or "")
    subject = str(normalized_message.get("subject") or "")
    if not message_id or classification_result is None:
        return subject

    primary = classification_result.get("primary_intent") or {}
    product = classification_result.get("product_line") or {}
    primary_label = str(primary.get("label") or "")
    product_label = str(product.get("label") or "")
    if not primary_label or not product_label:
        return subject

    best_ref = _best_ref_from_extraction(extraction_result=extraction_result, message_id=message_id)
    return f"[IEIM] {primary_label} {product_label} {best_ref}"


@dataclass(frozen=True)
class CaseStageResult:
    case_id: Optional[str]
    blocked: bool


@dataclass
class CaseStage:
    adapter: CaseAdapter

    def apply(
        self,
        *,
        normalized_message: dict,
        routing_decision: dict,
        attachments: list[dict],
        identity_result: Optional[dict] = None,
        classification_result: Optional[dict] = None,
        extraction_result: Optional[dict] = None,
        audit_chain_head_sha256: Optional[str] = None,
        request_info_draft: Optional[str] = None,
        reply_draft: Optional[str] = None,
    ) -> CaseStageResult:
        actions = list(routing_decision.get("actions") or [])
        message_fingerprint = str(normalized_message.get("message_fingerprint") or "")
        message_id = str(normalized_message.get("message_id") or "")
        rule_id = str(routing_decision.get("rule_id") or "")
        rule_version = str(routing_decision.get("rule_version") or "")

        if "BLOCK_CASE_CREATE" in actions:
            return CaseStageResult(case_id=None, blocked=True)

        create_case = "CREATE_CASE" in actions
        if create_case and "ADD_REQUEST_INFO_DRAFT" in actions and request_info_draft is None:
            raise ValueError("request_info_draft is required by routing action")
        if create_case and "ADD_REPLY_DRAFT" in actions and reply_draft is None:
            raise ValueError("reply_draft is required by routing action")

        case_id: Optional[str] = None
        if create_case:
            if not message_id:
                raise ValueError("normalized_message.message_id is required to create a case")
            key = f"IEIM:{message_id}"
            case_id = self.adapter.create_case(
                idempotency_key=key,
                queue_id=str(routing_decision.get("queue_id") or ""),
                title=_case_title(
                    normalized_message=normalized_message,
                    classification_result=classification_result,
                    extraction_result=extraction_result,
                ),
                context={
                    "normalized_message": normalized_message,
                    "identity_result": identity_result,
                    "classification_result": classification_result,
                    "extraction_result": extraction_result,
                    "routing_decision": routing_decision,
                    "audit_chain_head_sha256": audit_chain_head_sha256,
                },
            )

        if case_id is None:
            return CaseStageResult(case_id=None, blocked=False)

        if "ATTACH_ORIGINAL_EMAIL" in actions:
            key = build_idempotency_key(
                message_fingerprint=message_fingerprint,
                rule_id=rule_id,
                rule_version=rule_version,
                operation="ATTACH_ORIGINAL_EMAIL",
            )
            self.adapter.attach_artifact(
                idempotency_key=key,
                case_id=case_id,
                artifact={
                    "uri": str(normalized_message.get("raw_mime_uri") or ""),
                    "sha256": str(normalized_message.get("raw_mime_sha256") or ""),
                    "kind": "RAW_MIME",
                },
            )

        if "ATTACH_ALL_FILES" in actions:
            for att in attachments:
                att_id = str(att.get("attachment_id") or "")
                key = build_idempotency_key(
                    message_fingerprint=message_fingerprint,
                    rule_id=rule_id,
                    rule_version=rule_version,
                    operation=f"ATTACH:{att_id}",
                )
                self.adapter.attach_artifact(
                    idempotency_key=key,
                    case_id=case_id,
                    artifact={
                        "uri": str(att.get("extracted_text_uri") or ""),
                        "sha256": str(att.get("sha256") or ""),
                        "kind": "ATTACHMENT",
                        "attachment_id": att_id,
                        "filename": str(att.get("filename") or ""),
                        "mime_type": str(att.get("mime_type") or ""),
                    },
                )

        if "ADD_REQUEST_INFO_DRAFT" in actions:
            key = build_idempotency_key(
                message_fingerprint=message_fingerprint,
                rule_id=rule_id,
                rule_version=rule_version,
                operation="ADD_REQUEST_INFO_DRAFT",
            )
            self.adapter.add_draft_message(idempotency_key=key, case_id=case_id, draft=request_info_draft)

        if "ADD_REPLY_DRAFT" in actions:
            key = build_idempotency_key(
                message_fingerprint=message_fingerprint,
                rule_id=rule_id,
                rule_version=rule_version,
                operation="ADD_REPLY_DRAFT",
            )
            self.adapter.add_draft_message(idempotency_key=key, case_id=case_id, draft=reply_draft)

        return CaseStageResult(case_id=case_id, blocked=False)
