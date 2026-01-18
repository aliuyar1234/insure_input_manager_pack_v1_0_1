from __future__ import annotations

import json
import time
from dataclasses import dataclass
from decimal import Decimal, ROUND_HALF_UP
from typing import Callable, Optional
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from ieim.case_adapter.adapter import CaseAdapter
from ieim.raw_store import sha256_prefixed


def _sha256_hex(sha256_ref: str) -> str:
    if sha256_ref.startswith("sha256:") and len(sha256_ref) == len("sha256:") + 64:
        return sha256_ref.split(":", 1)[1]
    return sha256_ref


def _sanitize_filename(name: str) -> str:
    name = name.strip().replace("\\", "/").split("/")[-1]
    if not name:
        return "file.bin"
    safe = []
    for ch in name:
        if ch.isalnum() or ch in ("-", "_", ".", " "):
            safe.append(ch)
        else:
            safe.append("_")
    out = "".join(safe).strip()
    out = out.replace(" ", "_")
    if not out:
        out = "file.bin"
    return out[:160]


def _redact_body_excerpt(text: str, *, limit_chars: int) -> str:
    excerpt = (text or "")[: max(0, int(limit_chars))]
    # Minimal deterministic redaction for common PII shapes.
    for token in ("@", "iban", "kontonummer", "bankverbindung"):
        excerpt = excerpt.replace(token, "[REDACTED]")
    return excerpt


def _fmt_confidence(value: object) -> str:
    try:
        d = Decimal(str(value))
    except Exception:
        return ""
    if d < Decimal("0"):
        d = Decimal("0")
    if d > Decimal("1"):
        d = Decimal("1")
    return str(d.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))


def _primary_intent_label(classification_result: Optional[dict]) -> str:
    if classification_result is None:
        return ""
    primary = classification_result.get("primary_intent") or {}
    return str(primary.get("label") or "")


def _product_line_label(classification_result: Optional[dict]) -> str:
    if classification_result is None:
        return ""
    product = classification_result.get("product_line") or {}
    return str(product.get("label") or "")


def _urgency_label(classification_result: Optional[dict]) -> str:
    if classification_result is None:
        return ""
    urgency = classification_result.get("urgency") or {}
    return str(urgency.get("label") or "")


def _best_ref(extraction_result: Optional[dict], *, message_id: str) -> str:
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


def _identity_summary(identity_result: Optional[dict]) -> str:
    if identity_result is None:
        return "status=UNKNOWN"
    status = str(identity_result.get("status") or "")
    top_k = identity_result.get("top_k") or []
    parts = [f"status={status}"]
    if isinstance(top_k, list) and top_k:
        for cand in top_k[:5]:
            if not isinstance(cand, dict):
                continue
            entity_type = str(cand.get("entity_type") or "")
            entity_id = str(cand.get("entity_id") or "")
            score = str(cand.get("score") or "")
            ev = cand.get("evidence") or []
            hashes: list[str] = []
            if isinstance(ev, list):
                for e in ev:
                    if isinstance(e, dict):
                        h = e.get("snippet_sha256")
                        if isinstance(h, str) and h:
                            hashes.append(h)
            hashes_s = ",".join(hashes[:5])
            parts.append(f"- {entity_type}:{entity_id} score={score} evidence={hashes_s}")
    return "\n".join(parts)


def _classification_summary(classification_result: Optional[dict]) -> str:
    if classification_result is None:
        return "primary_intent=\nproduct_line=\nurgency=\nrisk_flags=[]"
    primary = classification_result.get("primary_intent") or {}
    product = classification_result.get("product_line") or {}
    urgency = classification_result.get("urgency") or {}
    risk_flags = classification_result.get("risk_flags") or []
    risk_labels: list[str] = []
    if isinstance(risk_flags, list):
        for rf in risk_flags:
            if isinstance(rf, dict):
                lbl = rf.get("label")
                if isinstance(lbl, str) and lbl:
                    risk_labels.append(lbl)
    risk_labels = sorted(set(risk_labels))
    return "\n".join(
        [
            f"primary_intent={str(primary.get('label') or '')} conf={_fmt_confidence(primary.get('confidence'))}",
            f"product_line={str(product.get('label') or '')} conf={_fmt_confidence(product.get('confidence'))}",
            f"urgency={str(urgency.get('label') or '')} conf={_fmt_confidence(urgency.get('confidence'))}",
            f"risk_flags={risk_labels}",
        ]
    )


def _extraction_summary(extraction_result: Optional[dict]) -> str:
    if extraction_result is None:
        return "entities=[]"
    entities = extraction_result.get("entities") or []
    out: list[str] = []
    if isinstance(entities, list):
        for ent in entities[:50]:
            if not isinstance(ent, dict):
                continue
            et = str(ent.get("entity_type") or "")
            val = ent.get("value_redacted")
            if not isinstance(val, str) or not val:
                val = ent.get("value_sha256")
            if not isinstance(val, str):
                val = ""
            out.append(f"{et}:{val}")
    return "entities=[" + ", ".join(out) + "]"


def _urgency_to_priority_fields(urgency_label: str) -> Optional[dict]:
    mapping = {
        "URG_CRITICAL": {"urgency": 1, "impact": 1, "priority": 1},
        "URG_HIGH": {"urgency": 2, "impact": 2, "priority": 2},
        "URG_NORMAL": {"urgency": 3, "impact": 3, "priority": 3},
        "URG_LOW": {"urgency": 4, "impact": 4, "priority": 4},
    }
    return mapping.get(urgency_label)


def _intent_to_category_fields(primary_intent: str) -> Optional[dict]:
    if primary_intent == "INTENT_BILLING_QUESTION":
        return {"category": "inquiry", "subcategory": "billing"}
    if primary_intent in ("INTENT_CLAIM_NEW", "INTENT_CLAIM_UPDATE"):
        return {"category": "inquiry", "subcategory": "claim"}
    if primary_intent == "INTENT_COMPLAINT":
        return {"category": "request", "subcategory": "complaint"}
    if primary_intent == "INTENT_LEGAL":
        return {"category": "request", "subcategory": "legal"}
    if primary_intent == "INTENT_GDPR_REQUEST":
        return {"category": "request", "subcategory": "gdpr"}
    return None


@dataclass(frozen=True)
class ServiceNowIncidentAdapterConfig:
    instance_url: str
    client_id: str
    client_secret: str
    assignment_group_by_queue_id: dict[str, str]
    get_bytes: Callable[[str], bytes]
    attach_stage_outputs: bool = False
    body_excerpt_chars: int = 800
    http_timeout_seconds: int = 20


class ServiceNowIncidentCaseAdapter(CaseAdapter):
    """Case adapter writing to ServiceNow ITSM Incident via Table + Attachment APIs."""

    def __init__(self, *, config: ServiceNowIncidentAdapterConfig) -> None:
        self._cfg = config
        self._token: Optional[str] = None
        self._token_expires_at: float = 0.0
        self._attachment_name_cache: dict[str, set[str]] = {}

    def _token_url(self) -> str:
        return self._cfg.instance_url.rstrip("/") + "/oauth_token.do"

    def _api_url(self, path: str, *, query: Optional[dict[str, str]] = None) -> str:
        base = self._cfg.instance_url.rstrip("/")
        url = base + path
        if query:
            url += "?" + urlencode(query)
        return url

    def _read_json(self, *, method: str, url: str, body: Optional[bytes] = None) -> dict:
        headers: dict[str, str] = {"Accept": "application/json"}
        token = self._get_access_token()
        headers["Authorization"] = f"Bearer {token}"
        if body is not None:
            headers["Content-Type"] = "application/json"

        req = Request(url, headers=headers, data=body, method=method)
        with urlopen(req, timeout=self._cfg.http_timeout_seconds) as resp:
            raw = resp.read()
        return json.loads(raw.decode("utf-8"))

    def _post_form(self, *, url: str, data: dict[str, str]) -> dict:
        encoded = urlencode(data).encode("utf-8")
        req = Request(
            url,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            data=encoded,
            method="POST",
        )
        with urlopen(req, timeout=self._cfg.http_timeout_seconds) as resp:
            raw = resp.read()
        return json.loads(raw.decode("utf-8"))

    def _get_access_token(self) -> str:
        now = time.time()
        if self._token and now < (self._token_expires_at - 30):
            return self._token

        obj = self._post_form(
            url=self._token_url(),
            data={
                "grant_type": "client_credentials",
                "client_id": self._cfg.client_id,
                "client_secret": self._cfg.client_secret,
            },
        )
        token = obj.get("access_token")
        if not isinstance(token, str) or not token:
            raise RuntimeError("ServiceNow token response missing access_token")

        expires_in = obj.get("expires_in")
        ttl = 300
        if isinstance(expires_in, (int, float)) and expires_in > 0:
            ttl = int(expires_in)
        self._token = token
        self._token_expires_at = now + ttl
        return token

    def _list_results(self, obj: dict) -> list[dict]:
        res = obj.get("result")
        if res is None:
            return []
        if isinstance(res, list):
            return [r for r in res if isinstance(r, dict)]
        if isinstance(res, dict):
            return [res]
        return []

    def _find_incident_by_correlation_id(self, correlation_id: str) -> Optional[dict]:
        url = self._api_url(
            "/api/now/table/incident",
            query={
                "sysparm_query": f"correlation_id={correlation_id}",
                "sysparm_fields": "sys_id,number,correlation_id",
            },
        )
        obj = self._read_json(method="GET", url=url)
        rows = self._list_results(obj)
        if not rows:
            return None
        if len(rows) > 1:
            raise RuntimeError("ServiceNow idempotency pre-check returned multiple incidents")
        return rows[0]

    def _lookup_unique_sys_user_id_by_email(self, email: str) -> Optional[str]:
        if not email:
            return None
        url = self._api_url(
            "/api/now/table/sys_user",
            query={"sysparm_query": f"email={email}", "sysparm_fields": "sys_id"},
        )
        try:
            obj = self._read_json(method="GET", url=url)
        except HTTPError:
            return None
        rows = self._list_results(obj)
        if len(rows) != 1:
            return None
        sys_id = rows[0].get("sys_id")
        if not isinstance(sys_id, str) or not sys_id:
            return None
        return sys_id

    def _incident_description(self, *, context: Optional[dict]) -> str:
        if context is None:
            return ""
        nm = context.get("normalized_message") if isinstance(context.get("normalized_message"), dict) else {}
        identity = context.get("identity_result") if isinstance(context.get("identity_result"), dict) else None
        cls = context.get("classification_result") if isinstance(context.get("classification_result"), dict) else None
        ext = context.get("extraction_result") if isinstance(context.get("extraction_result"), dict) else None
        routing = context.get("routing_decision") if isinstance(context.get("routing_decision"), dict) else {}

        subject = str(nm.get("subject") or "")
        from_email = str(nm.get("from_email") or "")
        received_at = str(nm.get("received_at") or "")
        body_c14n = str(nm.get("body_text_c14n") or "")
        body_excerpt = _redact_body_excerpt(body_c14n, limit_chars=self._cfg.body_excerpt_chars)

        decision_hash = ""
        if isinstance(routing.get("decision_hash"), str):
            decision_hash = str(routing.get("decision_hash") or "")

        audit_head = context.get("audit_chain_head_sha256")
        if not isinstance(audit_head, str):
            audit_head = ""

        lines = []
        lines.append("Normalized email header summary")
        lines.append(f"subject: {subject}")
        lines.append(f"from: {from_email}")
        lines.append(f"received_at: {received_at}")
        lines.append("")
        lines.append("Canonicalized body excerpt (redacted)")
        lines.append(body_excerpt)
        lines.append("")
        lines.append("Identity resolution summary")
        lines.append(_identity_summary(identity))
        lines.append("")
        lines.append("Classification summary")
        lines.append(_classification_summary(cls))
        lines.append("")
        lines.append("Extraction summary")
        lines.append(_extraction_summary(ext))
        lines.append("")
        lines.append("Routing decision summary")
        lines.append(
            json.dumps(
                {
                    "queue_id": str(routing.get("queue_id") or ""),
                    "sla_id": str(routing.get("sla_id") or ""),
                    "actions": list(routing.get("actions") or []),
                    "rule_id": str(routing.get("rule_id") or ""),
                    "rule_version": str(routing.get("rule_version") or ""),
                },
                ensure_ascii=False,
                sort_keys=True,
            )
        )
        lines.append("")
        lines.append("Artifact references")
        lines.append(f"raw_mime_sha256: {str(nm.get('raw_mime_sha256') or '')}")
        lines.append(f"decision_hash: {decision_hash}")
        lines.append(f"audit_chain_head_sha256: {audit_head}")
        return "\n".join(lines)

    def _ensure_attachment_name_cache(self, *, case_id: str) -> set[str]:
        cached = self._attachment_name_cache.get(case_id)
        if cached is not None:
            return cached

        url = self._api_url(
            "/api/now/attachment",
            query={
                "sysparm_query": f"table_name=incident^table_sys_id={case_id}",
                "sysparm_fields": "sys_id,file_name",
            },
        )
        obj = self._read_json(method="GET", url=url)
        names: set[str] = set()
        for row in self._list_results(obj):
            fn = row.get("file_name")
            if isinstance(fn, str) and fn:
                names.add(fn)
        self._attachment_name_cache[case_id] = names
        return names

    def _upload_attachment(self, *, case_id: str, file_name: str, data: bytes) -> None:
        names = self._ensure_attachment_name_cache(case_id=case_id)
        if file_name in names:
            return

        token = self._get_access_token()
        url = self._api_url(
            "/api/now/attachment/file",
            query={"table_name": "incident", "table_sys_id": case_id, "file_name": file_name},
        )
        req = Request(
            url,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/octet-stream"},
            data=data,
            method="POST",
        )
        with urlopen(req, timeout=self._cfg.http_timeout_seconds) as resp:
            _ = resp.read()
        names.add(file_name)

    def _attach_stage_outputs(self, *, case_id: str, context: dict) -> None:
        if not self._cfg.attach_stage_outputs:
            return

        def _attach_json(name: str, obj: Optional[dict]) -> None:
            if obj is None:
                return
            b = json.dumps(obj, ensure_ascii=False, sort_keys=True).encode("utf-8") + b"\n"
            sha = sha256_prefixed(b)
            fname = f"{name}_{_sha256_hex(sha)}.json"
            self._upload_attachment(case_id=case_id, file_name=fname, data=b)

        _attach_json("ieim_identity", context.get("identity_result"))
        _attach_json("ieim_classification", context.get("classification_result"))
        _attach_json("ieim_extraction", context.get("extraction_result"))
        _attach_json("ieim_routing", context.get("routing_decision"))

        head = context.get("audit_chain_head_sha256")
        if isinstance(head, str) and head:
            b = json.dumps({"audit_chain_head_sha256": head}, ensure_ascii=False, sort_keys=True).encode("utf-8") + b"\n"
            fname = f"ieim_audit_chain_head_{_sha256_hex(head)}.json"
            self._upload_attachment(case_id=case_id, file_name=fname, data=b)

    def create_case(
        self,
        *,
        idempotency_key: str,
        queue_id: str,
        title: str,
        context: Optional[dict] = None,
    ) -> str:
        correlation_id = idempotency_key

        group = self._cfg.assignment_group_by_queue_id.get(queue_id)
        if not group:
            raise RuntimeError(f"missing assignment_group mapping for queue_id: {queue_id}")

        existing = self._find_incident_by_correlation_id(correlation_id)
        if existing is not None:
            sys_id = str(existing.get("sys_id") or "")
            if not sys_id:
                raise RuntimeError("ServiceNow incident lookup returned empty sys_id")
            if context is not None:
                self._attach_stage_outputs(case_id=sys_id, context=context)
            return sys_id

        nm = context.get("normalized_message") if isinstance(context, dict) else {}
        from_email = str(nm.get("from_email") or "")

        payload: dict[str, object] = {
            "short_description": title,
            "description": self._incident_description(context=context),
            "contact_type": "email",
            "correlation_id": correlation_id,
            "assignment_group": group,
        }

        cls = context.get("classification_result") if isinstance(context, dict) else None
        if isinstance(cls, dict):
            urgency_fields = _urgency_to_priority_fields(_urgency_label(cls))
            if urgency_fields is not None:
                payload.update(urgency_fields)

            cat = _intent_to_category_fields(_primary_intent_label(cls))
            if cat is not None:
                payload.update(cat)

        caller_id = self._lookup_unique_sys_user_id_by_email(from_email)
        if caller_id:
            payload["caller_id"] = caller_id

        url = self._api_url("/api/now/table/incident")
        obj = self._read_json(method="POST", url=url, body=json.dumps(payload).encode("utf-8"))
        rows = self._list_results(obj)
        if not rows:
            raise RuntimeError("ServiceNow create incident returned no result")
        sys_id = str(rows[0].get("sys_id") or "")
        if not sys_id:
            raise RuntimeError("ServiceNow create incident returned empty sys_id")

        if context is not None:
            self._attach_stage_outputs(case_id=sys_id, context=context)

        return sys_id

    def update_case(self, *, idempotency_key: str, case_id: str, title: Optional[str] = None) -> None:
        raise NotImplementedError("update_case is not implemented for ServiceNow adapter v1")

    def attach_artifact(self, *, idempotency_key: str, case_id: str, artifact: dict) -> None:
        kind = str(artifact.get("kind") or "")
        uri = str(artifact.get("uri") or "")
        sha = str(artifact.get("sha256") or "")

        if not uri:
            raise ValueError("artifact.uri must be set")

        if kind == "RAW_MIME":
            file_name = f"ieim_raw_email_{_sha256_hex(sha)}.eml"
        elif kind == "ATTACHMENT":
            original_name = _sanitize_filename(str(artifact.get("filename") or "attachment.bin"))
            file_name = f"ieim_attach_{_sha256_hex(sha)}_{original_name}"
        else:
            file_name = f"ieim_artifact_{_sha256_hex(sha)}.bin"

        data = self._cfg.get_bytes(uri)
        self._upload_attachment(case_id=case_id, file_name=file_name, data=data)

    def add_note(self, *, idempotency_key: str, case_id: str, note: str) -> None:
        b = (note or "").encode("utf-8")
        sha = sha256_prefixed(b)
        file_name = f"ieim_note_{_sha256_hex(sha)}.txt"
        self._upload_attachment(case_id=case_id, file_name=file_name, data=b)

    def add_draft_message(self, *, idempotency_key: str, case_id: str, draft: str) -> None:
        b = (draft or "").encode("utf-8")
        sha = sha256_prefixed(b)
        file_name = f"ieim_draft_{_sha256_hex(sha)}.md"
        self._upload_attachment(case_id=case_id, file_name=file_name, data=b)
