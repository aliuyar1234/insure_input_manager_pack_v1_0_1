from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, ROUND_HALF_UP
from functools import lru_cache
from pathlib import Path
from typing import Optional

from ieim.determinism.decision_hash import decision_hash
from ieim.identity.adapters import CRMAdapter, ClaimsAdapter, PolicyAdapter
from ieim.identity.config import IdentityConfig, SignalSpec
from ieim.identity.identity_directory_client import IdentityDirectoryError
from ieim.identity.extract import IdentifierHit, find_claim_number, find_policy_number
from ieim.identity.request_info import load_request_info_template, render_request_info_draft
from ieim.raw_store import sha256_prefixed


@lru_cache(maxsize=1)
def _identity_schema_id_and_version() -> tuple[str, str]:
    root = Path(__file__).resolve().parents[2]
    schema_path = root / "schemas" / "identity_resolution_result.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    schema_id = schema.get("$id")
    if not isinstance(schema_id, str) or not schema_id:
        raise ValueError("identity_resolution_result.schema.json missing $id")
    version = schema_id.rsplit(":", 1)[-1]
    return schema_id, version


def _decimal_to_json_number(value: Decimal) -> float:
    return float(value)


def _snippet_sha256(snippet: str) -> str:
    return sha256_prefixed(snippet.encode("utf-8"))


def _evidence_span(hit: IdentifierHit) -> dict:
    return {
        "source": hit.source,
        "start": int(hit.start),
        "end": int(hit.end),
        "snippet_redacted": hit.snippet,
        "snippet_sha256": _snippet_sha256(hit.snippet),
    }


def _score_from_signals(*, config: IdentityConfig, specs: list[SignalSpec]) -> Decimal:
    raw = Decimal("0")
    for s in specs:
        raw += s.weight * s.strength
    score = config.score_transform.intercept + (config.score_transform.slope * raw)
    if score < Decimal("0"):
        score = Decimal("0")
    if score > Decimal("1"):
        score = Decimal("1")
    return score.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


def _is_high_risk_unresolved(nm: dict) -> bool:
    subject = str(nm.get("subject_c14n") or "")
    body = str(nm.get("body_text_c14n") or "")
    text = f"{subject}\n{body}"
    return any(token in text for token in ("ombudsmann", "anwalt", "frist"))


@dataclass
class IdentityResolver:
    config: IdentityConfig
    policy_adapter: PolicyAdapter
    claims_adapter: ClaimsAdapter
    crm_adapter: CRMAdapter

    def resolve(
        self,
        *,
        normalized_message: dict,
        attachment_texts_c14n: Optional[list[str]] = None,
    ) -> tuple[dict, Optional[str], list[dict]]:
        schema_id, schema_version = _identity_schema_id_and_version()

        message_id = str(normalized_message["message_id"])
        run_id = str(normalized_message["run_id"])
        created_at = str(normalized_message["ingested_at"])

        subject_c14n = str(normalized_message.get("subject_c14n") or "")
        body_c14n = str(normalized_message.get("body_text_c14n") or "")

        claim_hit = find_claim_number(subject_c14n=subject_c14n, body_c14n=body_c14n)
        policy_hit = find_policy_number(subject_c14n=subject_c14n, body_c14n=body_c14n)

        if claim_hit is None and policy_hit is None and attachment_texts_c14n:
            for text in attachment_texts_c14n:
                claim_hit = find_claim_number(subject_c14n="", body_c14n=text)
                policy_hit = find_policy_number(subject_c14n="", body_c14n=text)
                if claim_hit is not None or policy_hit is not None:
                    break

        candidates: list[dict] = []
        dependency_evidence: list[dict] = []

        def record_dependency_failure(*, err: Exception) -> None:
            snippet = f"{type(err).__name__}: {err}"
            if len(snippet) > 400:
                snippet = snippet[:400]
            dependency_evidence.append(
                {
                    "source": "DEPENDENCY_ID_DIR",
                    "start": 0,
                    "end": 0,
                    "snippet_redacted": snippet,
                    "snippet_sha256": _snippet_sha256(snippet),
                }
            )

        def add_signal(
            *,
            name: str,
            value: Optional[str],
            signal_specs: list[SignalSpec],
            out: list[dict],
        ) -> None:
            spec = self.config.signal_specs.get(name)
            if spec is None:
                raise ValueError(f"missing signal spec for {name}")
            signal_specs.append(spec)
            payload = {
                "name": name,
                "strength": _decimal_to_json_number(spec.strength),
                "weight": _decimal_to_json_number(spec.weight),
            }
            if value is not None:
                payload["value"] = value
            out.append(payload)

        if claim_hit is not None:
            try:
                record = self.claims_adapter.lookup_by_claim_number(claim_number=claim_hit.value)
            except IdentityDirectoryError as e:
                record_dependency_failure(err=e)
                record = None
            if record is not None:
                signal_specs: list[SignalSpec] = []
                signals: list[dict] = []
                add_signal(
                    name="SIG_CLAIM_NUMBER_LOOKUP_MATCH",
                    value=record.claim_id,
                    signal_specs=signal_specs,
                    out=signals,
                )
                score = _score_from_signals(config=self.config, specs=signal_specs)
                candidates.append(
                    {
                        "entity_type": "CLAIM",
                        "entity_id": record.claim_id,
                        "score": _decimal_to_json_number(score),
                        "signals": signals,
                        "evidence": [_evidence_span(claim_hit)],
                        "_has_hard": True,
                        "_has_medium": False,
                    }
                )

        if policy_hit is not None:
            try:
                record = self.policy_adapter.lookup_by_policy_number(policy_number=policy_hit.value)
            except IdentityDirectoryError as e:
                record_dependency_failure(err=e)
                record = None
            if record is not None:
                signal_specs = []
                signals = []
                add_signal(
                    name="SIG_POLICY_NUMBER_LOOKUP_MATCH",
                    value=policy_hit.value,
                    signal_specs=signal_specs,
                    out=signals,
                )

                sender_email = str(normalized_message.get("from_email") or "")
                sender_email_signal = False
                if sender_email:
                    try:
                        linked = set(self.crm_adapter.policy_numbers_for_sender_email(email=sender_email))
                    except IdentityDirectoryError as e:
                        record_dependency_failure(err=e)
                        linked = set()
                    if policy_hit.value in linked:
                        add_signal(
                            name="SIG_SENDER_EMAIL_MATCH",
                            value=sender_email,
                            signal_specs=signal_specs,
                            out=signals,
                        )
                        sender_email_signal = True

                score = _score_from_signals(config=self.config, specs=signal_specs)
                candidates.append(
                    {
                        "entity_type": "POLICY",
                        "entity_id": record.policy_id,
                        "score": _decimal_to_json_number(score),
                        "signals": signals,
                        "evidence": [_evidence_span(policy_hit)],
                        "_has_hard": True,
                        "_has_medium": sender_email_signal,
                    }
                )

        candidates.sort(key=lambda c: (-c["score"], c["entity_type"], c["entity_id"]))

        thresholds_out = {
            "confirmed_min_score": _decimal_to_json_number(self.config.thresholds.confirmed_min_score),
            "confirmed_min_margin": _decimal_to_json_number(self.config.thresholds.confirmed_min_margin),
            "probable_min_score": _decimal_to_json_number(self.config.thresholds.probable_min_score),
            "probable_min_margin": _decimal_to_json_number(self.config.thresholds.probable_min_margin),
        }

        status: str
        selected_candidate: Optional[dict]
        top_k: list[dict] = []

        if not candidates:
            status = "IDENTITY_NEEDS_REVIEW" if _is_high_risk_unresolved(normalized_message) else "IDENTITY_NO_CANDIDATE"
            selected_candidate = None
        else:
            top_score = Decimal(str(candidates[0]["score"]))
            second_score = Decimal(str(candidates[1]["score"])) if len(candidates) > 1 else Decimal("0")
            margin = top_score - second_score

            top = candidates[0]
            has_hard = bool(top.get("_has_hard"))
            has_medium = bool(top.get("_has_medium"))

            if (
                has_hard
                and top_score >= self.config.thresholds.confirmed_min_score
                and margin >= self.config.thresholds.confirmed_min_margin
            ):
                status = "IDENTITY_CONFIRMED"
                selected_candidate = top
            elif (
                has_medium
                and top_score >= self.config.thresholds.probable_min_score
                and margin >= self.config.thresholds.probable_min_margin
            ):
                status = "IDENTITY_PROBABLE"
                selected_candidate = top
            else:
                status = "IDENTITY_NEEDS_REVIEW"
                selected_candidate = None

            for idx, cand in enumerate(candidates[: self.config.top_k]):
                out = {k: v for k, v in cand.items() if not k.startswith("_")}
                out["rank"] = idx + 1
                top_k.append(out)

            if selected_candidate is not None:
                selected_candidate = {k: v for k, v in selected_candidate.items() if not k.startswith("_")}
                selected_candidate["rank"] = 1

        if dependency_evidence:
            status = "IDENTITY_NEEDS_REVIEW"
            selected_candidate = None

        decision_input = {
            "system_id": self.config.system_id,
            "canonical_spec_semver": self.config.canonical_spec_semver,
            "stage": "IDENTITY",
            "message_fingerprint": str(normalized_message.get("message_fingerprint") or ""),
            "raw_mime_sha256": str(normalized_message.get("raw_mime_sha256") or ""),
            "config_ref": {
                "config_path": self.config.config_path,
                "config_sha256": self.config.config_sha256,
            },
            "determinism_mode": self.config.determinism_mode,
            "decision": {
                "status": status,
                "selected": (
                    None
                    if selected_candidate is None
                    else {
                        "entity_type": selected_candidate["entity_type"],
                        "entity_id": selected_candidate["entity_id"],
                        "score": selected_candidate["score"],
                    }
                ),
                "top_k": [
                    {
                        "rank": c["rank"],
                        "entity_type": c["entity_type"],
                        "entity_id": c["entity_id"],
                        "score": c["score"],
                        "signals": c["signals"],
                        "evidence": [
                            {
                                "source": e["source"],
                                "start": e["start"],
                                "end": e["end"],
                                "snippet_sha256": e["snippet_sha256"],
                            }
                            for e in c.get("evidence", [])
                        ],
                    }
                    for c in top_k
                ],
                "thresholds": thresholds_out,
            },
        }

        out = {
            "schema_id": schema_id,
            "schema_version": schema_version,
            "message_id": message_id,
            "run_id": run_id,
            "status": status,
            "selected_candidate": selected_candidate,
            "top_k": top_k,
            "thresholds": thresholds_out,
            "created_at": created_at,
            "decision_hash": decision_hash(decision_input),
        }

        request_info = None
        if status in ("IDENTITY_NO_CANDIDATE", "IDENTITY_NEEDS_REVIEW"):
            lang = str(normalized_message.get("language") or "en")
            root_dir = Path(__file__).resolve().parents[2]
            template = load_request_info_template(root_dir=root_dir, language=lang)
            request_info = render_request_info_draft(template=template)

        return out, request_info, dependency_evidence
