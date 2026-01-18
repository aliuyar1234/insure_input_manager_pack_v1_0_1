from __future__ import annotations

import json
import statistics
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from ieim.config import IEIMConfig, load_config
from ieim.identity.adapters import InMemoryCRMAdapter, InMemoryClaimsAdapter, InMemoryPolicyAdapter
from ieim.identity.config import IdentityConfig, load_identity_config
from ieim.identity.resolver import IdentityResolver
from ieim.identity.config_select import select_config_path_for_message
from ieim.classify.classifier import DeterministicClassifier
from ieim.extract.extractor import DeterministicExtractor
from ieim.route.evaluator import evaluate_routing


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_attachments(*, attachments_dir: Path, nm: dict) -> list[dict]:
    out: list[dict] = []
    for att_id in nm.get("attachment_ids") or []:
        p = attachments_dir / f"{att_id}.artifact.json"
        if not p.exists():
            continue
        out.append(_load_json(p))
    return out


def _load_attachment_texts_c14n(*, repo_root: Path, attachments_dir: Path, nm: dict) -> list[str]:
    out: list[str] = []
    for att_id in nm.get("attachment_ids") or []:
        artifact_path = attachments_dir / f"{att_id}.artifact.json"
        if not artifact_path.exists():
            continue
        artifact = _load_json(artifact_path)
        if artifact.get("av_status") != "CLEAN":
            continue
        uri = artifact.get("extracted_text_uri")
        if not isinstance(uri, str) or not uri:
            continue
        text_path = (repo_root / uri).resolve()
        if not text_path.exists():
            continue
        out.append(text_path.read_text(encoding="utf-8").lower())
    return out


def _pctl(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    values_s = sorted(values)
    idx = (pct / 100.0) * (len(values_s) - 1)
    k = int(round(idx))
    k = max(0, min(len(values_s) - 1, k))
    return float(values_s[k])


@dataclass(frozen=True)
class LoadTestReport:
    status: str
    config_path: str
    messages: int
    iterations: int
    duration_ms_total: int
    throughput_msgs_per_s: float
    stage_ms: dict[str, dict[str, float]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "config_path": self.config_path,
            "messages": self.messages,
            "iterations": self.iterations,
            "duration_ms_total": self.duration_ms_total,
            "throughput_msgs_per_s": self.throughput_msgs_per_s,
            "stage_ms": dict(self.stage_ms),
        }


def run_load_test(
    *,
    repo_root: Path,
    normalized_dir: Path,
    attachments_dir: Path,
    iterations: int,
    config_path: Optional[Path] = None,
    crm_mapping: Optional[dict[str, list[str]]] = None,
) -> LoadTestReport:
    if iterations <= 0:
        raise ValueError("iterations must be >= 1")

    nms = sorted(normalized_dir.glob("*.json"))
    if not nms:
        raise ValueError(f"no normalized messages found in: {normalized_dir}")

    cfg_cache: dict[str, IEIMConfig] = {}
    id_cfg_cache: dict[str, IdentityConfig] = {}

    crm_mapping = crm_mapping or {}
    policy_adapter = InMemoryPolicyAdapter(valid_policy_numbers=None)
    claims_adapter = InMemoryClaimsAdapter(valid_claim_numbers=None)
    crm_adapter = InMemoryCRMAdapter(email_to_policy_numbers=dict(crm_mapping))

    stage_times: dict[str, list[float]] = {"IDENTITY": [], "CLASSIFY": [], "EXTRACT": [], "ROUTE": []}

    t0 = time.perf_counter()
    total_msgs = 0
    for _ in range(iterations):
        for nm_path in nms:
            nm = _load_json(nm_path)

            cfg_path = config_path or select_config_path_for_message(repo_root=repo_root, normalized_message=nm)
            cfg_key = cfg_path.as_posix()
            cfg = cfg_cache.get(cfg_key)
            if cfg is None:
                cfg = load_config(path=cfg_path)
                cfg_cache[cfg_key] = cfg

            id_cfg = id_cfg_cache.get(cfg_key)
            if id_cfg is None:
                id_cfg = load_identity_config(path=cfg_path)
                id_cfg_cache[cfg_key] = id_cfg

            attachments = _load_attachments(attachments_dir=attachments_dir, nm=nm)
            attachment_texts_c14n = _load_attachment_texts_c14n(
                repo_root=repo_root, attachments_dir=attachments_dir, nm=nm
            )

            resolver = IdentityResolver(
                config=id_cfg,
                policy_adapter=policy_adapter,
                claims_adapter=claims_adapter,
                crm_adapter=crm_adapter,
            )
            t_id0 = time.perf_counter()
            identity_result, _draft, _evidence = resolver.resolve(
                normalized_message=nm, attachment_texts_c14n=attachment_texts_c14n
            )
            stage_times["IDENTITY"].append((time.perf_counter() - t_id0) * 1000)

            classifier = DeterministicClassifier(config=cfg)
            t_cls0 = time.perf_counter()
            classification_result = classifier.classify(normalized_message=nm, attachments=attachments).result
            stage_times["CLASSIFY"].append((time.perf_counter() - t_cls0) * 1000)

            extractor = DeterministicExtractor(config=cfg)
            t_ex0 = time.perf_counter()
            extraction_result = extractor.extract(normalized_message=nm, attachments=attachments)
            stage_times["EXTRACT"].append((time.perf_counter() - t_ex0) * 1000)

            t_rt0 = time.perf_counter()
            _decision = evaluate_routing(
                repo_root=repo_root,
                config=cfg,
                normalized_message=nm,
                identity_result=identity_result,
                classification_result=classification_result,
            ).decision
            stage_times["ROUTE"].append((time.perf_counter() - t_rt0) * 1000)

            total_msgs += 1

    dur_ms = int((time.perf_counter() - t0) * 1000)
    throughput = float(total_msgs) / (max(1, dur_ms) / 1000.0)

    stage_stats: dict[str, dict[str, float]] = {}
    for stage, values in stage_times.items():
        stage_stats[stage] = {
            "count": int(len(values)),
            "avg_ms": float(statistics.mean(values)) if values else 0.0,
            "p50_ms": _pctl(values, 50),
            "p95_ms": _pctl(values, 95),
            "max_ms": float(max(values)) if values else 0.0,
        }

    if config_path is None:
        cfg_path_s = "AUTO"
    else:
        try:
            cfg_path_s = config_path.resolve().relative_to(repo_root.resolve()).as_posix()
        except Exception:
            cfg_path_s = config_path.as_posix()
    return LoadTestReport(
        status="OK",
        config_path=cfg_path_s,
        messages=len(nms),
        iterations=iterations,
        duration_ms_total=dur_ms,
        throughput_msgs_per_s=throughput,
        stage_ms=stage_stats,
    )
