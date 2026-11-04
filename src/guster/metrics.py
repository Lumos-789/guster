from __future__ import annotations

from typing import Any, Dict, List

from .util import now_iso


CHI_WEIGHTS = {
    "ssr": 0.20,
    "rbr": 0.15,
    "pcr": 0.15,
    "icr": 0.15,
    "frs": 0.15,
    "phr": 0.10,
    "sir": 0.10,
}
SCOPE_DIMS = {
    "machine": ["ssr", "rbr", "pcr", "icr", "frs", "phr", "sir"],
    "project": ["ssr", "pcr", "icr", "frs", "phr"],
    "group": ["ssr", "pcr", "icr", "frs", "phr"],
    "hub": ["ssr", "icr", "frs", "phr"],
}


def dimensions_for_scope(scope: str) -> List[str]:
    """Dimensions that enter CHI for a scope; the report must show exactly these."""
    return list(SCOPE_DIMS.get(scope) or SCOPE_DIMS["machine"])


def safe_ratio(numerator: float, denominator: float, default: float = 1.0) -> float:
    if denominator <= 0:
        return default
    return max(0.0, min(1.0, numerator / denominator))


def compute_metrics(registry: Dict[str, Any], policy_result: Dict[str, Any]) -> Dict[str, Any]:
    stats = policy_result.get("stats", {})
    governance_count = int(stats.get("governance_docs", 0))

    topic_data = registry.get("topics") or {}
    topic_total = int(topic_data.get("total", 0))
    topic_multi = int(topic_data.get("multi", 0))
    if topic_total:
        ssr = safe_ratio(topic_total - topic_multi, topic_total, 1.0)
    else:
        ssr = 0.6 if governance_count > 4 else 1.0

    resident_bytes = max(1, int(stats.get("resident_bytes", 0)))
    skill_chars = max(1, int(stats.get("skill_chars", 0)))
    resident_score = min(1.0, 20_000 / resident_bytes)
    skill_score = min(1.0, 6_000 / skill_chars)
    rbr = (resident_bytes / 20_000.0 + skill_chars / 6_000.0) / 2.0
    rbr_score = (resident_score + skill_score) / 2.0

    pcr = safe_ratio(
        int(stats.get("agents_dirs_compliant", 0)),
        int(stats.get("agents_dirs_total", 0)),
        1.0,
    )
    knowledge_icr = safe_ratio(
        int(stats.get("knowledge_indexed", 0)),
        int(stats.get("knowledge_total", 0)),
        1.0,
    )
    agents_icr = safe_ratio(
        int(stats.get("agents_indexed", 0)),
        int(stats.get("agents_dirs_total", 0)),
        1.0,
    )
    icr = (knowledge_icr + agents_icr) / 2.0
    frs = safe_ratio(
        int(stats.get("state_docs_fresh", 0)),
        int(stats.get("state_docs_total", 0)),
        1.0,
    )
    phr = safe_ratio(
        int(stats.get("pointers_valid", 0)),
        int(stats.get("pointers_checked", 0)),
        1.0,
    )
    secret_total = int(stats.get("secret_total", 0)) + int(stats.get("inline_bearers", 0))
    secret_bad = (
        int(stats.get("secret_outside_root", 0))
        + int(stats.get("inline_bearers", 0))
        + int(stats.get("secret_in_git", 0))
    )
    sir = 1.0 - safe_ratio(secret_bad, secret_total, 0.0)
    gcr = governance_count / 8.0 if governance_count else 0.0
    gcr_score = 1.0 if gcr == 0 else min(1.0, 0.5 / max(gcr, 0.01))

    dim_values = {
        "ssr": ssr,
        "rbr": rbr_score,
        "pcr": pcr,
        "icr": icr,
        "frs": frs,
        "phr": phr,
        "sir": sir,
    }
    scope = registry.get("scope", "machine")
    scope_dims = dimensions_for_scope(scope)
    total_weight = sum(CHI_WEIGHTS[dim] for dim in scope_dims)
    chi = sum(CHI_WEIGHTS[dim] * dim_values[dim] for dim in scope_dims) / total_weight

    return {
        "generated_at": now_iso(),
        "metrics": {
            "ssr": round(ssr, 4),
            "rbr": round(rbr, 4),
            "pcr": round(pcr, 4),
            "icr": round(icr, 4),
            "frs": round(frs, 4),
            "phr": round(phr, 4),
            "sir": round(sir, 4),
            "gcr": round(gcr, 4),
        },
        "scores": {
            "ssr": round(ssr * 100, 1),
            "rbr": round(rbr_score * 100, 1),
            "pcr": round(pcr * 100, 1),
            "icr": round(icr * 100, 1),
            "frs": round(frs * 100, 1),
            "phr": round(phr * 100, 1),
            "sir": round(sir * 100, 1),
            "gcr": round(gcr_score * 100, 1),
        },
        "chi": round(chi * 100, 1),
        "scope": scope,
        "dims": scope_dims,
        "raw": {
            "resident_bytes": resident_bytes,
            "resident_lines": int(stats.get("resident_lines", 0)),
            "skill_chars": skill_chars,
            "topics_total": topic_total,
            "topics_multi": topic_multi,
            "agents_dirs_total": int(stats.get("agents_dirs_total", 0)),
            "agents_dirs_compliant": int(stats.get("agents_dirs_compliant", 0)),
            "agents_indexed": int(stats.get("agents_indexed", 0)),
            "knowledge_total": int(stats.get("knowledge_total", 0)),
            "knowledge_indexed": int(stats.get("knowledge_indexed", 0)),
            "state_docs_total": int(stats.get("state_docs_total", 0)),
            "state_docs_fresh": int(stats.get("state_docs_fresh", 0)),
            "state_docs_fresh_declared": int(stats.get("state_docs_fresh_declared", 0)),
            "state_docs_fresh_from_git": int(stats.get("state_docs_fresh_from_git", 0)),
            "pointers_checked": int(stats.get("pointers_checked", 0)),
            "pointers_valid": int(stats.get("pointers_valid", 0)),
            "broken_pointers": int(stats.get("broken_pointers", 0)),
            "secret_total": int(stats.get("secret_total", 0)),
            "secret_outside_root": int(stats.get("secret_outside_root", 0)),
            "secret_in_git": int(stats.get("secret_in_git", 0)),
            "inline_bearers": int(stats.get("inline_bearers", 0)),
            "governance_docs": governance_count,
        },
    }


def metric_line(result: Dict[str, Any]) -> str:
    scores = result.get("scores", {})
    parts = [f"CHI {result.get('chi')} ({result.get('scope')})"]
    parts += [f"{dim.upper()} {scores.get(dim)}" for dim in result.get("dims") or []]
    return " | ".join(parts)
