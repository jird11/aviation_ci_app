# =============================================================================
# aviation_ci_app | Deterministic 5-factor I&W threat scoring
#
# Responsibility: Compute transparent, reproducible 1-10 potential severity scores
#   from five structured I&W factors (F1-F5) without invoking a separate Scoring LLM.
# Design boundary: Potential severity is strictly independent of source verification
#   status and confidence; confirmed critical escalation remains Harness-gated.
# =============================================================================

"""Deterministic 5-factor weighted I&W scoring and audit generation."""

from __future__ import annotations

import math
from datetime import date, datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from ews_state import EventFreshness, PropagationEffect, SCMTier, ThreatAssessment

# Explicit factor weights (sum = 1.00), grounded in 5-factor aerospace SCM I&W analysis.
SCORING_WEIGHTS: Dict[str, float] = {
    "impact_severity": 0.30,             # F1: Operational / strategic damage potential
    "supplier_criticality": 0.20,        # F2: Importance of affected node/supplier to program
    "substitutability_difficulty": 0.15, # F3: Difficulty of finding an alternative supplier/part
    "propagation_scope": 0.15,           # F4: Potential spillover across fleets/tiers/programs
    "temporal_urgency": 0.20,            # F5: Immediacy and horizon of impact
}

SCORING_FACTOR_META: Dict[str, Dict[str, Any]] = {
    "impact_severity": {"code": "F1", "label": "Impact Severity", "weight": 0.30},
    "supplier_criticality": {"code": "F2", "label": "Supplier Criticality", "weight": 0.20},
    "substitutability_difficulty": {"code": "F3", "label": "Substitutability Difficulty", "weight": 0.15},
    "propagation_scope": {"code": "F4", "label": "Propagation Scope", "weight": 0.15},
    "temporal_urgency": {"code": "F5", "label": "Temporal Urgency", "weight": 0.20},
}

SCORING_METHODOLOGY_META: Dict[str, Any] = {
    "version": "IW-5FACTOR-DET-V1",
    "method": "DETERMINISTIC_5_FACTOR_IW",
    "scale": "F1-F5 rated 1..5; final threat_score 1..10",
    "formula": "S = clamp(floor(sum(w_i * F_i) * 2 + 0.5), 1, 10)",
    "weights": dict(SCORING_WEIGHTS),
    "bands": {"monitored": "1-4", "elevated": "5-7", "high_potential_impact": "8-10"},
    "severity_independent_of_confidence": True,
}


def _round_half_up(value: float) -> int:
    """Deterministic half-up rounding (avoids Python banker's rounding ambiguity)."""
    return int(math.floor(value + 0.5))


def _days_since(publication_time: str, as_of_date: str) -> Optional[int]:
    try:
        ref = date.fromisoformat(str(as_of_date)[:10]) if as_of_date else datetime.now(timezone.utc).date()
        return (ref - date.fromisoformat(str(publication_time or "")[:10])).days
    except (TypeError, ValueError):
        return None


def _derive_fallback_factors(
    threat: ThreatAssessment,
    chronology_record: Optional[Dict[str, Any]] = None,
    as_of_date: str = "",
) -> Dict[str, Dict[str, Any]]:
    """Derive transparent F1-F5 defaults only if Analyst omitted risk_factors."""
    base_f1 = max(1, min(5, _round_half_up((threat.threat_score or 5) / 2.0)))

    tier_scores = {
        SCMTier.OEM: 5,
        SCMTier.TIER_1: 4,
        SCMTier.TIER_2: 3,
        SCMTier.TIER_3: 3,
        SCMTier.REGULATOR_AIRLINE: 3,
        SCMTier.UNKNOWN: 2,
    }
    f2 = tier_scores.get(threat.scm_tier, 2)
    f3 = 4 if threat.scm_tier in {SCMTier.OEM, SCMTier.TIER_1} else 3

    prop_scores = {
        PropagationEffect.SPILLOVER: 4,
        PropagationEffect.JIT: 4,
        PropagationEffect.BULLWHIP: 3,
        PropagationEffect.DIRECT: 3,
    }
    f4 = prop_scores.get(threat.propagation_effect, 3)

    age = _days_since(threat.publication_time, as_of_date)
    if (chronology_record or {}).get("fully_resolved") or threat.event_freshness == EventFreshness.HISTORICAL_CONTEXT:
        f5 = 1
    elif age is not None and age > 90:
        f5 = 2
    elif threat.event_freshness in {EventFreshness.NEW_EVENT, EventFreshness.NEW_DEVELOPMENT}:
        f5 = 4
    elif threat.event_freshness == EventFreshness.ONGOING_ISSUE:
        f5 = 3
    else:
        f5 = 2

    return {
        "impact_severity": {
            "score": base_f1,
            "rationale": "Derived from provisional Analyst severity estimate; explicit F1 rationale not supplied.",
        },
        "supplier_criticality": {
            "score": f2,
            "rationale": f"Derived from classified SCM tier ({threat.scm_tier.value}).",
        },
        "substitutability_difficulty": {
            "score": f3,
            "rationale": "Default aerospace tier substitutability estimate; direct supplier lock-in requires verification.",
        },
        "propagation_scope": {
            "score": f4,
            "rationale": f"Derived from classified propagation mechanism ({threat.propagation_effect.value}).",
        },
        "temporal_urgency": {
            "score": f5,
            "rationale": f"Derived from freshness ({threat.event_freshness.value}) and source age ({age if age is not None else 'unknown'} days).",
        },
    }


def compute_deterministic_threat_score(
    threat: ThreatAssessment,
    chronology_record: Optional[Dict[str, Any]] = None,
    as_of_date: str = "",
) -> Tuple[int, str, Dict[str, Any]]:
    """Calculate weighted 5-factor score and build a full explainable scoring_audit row."""
    provisional_score = threat.threat_score
    rf = getattr(threat, "risk_factors", None)

    if rf is not None:
        raw_factors = {
            key: {
                "score": int(getattr(rf, key).score),
                "rationale": str(getattr(rf, key).rationale).strip(),
            }
            for key in SCORING_WEIGHTS
        }
        scoring_source = "DETERMINISTIC_5_FACTOR_IW"
    else:
        raw_factors = _derive_fallback_factors(threat, chronology_record, as_of_date)
        scoring_source = "DETERMINISTIC_HEURISTIC_FALLBACK"

    breakdown: Dict[str, Dict[str, Any]] = {}
    weighted_sum = 0.0
    for key, weight in SCORING_WEIGHTS.items():
        val = max(1, min(5, int(raw_factors[key]["score"])))
        contrib = round(val * weight, 4)
        weighted_sum += val * weight
        meta = SCORING_FACTOR_META[key]
        breakdown[key] = {
            "code": meta["code"],
            "label": meta["label"],
            "score": val,
            "weight": weight,
            "weighted_contribution": contrib,
            "rationale": raw_factors[key]["rationale"],
        }

    weighted_sum = round(weighted_sum, 4)
    computed_score = max(1, min(10, _round_half_up(weighted_sum * 2.0)))
    final_score = computed_score
    cap_applied: Optional[str] = None

    if (chronology_record or {}).get("fully_resolved"):
        final_score = min(final_score, 2)
        cap_applied = "HISTORICALLY_RESOLVED_CAP_MAX_2"

    # Identify the two strongest contributing factors for a concise rationale.
    top_factors = sorted(
        breakdown.values(),
        key=lambda item: (-item["weighted_contribution"], item["code"]),
    )[:2]
    drivers = ", ".join(f"{f['code']} {f['label']} ({f['score']}/5, w={f['weight']:.2f})" for f in top_factors)
    formula_text = (
        f"S = round({weighted_sum:.2f} * 2) = {computed_score}/10"
        + (f" -> capped to {final_score}/10 ({cap_applied})" if cap_applied else "")
    )
    score_rationale = (
        f"Deterministic 5-factor I&W score {final_score}/10 ({formula_text}). "
        f"Primary drivers: {drivers}. Potential severity only; evidence validation is evaluated separately."
    )

    audit_row: Dict[str, Any] = {
        "event_id": threat.event_id,
        "provisional_score": provisional_score,
        "computed_score": computed_score,
        "final_score": final_score,
        "scoring_method": SCORING_METHODOLOGY_META["method"],
        "scoring_version": SCORING_METHODOLOGY_META["version"],
        "scoring_source": scoring_source,
        "formula": formula_text,
        "weighted_sum": weighted_sum,
        "weights": dict(SCORING_WEIGHTS),
        "factors": breakdown,
        "cap_applied": cap_applied,
        # Backwards-compatible summary fields consumed by reporting & dashboard.
        "impact_assessment": f"F1 ({breakdown['impact_severity']['score']}/5): {breakdown['impact_severity']['rationale']}",
        "supplier_criticality": (
            f"F2 ({breakdown['supplier_criticality']['score']}/5): {breakdown['supplier_criticality']['rationale']} | "
            f"F3 ({breakdown['substitutability_difficulty']['score']}/5): {breakdown['substitutability_difficulty']['rationale']}"
        ),
        "temporal_urgency": f"F5 ({breakdown['temporal_urgency']['score']}/5): {breakdown['temporal_urgency']['rationale']}",
        "score_rationale": score_rationale,
    }
    return final_score, score_rationale, audit_row


def score_threats_deterministically(
    threats: List[ThreatAssessment],
    chronology_by_event: Optional[Dict[str, Dict[str, Any]]] = None,
    as_of_date: str = "",
) -> Tuple[List[Dict[str, Any]], str, List[str]]:
    """Score all candidate threats deterministically and return (audit, status, fallback_ids)."""
    chronology_by_event = chronology_by_event or {}
    scoring_audit: List[Dict[str, Any]] = []
    fallback_ids: List[str] = []

    for threat in threats:
        final_score, rationale, row = compute_deterministic_threat_score(
            threat,
            chronology_record=chronology_by_event.get(threat.event_id),
            as_of_date=as_of_date,
        )
        threat.threat_score = final_score
        threat.score_rationale = rationale
        threat.is_critical = False  # Reassessed strictly after Harness validation.
        scoring_audit.append(row)
        if row["scoring_source"] != "DETERMINISTIC_5_FACTOR_IW":
            fallback_ids.append(threat.event_id)

    if not threats:
        status = "NOT_REQUIRED"
    elif not fallback_ids:
        status = "COMPLETED"
    elif len(fallback_ids) < len(threats):
        status = "PARTIAL_FALLBACK"
    else:
        status = "PROVISIONAL_FALLBACK"
    return scoring_audit, status, sorted(fallback_ids)