"""Lightweight KIT-to-KIQ guard for agentic planning (no legacy channel query rewriting)."""

import re

from ews_state import KIQPlan, logger
from ews_validation import _detect_engine_models, _detect_exact_variants
from tasks import InformationRequirement, SearchPurpose

_EXCLUSION = re.compile(
    r"(?i:\b(?:excluding|exclude|without|except(?:\s+for)?|other\s+than|not\s+including))\s+"
    r"([A-Za-z][\w-]*(?:\s+[A-Z][\w-]*)*)"
)
_CAUSE = re.compile(r"\b(?:why|caus\w*|because|due\s+to|led\s+to|leads\s+to|resulted\s+in)\b", re.I)
_AUTHORITIES = re.compile(r"\b(?:FAA|EASA|NTSB|TCCA|CAAC|ANAC|UK\s+CAA|CAA)\b", re.I)


def _sanitize_kiq_plan_for_kit(kit: str, plan: KIQPlan) -> KIQPlan:
    """Keep causal KIQ decomposition complete and guard rationale against excluded entities."""
    kit = (kit or "").strip()
    exclusions = {m.group(1).strip() for m in _EXCLUSION.finditer(kit)}
    subject = _EXCLUSION.sub("", kit).strip(" ,;-") or kit
    identities = list(dict.fromkeys([
        *sorted(_detect_exact_variants(subject)),
        *sorted(_detect_engine_models(subject)),
        *sorted({re.sub(r"\s+", " ", m.upper()) for m in _AUTHORITIES.findall(subject)}),
    ]))

    updates: dict = {}

    if _CAUSE.search(subject) and hasattr(plan, "information_requirements"):
        requirements = list(plan.information_requirements or [])
        core = re.sub(r"^(?:why|how|what)\s+(?:(?:did|does|do|has|have|is|are)\s+)?", "", subject, flags=re.I).rstrip(" ?")
        core = re.sub(r"\s+(?:occur|happen|arise|take\s+place)$", "", core, flags=re.I).strip()
        for purpose, question in (
            (SearchPurpose.CAUSE, f"What is the documented cause of {core}?"),
            (SearchPurpose.IMPACT, f"What was the documented impact of {core}?"),
            (None, f"What evidence supports a causal link for {core}?"),
        ):
            exists = any(
                (req.search_purposes == [purpose] if purpose else bool(re.search(r"\b(?:causal\s+link|causal\s+relation|causation)\b", req.question, re.I)))
                for req in requirements
            )
            if not exists:
                requirements.append(InformationRequirement(
                    question=question,
                    search_purposes=[purpose] if purpose else [SearchPurpose.CAUSE, SearchPurpose.IMPACT],
                    required_identity=identities,
                ))
        updates["information_requirements"] = requirements

    rationale = str(getattr(plan, "strategy_rationale", "") or "").strip()
    if rationale and any(
        re.search(rf"\b{re.escape(ex)}\b", rationale, re.I)
        and not re.search(rf"(?:excluding|without|except|not\s+including|-)\s*\"?{re.escape(ex)}\b", rationale, re.I)
        for ex in exclusions
    ):
        trimmed = subject[:110].rsplit(" ", 1)[0] if len(subject) > 110 else subject
        updates["strategy_rationale"] = f"Monitor {trimmed} with explicit KIT constraints and evidence-backed follow-up."
        logger.warning("[PLANNER KIT GUARD] strategy_rationale sanitized for excluded entity.")

    if not updates:
        return plan
    return type(plan).model_validate(plan.model_copy(update=updates).model_dump())