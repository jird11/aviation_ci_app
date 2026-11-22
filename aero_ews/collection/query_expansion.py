"""Optional exploratory searches across linked aerospace programs."""

import re

from aero_ews.collection.registry import AEROSPACE_SUPPLIER_REGISTRY
from aero_ews.domain.identity import _detect_aircraft_families, _detect_exact_variants

_EXCLUSION_RE = re.compile(
    r"\b(?:excluding|exclude|except(?:\s+for)?|without|not\s+including|kromě|vyjma)\b", re.I
)


def _program_matches_kit(
    program: str, kit_text: str, kit_variants: set, kit_families: set,
) -> bool:
    if re.search(rf"(?<!\w){re.escape(program)}(?!\w)", kit_text, re.I):
        return True
    p_vars = _detect_exact_variants(program)
    if p_vars and (p_vars & kit_variants):
        return True
    p_fams = _detect_aircraft_families(program)
    return bool(p_fams and not p_vars and (p_fams & kit_families))


def build_cross_program_queries(kit: str, max_queries: int = 2):
    """Derive exploratory related-program queries from known supplier links."""
    parts = _EXCLUSION_RE.split(kit or "", maxsplit=1)
    positive = parts[0].strip()
    excluded = parts[1].strip() if len(parts) > 1 else ""

    kit_lower = positive.lower()
    kit_variants = _detect_exact_variants(positive)
    kit_families = _detect_aircraft_families(positive)
    excl_variants = _detect_exact_variants(excluded) if excluded else set()
    excl_families = _detect_aircraft_families(excluded) if excluded else set()
    candidates = []

    for supplier in AEROSPACE_SUPPLIER_REGISTRY:
        if "OEM" in supplier.get("default_tier", ""):
            continue

        programs = supplier.get("programs", [])
        matched = [
            program for program in programs
            if _program_matches_kit(program, kit_lower, kit_variants, kit_families)
        ]
        if not matched:
            continue

        matched_fams = set().union(*(_detect_aircraft_families(p) for p in matched))
        related = []
        for p in programs:
            if p in matched:
                continue
            p_fams = _detect_aircraft_families(p)
            p_vars = _detect_exact_variants(p)
            if p_fams and p_fams.issubset(matched_fams):
                continue
            if (excl_variants and (p_vars & excl_variants)) or (excl_families and (p_fams & excl_families)):
                continue
            related.append(p)

        for program in related:
            candidates.append(
                {
                    "query": (
                        f"{supplier['official_name']} {program} "
                        "production delay shortage"
                    ),
                    "supplier": supplier["official_name"],
                    "related_program": program,
                    "original_programs": matched,
                    "relationship_status": "HYPOTHETICAL_SHARED_SUPPLIER",
                }
            )

    unique = {}
    for item in candidates:
        unique.setdefault(item["query"], item)

    return list(unique.values())[:max_queries]