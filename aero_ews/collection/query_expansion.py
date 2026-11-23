"""Optional exploratory searches across linked aerospace programs."""

import re

from aero_ews.collection.registry import AEROSPACE_SUPPLIER_REGISTRY
from aero_ews.domain.identity import _detect_aircraft_families, _detect_exact_variants

# Bilingual exclusion marker separating positive KIT scope from excluded programs (preserved verbatim).
_EXCLUSION_RE = re.compile(r"\b(?:excluding|exclude|except(?:\s+for)?|without|not\s+including|kromě|vyjma)\b", re.I)


def _program_matches_kit(program: str, kit_text: str, kit_variants: set, kit_families: set) -> bool:
    """Return True if a supplier program matches the KIT text directly, by exact variant, or by unspecific family."""
    if re.search(rf"(?<!\w){re.escape(program)}(?!\w)", kit_text, re.I):
        return True
    if p_vars := _detect_exact_variants(program):
        return bool(p_vars & kit_variants)
    return bool(_detect_aircraft_families(program) & kit_families)


def build_cross_program_queries(kit: str, max_queries: int = 2):
    """Derive exploratory related-program queries from non-OEM shared-supplier links."""
    positive, *rest = _EXCLUSION_RE.split(kit or "", maxsplit=1)
    positive, excluded = positive.strip(), (rest[0].strip() if rest else "")
    kit_lower = positive.lower()
    kit_vars, kit_fams = _detect_exact_variants(positive), _detect_aircraft_families(positive)
    excl_vars = _detect_exact_variants(excluded) if excluded else set()
    excl_fams = _detect_aircraft_families(excluded) if excluded else set()

    # Collect unique cross-program leads while skipping OEMs, same-family siblings, and excluded programs.
    unique = {}
    for sup in AEROSPACE_SUPPLIER_REGISTRY:
        if "OEM" in sup.get("default_tier", ""):
            continue
        programs = sup.get("programs", [])
        if not (matched := [p for p in programs if _program_matches_kit(p, kit_lower, kit_vars, kit_fams)]):
            continue
        matched_fams = set().union(*(_detect_aircraft_families(p) for p in matched))
        for p in programs:
            if p in matched:
                continue
            p_fams, p_vars = _detect_aircraft_families(p), _detect_exact_variants(p)
            if (p_fams and p_fams.issubset(matched_fams)) or (p_vars & excl_vars) or (p_fams & excl_fams):
                continue
            q = f"{sup['official_name']} {p} production delay shortage"
            unique.setdefault(q, {
                "query": q, "supplier": sup["official_name"], "related_program": p,
                "original_programs": matched, "relationship_status": "HYPOTHETICAL_SHARED_SUPPLIER",
            })

    return list(unique.values())[:max_queries]