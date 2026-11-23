"""Typed identity signals and conservative source/entity matching."""

import re
from dataclasses import dataclass
from difflib import get_close_matches
from enum import Enum
from typing import Any, Iterable, Mapping

from .identity_patterns import (
    AIRCRAFT_FAMILY_PATTERNS, ENGINE_CANONICAL_IDENTITIES, ENGINE_FAMILY_MEMBERS,
    ENGINE_KNOWN_ALIASES, ENGINE_MODEL_PATTERNS, SPECIFIC_AIRCRAFT_VARIANT_PATTERNS,
    SYNTACTIC_MODEL_TOKEN_RE, _EXACT_VARIANT_RE, _GTF_SPECIFIC_MODELS, _LEAP_SPECIFIC_MODELS,
)


class IdentityStatus(str, Enum):
    """Tri-state plus ambiguity status for conservative identity matching."""
    MATCH, MISMATCH, UNKNOWN, AMBIGUOUS = "MATCH", "MISMATCH", "UNKNOWN", "AMBIGUOUS"


class EntityType(str, Enum):
    """Canonical technical entity categories."""
    AIRCRAFT, ENGINE, COMPONENT = "AIRCRAFT", "ENGINE", "COMPONENT"
    MANUFACTURER, REGULATOR = "MANUFACTURER", "REGULATOR"
    UNKNOWN_TECHNICAL_IDENTIFIER = "UNKNOWN_TECHNICAL_IDENTIFIER"


@dataclass(frozen=True)
class IdentityResolution:
    """Result of resolving a technical identifier against the known catalog."""
    original_text: str
    canonical_identity: str | None
    entity_type: EntityType
    resolution_status: IdentityStatus
    candidate_aliases: tuple[str, ...] = ()
    identity_level: str = "UNKNOWN"
    suggested_identity: str | None = None
    suggestion_status: str | None = None
    reason: str = ""


@dataclass(frozen=True)
class IdentityDecision:
    """Auditable identity comparison outcome with optional document provenance."""
    status: IdentityStatus
    reason: str
    doc_id: str | None = None
    source_id: str | None = None


@dataclass(frozen=True)
class IdentitySignals:
    """Extracted entity, aircraft, engine, component, and regulator signals."""
    manufacturers: frozenset[str]
    aircraft_families: frozenset[str]
    exact_variants: frozenset[str]
    engines: frozenset[str]
    components: frozenset[str]
    regulatory_authorities: frozenset[str]


# Controlled bilingual component, authority, context, and manufacturer dictionaries (preserved verbatim).
_COMPONENT_PATTERNS = {
    "gearbox": r"gear[ -]?box|převodovk\w*",
    "fan blade": r"fan[ -]?blades?|lopatk\w* ventilátor\w*",
    "bearing": r"bearings?|ložisk\w*",
    "turbine": r"turbines?|turbín\w*",
    "compressor": r"compressors?|kompresor\w*",
    "combustor": r"combustors?|combustion chambers?",
    "landing gear": r"landing[ -]?gear|podvozk\w*",
    "nacelle": r"nacelles?",
}
_AUTHORITY_PATTERNS = {
    "FAA": r"FAA|Federal Aviation Administration",
    "EASA": r"EASA|European Union Aviation Safety Agency",
    "NTSB": r"NTSB|National Transportation Safety Board",
    "ICAO": r"ICAO|International Civil Aviation Organization",
    "TCCA": r"TCCA|Transport Canada Civil Aviation",
    "CAAC": r"CAAC|Civil Aviation Administration of China",
}
_AVIATION_CONTEXT = re.compile(
    r"\b(?:aviation|aerospace|aircraft|airline|airworthiness|airframe|"
    r"aeroengine|jet engine|letectv\w*|letadl\w*|leteck\w*)\b", re.I,
)
_MANUFACTURER_ALIASES = {
    "Airbus": ("Airbus",), "Boeing": ("Boeing",),
    "Pratt & Whitney": ("Pratt & Whitney", "Pratt and Whitney"),
    "CFM International": ("CFM International",), "GE Aerospace": ("GE Aerospace",),
    "Embraer": ("Embraer",), "COMAC": ("COMAC",),
}

# Precomputed lookups for model spans, typo suggestions, and engine/aircraft families.
_ALL_MODEL_PATTERNS = (*ENGINE_MODEL_PATTERNS.values(), *SPECIFIC_AIRCRAFT_VARIANT_PATTERNS.values(), *AIRCRAFT_FAMILY_PATTERNS.values())
_CATALOG_CODES = {
    **{re.sub(r"[^A-Z0-9]", "", name.upper()): name for name in ENGINE_CANONICAL_IDENTITIES.values()},
    **{re.sub(r"[^A-Z0-9]", "", name.upper()): name for name in SPECIFIC_AIRCRAFT_VARIANT_PATTERNS},
}
_ENGINE_FAMILIES = {"LEAP": _LEAP_SPECIFIC_MODELS, "GTF": _GTF_SPECIFIC_MODELS}
_BROAD_VARIANT_ALIASES = {"737_MAX", "737_NG", "A320NEO_FAMILY", "A320CEO_FAMILY"}


# Pattern-matching helpers for components, authorities, entities, and aircraft/engine models.
def _match_word_dict(text: str, table: Mapping[str, str]) -> list[str]: return [k for k, pat in table.items() if re.search(rf"\b(?:{pat})\b", text, re.I)]
def _mentions(text: str, name: str) -> bool: return bool(name and re.search(r"(?<!\w)" + re.escape(name).replace(r"\ ", r"[\s-]+") + r"(?!\w)", text, re.I))
def _detect_specific_variants(text: str) -> set[str]: return {k for k, pat in SPECIFIC_AIRCRAFT_VARIANT_PATTERNS.items() if pat.search(text or "")}
def _detect_aircraft_families(text: str) -> set[str]: return {k for k, pat in AIRCRAFT_FAMILY_PATTERNS.items() if pat.search(text or "")}
def _engine_models_match(query: str, evidence: str) -> bool: return engine_identity_status(query, evidence).status == IdentityStatus.MATCH


def _detect_engine_models(text: str) -> set[str]:
    """Detect engine models, preferring explicit variants over broad family labels."""
    detected = {k for k, pat in ENGINE_MODEL_PATTERNS.items() if pat.search(text or "")}
    if detected & _LEAP_SPECIFIC_MODELS: detected.discard("LEAP")
    if detected & _GTF_SPECIFIC_MODELS: detected.discard("GTF")
    return detected


def _detect_exact_variants(text: str) -> set[str]:
    """Detect exact numeric/suffixed aircraft variants only when an aircraft family/variant context exists."""
    if not (_detect_aircraft_families(text) or _detect_specific_variants(text)):
        return set()
    return {
        f"{base}:{'' if kind.lower() == 'max' else kind.upper()}{num or tail}"
        for base, kind, num, tail in _EXACT_VARIANT_RE.findall(text or "")
        if num or tail or (kind and kind.lower() != "max")
    }


def resolve_technical_identity(text: str, expected_identity: str | None = None) -> IdentityResolution:
    """Resolve catalog labels, not source truth; unrecognized codes remain unconfirmed suggestions."""
    text = text if isinstance(text, str) else ""
    engines, ac_exact, ac_vars, ac_fams = _detect_engine_models(text), _detect_exact_variants(text), _detect_specific_variants(text), _detect_aircraft_families(text)

    # Rank candidate catalog matches by specificity: engine > aircraft > component > regulator > manufacturer.
    candidates: list[tuple[EntityType, str, tuple[str, ...], str]] = []
    if engines:
        candidates = [(EntityType.ENGINE, ENGINE_CANONICAL_IDENTITIES[k], ENGINE_KNOWN_ALIASES.get(k, (ENGINE_CANONICAL_IDENTITIES[k],)), "FAMILY" if k in ENGINE_FAMILY_MEMBERS else "VARIANT") for k in sorted(engines)]
    elif ac_exact or ac_vars or ac_fams:
        precise = ac_vars - _BROAD_VARIANT_ALIASES
        names = precise if (len(ac_exact) == 1 and precise) else (ac_exact or ac_vars or ac_fams)
        candidates = [(EntityType.AIRCRAFT, n, (n,), "VARIANT" if (ac_exact or n not in ac_fams) else "FAMILY") for n in sorted(names)]
    else:
        makers = [k for k, aliases in _MANUFACTURER_ALIASES.items() if any(_mentions(text, a) for a in aliases)]
        for kind, names in ((EntityType.COMPONENT, _match_word_dict(text, _COMPONENT_PATTERNS)), (EntityType.REGULATOR, _match_word_dict(text, _AUTHORITY_PATTERNS)), (EntityType.MANUFACTURER, makers)):
            if names:
                candidates = [(kind, n, (n,), "UNKNOWN") for n in names]
                break

    # Flag any syntactic model token not covered by a known catalog match span.
    known_spans = [(m.start(), m.end()) for pat in _ALL_MODEL_PATTERNS for m in pat.finditer(text)]
    unknown_codes = [m.group().upper() for m in SYNTACTIC_MODEL_TOKEN_RE.finditer(text) if not any(s <= m.start() and m.end() <= e for s, e in known_spans)]
    if unknown_codes:
        if any(c[0] in {EntityType.ENGINE, EntityType.AIRCRAFT} for c in candidates) or len(set(unknown_codes)) > 1:
            return IdentityResolution(text, None, EntityType.UNKNOWN_TECHNICAL_IDENTIFIER, IdentityStatus.AMBIGUOUS, reason="MIXED_OR_MULTIPLE_UNRESOLVED_CODES")
        nearby = get_close_matches(re.sub(r"[^A-Z0-9]", "", unknown_codes[0]), _CATALOG_CODES, n=2, cutoff=0.84)
        if len(nearby) == 1:
            sug = _CATALOG_CODES[nearby[0]]
            return IdentityResolution(text, None, EntityType.UNKNOWN_TECHNICAL_IDENTIFIER, IdentityStatus.UNKNOWN, (sug,), suggested_identity=sug, suggestion_status="REQUIRES_CONFIRMATION", reason="POSSIBLE_TYPO")
        return IdentityResolution(text, None, EntityType.UNKNOWN_TECHNICAL_IDENTIFIER, IdentityStatus.AMBIGUOUS if nearby else IdentityStatus.UNKNOWN, tuple(_CATALOG_CODES[n] for n in nearby), reason="UNRECOGNIZED_MODEL_CODE")

    if not candidates: return IdentityResolution(text, None, EntityType.UNKNOWN_TECHNICAL_IDENTIFIER, IdentityStatus.UNKNOWN, reason="NO_KNOWN_IDENTITY")
    if len(candidates) != 1: return IdentityResolution(text, None, candidates[0][0], IdentityStatus.AMBIGUOUS, tuple(c[1] for c in candidates), reason="MULTIPLE_CATALOG_IDENTITIES")

    kind, canonical, aliases, level = candidates[0]
    if expected_identity is None:
        return IdentityResolution(text, canonical, kind, IdentityStatus.MATCH, aliases, identity_level=level, reason="CATALOG_ALIAS_MATCH")

    exp = resolve_technical_identity(expected_identity)
    if exp.resolution_status != IdentityStatus.MATCH or exp.entity_type != kind:
        status, reason = IdentityStatus.UNKNOWN, "EXPECTED_IDENTITY_UNVERIFIED"
    elif exp.canonical_identity == canonical or (kind == EntityType.ENGINE and exp.canonical_identity in ENGINE_FAMILY_MEMBERS and canonical in {ENGINE_CANONICAL_IDENTITIES[k] for k in ENGINE_FAMILY_MEMBERS[exp.canonical_identity]}):
        status, reason = IdentityStatus.MATCH, "EXPECTED_IDENTITY_MATCH"
    elif kind == EntityType.ENGINE and canonical in ENGINE_FAMILY_MEMBERS:
        status, reason = IdentityStatus.UNKNOWN, "FAMILY_DOES_NOT_VERIFY_VARIANT"
    else:
        status, reason = IdentityStatus.MISMATCH, "EXPECTED_IDENTITY_DIFFERENT"
    return IdentityResolution(text, canonical, kind, status, aliases, level, reason=reason)


def engine_identity_status(query: str, evidence: str) -> IdentityDecision:
    """A family may include a variant; a variant is never proven by its broad family."""
    wanted, found = _detect_engine_models(query), _detect_engine_models(evidence)
    if not wanted or not found: return IdentityDecision(IdentityStatus.UNKNOWN, "ENGINE_IDENTITY_MISSING")
    supported = {m for m in wanted if m in found or (m in _ENGINE_FAMILIES and (found & _ENGINE_FAMILIES[m]))}
    if supported == wanted:
        return IdentityDecision(IdentityStatus.AMBIGUOUS, "MULTIPLE_ENGINE_VARIANTS_IN_SOURCE") if (all(m not in _ENGINE_FAMILIES for m in wanted) and (found - wanted - _ENGINE_FAMILIES.keys())) else IdentityDecision(IdentityStatus.MATCH, "ENGINE_IDENTITY_MATCH")
    if supported or any(m in members and fam in found for m in wanted for fam, members in _ENGINE_FAMILIES.items()):
        return IdentityDecision(IdentityStatus.UNKNOWN, "ENGINE_VARIANT_NOT_VERIFIED")
    return IdentityDecision(IdentityStatus.MISMATCH, "ENGINE_IDENTITY_DIFFERENT")


def aircraft_identity_status(query: str, evidence: str) -> IdentityDecision:
    """Never promote a broad aircraft family to a requested exact or specific variant."""
    if exact_w := _detect_exact_variants(query):
        exact_f = _detect_exact_variants(evidence)
        if exact_w <= exact_f:
            return IdentityDecision(IdentityStatus.AMBIGUOUS, "MULTIPLE_AIRCRAFT_VARIANTS_IN_SOURCE") if (exact_f - exact_w) else IdentityDecision(IdentityStatus.MATCH, "AIRCRAFT_EXACT_VARIANT_MATCH")
        return IdentityDecision(IdentityStatus.UNKNOWN, "AIRCRAFT_VARIANT_INCOMPLETE") if ((exact_w & exact_f) or not exact_f) else IdentityDecision(IdentityStatus.MISMATCH, "AIRCRAFT_EXACT_VARIANT_DIFFERENT")

    if spec_w := _detect_specific_variants(query):
        spec_f = _detect_specific_variants(evidence)
        if spec_w <= spec_f:
            return IdentityDecision(IdentityStatus.AMBIGUOUS, "MULTIPLE_AIRCRAFT_VARIANTS_IN_SOURCE") if (spec_f - spec_w) else IdentityDecision(IdentityStatus.MATCH, "AIRCRAFT_VARIANT_MATCH")
        if spec_w & spec_f: return IdentityDecision(IdentityStatus.UNKNOWN, "AIRCRAFT_VARIANT_INCOMPLETE")
        return IdentityDecision(IdentityStatus.MISMATCH, "AIRCRAFT_VARIANT_DIFFERENT") if spec_f else IdentityDecision(IdentityStatus.UNKNOWN, "AIRCRAFT_VARIANT_NOT_VERIFIED")

    wanted, found = _detect_aircraft_families(query), _detect_aircraft_families(evidence)
    if not wanted or not found: return IdentityDecision(IdentityStatus.UNKNOWN, "AIRCRAFT_FAMILY_MISSING")
    if wanted <= found: return IdentityDecision(IdentityStatus.MATCH, "AIRCRAFT_FAMILY_MATCH")
    return IdentityDecision(IdentityStatus.UNKNOWN, "AIRCRAFT_FAMILY_INCOMPLETE") if (wanted & found) else IdentityDecision(IdentityStatus.MISMATCH, "AIRCRAFT_FAMILY_DIFFERENT")


def extract_identity_signals(text: str, manufacturers: Iterable[str] = ()) -> IdentitySignals:
    """Extract typed identity signals; manufacturer labels are explicit inputs, never inferred."""
    text = text or ""
    return IdentitySignals(
        frozenset(name for name in manufacturers if _mentions(text, name)),
        frozenset(_detect_aircraft_families(text)),
        frozenset(_detect_specific_variants(text) | _detect_exact_variants(text)),
        frozenset(_detect_engine_models(text)),
        frozenset(_match_word_dict(text, _COMPONENT_PATTERNS)),
        frozenset(_match_word_dict(text, _AUTHORITY_PATTERNS)),
    )


def topic_identity_status(query: str, evidence: str) -> IdentityDecision:
    """Check explicit entity constraints without inferring claim truth or meaning."""
    res = resolve_technical_identity(query)
    if res.entity_type == EntityType.UNKNOWN_TECHNICAL_IDENTIFIER and res.resolution_status in {IdentityStatus.UNKNOWN, IdentityStatus.AMBIGUOUS} and SYNTACTIC_MODEL_TOKEN_RE.search(query):
        return IdentityDecision(IdentityStatus.UNKNOWN, "MODEL_TOKEN_UNRESOLVED")

    wanted, found, decisions = extract_identity_signals(query), extract_identity_signals(evidence), []
    if wanted.engines: decisions.append(engine_identity_status(query, evidence))
    if wanted.aircraft_families or wanted.exact_variants: decisions.append(aircraft_identity_status(query, evidence))
    for cat in ("components", "regulatory_authorities"):
        if req := getattr(wanted, cat):
            obs = getattr(found, cat)
            st = IdentityStatus.MATCH if req <= obs else (IdentityStatus.UNKNOWN if (not obs or (req & obs)) else IdentityStatus.MISMATCH)
            decisions.append(IdentityDecision(st, f"{cat.upper()}_{st.value}"))

    if not decisions: return IdentityDecision(IdentityStatus.UNKNOWN, "TOPIC_IDENTIFIERS_MISSING")
    for priority in (IdentityStatus.MISMATCH, IdentityStatus.AMBIGUOUS, IdentityStatus.UNKNOWN):
        if hit := next((d for d in decisions if d.status == priority), None):
            return hit
    return IdentityDecision(IdentityStatus.MATCH, "TOPIC_IDENTIFIERS_MATCH")


def assess_manufacturer_identity(
    manufacturer: str, document: Mapping[str, Any], aliases: Iterable[str] = (), *, topic: str = "",
) -> IdentityDecision:
    """Verify an aviation manufacturer identity, not the truth of its claims.

    Publisher/issuer identity must be independently verified; third-party mentions do not qualify.
    """
    names, text = (manufacturer, *aliases), f"{document.get('title') or ''} {document.get('text') or ''}"
    issuer, subject = str(document.get("issuer") or document.get("publisher") or ""), str(document.get("manufacturer") or "")
    prov = {"doc_id": document.get("doc_id"), "source_id": document.get("source_id")}

    verified_issuer = document.get("issuer_identity_verified") is True or document.get("publisher_identity_verified") is True
    if not ((verified_issuer and any(_mentions(issuer, n) for n in names)) or (document.get("manufacturer_identity_verified") is True and any(_mentions(subject, n) for n in names))):
        return IdentityDecision(IdentityStatus.UNKNOWN, "SOURCE_IDENTITY_UNVERIFIED", **prov)
    if not (_AVIATION_CONTEXT.search(text) or _detect_aircraft_families(text) or _detect_engine_models(text)):
        return IdentityDecision(IdentityStatus.UNKNOWN, "AVIATION_CONTEXT_UNVERIFIED", **prov)
    if topic:
        c = extract_identity_signals(topic)
        if any((c.engines, c.exact_variants, c.aircraft_families, c.components, c.regulatory_authorities)) and topic_identity_status(topic, text).status != IdentityStatus.MATCH:
            return IdentityDecision(IdentityStatus.UNKNOWN, "TOPIC_IDENTITY_UNVERIFIED", **prov)
    return IdentityDecision(IdentityStatus.MATCH, "MANUFACTURER_IDENTITY_VERIFIED", **prov)