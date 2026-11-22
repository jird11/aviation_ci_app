"""Typed identity signals and conservative source/entity matching."""

import re
from dataclasses import dataclass
from difflib import get_close_matches
from enum import Enum
from typing import Any, Iterable, Mapping

from .identity_patterns import (
    AIRCRAFT_FAMILY_PATTERNS,
    ENGINE_MODEL_PATTERNS,
    SPECIFIC_AIRCRAFT_VARIANT_PATTERNS,
    _EXACT_VARIANT_RE,
    _GTF_SPECIFIC_MODELS,
    _LEAP_SPECIFIC_MODELS,
    ENGINE_CANONICAL_IDENTITIES,
    ENGINE_FAMILY_MEMBERS,
    ENGINE_KNOWN_ALIASES,
    SYNTACTIC_MODEL_TOKEN_RE,
)


class IdentityStatus(str, Enum):
    MATCH = "MATCH"
    MISMATCH = "MISMATCH"
    UNKNOWN = "UNKNOWN"
    AMBIGUOUS = "AMBIGUOUS"


class EntityType(str, Enum):
    AIRCRAFT = "AIRCRAFT"
    ENGINE = "ENGINE"
    COMPONENT = "COMPONENT"
    MANUFACTURER = "MANUFACTURER"
    REGULATOR = "REGULATOR"
    UNKNOWN_TECHNICAL_IDENTIFIER = "UNKNOWN_TECHNICAL_IDENTIFIER"


@dataclass(frozen=True)
class IdentityResolution:
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
    status: IdentityStatus
    reason: str
    doc_id: str | None = None
    source_id: str | None = None


@dataclass(frozen=True)
class IdentitySignals:
    manufacturers: frozenset[str]
    aircraft_families: frozenset[str]
    exact_variants: frozenset[str]
    engines: frozenset[str]
    components: frozenset[str]
    regulatory_authorities: frozenset[str]


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
    r"aeroengine|jet engine|letectv\w*|letadl\w*|leteck\w*)\b", re.I
)
_MANUFACTURER_ALIASES = {
    "Airbus": ("Airbus",), "Boeing": ("Boeing",),
    "Pratt & Whitney": ("Pratt & Whitney", "Pratt and Whitney"),
    "CFM International": ("CFM International",), "GE Aerospace": ("GE Aerospace",),
    "Embraer": ("Embraer",), "COMAC": ("COMAC",),
}


def resolve_technical_identity(text: str, expected_identity: str | None = None) -> IdentityResolution:
    """Resolve catalog labels, not source truth; typos remain unconfirmed suggestions."""
    text = text if isinstance(text, str) else ""
    engines = _detect_engine_models(text)
    aircraft_exact = _detect_exact_variants(text)
    aircraft_variants = _detect_specific_variants(text)
    aircraft_families = _detect_aircraft_families(text)
    candidates: list[tuple[EntityType, str, tuple[str, ...], str]] = []
    if engines:
        candidates = [
            (EntityType.ENGINE, ENGINE_CANONICAL_IDENTITIES[key],
             ENGINE_KNOWN_ALIASES.get(key, (ENGINE_CANONICAL_IDENTITIES[key],)),
             "FAMILY" if key in ENGINE_FAMILY_MEMBERS else "VARIANT")
            for key in sorted(engines)
        ]
    elif aircraft_exact or aircraft_variants or aircraft_families:
        precise_aliases = aircraft_variants - {"737_MAX", "737_NG", "A320NEO_FAMILY", "A320CEO_FAMILY"}
        names = precise_aliases if len(aircraft_exact) == 1 and precise_aliases else (
            aircraft_exact or aircraft_variants or aircraft_families)
        candidates = [(EntityType.AIRCRAFT, name, (name,),
                       "VARIANT" if aircraft_exact or name not in aircraft_families else "FAMILY")
                      for name in sorted(names)]
    else:
        components = [key for key, pat in _COMPONENT_PATTERNS.items()
                      if re.search(r"\b(?:" + pat + r")\b", text, re.I)]
        regulators = [key for key, pat in _AUTHORITY_PATTERNS.items()
                      if re.search(r"\b(?:" + pat + r")\b", text, re.I)]
        makers = [key for key, aliases in _MANUFACTURER_ALIASES.items()
                  if any(_mentions(text, alias) for alias in aliases)]
        for kind, names in ((EntityType.COMPONENT, components), (EntityType.REGULATOR, regulators),
                            (EntityType.MANUFACTURER, makers)):
            if names:
                candidates = [(kind, name, (name,), "UNKNOWN") for name in names]
                break

    patterns = (*ENGINE_MODEL_PATTERNS.values(), *SPECIFIC_AIRCRAFT_VARIANT_PATTERNS.values(),
                *AIRCRAFT_FAMILY_PATTERNS.values())
    known_spans = [(match.start(), match.end()) for pat in patterns for match in pat.finditer(text)]
    unknown_codes = [match.group().upper() for match in SYNTACTIC_MODEL_TOKEN_RE.finditer(text)
                     if not any(start <= match.start() and match.end() <= end
                                for start, end in known_spans)]
    if unknown_codes:
        if any(item[0] in {EntityType.ENGINE, EntityType.AIRCRAFT} for item in candidates) or len(set(unknown_codes)) > 1:
            return IdentityResolution(text, None, EntityType.UNKNOWN_TECHNICAL_IDENTIFIER,
                                      IdentityStatus.AMBIGUOUS, reason="MIXED_OR_MULTIPLE_UNRESOLVED_CODES")
        catalog_codes = {re.sub(r"[^A-Z0-9]", "", name.upper()): name
                         for name in ENGINE_CANONICAL_IDENTITIES.values()}
        catalog_codes.update({re.sub(r"[^A-Z0-9]", "", name.upper()): name
                              for name in SPECIFIC_AIRCRAFT_VARIANT_PATTERNS})
        token = re.sub(r"[^A-Z0-9]", "", unknown_codes[0])
        nearby = get_close_matches(token, catalog_codes, n=2, cutoff=0.84)
        if len(nearby) == 1:
            return IdentityResolution(text, None, EntityType.UNKNOWN_TECHNICAL_IDENTIFIER,
                                      IdentityStatus.UNKNOWN, (catalog_codes[nearby[0]],),
                                      suggested_identity=catalog_codes[nearby[0]],
                                      suggestion_status="REQUIRES_CONFIRMATION", reason="POSSIBLE_TYPO")
        return IdentityResolution(text, None, EntityType.UNKNOWN_TECHNICAL_IDENTIFIER,
                                  IdentityStatus.AMBIGUOUS if nearby else IdentityStatus.UNKNOWN,
                                  tuple(catalog_codes[n] for n in nearby), reason="UNRECOGNIZED_MODEL_CODE")
    if not candidates:
        return IdentityResolution(text, None, EntityType.UNKNOWN_TECHNICAL_IDENTIFIER,
                                  IdentityStatus.UNKNOWN, reason="NO_KNOWN_IDENTITY")
    if len(candidates) != 1:
        return IdentityResolution(text, None, candidates[0][0], IdentityStatus.AMBIGUOUS,
                                  tuple(item[1] for item in candidates), reason="MULTIPLE_CATALOG_IDENTITIES")
    kind, canonical, aliases, level = candidates[0]
    result = IdentityResolution(text, canonical, kind, IdentityStatus.MATCH, aliases,
                                identity_level=level, reason="CATALOG_ALIAS_MATCH")
    if expected_identity is None:
        return result
    expected = resolve_technical_identity(expected_identity)
    if expected.resolution_status != IdentityStatus.MATCH or expected.entity_type != kind:
        status, reason = IdentityStatus.UNKNOWN, "EXPECTED_IDENTITY_UNVERIFIED"
    elif expected.canonical_identity == canonical or (
        kind == EntityType.ENGINE and expected.canonical_identity in ENGINE_FAMILY_MEMBERS
        and canonical in {ENGINE_CANONICAL_IDENTITIES[k]
                          for k in ENGINE_FAMILY_MEMBERS[expected.canonical_identity]}
    ):
        status, reason = IdentityStatus.MATCH, "EXPECTED_IDENTITY_MATCH"
    elif kind == EntityType.ENGINE and canonical in ENGINE_FAMILY_MEMBERS:
        status, reason = IdentityStatus.UNKNOWN, "FAMILY_DOES_NOT_VERIFY_VARIANT"
    else:
        status, reason = IdentityStatus.MISMATCH, "EXPECTED_IDENTITY_DIFFERENT"
    return IdentityResolution(text, canonical, kind, status, aliases, level, reason=reason)


def _detect_engine_models(text: str) -> set[str]:
    """Prefer explicit engine variants to their broad family labels."""
    detected = {key for key, pattern in ENGINE_MODEL_PATTERNS.items() if pattern.search(text or "")}
    if detected & _LEAP_SPECIFIC_MODELS:
        detected.discard("LEAP")
    if detected & _GTF_SPECIFIC_MODELS:
        detected.discard("GTF")
    return detected


def engine_identity_status(query: str, evidence: str) -> IdentityDecision:
    """A family may include a variant; a variant is not proven by its family."""
    wanted, found = _detect_engine_models(query), _detect_engine_models(evidence)
    if not wanted or not found:
        return IdentityDecision(IdentityStatus.UNKNOWN, "ENGINE_IDENTITY_MISSING")

    families = {"LEAP": _LEAP_SPECIFIC_MODELS, "GTF": _GTF_SPECIFIC_MODELS}
    supported = {
        model for model in wanted
        if model in found or (model in families and found & families[model])
    }
    if supported == wanted:
        if all(model not in families for model in wanted) and found - wanted - families.keys():
            return IdentityDecision(IdentityStatus.AMBIGUOUS, "MULTIPLE_ENGINE_VARIANTS_IN_SOURCE")
        return IdentityDecision(IdentityStatus.MATCH, "ENGINE_IDENTITY_MATCH")
    if supported or any(model in members and family in found
                        for model in wanted for family, members in families.items()):
        return IdentityDecision(IdentityStatus.UNKNOWN, "ENGINE_VARIANT_NOT_VERIFIED")
    return IdentityDecision(IdentityStatus.MISMATCH, "ENGINE_IDENTITY_DIFFERENT")


def _engine_models_match(query: str, evidence: str) -> bool:
    return engine_identity_status(query, evidence).status == IdentityStatus.MATCH


def _detect_specific_variants(text: str) -> set[str]:
    return {key for key, pattern in SPECIFIC_AIRCRAFT_VARIANT_PATTERNS.items()
            if pattern.search(text or "")}


def _detect_exact_variants(text: str) -> set[str]:
    # A three-digit number with a suffix is not necessarily an aircraft model.
    if not (_detect_aircraft_families(text) or _detect_specific_variants(text)):
        return set()
    return {
        f"{base}:{'' if kind.lower() == 'max' else kind.upper()}{num or tail}"
        for base, kind, num, tail in _EXACT_VARIANT_RE.findall(text or "")
        if num or tail or (kind and kind.lower() != "max")
    }


def _detect_aircraft_families(text: str) -> set[str]:
    return {key for key, pattern in AIRCRAFT_FAMILY_PATTERNS.items()
            if pattern.search(text or "")}


def aircraft_identity_status(query: str, evidence: str) -> IdentityDecision:
    """Never promote a broad aircraft family to a requested exact variant."""
    exact_wanted, exact_found = _detect_exact_variants(query), _detect_exact_variants(evidence)
    if exact_wanted:
        if exact_wanted <= exact_found:
            return (IdentityDecision(IdentityStatus.AMBIGUOUS, "MULTIPLE_AIRCRAFT_VARIANTS_IN_SOURCE")
                    if exact_found - exact_wanted else
                    IdentityDecision(IdentityStatus.MATCH, "AIRCRAFT_EXACT_VARIANT_MATCH"))
        if exact_wanted & exact_found or not exact_found:
            return IdentityDecision(IdentityStatus.UNKNOWN, "AIRCRAFT_VARIANT_INCOMPLETE")
        return IdentityDecision(IdentityStatus.MISMATCH, "AIRCRAFT_EXACT_VARIANT_DIFFERENT")
    variants = [(_detect_specific_variants(query), _detect_specific_variants(evidence))]
    constrained = [(wanted, found) for wanted, found in variants if wanted]
    if constrained:
        if all(wanted <= found for wanted, found in constrained):
            if any(found - wanted for wanted, found in constrained):
                return IdentityDecision(IdentityStatus.AMBIGUOUS, "MULTIPLE_AIRCRAFT_VARIANTS_IN_SOURCE")
            return IdentityDecision(IdentityStatus.MATCH, "AIRCRAFT_VARIANT_MATCH")
        if any(wanted & found for wanted, found in constrained):
            return IdentityDecision(IdentityStatus.UNKNOWN, "AIRCRAFT_VARIANT_INCOMPLETE")
        if any(found for _, found in constrained):
            return IdentityDecision(IdentityStatus.MISMATCH, "AIRCRAFT_VARIANT_DIFFERENT")
        return IdentityDecision(IdentityStatus.UNKNOWN, "AIRCRAFT_VARIANT_NOT_VERIFIED")

    wanted, found = _detect_aircraft_families(query), _detect_aircraft_families(evidence)
    if not wanted or not found:
        return IdentityDecision(IdentityStatus.UNKNOWN, "AIRCRAFT_FAMILY_MISSING")
    if wanted <= found:
        return IdentityDecision(IdentityStatus.MATCH, "AIRCRAFT_FAMILY_MATCH")
    return IdentityDecision(IdentityStatus.MISMATCH if not wanted & found else IdentityStatus.UNKNOWN,
                            "AIRCRAFT_FAMILY_DIFFERENT" if not wanted & found else "AIRCRAFT_FAMILY_INCOMPLETE")


def _mentions(text: str, name: str) -> bool:
    return bool(name and re.search(r"(?<!\w)" + re.escape(name).replace(r"\ ", r"[\s-]+")
                                   + r"(?!\w)", text, re.I))


def extract_identity_signals(text: str, manufacturers: Iterable[str] = ()) -> IdentitySignals:
    """Manufacturer labels are explicit inputs, never inferred from a bare proper name."""
    text = text or ""
    return IdentitySignals(
        frozenset(name for name in manufacturers if _mentions(text, name)),
        frozenset(_detect_aircraft_families(text)),
        frozenset(_detect_specific_variants(text) | _detect_exact_variants(text)),
        frozenset(_detect_engine_models(text)),
        frozenset(key for key, pat in _COMPONENT_PATTERNS.items()
                  if re.search(r"\b(?:" + pat + r")\b", text, re.I)),
        frozenset(key for key, pat in _AUTHORITY_PATTERNS.items()
                  if re.search(r"\b(?:" + pat + r")\b", text, re.I)),
    )


def topic_identity_status(query: str, evidence: str) -> IdentityDecision:
    """Check explicit entity constraints, not the meaning or truth of a claim."""
    resolution = resolve_technical_identity(query)
    if (resolution.entity_type == EntityType.UNKNOWN_TECHNICAL_IDENTIFIER
            and resolution.resolution_status in {IdentityStatus.UNKNOWN, IdentityStatus.AMBIGUOUS}
            and SYNTACTIC_MODEL_TOKEN_RE.search(query)):
        return IdentityDecision(IdentityStatus.UNKNOWN, "MODEL_TOKEN_UNRESOLVED")
    wanted = extract_identity_signals(query)
    found = extract_identity_signals(evidence)
    decisions = []
    if wanted.engines:
        decisions.append(engine_identity_status(query, evidence))
    if wanted.aircraft_families or wanted.exact_variants:
        decisions.append(aircraft_identity_status(query, evidence))
    for category in ("components", "regulatory_authorities"):
        required, observed = getattr(wanted, category), getattr(found, category)
        if required:
            label = category.upper()
            status = (IdentityStatus.MATCH if required <= observed else
                      IdentityStatus.UNKNOWN if not observed or required & observed else
                      IdentityStatus.MISMATCH)
            decisions.append(IdentityDecision(status, f"{label}_{status.value}"))
    if not decisions:
        return IdentityDecision(IdentityStatus.UNKNOWN, "TOPIC_IDENTIFIERS_MISSING")
    for status in (IdentityStatus.MISMATCH, IdentityStatus.AMBIGUOUS, IdentityStatus.UNKNOWN):
        if any(decision.status == status for decision in decisions):
            return next(decision for decision in decisions if decision.status == status)
    return IdentityDecision(IdentityStatus.MATCH, "TOPIC_IDENTIFIERS_MATCH")


def assess_manufacturer_identity(
    manufacturer: str, document: Mapping[str, Any], aliases: Iterable[str] = (),
    *, topic: str = ""
) -> IdentityDecision:
    """Verify an aviation manufacturer identity, not the truth of its claims.

    Publisher/issuer identity must be independently verified. A third-party
    publisher mentioning the manufacturer is not its verified issuer.
    """
    names = (manufacturer, *aliases)
    text = " ".join(str(document.get(key) or "") for key in ("title", "text"))
    issuer = str(document.get("issuer") or document.get("publisher") or "")
    subject = str(document.get("manufacturer") or "")
    provenance = {"doc_id": document.get("doc_id"), "source_id": document.get("source_id")}
    verified_issuer = (document.get("issuer_identity_verified") is True
                       or document.get("publisher_identity_verified") is True)
    verified_subject = document.get("manufacturer_identity_verified") is True
    identified = ((verified_issuer and any(_mentions(issuer, name) for name in names))
                  or (verified_subject and any(_mentions(subject, name) for name in names)))
    if not identified:
        return IdentityDecision(IdentityStatus.UNKNOWN, "SOURCE_IDENTITY_UNVERIFIED", **provenance)
    context = (bool(_AVIATION_CONTEXT.search(text))
               or bool(_detect_aircraft_families(text) or _detect_engine_models(text)))
    if not context:
        return IdentityDecision(IdentityStatus.UNKNOWN, "AVIATION_CONTEXT_UNVERIFIED", **provenance)
    constraints = extract_identity_signals(topic) if topic else None
    if (constraints
            and any((constraints.engines, constraints.exact_variants,
                     constraints.aircraft_families, constraints.components,
                     constraints.regulatory_authorities))
            and topic_identity_status(topic, text).status != IdentityStatus.MATCH):
        return IdentityDecision(IdentityStatus.UNKNOWN, "TOPIC_IDENTITY_UNVERIFIED", **provenance)
    return IdentityDecision(IdentityStatus.MATCH, "MANUFACTURER_IDENTITY_VERIFIED", **provenance)

