# =============================================================================
# aviation_ci_app | Deterministic evidence, technical-identity, and alert validation
#
# Responsibility: Verify source provenance, quotation alignment, aircraft/engine identity, event
#   freshness, corroboration, and impact assertions.
# Design boundary: Confirmed critical escalation requires source-supported findings, direct KIT relevance,
#   and adequate confidence.
# =============================================================================

"""Deterministic checks for source grounding, event identity, and alert eligibility."""

import calendar
import hashlib
from datetime import date, datetime, timezone

from ews_database import get_active_kiq_catalog
from ews_evidence_contract import inspect_official_faa_publication
from ews_kiq import match_kiqs_for_threat
from ews_state import (
    AEROSPACE_SUPPLIER_REGISTRY, Any, CONTRADICTION_MARKERS, ConfidenceLevel, Dict, EWSReport,
    EscalationStatus, EventFreshness, EventStatus, IntelligenceGap,
    KIQAnswer, List, Optional, SCMTier, SPECULATIVE_DISINFO_MARKERS,
    SequenceMatcher, ThreatAssessment, Tuple, UNVERIFIED_SOCIAL_VIDEO_DOMAINS,
    UrgencyLevel, ValidationStatus, get_collected_documents,
    lookup_supplier_in_registry, normalize_date_str, re, urlparse,
)
from aero_ews.domain.evidence_text import _is_snippet_only, _normalize_for_quote_match, normalize_text
from aero_ews.domain.identity import (
    _detect_engine_models,
    _engine_models_match,
    _detect_specific_variants,
    _detect_exact_variants,
    _detect_aircraft_families,
)
from aero_ews.domain.identity_patterns import (
    ENGINE_MODEL_PATTERNS,
    SPECIFIC_AIRCRAFT_VARIANT_PATTERNS,
    AIRCRAFT_FAMILY_PATTERNS,
    COMPONENT_KEYWORDS_MAP,
    HYPOTHETICAL_IN_FACTS_REGEX,
    CAUSAL_CLAIM_REGEX,
    EVENT_LOCATION_EVIDENCE_MAP,
    _EVENT_LOCATION_PATTERN,
    _LOCATION_TO_REGION,
    _WIRE_PATTERNS,
    _PRIOR_PERIOD_CAUSE_RE,
    _CURRENT_PERIOD_RE,
    _CLAIM_CAUSE_RE,
    _EXACT_VARIANT_RE,
    AIRLINE_AND_REGULATOR_PATTERN,
    REGISTRY_TIER_MAP,
    ONGOING_OR_RECONFIRMED_PATTERNS,
    HISTORICAL_RECAP_PATTERNS,
    _GTF_SPECIFIC_MODELS,
    _LEAP_SPECIFIC_MODELS,
)

_PRIMARY_REGULATOR_DOMAINS = {
    "federalregister.gov", "faa.gov", "easa.europa.eu", "ntsb.gov",
    "caa.co.uk", "tc.canada.ca", "tsb.gc.ca", "caac.gov.cn",
    "anac.gov.br", "casa.gov.au", "bea.aero", "icao.int",
    "regulations.gov", "eur-lex.europa.eu",
}

_PRIMARY_OEM_AND_TIER1_DOMAINS = {
    "airbus.com", "boeing.com", "boeing.mediaroom.com", "comac.cc",
    "embraer.com", "atr-aircraft.com", "dehavilland.com", "bombardier.com",
    "gulfstream.com", "gulfstreamnews.com", "txtav.com", "textron.com",
    "dassault-aviation.com", "pilatus-aircraft.com",
    "lockheedmartin.com", "northropgrumman.com", "leonardo.com", "baesystems.com",
    "geaerospace.com", "rtx.com", "prattwhitney.com", "rolls-royce.com",
    "safran-group.com", "cfmaeroengines.com", "honeywell.com",
    "spiritaero.com", "mtu.de", "liebherr.com", "howmet.com", "hexcel.com",
}


# Check the full evidence, confidence, relevance, and escalation conditions for critical alerts.
def is_confirmed_critical(threat: ThreatAssessment) -> bool:
    """A confirmed critical alert requires both high severity and sufficient evidence."""
    return (
            threat.threat_score >= 8
            and threat.validation_status == ValidationStatus.SUPPORTED
            and threat.confidence_level == ConfidenceLevel.HIGH
            and threat.escalation_level == EscalationStatus.CRITICAL_CONFIRMED_ALERT
            and threat.program_relevance == "DIRECT_KIT_MATCH"
            and threat.event_freshness in {EventFreshness.NEW_EVENT, EventFreshness.NEW_DEVELOPMENT}
            and threat.technical_grounding_status == "PASS"
            and threat.claim_support_status == "STATED_IN_SOURCE"
            and threat.causal_support_status in {"EVIDENCED_IN_VERIFIED_SOURCE", "NOT_ASSERTED"}
    )

# Detect assessment states that do not establish a verified event.
def is_unverified_signal(threat: ThreatAssessment) -> bool:
    return threat.validation_status in {
        ValidationStatus.UNSUPPORTED,
        ValidationStatus.CONTRADICTED,
        ValidationStatus.UNVERIFIED_COMMUNITY,
    }

# Canonicalize punctuation and spacing before source-grounding comparisons.
# KIT-specific shortage evidence is not established by aircraft/program overlap alone.
def kit_direct_relevance_gap(kit_query: str, source_text: str) -> str:
    """Return a conservative reason when a source lacks a *requested shortage* facet."""
    kit = str(kit_query or "")
    source = str(source_text or "")
    if not re.search(r"\b(?:shortag\w*|scarcity|supply\s+(?:constraints?|shortfalls?)|material\s+shortfalls?)\b", kit, re.I):
        return ""

    if not re.search(
        r"\b(?:shortag\w*|scarcity|scarce|bottleneck\w*|"
        r"supply\s+(?:constraints?|shortfalls?|disruptions?)|"
        r"material\s+(?:shortfalls?|constraints?)|"
        r"unable\s+to\s+meet\s+demand|allocation\s+restrictions?)\b",
        source, re.I,
    ):
        return "RELATED_CONTEXT: the source does not establish the shortage or supply constraint specified in the KIT."

    material_groups = (
        (r"\b(?:carbon[ -]?fib(?:er|re)|carbon[ -]?composites?)\b",
         r"\b(?:carbon[ -]?fib(?:er|re)|carbon[ -]?composites?)\b"),
        (r"\bcomposites?\b", r"\bcomposites?\b"),
        (r"\btitanium\b", r"\btitanium\b"),
        (r"\bforgings?\b", r"\bforg(?:e|ed|es|ing|ings)\b"),
        (r"\balumini?um\b", r"\balumini?um\b"),
        (r"\b(?:superalloys?|nickel(?:\s+alloys?)?)\b", r"\b(?:superalloys?|nickel(?:\s+alloys?)?)\b"),
        (r"\bcastings?\b", r"\bcast(?:ing|ings|ed)?\b"),
        (r"\bfasteners?\b", r"\bfasteners?\b"),
        (r"\b(?:semiconductors?|avionics)\b", r"\b(?:semiconductors?|avionics)\b"),
    )
    requested_materials = [
        evidenced for required, evidenced in material_groups if re.search(required, kit, re.I)
    ]
    if requested_materials and not any(re.search(evidenced, source, re.I) for evidenced in requested_materials):
        return "RELATED_CONTEXT: the source does not identify the material specified in the KIT."

    # Suppliers explicitly named in the existing registry; ignore engines/model aliases.
    matched_suppliers = []
    for entry in AEROSPACE_SUPPLIER_REGISTRY:
        if entry.get("default_tier") == "OEM (Final Assembler)":
            continue
        names = [entry.get("official_name", ""), *entry.get("aliases", [])]
        names = [n for n in names if len(n) >= 4 and not re.search(r"\d", n)]
        if any(re.search(r"(?<!\w)" + re.escape(n) + r"(?!\w)", kit, re.I) for n in names):
            matched_suppliers.append((entry.get("official_name", ""), names))

    if len(matched_suppliers) == 1:
        supplier, names = matched_suppliers[0]
        if not any(re.search(r"(?<!\w)" + re.escape(n) + r"(?!\w)", source, re.I) for n in names):
            return f"RELATED_CONTEXT: the cited source does not identify the KIT-specific supplier {supplier}."
    elif not matched_suppliers:
        # Conservative fallback for unregistered proper names (e.g. a newly added supplier).
        oem_tokens = {
            tok.lower()
            for entry in AEROSPACE_SUPPLIER_REGISTRY
            if entry.get("default_tier") == "OEM (Final Assembler)"
            for name in (entry.get("official_name", ""), *(entry.get("aliases") or []))
            for tok in re.findall(r"\b[a-z]{3,}\b", name.lower())
        }
        skip = oem_tokens | {
            "airbus", "boeing", "embraer", "comac", "aerospace", "aircraft",
            "engine", "engines", "supply", "chain", "shortage", "supplier",
            "suppliers", "carbon", "fiber", "fibre", "composite", "composites",
            "material", "materials", "production", "technical", "problems",
            "issues", "monitor", "review", "compare", "competitive", "intelligence",
            "risk", "risks", "fleet", "capacity", "constraints", "aviation",
            "impact", "delivery", "the", "and", "for", "from", "with",
        }
        unknown = {name for name in re.findall('\\b[A-Z][a-z]{3,}\\b', kit) if name.lower() not in skip}
        if len(unknown) == 1:
            supplier = next(iter(unknown))
            if not re.search(r"(?<!\w)" + re.escape(supplier) + r"(?!\w)", source, re.I):
                return f"RELATED_CONTEXT: the source does not identify named KIT entity {supplier}."

    return ""

# Extract the normalized publisher hostname from a source URL.
def extract_effective_publisher_domain(url: str) -> str:
    if not url:
        return ""
    netloc = urlparse(url).netloc.lower()
    return netloc[4:] if netloc.startswith("www.") else netloc

# Match trusted domains without accepting deceptive suffix lookalikes.
def is_exact_or_subdomain(domain: str, trusted_set: set[str]) -> bool:
    """Require an exact trusted domain or a genuine subdomain boundary."""
    return bool(domain) and any(domain == td or domain.endswith("." + td) for td in trusted_set)

# Check grounded source mentions against normalized evidence text.
def _source_mentions(value: str, text: str) -> bool:
    value = str(value or "").strip()
    if not value or value.lower().startswith(("unknown", "not specified")):
        return False
    terms = re.findall(r"[a-z0-9]+", value.lower())
    return bool(
        terms and re.search(r"(?<!\w)" + r"[\W_]*".join(map(re.escape, terms)) + r"(?!\w)", (text or "").lower()))

# Resolve the component and aircraft program supported by source evidence.
def _extract_component_and_program(
        doc_raw_full: str, quote_text: str = "", proposed_component: str = "", proposed_program: str = ""
) -> Tuple[str, str]:
    unknown = "Unknown / Not specified in source"
    quote = (quote_text or "").strip()
    component = proposed_component if _source_mentions(proposed_component, quote) else unknown
    quoted = _detect_specific_variants(quote)
    program = ", ".join(sorted(quoted)) if quoted else (
        proposed_program if _source_mentions(proposed_program, quote) else unknown)
    return component, program

# Separate geographic interest from the location of the underlying incident.
def _resolve_geography_dimensions(threat: ThreatAssessment, doc_raw_full: str) -> Tuple[str, str]:
    matches = _EVENT_LOCATION_PATTERN.findall(doc_raw_full or "")
    evidenced_regions = {_LOCATION_TO_REGION[loc.lower()] for loc in matches if loc.lower() in _LOCATION_TO_REGION}
    event_epicenter = next(iter(evidenced_regions)) if len(evidenced_regions) == 1 else "Unknown"
    return event_epicenter, "Unknown (Requires Operator/Fleet Mapping)"

# Normalize quotations before checking exact source support.

# Recognize source records whose limited text cannot support a factual finding.
# Split and normalize multiple organizations named in one event.
def _split_affected_entities(company_affected: str) -> List[str]:
    if not company_affected:
        return []
    protected = re.sub(r"pratt\s*&\s*whitney", "Pratt_And_Whitney", company_affected, flags=re.I)
    # A comma before a legal suffix is not a separator between organizations.
    protected = re.sub(r",(?=\s*(?:S\.?\s*A\.?|Inc\.?|Ltd\.?|LLC|GmbH|Corp\.?|PLC)\s*(?:$|[,;/|]))", "", protected, flags=re.I)
    entities = [
        p.replace("Pratt_And_Whitney", "Pratt & Whitney").strip()
        for p in re.split(r"[,;/|]+|\band\b", protected, flags=re.I)
    ]
    return [e for e in entities if len(e) >= 2 and not re.fullmatch(
        r"(?:S\.?\s*A\.?|Inc\.?|Ltd\.?|LLC|GmbH|Corp\.?|PLC)", e, re.I
    )] or ["Unknown"]

# Remove unsupported or contradictory supply-chain role assertions.
def _sanitize_conflicting_scm_text(text: str, entity_roles: List[Tuple[str, SCMTier, Optional[Dict[str, Any]]]]) -> str:
    if not text:
        return ""
    cleaned = text
    for ent_name, ent_tier, _ in entity_roles:
        if ent_tier == SCMTier.OEM:
            cleaned = re.sub(
                r"\b(?:tier[- ]?[123]\s+(?:supplier|manufacturer)s?\s+)?" + re.escape(
                    ent_name) + r"\s*\(\s*tier[- ]?[123][^)]*\)",
                f"{ent_name} ({SCMTier.OEM.value})",
                cleaned,
                flags=re.I,
            )
        elif ent_tier == SCMTier.REGULATOR_AIRLINE:
            cleaned = re.sub(r"\(\s*Tier\s*[123][^)]*\)", f"({SCMTier.REGULATOR_AIRLINE.value})", cleaned, flags=re.I)
    return cleaned

# Derive SCM tier and propagation only from evidenced relationships.
# Do not infer supply-chain propagation from a registry relationship alone.
def _resolve_scm_roles_and_impact_path(
        threat: ThreatAssessment, doc_raw_full: str
) -> Tuple[SCMTier, str, List[str], bool]:
    entities = _split_affected_entities(threat.company_affected)
    doc_low = (doc_raw_full or "").lower()

    entity_roles: List[Tuple[str, SCMTier, Optional[Dict[str, Any]]]] = []
    role_descriptions: List[str] = []
    has_unknown_entity = False

    for ent in entities:
        ent_low = ent.lower()
        # Ignore legal-form suffixes and parenthetical division labels for registry matching.
        registry_name = re.sub(r"\s+(?:S\.?\s*A\.?|Inc\.?|Ltd\.?|LLC|GmbH|Corp\.?|PLC)$", "", ent, flags=re.I)
        reg_match = lookup_supplier_in_registry(registry_name, exact=True)
        if not reg_match and "(" in ent and ")" in ent:
            outer = re.sub(r"\s*\([^)]*\)", "", ent).strip()
            outer_clean = re.sub(r"\s+(?:S\.?\s*A\.?|Inc\.?|Ltd\.?|LLC|GmbH|Corp\.?|PLC)$", "", outer,
                                 flags=re.I).strip()
            for candidate in (outer, outer_clean, *re.findall(r"\(([^)]+)\)", ent)):
                if candidate and (reg_match := lookup_supplier_in_registry(candidate.strip(), exact=True)):
                    break
        if reg_match and not AIRLINE_AND_REGULATOR_PATTERN.search(ent_low):
            mapped_tier = REGISTRY_TIER_MAP.get(reg_match["default_tier"], SCMTier.UNKNOWN)
            entity_roles.append((reg_match["official_name"], mapped_tier, reg_match))
            role_descriptions.append(
                f"Company: {reg_match['official_name']} -> Role: {mapped_tier.value} (Registry Source: {reg_match['source_ref']})"
            )
        elif AIRLINE_AND_REGULATOR_PATTERN.search(ent_low):
            entity_roles.append((ent, SCMTier.REGULATOR_AIRLINE, None))
            role_descriptions.append(f"Company/Authority: {ent} -> Role: {SCMTier.REGULATOR_AIRLINE.value}")
        else:
            has_unknown_entity = True
            entity_roles.append((ent, SCMTier.UNKNOWN, None))
            role_descriptions.append(f"Company: {ent} -> Role: {SCMTier.UNKNOWN.value}")

    known_tiers = [r[1] for r in entity_roles if r[1] != SCMTier.UNKNOWN]
    primary_tier = (
        entity_roles[0][1]
        if (len(entity_roles) == 1 or entity_roles[0][1] != SCMTier.UNKNOWN)
        else (known_tiers[0] if known_tiers else SCMTier.UNKNOWN)
    )

    component, evidenced_program = _extract_component_and_program(
        doc_raw_full, threat.fact_check_quote or "", threat.affected_component or "", threat.affected_program or ""
    )
    threat.affected_component = component
    threat.affected_program = evidenced_program

    hyp_deps: List[str] = []
    for _, _, reg_info in entity_roles:
        if reg_info:
            for p in reg_info.get("programs", []):
                if p.lower() not in evidenced_program.lower() and p not in hyp_deps:
                    hyp_deps.append(p)
    threat.hypothetical_dependencies = hyp_deps

    basis_str = (
        f"{' | '.join(role_descriptions)} || "
        f"Source-Evidenced Component: {component} || Source-Evidenced Program: {evidenced_program}"
    )

    threat.threat_description = _sanitize_conflicting_scm_text(threat.threat_description, entity_roles)
    threat.confirmed_facts = _sanitize_conflicting_scm_text(threat.confirmed_facts, entity_roles)
    threat.analytical_interpretation = _sanitize_conflicting_scm_text(threat.analytical_interpretation, entity_roles)
    dep_note = f" (Hypothetical shared-OEM/supplier dependencies not evidenced in source: {', '.join(hyp_deps[:3])})" if hyp_deps else ""
    threat.hypothetical_scenario = (
        f"Hypothetical {threat.propagation_effect.value} scenario affecting "
        f"{', '.join(f'{n} ({t.value})' for n, t, _ in entity_roles)} "
        f"on source-evidenced program {evidenced_program}.{dep_note}"
    )

    structured_path = [
        f"{'[Evidenced Entity]' if any(tok in doc_low for tok in re.findall(r'\b[a-z0-9]{3,}\b', ent_name.lower())) else '[Unconfirmed Entity]'} {ent_name} -> Role: {ent_tier.value}"
        for ent_name, ent_tier, _ in entity_roles
    ]
    structured_path.extend([
        f"[Source-Evidenced Component] {component}",
        f"[Source-Evidenced Program] {evidenced_program}",
    ])
    if hyp_deps:
        structured_path.append(
            f"[Hypothetical Shared-Supplier Dependencies - NOT Evidenced in Source] {', '.join(hyp_deps[:3])}")
    structured_path.append(f"[Hypothetical Propagation Mechanism] {threat.propagation_effect.value}")

    return primary_tier, basis_str, structured_path, has_unknown_entity

# Count corroborating publications after syndication and origin deduplication.
# Corroboration requires distinct publishing origins, not merely distinct URLs.
def _count_independent_confirmations(corroborating_docs: List[Dict[str, Any]]) -> Tuple[int, bool, bool]:
    # Read wire-service markers before counting supposedly independent sources.
    def detect_wire_origin(doc: Dict[str, Any]) -> Optional[str]:
        combined = f"{doc.get('title') or ''} {doc.get('text') or ''}"
        return next((w for w, pat in _WIRE_PATTERNS.items() if pat.search(combined)), None)

    distinct_clusters: List[Tuple[str, str, Optional[str]]] = []
    for doc in corroborating_docs:
        fp = doc.get("syndication_fingerprint") or ""
        title_norm = _normalize_for_quote_match(doc.get("title", ""))
        wire = detect_wire_origin(doc)

        if not any(
                (fp and fp == ex_fp)
                or (wire and ex_wire and wire == ex_wire)
                or (title_norm and ex_title and SequenceMatcher(None, title_norm, ex_title).ratio() >= 0.65)
                for ex_fp, ex_title, ex_wire in distinct_clusters
        ):
            distinct_clusters.append((fp, title_norm, wire))

    has_true_primary_regulator = has_true_primary_oem = False
    for doc in corroborating_docs:
        domain = extract_effective_publisher_domain(doc.get("url", ""))
        if not domain or "news.google.com" in domain:
            continue
        if is_exact_or_subdomain(domain, _PRIMARY_REGULATOR_DOMAINS):
            has_true_primary_regulator = True
        elif is_exact_or_subdomain(domain, _PRIMARY_OEM_AND_TIER1_DOMAINS):
            has_true_primary_oem = True

    return len(distinct_clusters), has_true_primary_regulator, has_true_primary_oem

def _certification_model_ids(text: str) -> set[str]:
    """Normalize exact technical models, including 737-10 / 737 MAX 10."""
    from aero_ews.collection.queries import _model_tokens

    codes = set()
    for token in _model_tokens(text or ""):
        code = re.sub(r"[^a-z0-9]", "", token.lower())
        variant = re.fullmatch(r"737(?:max)?(\d{1,2})", code)
        codes.add(f"737max{variant.group(1)}" if variant else code)
    return {code for code in codes if not re.fullmatch(r"\d{3}", code)}


_CLAIM_STATES = {
    "DELAYED": "ISSUE_ACTIVE", "PENDING": "ISSUE_ACTIVE", "ONGOING": "ISSUE_ACTIVE",
    "STARTED": "ISSUE_ACTIVE", "STRIKE_STARTED": "ISSUE_ACTIVE",
    "PRODUCTION_HALTED": "ISSUE_ACTIVE", "PRODUCTION_STOPPED": "ISSUE_ACTIVE",
    "DELIVERIES_SUSPENDED": "ISSUE_ACTIVE", "CERTIFICATION_DELAYED": "ISSUE_ACTIVE",
    "CERTIFIED": "ISSUE_RESOLVED", "GRANTED": "ISSUE_RESOLVED",
    "RESOLVED": "ISSUE_RESOLVED", "COMPLETED": "ISSUE_RESOLVED",
    "STRIKE_ENDED": "ISSUE_RESOLVED", "AGREEMENT_REACHED": "ISSUE_RESOLVED",
    "PRODUCTION_RESUMED": "ISSUE_RESOLVED", "DELIVERIES_RESUMED": "ISSUE_RESOLVED",
    "CERTIFICATION_COMPLETED": "ISSUE_RESOLVED", "APPROVED": "ISSUE_RESOLVED",
    "PROPOSED": "PROCESS_PROPOSED", "NPRM": "PROCESS_PROPOSED",
    "FINAL_ISSUED": "PROCESS_FINAL", "ADOPTED": "PROCESS_FINAL",
    "EFFECTIVE": "PROCESS_EFFECTIVE",
    "PLANNED": "PLANNED_CHANGE", "CAPACITY_INCREASE_PLANNED": "PLANNED_CHANGE",
    "CAPACITY_INCREASED": "CHANGE_IMPLEMENTED", "CAPACITY_EXPANDED": "CHANGE_IMPLEMENTED",
    "WITHDRAWN": "ISSUE_WITHDRAWN_OR_REPLACED", "REVOKED": "ISSUE_WITHDRAWN_OR_REPLACED",
}


def _claim_day(claim: Dict[str, Any]) -> Optional[date]:
    for field in ("state_as_of", "event_date", "regulatory_decision_date", "published_at", "publication_date"):
        try:
            return date.fromisoformat(str(claim.get(field) or "")[:10])
        except ValueError:
            continue
    return None


def _claim_instant(claim: Dict[str, Any]) -> Optional[datetime]:
    """Use exact event time when two states occurred on the same calendar day."""
    for field in ("state_as_of", "event_date", "regulatory_decision_date"):
        raw = str(claim.get(field) or "")
        if "T" not in raw and " " not in raw:
            continue
        try:
            timestamp = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            return timestamp.replace(tzinfo=timezone.utc) if timestamp.tzinfo is None else timestamp.astimezone(timezone.utc)
        except ValueError:
            continue
    return None


def _verified_faa_publication(claim: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Verify a Federal Register publication independently of docket lifecycle checks."""
    if claim.get("source_id") != "SRC_001":
        return None
    url = str(claim.get("url") or "").strip()
    source_url = str(claim.get("source_url") or "").strip()
    if url and source_url:
        try:
            original, reported = urlparse(url), urlparse(source_url)
            if (original.scheme != reported.scheme
                    or original.hostname != reported.hostname
                    or original.path.rstrip("/") != reported.path.rstrip("/")):
                return None
        except ValueError:
            return None
    normalized = dict(claim)
    normalized["url"] = url or source_url
    return inspect_official_faa_publication(normalized)


def _claim_authority(claim: Dict[str, Any]) -> str:
    parsed = urlparse(str(claim.get("source_url") or claim.get("url") or ""))
    if parsed.scheme != "https":
        return ""
    host = (parsed.hostname or "").lower()
    explicit = str(claim.get("regulatory_authority") or claim.get("authority") or "").upper()
    rejected_evidence_roles = {
        "SEC_EDGAR", "OFFICIAL_ISSUER_IR", "SECONDARY_MEDIA", "FILING_INDEX_METADATA"
    }
    # The source's official identity and its subsequent regulatory lifecycle
    # are distinct facts. A missing supersession check must not erase origin.
    authority_domains = {
        "FAA": {"faa.gov", "federalregister.gov"},
        "EASA": {"easa.europa.eu"},
        "NTSB": {"ntsb.gov"},
        "CAA": {"caa.co.uk"},
        "TCCA": {"tc.canada.ca"},
        "TSB": {"tsb.gc.ca"},
        "CAAC": {"caac.gov.cn"},
        "ANAC": {"anac.gov.br"},
        "CASA": {"casa.gov.au"},
        "BEA": {"bea.aero"},
    }
    if is_exact_or_subdomain(host, {"federalregister.gov"}):
        if (explicit in (set(authority_domains) - {"FAA"})
                or str(claim.get("evidence_authority") or "").upper() in rejected_evidence_roles):
            return ""
        return "FAA" if _verified_faa_publication(claim) else ""
    if explicit not in authority_domains:
        explicit = ""
    for authority, domains in authority_domains.items():
        if (explicit in {"", authority} and is_exact_or_subdomain(host, domains)
                and str(claim.get("evidence_authority") or "").upper() not in rejected_evidence_roles):
            return authority
    return ""


def _reference_day(as_of_date: str, query: str = "") -> Optional[date]:
    """Respect an explicit historical cutoff; month-only means its last calendar day."""
    try:
        if as_of_date:
            raw = str(as_of_date).strip()
            if re.fullmatch(r"20\d{2}-\d{2}", raw):
                year, month = map(int, raw.split("-"))
                return date(year, month, calendar.monthrange(year, month)[1])
            return date.fromisoformat(raw[:10])
    except ValueError:
        return None
    match = re.search(r"\bas\s+of\s+(20\d{2}-\d{2}-\d{2})\b", query or "", re.I)
    if match:
        try:
            return date.fromisoformat(match.group(1))
        except ValueError:
            return None
    months = "january february march april may june july august september october november december".split()
    match = re.search(r"\bas\s+of\s+(" + "|".join(months) + r")\s+(20\d{2})\b", query or "", re.I)
    if match:
        month, year = months.index(match.group(1).lower()) + 1, int(match.group(2))
        return date(year, month, calendar.monthrange(year, month)[1])
    match = re.search(r"\bas\s+of\s+(20\d{2})-(\d{2})(?!-\d)", query or "", re.I)
    if match and 1 <= int(match.group(2)) <= 12:
        year, month = map(int, match.groups())
        return date(year, month, calendar.monthrange(year, month)[1])
    return None


def _document_date(doc: Dict[str, Any], key: str) -> str:
    """Never substitute publication, occurrence, effectiveness, and deadline dates."""
    value = doc.get(key)
    try:
        return date.fromisoformat(str(value)[:10]).isoformat() if value else "DATE_UNKNOWN"
    except ValueError:
        return "DATE_UNKNOWN"


def _verified_filing_passage(doc: Dict[str, Any], quote: str) -> bool:
    """A filing index or unverified LLM excerpt cannot establish a substantive fact."""
    if doc.get("source_id") not in {"SRC_027", "SRC_031"}:
        return True
    if doc.get("content_status") not in {"PARTIAL_TEXT", "FULL_TEXT"}:
        return False
    source_hash = str(doc.get("source_content_sha256") or "")
    if not re.fullmatch(r"[0-9a-f]{64}", source_hash):
        return False
    needle = _normalize_for_quote_match(quote)
    return bool(needle and doc.get("evidence_verified") is True and any(
        passage.get("validated") is True
        and isinstance(passage.get("text"), str)
        and hashlib.sha256(passage["text"].encode("utf-8")).hexdigest() == passage.get("passage_sha256")
        and needle in _normalize_for_quote_match(passage["text"])
        and passage.get("source_content_sha256") == source_hash
        and passage.get("source_url") == doc.get("source_url", doc.get("url"))
        and (doc.get("source_id") != "SRC_027" or passage.get("issuer_cik"))
        for passage in doc.get("evidence_passages") or [] if isinstance(passage, dict)
    ))


def _kit_fact_audit(query: str, quote: str, doc: Dict[str, Any], cutoff: Optional[date]) -> Dict[str, str]:
    """Tri-state checks of only the fact dimensions explicitly constrained by a KIT."""
    checks = dict.fromkeys(
        ("ENTITY", "PROGRAM", "VARIANT", "COMPONENT", "ISSUE", "STATUS",
         "AUTHORITY", "DATE", "CAUSE", "IMPACT"), "NOT_REQUIRED"
    )
    query = re.split(
        r"\b(?:exclude|excluding|except(?:\s+for)?|without|not\s+including|kromě|vyjma)\b",
        str(query or ""), maxsplit=1, flags=re.I,
    )[0].strip()
    quote = str(quote or "")
    summary_ctx = ""
    if doc.get("source_id") == "SRC_001":
        if summary_m := re.search(r"(?im)^Official Summary:\s*(.+)$", str(doc.get("text") or "")):
            summary_ctx = summary_m.group(1).strip()
    context = f"{doc.get('title') or ''} {doc.get('issuer_name') or ''} {quote} {summary_ctx}"
    names = []
    for entry in AEROSPACE_SUPPLIER_REGISTRY:
        aliases = [entry.get("official_name", ""), *(entry.get("aliases") or [])]
        if any(len(alias) >= 4 and _source_mentions(alias, query) for alias in aliases):
            is_oem = entry.get("default_tier") == "OEM (Final Assembler)"
            programs = list(entry.get("programs") or []) if is_oem else []
            names.append((aliases, programs))
    if names:
        def _entity_evidenced(aliases: List[str], programs: List[str]) -> bool:
            if any(_source_mentions(alias, context) for alias in aliases):
                return True
            if programs:
                q_vars = _detect_exact_variants(query) | _detect_specific_variants(query)
                c_vars = _detect_exact_variants(context) | _detect_specific_variants(context)
                if q_vars and c_vars and q_vars.intersection(c_vars):
                    oem_vars = _detect_exact_variants(" ".join(programs)) | _detect_specific_variants(
                        " ".join(programs))
                    if q_vars.intersection(oem_vars) and c_vars.intersection(oem_vars):
                        return True
            return False

        checks["ENTITY"] = "POSITIVE" if any(
            _entity_evidenced(aliases, programs) for aliases, programs in names
        ) else "UNKNOWN"

    requested_models = _detect_engine_models(query)
    if requested_models:
        observed_models = _detect_engine_models(context)
        checks["PROGRAM"] = (
            "POSITIVE" if (_engine_models_match(query, context) or bool(requested_models & observed_models))
            else "NEGATIVE" if observed_models else "UNKNOWN")
    requested_exact = _detect_exact_variants(query)
    requested_specific = _detect_specific_variants(query)
    observed_exact = _detect_exact_variants(context)
    observed_specific = _detect_specific_variants(context)

    if requested_exact:
        checks["VARIANT"] = (
            "POSITIVE" if bool(requested_exact & observed_exact)
            else "NEGATIVE" if observed_exact and requested_exact.isdisjoint(observed_exact)
            else "NOT_REQUIRED" if checks["PROGRAM"] == "POSITIVE"
            else "UNKNOWN"
        )
    elif requested_specific:
        checks["VARIANT"] = (
            "POSITIVE" if bool(requested_specific & observed_specific)
            else "NEGATIVE" if observed_specific or observed_exact
            else "NOT_REQUIRED" if checks["PROGRAM"] == "POSITIVE"
            else "UNKNOWN"
        )

    components = {kw for kw in COMPONENT_KEYWORDS_MAP
                  if re.search(rf"\b{re.escape(kw)}\b", query, re.I)}
    if re.search(r"\bgearbox\b", query, re.I):
        components.add("gearbox")
    if components:
        observed = {kw for kw in set(COMPONENT_KEYWORDS_MAP) | {"gearbox"}
                    if re.search(rf"\b{re.escape(kw)}\b", context, re.I)}
        checks["COMPONENT"] = ("POSITIVE" if bool(components & observed)
                               else "NEGATIVE" if observed else "UNKNOWN")

    if re.search(r"\binspect\w*\s+(?:requirements?|mandates?|intervals?)\b", query, re.I):
        checks["ISSUE"] = ("POSITIVE" if re.search(r"\binspect\w*\b", quote, re.I)
                                         and re.search(r"\b(?:requir\w*|mandat\w*|shall|must|compliance)\b", quote,
                                                       re.I)
                           else "UNKNOWN")
    elif re.search(r"\b(?:shortag\w*|scarcity|supply\s+constraints?)\b", query, re.I):
        checks["ISSUE"] = ("POSITIVE" if not kit_direct_relevance_gap(query, quote)
                           else "UNKNOWN")
    if re.search(r"\b(?:certification|approval|production|delivery)\s+status\b", query, re.I):
        checks["STATUS"] = ("POSITIVE" if re.search(
            r"\b(?:pending|delayed|ongoing|issued|certified|approved|completed|"
            r"suspended|resumed|withdrawn|revoked|effective)\b|"
            r"\b(?:achieved|granted|received|obtained|secured)\s+(?:amended\s+)?(?:type\s+)?certif\w*",
            quote, re.I,
        ) else "UNKNOWN")
    authorities = set(re.findall(r"\b(?:FAA|EASA|NTSB|CAA|TCCA|TSB|CAAC|ANAC|CASA|BEA)\b", query, re.I))
    if authorities:
        actual = _claim_authority(doc)
        checks["AUTHORITY"] = ("POSITIVE" if actual and actual in {a.upper() for a in authorities}
                               else "NEGATIVE" if actual else "UNKNOWN")
    if cutoff:
        published = _document_date(doc, "published_at")
        checks["DATE"] = ("UNKNOWN" if published == "DATE_UNKNOWN" else
                          "NEGATIVE" if published > cutoff.isoformat() else "POSITIVE")
    if re.search(r"\b(?:why|causes?|caused|causality|due\s+to|drivers?)\b", query, re.I):
        checks["CAUSE"] = "POSITIVE" if _causal_roles(quote) else "UNKNOWN"
    if target := re.search(r"\bimpact\s+(?:on|of)\s+(?:\w+\s+){0,2}(deliver\w*|produc\w*)\b", query, re.I):
        stem = "deliver" if target.group(1).lower().startswith("deliver") else "produc"
        checks["IMPACT"] = ("POSITIVE" if re.search(rf"\b{stem}\w*\b", quote, re.I)
                            and re.search(r"\b(?:impact\w*|affect\w*|disrupt\w*|delay\w*)\b", quote, re.I)
                            else "UNKNOWN")
    return checks


def _claim_model_ids(text: str) -> set[str]:
    codes = _certification_model_ids(text)
    return {code for code in codes if not any(
        code != other and other.startswith(code) for other in codes
    )}


def compare_evidence_claims(
    earlier: Dict[str, Any], later: Dict[str, Any], as_of_date: str = "",
) -> Dict[str, Any]:
    """Compare grounded states without conflating programs, authorities or reporting dates."""
    def norm(value: Any) -> str:
        return re.sub(r"[^a-z0-9]+", "", str(value or "").lower())

    def entity(value: Any) -> str:
        registered = lookup_supplier_in_registry(str(value or ""), exact=True)
        return norm(registered["official_name"] if registered else value)

    def identity(claim: Dict[str, Any], field: str) -> Any:
        return (claim.get("entity") or claim.get("issuer_name") or claim.get("company")
                if field == "entity" else claim.get(field))

    def issue_name(value: Any) -> str:
        return re.sub(
            r"(?<=\w)(?:delay(?:ed)?|status|issue|update|halt(?:ed)?|stop(?:ped|page)?|"
            r"resum(?:ed|ption)|restart(?:ed)?|complet(?:ed|ion)|propos(?:ed|al)|"
            r"adopt(?:ed|ion)|withdraw(?:n|al)|start(?:ed)?|end(?:ed)?|"
            r"suspend(?:ed|sion)|plan(?:ned)?|expand(?:ed|sion))$", "", norm(value),
        )

    def eligible(claim: Dict[str, Any]) -> bool:
        status = str(claim.get("verification") or "").upper()
        source = urlparse(str(claim.get("source_url") or claim.get("url") or ""))
        excerpt = str(claim.get("evidence_excerpt") or claim.get("quote") or "").strip()
        if (not claim.get("doc_id") or source.scheme != "https" or not source.hostname
                or not excerpt or claim.get("verified") is not True):
            return False
        if status == "OFFICIAL_REGULATOR":
            if not _claim_authority(claim):
                return False
        return claim.get("content_status") not in {
            "METADATA_ONLY", "SUMMARY_ONLY", "SOURCE_METADATA_ONLY", "SOURCE_POLICY_RESTRICTED", "UNAVAILABLE",
        } and claim.get("source_content_retrieved") is not False

    def forecast(claim: Dict[str, Any]) -> bool:
        if any(str(claim.get(key) or "").upper() == "FORECAST" for key in ("modality", "claim_type")):
            return True
        if str(claim.get("state") or "").upper() in {
            "CAPACITY_INCREASED", "CAPACITY_EXPANDED", "COMPLETED", "CERTIFIED",
            "PRODUCTION_RESUMED", "DELIVERIES_RESUMED", "AGREEMENT_REACHED",
        }:
            return False
        return bool(re.search(r"\b(?:expects?|forecast\w*|anticipated|planned|may|might)\b",
                              str(claim.get("evidence_excerpt") or ""), re.I))

    def result(relation: str, reason: str) -> Dict[str, Any]:
        issue = issue_name(earlier.get("issue"))
        authority_required = bool(re.search(r"certif|regulat|airworth|approval|directive|nprm", issue))
        regulator_verified = (str(later.get("verification") or "").upper() == "OFFICIAL_REGULATOR"
                              and bool(_claim_authority(later)) and _claim_authority(earlier) == _claim_authority(later))
        status_change = relation in {"SUPERSEDES", "CORRECTS"} or reason == "FORECAST_FULFILLED_BY_LATER_EVIDENCE"
        same_issue = relation not in {"RELATES_TO", "CONTRADICTS"}
        return {"relation": relation, "reason": reason, "evidence_eligible": both_verified,
                "can_update_status": both_verified and (status_change or relation == "CORROBORATES")
                                     and (not authority_required or regulator_verified),
                "reported_status_change": both_verified and same_issue and status_change,
                "issuer_statement_supported": both_verified and same_issue and not regulator_verified and (
                    str(later.get("verification") or "").upper() in {"PRIMARY_ISSUER", "ISSUER_DISCLOSURE"}
                    or str(later.get("evidence_authority") or "").upper() in {
                        "ISSUER_OFFICIAL_STATEMENT", "SEC_EDGAR", "OFFICIAL_ISSUER_IR"}),
                "regulator_decision_verified": both_verified and authority_required and regulator_verified}

    both_verified = eligible(earlier) and eligible(later)
    first_day, second_day = _claim_day(earlier), _claim_day(later)
    try:
        cutoff = date.fromisoformat(as_of_date[:10]) if as_of_date else None
    except ValueError:
        cutoff = None
    if cutoff and (not first_day or not second_day or max(first_day, second_day) > cutoff):
        return result("RELATES_TO", "OUTSIDE_REFERENCE_DATE")
    if cutoff and any(
        published and published > cutoff for published in (
            _claim_day({"published_at": earlier.get("published_at")}),
            _claim_day({"published_at": later.get("published_at")}),
        )
    ):
        return result("RELATES_TO", "FUTURE_PUBLICATION_NOT_AVAILABLE_AT_REFERENCE_DATE")
    if not both_verified:
        return result("RELATES_TO", "EVIDENCE_NOT_VERIFIED")

    for field in ("entity", "component"):
        left, right = identity(earlier, field), identity(later, field)
        if field == "entity" and not (left and right):
            return result("RELATES_TO", "ENTITY_NOT_ESTABLISHED")
        if bool(left) != bool(right):
            return result("RELATES_TO", f"{field.upper()}_NOT_ESTABLISHED")
        comparable = entity if field == "entity" else norm
        if left and right and comparable(left) != comparable(right):
            return result("RELATES_TO", f"{field.upper()}_CONFLICT")
    first_program = str(earlier.get("program") or "")
    second_program = str(later.get("program") or "")
    if bool(first_program) != bool(second_program):
        return result("RELATES_TO", "PROGRAM_NOT_ESTABLISHED")
    if first_program and second_program:
        a, b = _claim_model_ids(first_program), _claim_model_ids(second_program)
        if (a and b and a.isdisjoint(b)) or ((not a or not b) and norm(first_program) != norm(second_program)):
            return result("RELATES_TO", "PROGRAM_CONFLICT")
    if not issue_name(earlier.get("issue")) or not issue_name(later.get("issue")):
        return result("RELATES_TO", "ISSUE_NOT_ESTABLISHED")
    if issue_name(earlier.get("issue")) != issue_name(later.get("issue")):
        return result("RELATES_TO", "ISSUE_CONFLICT")
    if (earlier.get("episode_id") and later.get("episode_id")
            and str(earlier["episode_id"]) != str(later["episode_id"])):
        return result("RELATES_TO", "DIFFERENT_EVENT_EPISODES")

    issue = issue_name(earlier.get("issue"))
    first_authority, second_authority = _claim_authority(earlier), _claim_authority(later)
    if (first_authority and second_authority and first_authority != second_authority):
        return result("RELATES_TO", "REGULATORY_AUTHORITY_CONFLICT")
    if re.search(r"certif|regulat|airworth|approval|directive|nprm", issue) and not (
            first_authority and second_authority):
        return result("RELATES_TO", "REGULATORY_AUTHORITY_UNVERIFIED")

    first_state = _CLAIM_STATES.get(str(earlier.get("state") or "").upper(),
                                    str(earlier.get("state") or "").upper())
    second_state = _CLAIM_STATES.get(str(later.get("state") or "").upper(),
                                     str(later.get("state") or "").upper())
    if not first_day or not second_day or not first_state or not second_state:
        return result("RELATES_TO", "STATE_OR_DATE_UNESTABLISHED")
    prior_doc_id = str(earlier.get("doc_id") or "")
    corrected_doc_id = str(later.get("corrects_doc_id") or later.get("correction_of") or "")
    if prior_doc_id and corrected_doc_id == prior_doc_id and second_day >= first_day:
        return result("CORRECTS", "EXPLICIT_CORRECTION_OF_EARLIER_CLAIM")
    if second_day > first_day:
        if forecast(later):
            return result("RELATES_TO", "LATER_FORECAST_NOT_VERIFIED_AS_ACTUAL_CHANGE")
        if str(later.get("claim_type") or "").upper() == "HISTORICAL_STATUS" and not any(
                later.get(key) for key in ("state_as_of", "event_date", "regulatory_decision_date")):
            return result("RELATES_TO", "LATER_PUBLICATION_DESCRIBES_HISTORY")
        if forecast(earlier) and (second_state == "ISSUE_RESOLVED" or
                                  second_state in {"ISSUE_WITHDRAWN_OR_REPLACED", "CHANGE_IMPLEMENTED", "PROCESS_FINAL"}):
            return result("REFINES", "FORECAST_FULFILLED_BY_LATER_EVIDENCE")
        if first_state != second_state:
            return result("SUPERSEDES", "NEWER_STATE_SAME_ISSUE")
        old_text, new_text = norm(earlier.get("evidence_excerpt")), norm(later.get("evidence_excerpt"))
        if old_text and new_text.startswith(old_text) and len(new_text) > len(old_text):
            return result("REFINES", "ADDITIONAL_DETAIL_SAME_STATE")
        return result("CORROBORATES", "SAME_STATE_AT_LATER_DATE")
    if second_day == first_day and first_state != second_state:
        first_instant, second_instant = _claim_instant(earlier), _claim_instant(later)
        if first_instant and second_instant and second_instant > first_instant and not forecast(later):
            return result("SUPERSEDES", "NEWER_STATE_SAME_DAY")
    if second_day == first_day and first_state != second_state and all(
        claim.get("state_date_explicit") or claim.get("state_as_of") or claim.get("event_date")
        for claim in (earlier, later)
    ):
        return result("CONTRADICTS" if both_verified else "RELATES_TO",
                      "CONFLICTING_CLAIMS_FOR_SAME_EFFECTIVE_DATE" if both_verified
                      else "UNVERIFIED_CONFLICT_FOR_SAME_EFFECTIVE_DATE")
    if first_state == second_state:
        old_text = norm(earlier.get("evidence_excerpt"))
        new_text = norm(later.get("evidence_excerpt"))
        if old_text and new_text.startswith(old_text) and len(new_text) > len(old_text):
            return result("REFINES", "ADDITIONAL_DETAIL_SAME_STATE")
        return result("CORROBORATES", "SAME_STATE_SAME_SCOPE")
    return result("RELATES_TO", "TEMPORAL_CONTEXT_NOT_COMPARABLE")


def find_superseding_faa_certification(threat, documents, as_of_date="", kit_query=""):
    """Find a later primary FAA certification decision for the same exact program."""
    from aero_ews.collection.queries import AGENCIES

    claim = f"{threat.fact_check_quote or ''} {threat.threat_description or ''}"
    named_regulators = {
        token.lower() for token in re.findall(r"\b[A-Z]{3,5}\b", f"{claim} {kit_query}")
        if token.lower() in AGENCIES
    }
    if named_regulators - {"faa"}:
        return None
    if not (re.search(r"\b(?:certif\w*|type\s+approv\w*|faa\s+approv\w*)\b", claim, re.I)
            and re.search(
                r"\b(?:delay\w*|pending|await\w*|expect\w*|not\s+yet|not\s+certif\w*|"
                r"uncertif\w*|imminent|postpon\w*|could\s+come|may\s+come|"
                r"still\s+(?:in\s+review|uncertified)|unapproved)\b", claim, re.I,
            )):
        return None

    models = _certification_model_ids(str(getattr(threat, "affected_program", "") or ""))
    models = models or _certification_model_ids(claim)
    try:
        old_date = date.fromisoformat(str(threat.publication_time)[:10])
        cutoff = date.fromisoformat(str(as_of_date)[:10]) if as_of_date else datetime.now(timezone.utc).date()
    except ValueError:
        return None
    if not models:
        return None

    decision_re = re.compile(
        r"\b(?:issued|granted|approv\w*)\s+(?:(?:an?|the|its)\s+)?"
        r"(?:amended\s+)?(?:type\s+certificat\w*|certification|type\s+approval)\b"
        r"|\b(?:type\s+certificat\w*|certification|type\s+approval)\b[^.;!?]{0,55}"
        r"\b(?:issued|granted|approved|completed)\b"
        r"|\b(?:received|achieved)\s+(?:amended\s+type\s+)?certification\b"
        r"|\b(?:FAA|Federal Aviation Administration)\s+(?:has\s+)?certif(?:ied|ies)\b",
        re.I,
    )
    negated_re = re.compile(
        r"\b(?:not|never|without|pending|planned|proposed|expected|awaiting|denied|revoked|suspended)\b"
        r".{0,45}\b(?:issued|granted|approved|completed|certified|certifies|certification)\b"
        r"|\b(?:certification|type\s+certificate)\b[^.;!?]{0,50}"
        r"\b(?:pending|expected|awaiting|under\s+review|not\s+yet)\b", re.I,
    )
    matches = []
    for doc in documents:
        url = urlparse(str(doc.get("url") or ""))
        if (url.scheme != "https" or url.hostname not in {"faa.gov", "www.faa.gov"}
                or not re.fullmatch(r"/newsroom/[a-z0-9-]+/?", url.path, re.I)
                or doc.get("source_id") != "SRC_001"
                or doc.get("content_status") != "FULL_TEXT"
                or doc.get("content_truncated")
                or not doc.get("verified_domain")
                or str(doc.get("regulatory_authority") or "FAA").upper() != "FAA"
                or doc.get("faa_record_category") not in {
                    None, "FAA_TYPE_CERTIFICATION", "FAA_NEWSROOM_ANNOUNCEMENT",
                }
                or _is_snippet_only(doc)):
            continue
        try:
            published = date.fromisoformat(str(doc.get("published_at") or "")[:10])
        except ValueError:
            continue
        if not old_date < published <= cutoff:
            continue
        body = str(doc.get("text") or "")
        title_models = _certification_model_ids(str(doc.get("title") or ""))
        for sentence in re.split(r"(?<=[.!?])\s+|\n+", body):
            local_models = _certification_model_ids(sentence)
            if not (models.issubset(local_models) or
                    (models.issubset(title_models) and not local_models and
                     re.search(r"\b(?:FAA|Federal Aviation Administration|the agency|"
                               r"the regulator|aviation authority)\b", sentence, re.I))):
                continue
            if decision_re.search(sentence) and not negated_re.search(sentence):
                matches.append((published, doc))
                break
    return max(matches, key=lambda item: item[0])[1] if matches else None

# Compute source age relative to the analysis reference date.
def _source_age_days(publication_time: str, as_of_date: str = "") -> Optional[int]:
    try:
        source_date = date.fromisoformat(str(publication_time or "")[:10])
        reference_date = date.fromisoformat(str(as_of_date)[:10]) if as_of_date else datetime.now(timezone.utc).date()
        return (reference_date - source_date).days
    except (TypeError, ValueError):
        return None

# Classify current developments separately from historical event context.
# Source age and event timing are different: an old incident can be mentioned in a new article.
def _evaluate_event_freshness(
        threat: ThreatAssessment, doc_raw_full: str, is_already_in_db: bool = False,
        as_of_date: str = "", event_date: str = "",
) -> EventFreshness:
    age = _source_age_days(threat.publication_time, as_of_date)
    if age is not None and age > 90:
        return EventFreshness.HISTORICAL_CONTEXT

    combined = f"{threat.confirmed_facts} {threat.threat_description} {threat.fact_check_quote} {doc_raw_full}"
    comb_low = combined.lower()

    historical_years = [
        int(y) for y in re.findall(
            r"\b(?:in|im|on|during)\s+(?:january|february|march|april|may|june|july|august|september|october|november|december|"
            r"januar|februar|märz|mai|juni|juli|oktober|dezember)\s+(20\d{2})\b",
            threat.fact_check_quote or "",
            flags=re.I,
        )
    ]
    reference_year = int(as_of_date[:4]) if re.match(r"^20\d{2}", as_of_date or "") else datetime.now(timezone.utc).year

    if historical_years and max(historical_years) < reference_year:
        return EventFreshness.HISTORICAL_CONTEXT
    if ONGOING_OR_RECONFIRMED_PATTERNS.search(combined):
        return EventFreshness.ONGOING_ISSUE
    if HISTORICAL_RECAP_PATTERNS.search(threat.fact_check_quote or "") and not any(
            k in comb_low for k in ("today", "this week", "newly")):
        return EventFreshness.HISTORICAL_CONTEXT
    if is_already_in_db:
        return EventFreshness.ONGOING_ISSUE
    if age is None or age < 0 or age > 30 or threat.claim_support_status == "UNSUPPORTED":
        return EventFreshness.EVENT_DATE_UNKNOWN

    event_day = _document_date({"event_date": event_date}, "event_date")
    if event_day == "DATE_UNKNOWN":
        return EventFreshness.EVENT_DATE_UNKNOWN
    event_age = (_reference_day(as_of_date) or datetime.now(timezone.utc).date()) - date.fromisoformat(event_day)
    if event_age.days < 0:
        return EventFreshness.EVENT_DATE_UNKNOWN
    if event_age.days > 90:
        return EventFreshness.HISTORICAL_CONTEXT

    return threat.event_freshness


_CAUSAL_CONNECTOR = re.compile(
    r"\b(?:due\s+to|because\s+of|because|caused\s+by|prompted\s+by|caus(?:ed|ing|es)|"
    r"(?:led|leading)\s+to|result(?:ed|ing)\s+in|contribut(?:ed|ing)\s+to|"
    r"triggered|forced|stemming\s+from|attributable\s+to|as\s+a\s+result\s+of)\b", re.I,
)
_REVERSE_CAUSAL_CONNECTORS = {"due to", "because of", "because", "caused by",
                               "prompted by", "stemming from", "attributable to", "as a result of"}


def _causal_roles(text: str) -> Optional[Tuple[set[str], set[str]]]:
    """Extract causes and effects only when one sentence explicitly links them."""
    for sentence in re.split(r"(?<=[.!?])\s+|\n+", text or ""):
        if not (match := _CAUSAL_CONNECTOR.search(sentence)):
            continue
        before, after = sentence[:match.start()], sentence[match.end():]
        def words(value: str) -> set[str]:
            tokens = set(re.findall(
                r"\b(?:ad|pad|aog|mel|mmel|hpc|hpt|gtf|ifsd|[a-z0-9]{4,})\b", value.lower()
            )) - {
                "that", "this", "with", "from", "which", "were", "have", "been", "their",
            }
            mapped = set()
            for word in tokens:
                if word in {"ad", "pad"}:
                    mapped.add("directive")
                elif word.endswith("ies"):
                    mapped.add(word[:-3] + "y")
                elif len(word) > 5 and word.endswith("s"):
                    mapped.add(word[:-1])
                else:
                    mapped.add(word)
            return mapped

        if match.group().lower() in _REVERSE_CAUSAL_CONNECTORS:
            if words(before):
                cause, effect = after, before
            elif "," in after:
                cause, effect = after.split(",", 1)
            else:
                cause, effect = after, before
        else:
            cause, effect = before, after
        if words(cause) and words(effect):
            return words(cause), words(effect)
    return None


def _causal_quote_support(
    threat: ThreatAssessment, doc: Dict[str, Any], grounded_text: str = "",
) -> Tuple[bool, str]:
    """Require the cited assertion to express the same participants, cause and effect."""
    quote = str(grounded_text or threat.fact_check_quote or "")
    statement = f"{threat.confirmed_facts or ''} {threat.threat_description or ''}"
    cited_roles, claimed_roles = _causal_roles(quote), _causal_roles(statement)
    if not cited_roles or not claimed_roles:
        return False, "CAUSAL_LINK_NOT_EXPLICIT_IN_CITED_PASSAGE"
    if not all(source & claimed for source, claimed in zip(cited_roles, claimed_roles)):
        return False, "CAUSE_OR_EFFECT_PARTICIPANTS_NOT_ALIGNED"
    context = f"{doc.get('title') or ''} {doc.get('issuer_name') or ''} {quote}"
    body = str(doc.get("text") or "")
    if quote and (position := body.find(quote)) >= 0:
        start = body.rfind("\n\n", 0, position) + 2
        end = body.find("\n\n", position + len(quote))
        context += " " + body[start:end if end >= 0 else len(body)][:800]
    actors = [name for name in _split_affected_entities(threat.company_affected)
              if name.lower() != "unknown"]
    if actors and not any(_source_mentions(name, context) for name in actors):
        return False, "CAUSAL_ENTITY_NOT_ESTABLISHED"
    target = str(threat.affected_program or "")
    if target:
        exact = _detect_exact_variants(target)
        observed_exact = _detect_exact_variants(context)
        models = _claim_model_ids(target)
        observed_models = _claim_model_ids(context)
        if ((_detect_engine_models(target) and not _engine_models_match(target, context))
                or (exact and observed_exact and (not exact.issubset(observed_exact) or observed_exact - exact))
                or (models and not models.intersection(observed_models))):
            return False, "CAUSAL_PROGRAM_NOT_ESTABLISHED"
    component = str(getattr(threat, "affected_component", "") or "").strip()
    if component and not re.search(r"\b(?:unknown|not specified|n/a)\b", component, re.I):
        if not re.search(rf"\b{re.escape(component)}\b", context, re.I):
            return False, "CAUSAL_COMPONENT_NOT_ESTABLISHED"
    claim_years = set(re.findall(r"\b20\d{2}\b", statement))
    quote_years = set(re.findall(r"\b20\d{2}\b", quote))
    if claim_years and quote_years and claim_years.isdisjoint(quote_years):
        return False, "CAUSAL_TIME_PERIOD_CONFLICT"
    return True, "CAUSE_EFFECT_STATED_TOGETHER_IN_VERIFIED_QUOTE"

# Separate stated source facts from speculative causal explanations.
# Treat unverified causal explanations separately from the source’s direct assertions.
def _evaluate_claim_and_causal_support(
        threat: ThreatAssessment,
        matched_doc: Dict[str, Any],
        full_quote_verified: bool,
        is_unverified_or_community_source: bool,
) -> Tuple[str, str, List[str]]:
    notes: List[str] = []
    doc_title = (matched_doc.get("title") or "").strip()
    doc_text = (matched_doc.get("text") or "").strip()
    doc_raw_full = f"{doc_title} {doc_text}"
    claim_combined = f"{threat.company_affected} {threat.threat_description} {threat.confirmed_facts}"

    claim_variants, doc_variants = _detect_specific_variants(claim_combined), _detect_specific_variants(doc_raw_full)
    if claim_variants and claim_variants.isdisjoint(doc_variants):
        notes.append(f"Variant mismatch: {sorted(claim_variants)} vs source {sorted(doc_variants)}")
        return "UNSUPPORTED", "UNSUPPORTED", notes

    claim_families, doc_families = _detect_aircraft_families(claim_combined), _detect_aircraft_families(doc_raw_full)
    if claim_families and doc_families and not claim_families.intersection(doc_families):
        notes.append(
            f"Aircraft family mismatch: Claim references {sorted(claim_families)} vs source {sorted(doc_families)}")
        return "UNSUPPORTED", "UNSUPPORTED", notes

    claim_engines, doc_engines = _detect_engine_models(claim_combined), _detect_engine_models(doc_raw_full)
    if (
            claim_engines
            and doc_engines
            and not _engine_models_match(claim_combined, doc_raw_full)
    ):
        notes.append(f"Engine mismatch: Claim references {sorted(claim_engines)} vs source {sorted(doc_engines)}")
        return "UNSUPPORTED", "UNSUPPORTED", notes

    if not full_quote_verified:
        notes.append("Full verbatim quote could not be verified in source document")
        return "UNSUPPORTED", "UNSUPPORTED", notes

    if matched_doc.get("content_status") in {"METADATA_ONLY", "UNAVAILABLE", "STRUCTURED_DATA"}:
        notes.append("CONTENT_QUALITY_GUARD: Metadata/structured facts cannot verify a narrative event or cause.")
        return "UNSUPPORTED", "HYPOTHETICAL_ONLY", notes

    # SEC metadata prove the existence and timing of a filing,
    # not the underlying financial or operational claims.
    if (
            matched_doc.get("source_id") == "SRC_027"
            and (
            matched_doc.get("document_type")
            == "SEC_FILING_METADATA_ONLY"
            or matched_doc.get("content_status") == "METADATA_ONLY"
            or "[SEC_METADATA_ONLY]" in doc_raw_full
            or "FULL_TEXT_UNAVAILABLE:" in doc_raw_full
    )
    ):
        notes.append(
            "SEC_METADATA_ONLY_GUARD: Verified filing metadata "
            "cannot establish substantive financial results, "
            "operational disruptions or causal explanations."
        )

        return ('PARTIALLY_STATED_IN_SOURCE', 'HYPOTHETICAL_ONLY', notes)

    # ESEF index metadata prove filing existence only.
    # They do not prove financial figures or operational events.
    if (
        matched_doc.get("source_id") == "SRC_031"
        and (
            matched_doc.get("document_type")
            == "ESEF_FILING_METADATA_ONLY"
            or matched_doc.get("content_status") == "METADATA_ONLY"
            or "[ESEF_FILING_METADATA_ONLY]" in doc_raw_full
        )
    ):
        notes.append(
            "ESEF_METADATA_ONLY_GUARD: "
            "Filing index metadata cannot establish "
            "financial losses, disruptions or causality."
        )

        return ('UNSUPPORTED', 'HYPOTHETICAL_ONLY', notes)

    is_snippet_only = _is_snippet_only(matched_doc) and not (
        matched_doc.get("source_id") in {"SRC_027", "SRC_031"}
        and _verified_filing_passage(matched_doc, threat.fact_check_quote)
    )
    grounded_quotes = [threat.fact_check_quote or ""]
    doc_norm_full = _normalize_for_quote_match(doc_raw_full)
    matched_doc_id = str(matched_doc.get("doc_id") or "")
    for passage in getattr(threat, "evidence_passages", None) or []:
        p_doc = str(getattr(passage, "document_id", "") or (
            passage.get("document_id", "") if isinstance(passage, dict) else ""))
        p_text = str(getattr(passage, "passage_text", "") or (
            passage.get("passage_text", "") if isinstance(passage, dict) else ""))
        if matched_doc_id and p_doc and p_doc != matched_doc_id:
            continue
        p_segs = [
            seg_norm for seg in re.split(r"\.{3,}|…", p_text)
            if len(seg_norm := _normalize_for_quote_match(seg)) >= 6
        ]
        if p_segs and all(seg in doc_norm_full for seg in p_segs):
            grounded_quotes.append(p_text)
    if full_quote_verified and not is_snippet_only and not is_unverified_or_community_source:
        q_tokens = re.findall(r"\w+", threat.fact_check_quote or "")
        if len(q_tokens) >= 6:
            anchor = re.search(r"\W+".join(map(re.escape, q_tokens[:10])), doc_raw_full, re.I)
            if anchor:
                win_start = max(0, anchor.start() - 250)
                win_end = min(len(doc_raw_full), anchor.end() + 400)
                grounded_quotes.append(doc_raw_full[win_start:win_end].strip())
        for claim_obj in getattr(threat, "evidence_claims", None) or []:
            c_doc = str(getattr(claim_obj, "document_id", "") or "")
            c_quote = str(getattr(claim_obj, "quote", "") or "")
            if matched_doc_id and c_doc and c_doc != matched_doc_id:
                continue
            c_segs = [
                seg_norm for seg in re.split(r"\.{3,}|…", c_quote)
                if len(seg_norm := _normalize_for_quote_match(seg)) >= 6
            ]
            if c_segs and all(seg in doc_norm_full for seg in c_segs):
                grounded_quotes.append(c_quote)
    if full_quote_verified and matched_doc.get("source_id") == "SRC_001":
        fr_header = doc_text.split("Official Full Text:", 1)[0].strip()
        if fr_header:
            grounded_quotes.append(fr_header)
    grounded_quote_text = " ".join(q for q in grounded_quotes if q)

    fact_source_text = (threat.confirmed_facts or "").strip() or (threat.threat_description or "").strip()
    fact_stopwords = {
        "source", "states", "confirmed", "reports", "aircraft", "airline", "company",
        "january", "february", "march", "april", "june", "july", "august",
        "september", "october", "november", "december",
        "that", "this", "with", "from", "which", "were", "have", "been", "under",
        "also", "into", "their", "these", "those", "such", "when", "where",
        "between", "within", "about", "after", "before", "during", "through",
        "including", "regarding", "following", "according", "based", "certain",
        "specific", "other", "more", "than", "some", "will", "would",
    }
    fact_words = [
        w for w in re.findall(r"\b[a-z0-9]{4,}\b", _normalize_for_quote_match(fact_source_text))
        if w not in fact_stopwords
    ]
    overlap_corpus = (
        doc_norm_full
        if (full_quote_verified and not is_snippet_only and not is_unverified_or_community_source)
        else _normalize_for_quote_match(grounded_quote_text)
    )

    def _word_supported(word: str) -> bool:
        if word in overlap_corpus:
            return True
        if len(word) >= 6:
            for suffix in ("ings", "ing", "ied", "ies", "ed", "es", "s"):
                if word.endswith(suffix) and len(word) - len(suffix) >= 4:
                    if word[:-len(suffix)] in overlap_corpus:
                        return True
        return False

    fact_overlap = (
            sum(1 for w in fact_words if _word_supported(w)) / len(fact_words)
    ) if fact_words else 0.0

    claim_has_causality = bool(CAUSAL_CLAIM_REGEX.search(f"{threat.confirmed_facts} {threat.threat_description}"))
    causal_grounded, causal_reason = (
        _causal_quote_support(threat, matched_doc, grounded_quote_text) if claim_has_causality else (False, "")
    )

    if claim_has_causality and causal_grounded and fact_overlap >= 0.50:
        if is_unverified_or_community_source or is_snippet_only:
            causal_status = "CLAIMED_IN_UNVERIFIED_SOURCE"
            notes.append("Causality is stated in an unverified/community or snippet source (not objectively proven)")
        else:
            causal_status = "EVIDENCED_IN_VERIFIED_SOURCE"
    elif claim_has_causality:
        causal_status = "HYPOTHETICAL_ONLY"
        reason_label = (
            "INSUFFICIENT_FACT_OVERLAP_FOR_CAUSAL_CLAIM"
            if causal_grounded
            else (causal_reason or "CAUSAL_CLAIM_NOT_GROUNDED")
        )
        notes.append(f"{reason_label}: downstream causality is not verified")
    else:
        causal_status = "NOT_ASSERTED"

    if is_snippet_only:
        notes.append("Source record contains only a headline or short snippet; confirms headline publication only")
        claim_status = "PARTIALLY_STATED_IN_SOURCE" if fact_overlap >= 0.50 else "UNSUPPORTED"
    elif fact_overlap >= 0.65:
        claim_status = "STATED_IN_SOURCE"
    elif fact_overlap >= 0.45:
        notes.append("Source states only part of the claim details")
        claim_status = "PARTIALLY_STATED_IN_SOURCE"
    else:
        notes.append("Claim extrapolates beyond what is stated in the source document")
        claim_status = "UNSUPPORTED"

    if claim_has_causality and causal_status != "EVIDENCED_IN_VERIFIED_SOURCE":
        if claim_status == "STATED_IN_SOURCE":
            claim_status = "PARTIALLY_STATED_IN_SOURCE"
        notes.append("Unverified causal interpretation cannot be included among confirmed facts.")

    actual_status = r"\b(?:certified|approved|completed|resumed|restored|issued|effective|delivered)\b"
    uncertain_status = r"\b(?:not\s+yet|never|without|pending|expect\w*|anticipat\w*|plan\w*|propos\w*|await\w*|may|might|could)\b"
    if (re.search(actual_status, claim_combined, re.I)
            and re.search(uncertain_status, threat.fact_check_quote or "", re.I)
            and not re.search(r"\b(?:has|have|was|were)\s+(?:already\s+)?(?:been\s+)?"
                              r"(?:certified|approved|completed|resumed|restored|issued|delivered)\b",
                              threat.fact_check_quote or "", re.I)):
        claim_status = "PARTIALLY_STATED_IN_SOURCE" if claim_status == "STATED_IN_SOURCE" else claim_status
        notes.append("ACTUAL_STATUS_UNVERIFIED: forecast, proposal or negation cannot establish completed action")

    if (
            _PRIOR_PERIOD_CAUSE_RE.search(doc_raw_full)
            and _CURRENT_PERIOD_RE.search(claim_combined)
            and _CLAIM_CAUSE_RE.search(claim_combined)
    ):
        claim_status = "PARTIALLY_STATED_IN_SOURCE"
        causal_status = "HYPOTHETICAL_ONLY"
        notes.append(
            "TEMPORAL_SCOPE_MISMATCH: Causal attribution belongs to the prior comparison period, "
            "not demonstrably to the current period"
        )

    impact_re = (
        r"\b(delay|shortag|disrupt|impact|affect|threaten|ground|halt|"
        r"caus|trigger|intensif|increas|pressur|strain|bottleneck|constrain|allocat)\w*\b"
    )
    claimed = {
        m.lower()
        for m in re.findall(impact_re, f"{threat.threat_description or ''} {threat.confirmed_facts or ''}", re.I)
    }
    cited = {m.lower() for m in re.findall(impact_re, grounded_quote_text, re.I)}

    if claimed - cited:
        causal_status = "HYPOTHETICAL_ONLY"
        if claim_status == "STATED_IN_SOURCE":
            claim_status = "PARTIALLY_STATED_IN_SOURCE"
        notes.append("Claimed operational impact is not supported by the cited quotation.")

    return claim_status, causal_status, notes

# Validate every event’s grounding, technical identity, source quality, and escalation eligibility.
# Downgrade uncertain or contradictory evidence rather than relying on Analyst confidence alone.
# A high model score cannot bypass source, technical or status checks.
def deterministic_harness_validation(
        report: EWSReport,
        raw_data: str,
        collected_docs: Optional[List[Dict[str, Any]]] = None,
        user_query: str = "",
        as_of_date: str = "",
) -> Tuple[EWSReport, int]:
    # Start evidence-based validation for every candidate, irrespective of model-provided confidence.
    """Five-Dimensional Grounding, Source-Evidenced Program Guard, Event Freshness & Watchlist Validator."""
    docs = collected_docs if collected_docs is not None else get_collected_documents()
    docs_by_id: Dict[str, Dict[str, Any]] = {
        d["doc_id"]: d for d in docs if isinstance(d, dict) and d.get("doc_id")
    }
    docs_by_url: Dict[str, Dict[str, Any]] = {
        d["url"]: d for d in docs if isinstance(d, dict) and d.get("url")
    }

    active_kit_query = user_query or (report.run_metadata or {}).get("query", "")
    reference_date = _reference_day(as_of_date, active_kit_query)
    invalid_reference_date = bool(as_of_date and not reference_date)
    if reference_date:
        as_of_date = reference_date.isoformat()
    positive_kit_query = re.split(
        r"\b(?:exclude|excluding|except(?:\s+for)?|without|not\s+including|kromě|vyjma)\b",
        active_kit_query, maxsplit=1, flags=re.I,
    )[0].strip()
    kit_target_variants = _detect_specific_variants(positive_kit_query)
    kit_exact = _detect_exact_variants(positive_kit_query)
    kit_engines = _detect_engine_models(positive_kit_query)
    kit_components = {
        comp_label for kw, comp_label in COMPONENT_KEYWORDS_MAP.items()
        if re.search(rf"\b{re.escape(kw)}\b", positive_kit_query, re.I)
    }

    catalog = get_active_kiq_catalog()
    validated_threats: List[ThreatAssessment] = []
    watchlist_threats: List[ThreatAssessment] = []
    metadata_mismatches = validation_errors = flagged_unverified = 0

    # Assess each event separately so a well-supported event cannot validate an unrelated claim.
    for threat in report.threats:
        llm_raw_url = re.sub(
            r"^(?:SOURCE_URL:|LINK:|Link:|SOURCE:|URL:)\s*", "", (threat.evidence_citation or "").strip(), flags=re.I
        ).rstrip(".,;)")

        explicit_docs = [
            docs_by_id[eid.strip().upper()]
            for eid in (threat.evidence_ids or [])
            if eid.strip().upper() in docs_by_id
        ]
        # Locate the cited source record and require normalized quotation alignment.
        audit_notes: List[str] = []
        full_quote_norm = _normalize_for_quote_match(threat.fact_check_quote)

        quote_matching_docs = [
            ed for ed in explicit_docs
            if full_quote_norm and full_quote_norm in _normalize_for_quote_match(
                f"{ed.get('title', '')} {ed.get('text', '')}"
            )
        ]
        if quote_matching_docs:
            matched_doc = next(
                (ed for ed in quote_matching_docs if llm_raw_url and ed.get("url") == llm_raw_url),
                max(quote_matching_docs, key=lambda ed: str(ed.get("published_at") or "")),
            )
        else:
            matched_doc = next(
                (ed for ed in explicit_docs if llm_raw_url and ed.get("url") == llm_raw_url),
                explicit_docs[0] if explicit_docs else None,
            )

        primary_title_recovered = False
        if matched_doc and not any(
                full_quote_norm and full_quote_norm in _normalize_for_quote_match(
                    f"{d.get('title', '')} {d.get('text', '')}"
                )
                for d in explicit_docs
        ):
            exact_kit = _detect_exact_variants(active_kit_query)
            primary = next((
                d for d in explicit_docs
                if exact_kit
                   and _detect_exact_variants(d.get("title", "")) & exact_kit
                   and re.search(r"\b(?:certif\w*|approv\w*|airworth\w*)\b",
                                 d.get("title", ""), re.I)
                   and 6 <= len(d.get("title", "").split()) <= 25
                   and len(d.get("title", "")) <= 400
                   and is_exact_or_subdomain(
                extract_effective_publisher_domain(d.get("url", "")),
                _PRIMARY_REGULATOR_DOMAINS | _PRIMARY_OEM_AND_TIER1_DOMAINS
            )
            ), None)

            if primary:
                matched_doc = primary
                primary_title_recovered = True
                threat.fact_check_quote = primary["title"].strip()
                full_quote_norm = _normalize_for_quote_match(threat.fact_check_quote)
                audit_notes.append(
                    "Original quote not found; using exact official headline. "
                    "Operational impacts remain unverified."
                )

        recovered_source_quote = False
        original_quote = threat.fact_check_quote or ""
        regulator = re.search(r"\b(?:FAA|EASA)\b", original_quote, re.I)

        if (
                matched_doc and regulator and kit_exact
                and matched_doc.get("source_id") in {"SRC_004", "SRC_007", "SRC_008"}
                and (
                matched_doc.get("source_id") != "SRC_004"
                or full_quote_norm not in _normalize_for_quote_match(
            f"{matched_doc.get('title', '')} {matched_doc.get('text', '')}"
        )
        )
                and re.search(r"\b(?:certif\w*|approv\w*|clear\w*|grant\w*)\b", original_quote, re.I)
                and not re.search(
            r"\b(?:pending|propos\w*|await\w*|expect\w*|could|might|deni\w*|reject\w*|revok\w*|suspend\w*|withdraw\w*|not\s+yet)\b",
            original_quote, re.I
        )
        ):
            for doc in explicit_docs:
                title = (doc.get("title") or "").strip()
                if (
                        doc.get("source_id") == "SRC_004"
                        and not _is_snippet_only(doc)
                        and "[NEWSAPI_METADATA_ONLY:" not in (doc.get("text") or "")
                        and 5 <= len(title.split()) <= 25
                        and _detect_exact_variants(title) == kit_exact
                        and re.search(rf"\b{regulator.group()}\b", title, re.I)
                        and re.search(r"\b(?:certif\w*|approv\w*|clear\w*|grant\w*)\b", title, re.I)
                        and not re.search(
                    r"\b(?:pending|propos\w*|await\w*|expect\w*|deni\w*|reject\w*|revok\w*|suspend\w*)\b",
                    title, re.I
                )
                        and threat.company_affected.lower() in title.lower()
                ):
                    matched_doc = doc
                    threat.fact_check_quote = title
                    full_quote_norm = _normalize_for_quote_match(title)
                    recovered_source_quote = True
                    audit_notes.append(
                        "Original LLM quote replaced with exact full-text source title; broader claims remain unverified."
                    )
                    break

        if not matched_doc and llm_raw_url and llm_raw_url in docs_by_url:
            matched_doc = docs_by_url[llm_raw_url]
            audit_notes.append("DOC_ID missing or invalid; matched via exact collected URL")

        # Missing source provenance must reduce confidence rather than be inferred from the model
        #   response.
        if not matched_doc:
            validation_errors += 1
            flagged_unverified += 1
            threat.technical_grounding_status = "FAIL"
            threat.claim_support_status = "UNSUPPORTED"
            threat.causal_support_status = "UNSUPPORTED"
            threat.independent_verification_status = "UNVERIFIED_SINGLE_SOURCE"
            threat.validation_status = ValidationStatus.UNSUPPORTED
            threat.confidence_level = ConfidenceLevel.LOW
            threat.event_status = EventStatus.UNDER_REVIEW
            threat.escalation_level = EscalationStatus.PRIORITY_VERIFICATION_REQUIRED
            threat.evidence_citation = ""
            threat.source_urls = []
            threat.evidence_ids = []
            threat.affected_program = "Unknown / Not specified in source"
            threat.affected_component = "Unknown / Not specified in source"
            threat.geographic_epicenter = "Unknown"
            threat.verification_status = (
                "UNVERIFIED: Cited DOC_ID/URL not found in collected OSINT documents (Manual HITL Review Required)"
            )
            threat.missing_data = "Source document could not be traced in collected dataset; manual verification required."
            threat.intelligence_gap = IntelligenceGap(
                what_is_missing=threat.missing_data,
                why_important="Cannot confirm claim without a traceable primary/secondary OSINT document.",
                affected_kiq_id=threat.kiq_ids[0] if threat.kiq_ids else "",
                recommended_source="Manual Analyst Verification",
                can_auto_scan=True,
                status="OPEN",
            )
            threat.confirmed_facts = ""
            threat.threat_description = (
                "Unverified intelligence claim: the cited source could not be traced to the collected OSINT dataset."
            )
            threat.analytical_interpretation = (
                "No source-grounded interpretation is possible until the source reference is verified."
            )
            validated_threats.append(threat)
            continue

        canonical_doc_url = matched_doc["url"]
        canonical_doc_date = matched_doc.get("published_at") or "DATE_UNKNOWN"

        url_consistent = not (llm_raw_url and llm_raw_url != canonical_doc_url)
        if not url_consistent:
            metadata_mismatches += 1
            audit_notes.append(
                f"LLM URL differed from {matched_doc['doc_id']} metadata; overwritten with canonical document URL")

        llm_norm_date = normalize_date_str(threat.publication_time)
        date_consistent = not (
                canonical_doc_date != "DATE_UNKNOWN" and llm_norm_date and llm_norm_date != canonical_doc_date)
        if not date_consistent:
            metadata_mismatches += 1
            audit_notes.append(
                f"LLM date ({llm_norm_date}) differed from {matched_doc['doc_id']} date ({canonical_doc_date}); corrected")

        # Bind canonical source metadata to the event before corroboration checks.
        threat.evidence_citation = canonical_doc_url
        threat.publication_time = canonical_doc_date

        corroborating_docs = [matched_doc] + [ed for ed in explicit_docs if ed["doc_id"] != matched_doc["doc_id"]]

        if matched_doc.get("source_id") == "SRC_001":
            # Extract the FAA docket reference from the current source record.
            def _faa_docket(doc):
                m = re.search(r"(?im)^FAA Docket:\s*(FAA-\d{4}-\d+)\s*$", doc.get("text", ""))
                return m.group(1) if m else ""

            if primary_docket := _faa_docket(matched_doc):
                orig_len = len(corroborating_docs)
                corroborating_docs = [d for d in corroborating_docs if
                                      d.get("source_id") != "SRC_001" or _faa_docket(d) == primary_docket]
                if len(corroborating_docs) < orig_len:
                    audit_notes.append("Evidence from different FAA dockets removed.")

        threat.evidence_ids = list(dict.fromkeys(d["doc_id"] for d in corroborating_docs))
        threat.source_urls = list(dict.fromkeys(d["url"] for d in corroborating_docs if d.get("url")))

        doc_raw_full = f"{matched_doc.get('title', '')} {matched_doc.get('text', '')}"
        target_corpus_norm = _normalize_for_quote_match(doc_raw_full)

        threat.scm_tier, threat.supplier_registry_basis, threat.impact_path, has_unknown_scm = (
            _resolve_scm_roles_and_impact_path(threat, doc_raw_full)
        )
        threat.geographic_epicenter, threat.geographic_impact_scope = _resolve_geography_dimensions(threat,
                                                                                                    doc_raw_full)

        independent_source_count, has_true_primary_regulator, has_true_primary_oem = (
            _count_independent_confirmations(corroborating_docs)
        )
        domain = extract_effective_publisher_domain(canonical_doc_url)
        is_official_domain = urlparse(canonical_doc_url).scheme == "https" and is_exact_or_subdomain(
            domain, _PRIMARY_REGULATOR_DOMAINS | _PRIMARY_OEM_AND_TIER1_DOMAINS | {"sec.gov"},
        )
        has_community = any(d.get("source_type") in {"COMMUNITY_SOCIAL", "VIDEO_MEDIA"} for d in corroborating_docs)
        has_media = any(
            d.get("source_type") in {"MEDIA_AGGREGATOR", "INDUSTRY_EVENT", "GEOGRAPHIC_SIGNAL"}
            or "news.google.com" in extract_effective_publisher_domain(d.get("url", ""))
            for d in corroborating_docs
        )
        is_social_or_video = is_exact_or_subdomain(domain, UNVERIFIED_SOCIAL_VIDEO_DOMAINS) or (
                has_community and not is_official_domain and not has_media
        )

        if independent_source_count >= 2 or (is_official_domain and has_media):
            threat.independent_verification_status = "CORROBORATED_INDEPENDENTLY"
        elif is_official_domain:
            threat.independent_verification_status = "SINGLE_PRIMARY_SOURCE"
        elif has_media and not is_social_or_video:
            threat.independent_verification_status = "SINGLE_SECONDARY_SOURCE"
        else:
            threat.independent_verification_status = "UNVERIFIED_SINGLE_SOURCE"

        quote_segments = [
            normalized
            for seg in re.split(r"\.{3,}|…", threat.fact_check_quote or "")
            if len(normalized := _normalize_for_quote_match(seg)) >= 6
        ]
        full_quote_verified = bool(
            full_quote_norm
            and len(full_quote_norm) >= 12
            and quote_segments
            and all(seg in target_corpus_norm for seg in quote_segments)
        )
        if not _verified_filing_passage(matched_doc, threat.fact_check_quote):
            full_quote_verified = False
            audit_notes.append("FILING_PASSAGE_UNVERIFIED: source-exact filing excerpt or stored hash is missing")
        # Check quotation provenance and avoid treating generated prose as an exact source quote.
        threat.technical_grounding_status = "PASS" if full_quote_verified else "FAIL"

        matched_text_str = str(matched_doc.get("text") or "")
        faa_publication = _verified_faa_publication(matched_doc)
        faa_publication_verified = bool(faa_publication)
        faa_lifecycle_verified = bool(
            faa_publication_verified
            and re.search(r"(?im)^Regulatory Lifecycle Check:\s*VERIFIED\s*$", matched_text_str)
        )

        quote_recovered_from_faa_abstract = False
        if faa_publication_verified and not full_quote_verified:
            if abstract_match := re.search(r"(?is)Official Summary:\s*(.+)", matched_text_str):
                abstract = abstract_match.group(1).strip()
                if spans := list(re.finditer(r"\S+", abstract)):
                    candidate_quote = abstract[:spans[min(25, len(spans)) - 1].end()].strip()
                    candidate_norm = _normalize_for_quote_match(candidate_quote)
                    if len(candidate_norm) >= 30 and candidate_norm in target_corpus_norm:
                        threat.fact_check_quote = candidate_quote
                        full_quote_norm = candidate_norm
                        full_quote_verified = True
                        quote_recovered_from_faa_abstract = True
                        threat.technical_grounding_status = "PASS"
                        audit_notes.append(
                            "Original LLM quote was not traceable; replaced by a literal excerpt of the "
                            "stored FAA abstract. This does not verify unquoted operational effects."
                        )

        quote_recovered_from_title = False
        title = (matched_doc.get("title") or "").strip()

        if (
                not full_quote_verified
                and matched_doc.get("source_id") == "SRC_004"
                and not _is_snippet_only(matched_doc)
                and 10 <= len(title) <= 400
                and len(title.split()) <= 25
                and SequenceMatcher(
            None, full_quote_norm, _normalize_for_quote_match(title)
        ).ratio() >= 0.90
        ):
            threat.fact_check_quote = title
            full_quote_norm = _normalize_for_quote_match(title)
            full_quote_verified = True
            quote_recovered_from_title = True
            threat.technical_grounding_status = "PASS"
            audit_notes.append(
                "LLM near-quote replaced with exact stored source title; broader claims remain unverified."
            )

        if faa_publication_verified and full_quote_verified:
            impact_pattern = r"\b(?:ground\w*|production|deliver\w*|capacity|bottleneck\w*|shortag\w*|disrupt\w*)\b"
            if (
                    re.search(impact_pattern, f"{threat.threat_description} {threat.confirmed_facts}", re.I)
                    and not re.search(impact_pattern, threat.fact_check_quote or "", re.I)
            ):
                threat.analytical_interpretation = (
                                                           "Possible downstream effects are hypothetical and require independent operational evidence. "
                                                           + (threat.analytical_interpretation or "")
                                                   )[:800]
                threat.threat_description = (threat.fact_check_quote or "")[:800]
                threat.confirmed_facts = (threat.fact_check_quote or "")[:400]
                audit_notes.append("FAA regulatory fact kept separate from unverified downstream effects.")

        source_fact = str(threat.fact_check_quote or "").strip()
        if (
                is_official_domain
                and full_quote_verified
                and source_fact
                and not str(threat.confirmed_facts or "").strip()
                and not _is_snippet_only(matched_doc)
                and matched_doc.get("content_status") not in {"METADATA_ONLY", "UNAVAILABLE", "STRUCTURED_DATA"}
        ):
            threat.confirmed_facts = source_fact[:400]
            audit_notes.append(
                "Source-exact statement retained as confirmed fact; "
                "unquoted operational consequences remain unverified."
            )

        # Evaluate factual statements and causal interpretations separately.
        threat.claim_support_status, threat.causal_support_status, content_notes = _evaluate_claim_and_causal_support(
            threat, matched_doc, full_quote_verified, is_unverified_or_community_source=is_social_or_video
        )

        claim_text = f"{threat.confirmed_facts} {threat.threat_description}"
        entity_names = tuple(dict.fromkeys([
            *(
                re.sub(
                    r"^The\s+|\s*\([^)]*\)|\s+(?:Company|S\.?p\.?A\.?|S\.?A\.?|SE|Inc\.?|Ltd\.?|LLC|Corp\.?|Holdings|Corporation)$",
                    "", e.get("official_name", ""), flags=re.I,
                ).strip()
                for e in AEROSPACE_SUPPLIER_REGISTRY
                if e.get("official_name")
            ),
            "Pratt & Whitney", "Aequs",
        ]))

        oem_programs_by_name = {
            re.sub(
                r"^The\s+|\s*\([^)]*\)|\s+(?:Company|S\.?p\.?A\.?|S\.?A\.?|SE|Inc\.?|Ltd\.?|LLC|Corp\.?|Holdings|Corporation)$",
                "", e.get("official_name", ""), flags=re.I,
            ).strip().lower(): e.get("programs") or []
            for e in AEROSPACE_SUPPLIER_REGISTRY
            if e.get("default_tier") == "OEM (Final Assembler)" and e.get("official_name")
        }

        # Match company mentions against the source rather than inferred relationships.
        def _entity_mentioned(name: str, text: str) -> bool:
            pat = r"(?<!\w)pratt\s*(?:&|and)\s*whitney(?!\w)" if name == "Pratt & Whitney" else rf"(?<!\w){re.escape(name)}(?!\w)"
            if re.search(pat, text or "", re.I):
                return True
            programs = oem_programs_by_name.get(name.lower())
            if programs:
                text_vars = _detect_exact_variants(text) | _detect_specific_variants(text)
                oem_vars = _detect_exact_variants(" ".join(programs)) | _detect_specific_variants(" ".join(programs))
                if text_vars and oem_vars and (text_vars & oem_vars):
                    return True
            return False

        if unsupported_entities := [n for n in entity_names if
                                    _entity_mentioned(n, claim_text) and not _entity_mentioned(n, doc_raw_full)]:
            if threat.claim_support_status == "STATED_IN_SOURCE":
                threat.claim_support_status = "PARTIALLY_STATED_IN_SOURCE"
            threat.causal_support_status = "HYPOTHETICAL_ONLY"
            audit_notes.append(
                f"Entity relationship requires verification: {', '.join(unsupported_entities)} not explicitly identified in cited source."
            )

        if any(note.startswith("TEMPORAL_SCOPE_MISMATCH") for note in content_notes):
            threat.threat_description = (
                    re.sub(r",?\s+(?:mainly|primarily|mostly|largely)\s+(?:due\s+to|because\s+of)\b.*$", "",
                           threat.threat_description, flags=re.I).rstrip(" ,.;") + "."
            )
            threat.confirmed_facts = (
                    re.sub(r";?\s*(?:primary|main)\s+cause\s*:\s*.*$", "", threat.confirmed_facts, flags=re.I).rstrip(
                        " ,.;") + "."
            )
            threat.analytical_interpretation = (
                "The source attributes a cause to the prior comparison period. "
                "The cause of the current-period result requires separate evidence."
            )
            threat.missing_data = "Verify current-period causality in an independent primary financial or regulatory disclosure."

        audit_notes.extend(content_notes)

        threat.event_freshness = _evaluate_event_freshness(
            threat, doc_raw_full, as_of_date=as_of_date,
            event_date=matched_doc.get("event_date") or "",
        )
        age = _source_age_days(threat.publication_time, as_of_date)
        if age is not None and age > 90:
            audit_notes.append(
                f"Source published {age} days before reference date; historical source alone "
                "does not prove a new event or current disruption"
            )
        elif age is not None and age < 0:
            audit_notes.append(
                "Publication date is later than analysis reference date; temporal integrity review required")

        if threat.event_freshness == EventFreshness.ONGOING_ISSUE:
            audit_notes.append(
                "Classified as ONGOING_ISSUE (reconfirmation of previously known schedule/issue, not a newly announced deterioration)"
            )
        elif threat.event_freshness == EventFreshness.HISTORICAL_CONTEXT:
            audit_notes.append("Classified as HISTORICAL_CONTEXT (older event referenced in recent source)")

        event_variants = _detect_specific_variants(threat.affected_program or "")
        source_exact = _detect_exact_variants(threat.fact_check_quote or "")
        event_quote_and_claim = f"{threat.affected_component or ''} {threat.affected_program or ''} {threat.fact_check_quote or ''}"
        event_engines = _detect_engine_models(event_quote_and_claim)
        event_components = {
            comp_label for kw, comp_label in COMPONENT_KEYWORDS_MAP.items()
            if re.search(rf"\b{re.escape(kw)}\b", event_quote_and_claim, re.I)
        }

        # Detect aircraft, engine, and component mismatches with the original monitoring KIT.
        exact_mismatch = bool(kit_exact and source_exact and kit_exact.isdisjoint(source_exact))
        variant_mismatch = bool(
            kit_target_variants and event_variants and kit_target_variants.isdisjoint(event_variants))
        engine_mismatch = bool(
            kit_engines
            and event_engines
            and not _engine_models_match(
                active_kit_query,
                event_quote_and_claim,
            )
        )
        component_mismatch = bool(kit_components and event_components and kit_components.isdisjoint(event_components))

        is_sibling_watchlist = bool(exact_mismatch or variant_mismatch or engine_mismatch or component_mismatch)
        engine_directly_matched = bool(kit_engines and event_engines and not engine_mismatch)
        airframe_directly_matched = bool(
            (kit_exact and source_exact and not exact_mismatch)
            or (kit_target_variants and event_variants and not variant_mismatch)
        )
        missing_program_facet = bool(
            ((kit_target_variants and not event_variants) or (kit_exact and not source_exact))
            and not engine_directly_matched
        )
        missing_technical_subfacet = bool(
            (kit_engines and not event_engines and not airframe_directly_matched)
            or (kit_components and not event_components)
        )

        if is_sibling_watchlist:
            threat.program_relevance = "RELATED_PROGRAM_WATCHLIST"
            mismatch_reasons = []
            # Exact technical mismatches override generic aircraft/manufacturer overlap.
            if exact_mismatch or variant_mismatch:
                mismatch_reasons.append(
                    f"program {sorted(event_variants or source_exact)} vs KIT {sorted(kit_target_variants or kit_exact)}")
            if engine_mismatch:
                mismatch_reasons.append(f"propulsion {sorted(event_engines)} vs KIT {sorted(kit_engines)}")
            if component_mismatch:
                mismatch_reasons.append(f"component {sorted(event_components)} vs KIT {sorted(kit_components)}")
            audit_notes.append(
                "Classified as RELATED_PROGRAM_WATCHLIST: Event evidence conflicts with constraining KIT facet(s) "
                f"({'; '.join(mismatch_reasons)}); direct cross-program or cross-configuration impact is not established"
            )
        elif missing_program_facet or missing_technical_subfacet:
            threat.program_relevance = "PROGRAM_UNVERIFIED"
            audit_notes.append(
                "All constraining technical facets of the KIT (aircraft program and/or specific propulsion/component scope) "
                "could not be simultaneously verified from event evidence. Direct KIT relevance remains unconfirmed."
            )
        else:
            threat.program_relevance = "DIRECT_KIT_MATCH"

        # A regulatory notice is not evidence extracted from the requested SEC/ESEF filing.
        filing_specific_kit = bool(re.search(r"\b(?:sec|edgar|esef|xbrl|10-[kq]|20-f|6-k)\b", active_kit_query, re.I))
        if filing_specific_kit and matched_doc.get("source_id") not in {"SRC_027", "SRC_031"}:
            if threat.program_relevance == "DIRECT_KIT_MATCH":
                threat.program_relevance = "RELATED_CONTEXT"
            audit_notes.append("FINANCIAL_SOURCE_SCOPE: non-filing source cannot directly evidence a filing-specific KIT")

        # A true A350/787 announcement is not proof of a requested supplier shortage.
        issue_gap = kit_direct_relevance_gap(active_kit_query, doc_raw_full)
        if issue_gap and not is_sibling_watchlist:
            threat.program_relevance = "RELATED_CONTEXT"
            threat.claim_support_status = (
                "PARTIALLY_STATED_IN_SOURCE" if full_quote_verified else "UNSUPPORTED"
            )
            threat.causal_support_status = "HYPOTHETICAL_ONLY"
            audit_notes.append(issue_gap)

        fact_audit = _kit_fact_audit(active_kit_query, threat.fact_check_quote, matched_doc, reference_date)
        unverified_facets = {name: state for name, state in fact_audit.items()
                             if state in {"NEGATIVE", "UNKNOWN"}}
        if unverified_facets:
            audit_notes.append("KIT_FACT_GAP: " + ", ".join(
                f"{name}={state}" for name, state in unverified_facets.items()
            ))
            only_issuer_authority_gap = (
                    unverified_facets == {"AUTHORITY": "UNKNOWN"}
                    and is_official_domain
                    and matched_doc.get("source_id") in {"SRC_027", "SRC_031", "SRC_005", "SRC_030"}
            )
            if any(fact_audit[key] == "NEGATIVE" for key in ("PROGRAM", "VARIANT", "COMPONENT")):
                is_sibling_watchlist = True
                threat.program_relevance = "RELATED_PROGRAM_WATCHLIST"
            elif any(fact_audit[key] == "UNKNOWN" for key in ("ENTITY", "PROGRAM", "VARIANT", "COMPONENT")):
                if not is_sibling_watchlist:
                    threat.program_relevance = "PROGRAM_UNVERIFIED"
            elif not is_sibling_watchlist and not only_issuer_authority_gap and threat.program_relevance == "DIRECT_KIT_MATCH":
                threat.program_relevance = "RELATED_CONTEXT"

        combined_claim = f"{threat.threat_description} {threat.fact_check_quote} {threat.adversarial_scenario}"
        has_speculation = bool(SPECULATIVE_DISINFO_MARKERS.search(combined_claim))

        # Rozpor nelze prokazovat nalezením záporného slova
        # kdekoli v rozsáhlém dokumentu.
        if is_social_or_video:
            threat.validation_status = ValidationStatus.UNVERIFIED_COMMUNITY
            threat.confidence_level = ConfidenceLevel.LOW
            flagged_unverified += 1
        elif (
                threat.technical_grounding_status == "PASS"
                and threat.claim_support_status == "STATED_IN_SOURCE"
                and threat.causal_support_status in {"EVIDENCED_IN_VERIFIED_SOURCE", "NOT_ASSERTED"}
                and not is_sibling_watchlist
        ):
            threat.validation_status = ValidationStatus.SUPPORTED
            threat.confidence_level = (
                ConfidenceLevel.HIGH
                if (
                           is_official_domain or independent_source_count >= 2) and url_consistent and date_consistent and not has_speculation
                else ConfidenceLevel.MEDIUM
            )
        elif (
                threat.technical_grounding_status == "PASS"
                and threat.claim_support_status in {"STATED_IN_SOURCE", "PARTIALLY_STATED_IN_SOURCE"}
        ):
            threat.validation_status = ValidationStatus.PARTIALLY_SUPPORTED
            threat.confidence_level = ConfidenceLevel.MEDIUM if is_official_domain else ConfidenceLevel.LOW
            flagged_unverified += 1
        else:
            threat.validation_status = ValidationStatus.UNSUPPORTED
            threat.confidence_level = ConfidenceLevel.LOW
            validation_errors += 1
            flagged_unverified += 1

        if (
                quote_recovered_from_faa_abstract or primary_title_recovered or quote_recovered_from_title or recovered_source_quote) and threat.validation_status == ValidationStatus.SUPPORTED:
            threat.validation_status = ValidationStatus.PARTIALLY_SUPPORTED
            threat.confidence_level = ConfidenceLevel.LOW
            audit_notes.append(
                "Recovered quotation establishes a source statement; further factual verification is required."
            )

        # Metadata-only news snippets cannot establish a fully sourced causal narrative.
        if matched_doc.get("source_id") == "SRC_004" and "[NEWSAPI_METADATA_ONLY:" in matched_text_str:
            if threat.validation_status == ValidationStatus.SUPPORTED:
                threat.validation_status = ValidationStatus.PARTIALLY_SUPPORTED
                flagged_unverified += 1
            threat.confidence_level = ConfidenceLevel.LOW
            audit_notes.append(
                "NEWSAPI_METADATA_ONLY: Full publisher article was unavailable; the summary cannot independently establish the claim."
            )

        if (matched_doc.get("evidence_authority") == "OFFICIAL_ISSUER_IR"
                and matched_doc.get("evidence_issuer_identity_verified") is not True):
            if threat.validation_status == ValidationStatus.SUPPORTED:
                threat.validation_status = ValidationStatus.PARTIALLY_SUPPORTED
            threat.confidence_level = ConfidenceLevel.LOW
            audit_notes.append("IR_ISSUER_IDENTITY_UNKNOWN: quoted page is verified, issuer attribution is not")

        if "SCHEMA_RECOVERY_MALFORMED_CONFIRMED_FACTS" in (threat.missing_data or ""):
            if threat.validation_status == ValidationStatus.SUPPORTED:
                flagged_unverified += 1
            if threat.validation_status in {ValidationStatus.SUPPORTED, ValidationStatus.PARTIALLY_SUPPORTED}:
                # Reject malformed factual claims as support for escalation.
                validation_errors += 1
                threat.validation_status = ValidationStatus.UNSUPPORTED
            threat.confidence_level = ConfidenceLevel.LOW
            threat.claim_support_status = "UNSUPPORTED"
            threat.causal_support_status = "UNSUPPORTED"
            audit_notes.append(
                "Analyst confirmed_facts contained malformed JSON; its factual assertions "
                "were discarded and cannot support escalation without fresh source verification"
            )

        future_event = bool(reference_date and _document_date(matched_doc, "event_date") != "DATE_UNKNOWN"
                            and _document_date(matched_doc, "event_date") > reference_date.isoformat())
        historical_availability_unknown = bool(reference_date and canonical_doc_date == "DATE_UNKNOWN")
        if (age is not None and age < 0) or future_event or historical_availability_unknown or invalid_reference_date:
            threat.validation_status = ValidationStatus.UNSUPPORTED
            threat.confidence_level = ConfidenceLevel.LOW
            threat.claim_support_status = "UNSUPPORTED"
            flagged_unverified += 1
            validation_errors += 1
            audit_notes.append("HISTORICAL_AS_OF_GUARD: source availability or actual event timing cannot be established at cutoff")

        if (threat.causal_support_status != "EVIDENCED_IN_VERIFIED_SOURCE"
                and CAUSAL_CLAIM_REGEX.search(f"{threat.confirmed_facts} {threat.threat_description}")):
            threat.confirmed_facts = (threat.fact_check_quote or "")[:600] if full_quote_verified else ""
            audit_notes.append("Unverified cause removed from confirmed facts; source wording retained only as a quotation")

        if is_unverified_signal(threat):
            if threat.confirmed_facts:
                audit_notes.append(
                    "LLM-proposed confirmed_facts were withheld because the claim did not pass Harness validation.")
            threat.confirmed_facts = ""
            threat.analytical_interpretation = (
                "The available evidence does not establish the event's asserted causes or consequences. "
                "Independent verification is required."
            )
            source_title = str(matched_doc.get("title") or threat.fact_check_quote or "Unknown claim").strip()
            threat.threat_description = (
                                            f"Unverified source claim ({matched_doc.get('doc_id', 'UNKNOWN')}): {source_title[:550]}. "
                                            "The reported event and its operational impacts have not been independently confirmed."
                                        )[:800]

        if threat.validation_status == ValidationStatus.PARTIALLY_SUPPORTED:
            if threat.claim_support_status != "STATED_IN_SOURCE" and full_quote_verified:
                threat.confirmed_facts = (
                    f"Source statement (event not fully verified): {threat.fact_check_quote or ''}"
                )[:600]
            source_title = str(matched_doc.get("title") or "").strip()
            if _is_snippet_only(matched_doc) and source_title:
                doc_id = matched_doc.get("doc_id", "UNKNOWN")
                threat.confirmed_facts = (
                    f"{doc_id}: A source headline was published (underlying claim not independently verified): {source_title}"
                )
                threat.threat_description = f"Preliminary source report ({doc_id}): {source_title}"[:800]
                threat.analytical_interpretation = (
                    "A headline or short excerpt alone cannot establish the alleged cause, financial impact, "
                    "or downstream operational consequences. Additional evidence is required."
                )
                audit_notes.append(
                    "Headline-only source: headline recorded, substantive claims and causal implications not independently verified"
                )

        if has_unknown_scm:
            flagged_unverified += 1
            threat.confidence_level = ConfidenceLevel.LOW
            audit_notes.append(
                f"Unclassified SCM entity in '{threat.company_affected}' set to Unknown (Verification Required)")

        threat.corroboration_summary = {
            "1. Technical Grounding": f"{threat.technical_grounding_status} (Full Quote & URL Match: {'YES' if full_quote_verified else 'NO'})",
            "2. Claim Support": threat.claim_support_status,
            "3. Causal Support": threat.causal_support_status,
            "4. Independent Verification": f"{threat.independent_verification_status} ({independent_source_count} non-syndicated source(s))",
            "5. Event Freshness": threat.event_freshness.value,
            "Program Relevance Scope": threat.program_relevance,
            "Source-Evidenced Program": threat.affected_program,
            "Hypothetical Shared Dependencies": ", ".join(
                threat.hypothetical_dependencies) if threat.hypothetical_dependencies else "None",
            "Event Epicenter": threat.geographic_epicenter,
            "Evidence Authority": str(
                matched_doc.get("evidence_authority")
                or ("FAA_FEDERAL_REGISTER" if faa_publication_verified
                    else f"{_claim_authority(matched_doc)}_OFFICIAL_SOURCE" if _claim_authority(matched_doc)
                    else "SEC_EDGAR" if is_exact_or_subdomain(domain, {"sec.gov"})
                    else "OEM_OFFICIAL_RELEASE" if (is_official_domain and str(matched_doc.get("origin_type") or "").startswith("PRIMARY"))
                    else "UNDETERMINED")
            ),
            "Claim Authority": str(
                matched_doc.get("claim_authority")
                or ("REGULATOR_OFFICIAL_PUBLICATION" if (faa_publication_verified or _claim_authority(matched_doc))
                    else "ISSUER_REPORTED" if (is_official_domain and str(matched_doc.get("origin_type") or "").startswith("PRIMARY"))
                    else "UNDETERMINED")
            ),
            "Regulatory Decision Verified": "YES" if (
                full_quote_verified and _claim_authority(matched_doc)
                and matched_doc.get("regulator_decision_verified") is True
            ) else "NO_OR_UNKNOWN",
            "KIT Fact Dimensions": ", ".join(f"{key}={value}" for key, value in fact_audit.items()),
            "publication_date": _document_date(matched_doc, "published_at"),
            "event_date": _document_date(matched_doc, "event_date"),
            "effective_date": _document_date(matched_doc, "effective_date"),
            "deadline": _document_date(
                {"deadline": matched_doc.get("deadline") or matched_doc.get("regulatory_compliance_deadline")},
                "deadline",
            ),
        }

        scm_label = getattr(threat.scm_tier, "value", str(threat.scm_tier))
        rationale = threat.score_rationale or ""
        claimed_tier = re.search(r"\bTier\s*[- ]?\s*([123])\b", rationale, flags=re.I)
        expected_tier = re.search(r"\bTier\s*[- ]?\s*([123])\b", scm_label, flags=re.I)

        if claimed_tier and (not expected_tier or claimed_tier.group(1) != expected_tier.group(1)):
            corrected_rationale = re.sub(r"[^.!?]*\bTier\s*[- ]?\s*[123]\b[^.!?]*[.!?]?", "", rationale,
                                         flags=re.I).strip()
            threat.score_rationale = (
                    corrected_rationale
                    or f"Potential severity: {threat.threat_score}/10. Supplier-tier contribution requires verification."
            )
            threat.corroboration_summary["SCM Scoring Consistency"] = (
                f"Conflicting supplier-tier assertion removed from score rationale. Validated classification: {scm_label}."
            )
            audit_notes.append(
                "Scoring rationale contained a supplier-tier assertion inconsistent with validated SCM classification.")

        risk_type_value = getattr(threat.risk_type, "value", str(threat.risk_type))
        if risk_type_value == "REGULATORY":
            regulatory_evidence = f"{matched_doc.get('title', '')} {threat.fact_check_quote or ''}"
            if stage_match := re.search(r"(?im)^Regulatory Stage:\s*(EFFECTIVE|FINAL_ISSUED|WITHDRAWN|PROPOSED|UNKNOWN)\s*$",
                                        matched_text_str):
                regulatory_stage = stage_match.group(1)
            elif re.search(r"\b(?:withdrawn|withdrawal of (?:an? )?nprm)\b", regulatory_evidence, re.I):
                regulatory_stage = "WITHDRAWN"
            elif re.search(r"\b(?:final rule|adopt(?:s|ed|ing) an? (?:new )?airworthiness directive)\b",
                           regulatory_evidence, re.I):
                regulatory_stage = "FINAL_ISSUED"
            elif re.search(r"\b(?:propos(?:e|es|ed|ing|al)|notice of proposed rulemaking|NPRM)\b", regulatory_evidence,
                           re.I):
                regulatory_stage = "PROPOSED"
            else:
                regulatory_stage = "UNKNOWN"

            if not _claim_authority(matched_doc) or not full_quote_verified:
                regulatory_stage = "UNKNOWN"
                audit_notes.append("REGULATORY_AUTHORITY_NOT_VERIFIED: issuer or media statements do not establish an agency decision")

            lifecycle_match = re.search(r"(?im)^Regulatory Lifecycle Check:\s*(VERIFIED|UNVERIFIED)\s*$",
                                        matched_text_str)
            if lifecycle_match and lifecycle_match.group(1) == "UNVERIFIED":
                audit_notes.append(
                    "FAA docket lifecycle search unavailable; latest regulatory status not independently checked.")

            if regulatory_stage in {"FINAL_ISSUED", "EFFECTIVE"}:
                if official := re.search(r"(?im)^Official Summary:\s*(.+)$", matched_text_str):
                    actual_summary = official.group(1).strip()[:350]
                    if re.search(r"\bpropos(?:e|es|ed|ing)\b", threat.threat_description or "", re.I):
                        threat.threat_description = actual_summary
                    if re.search(r"\bpropos(?:e|es|ed|ing)\b", threat.confirmed_facts or "", re.I):
                        threat.confirmed_facts = actual_summary

            # Review FAA docket and regulatory stage before treating a notice as an effective directive.
            if matched_doc.get("source_id") == "SRC_001":
                # A validated publication can establish its own dated fields even
                # when the search for subsequent docket changes was incomplete.
                docket_match = re.search(r"(?im)^FAA Docket:\s*(FAA-\d{4}-\d+)\s*$", matched_text_str)
                older_match = re.search(r"(?im)^Related earlier document:\s*(https://\S+)", matched_text_str)
                effective_match = re.search(r"(?im)^Effective Date:\s*(\d{4}-\d{2}-\d{2})\s*$", matched_text_str)
                effective_date = (_document_date({"value": effective_match.group(1)}, "value")
                                  if effective_match else "DATE_UNKNOWN")
                if effective_date == "DATE_UNKNOWN":
                    effective_date = ""
                metadata_effective = str(matched_doc.get("regulatory_effective_date") or "")[:10]
                if metadata_effective and effective_date and metadata_effective != effective_date:
                    effective_date = ""
                    audit_notes.append("FAA_EFFECTIVE_DATE_CONFLICT: official label and metadata disagree")
                reference = _reference_day(as_of_date) or datetime.now(timezone.utc).date()
                effective_reached = bool(effective_date and date.fromisoformat(effective_date) <= reference)

                if regulatory_stage == "EFFECTIVE" and not effective_date:
                    regulatory_stage = "FINAL_ISSUED"
                    audit_notes.append("EFFECTIVE_DATE_UNKNOWN: final issuance does not prove current legal effectiveness")
                if regulatory_stage == "EFFECTIVE" and effective_date and not effective_reached:
                    regulatory_stage = "FINAL_ISSUED"

                if faa_publication_verified and docket_match:
                    threat.corroboration_summary["FAA Publication Verified"] = "YES"
                    threat.corroboration_summary["FAA Document Number"] = faa_publication["document_number"]
                    threat.corroboration_summary["FAA Docket"] = docket_match.group(1).upper()
                    threat.corroboration_summary["FAA Publication Date"] = faa_publication["publication_date"]
                    threat.corroboration_summary["FAA Lifecycle Verified"] = (
                        "YES" if faa_lifecycle_verified else "NO"
                    )
                    threat.corroboration_summary["FAA Supersession Status"] = (
                        "CHECKED" if faa_lifecycle_verified else "UNKNOWN"
                    )
                    threat.corroboration_summary["FAA Effective Date Established"] = (
                        "YES" if effective_date else "NO"
                    )
                    if effective_date:
                        threat.corroboration_summary["effective_date"] = effective_date
                        threat.corroboration_summary["FAA Effective Date"] = effective_date
                    threat.corroboration_summary["FAA Effective As Of Date"] = (
                        "NO" if effective_date and not effective_reached else
                        "YES" if effective_reached and faa_lifecycle_verified
                                 and regulatory_stage == "EFFECTIVE" else "UNKNOWN"
                    )
                    if not faa_lifecycle_verified and threat.confidence_level == ConfidenceLevel.HIGH:
                        threat.confidence_level = ConfidenceLevel.MEDIUM

                if faa_publication_verified and faa_lifecycle_verified and docket_match:
                    threat.corroboration_summary["FAA Compliance Deadline"] = (
                        matched_doc.get("regulatory_compliance_deadline") or "NOT_ESTABLISHED"
                    )
                    if older_match:
                        threat.corroboration_summary["FAA Prior Document"] = older_match.group(1)
                    if regulatory_stage in {"FINAL_ISSUED", "EFFECTIVE"} and age is not None:
                        if 0 <= age <= 90:
                            threat.event_freshness = EventFreshness.NEW_DEVELOPMENT
                        elif age > 90:
                            threat.event_freshness = EventFreshness.HISTORICAL_CONTEXT
                        threat.corroboration_summary["5. Event Freshness"] = threat.event_freshness.value

            threat.corroboration_summary["Regulatory Stage"] = regulatory_stage

            if regulatory_stage == "WITHDRAWN":
                threat.analytical_interpretation = (
                    "The cited NPRM was withdrawn; this document does not establish an enforceable "
                    "new compliance obligation. " + (threat.analytical_interpretation or "")
                )
                audit_notes.append("Withdrawn NPRM; no new binding compliance requirement from this notice.")
            if regulatory_stage == "PROPOSED":
                threat.analytical_interpretation = (
                        "Regulatory proposal identified; legal effectiveness and implementation obligations are not established "
                        "by this evidence. " + (threat.analytical_interpretation or "")
                )
                if re.search(r"\b(?:mandat(?:e|es|ed|ory)|requires?|in force|effective)\b",
                             threat.score_rationale or "", flags=re.I):
                    threat.score_rationale = (
                        f"Potential severity: {threat.threat_score}/10. "
                        "The cited regulatory measure is a proposal. "
                        "Binding obligations and downstream operational impacts require additional evidence."
                    )
                audit_notes.append(
                    "Regulatory proposal detected; binding implementation requirements must not be assumed.")

        audit_suffix = f" [{' | '.join(audit_notes)}]" if audit_notes else ""
        is_fresh = threat.event_freshness in {EventFreshness.NEW_EVENT, EventFreshness.NEW_DEVELOPMENT}

        if is_sibling_watchlist:
            threat.event_status = EventStatus.RELATED_PROGRAM_WATCHLIST
            threat.verification_status = (
                f"RELATED PROGRAM WATCHLIST ({threat.affected_program}): "
                f"Awaiting proof of shared-supplier impact on {sorted(kit_target_variants)}{audit_suffix}"
            )
        elif threat.validation_status == ValidationStatus.SUPPORTED and threat.program_relevance != "DIRECT_KIT_MATCH":
            threat.event_status = EventStatus.UNDER_REVIEW
            threat.verification_status = f"SUPPORTED SOURCE; DIRECT KIT RELEVANCE UNVERIFIED ({threat.event_freshness.value}){audit_suffix}"
        elif threat.validation_status == ValidationStatus.SUPPORTED and not has_unknown_scm:
            src_label = (
                f"Verified Issuer Filing Statement ({threat.event_freshness.value})"
                if is_exact_or_subdomain(domain, {"sec.gov"})
                else f"Verified Primary Source ({threat.event_freshness.value} | 5-Step Grounding PASS)"
                if is_official_domain
                else f"Verified Secondary Source ({threat.event_freshness.value} | {independent_source_count} independent source(s))"
            )
            threat.verification_status = f"{src_label}{audit_suffix}"
            threat.event_status = (
                EventStatus.CRITICAL_RISK
                if (threat.threat_score >= 8 and threat.confidence_level == ConfidenceLevel.HIGH and is_fresh)
                else (EventStatus.ELEVATED_RISK if threat.threat_score >= 5 else EventStatus.CONFIRMED_EVENT)
            )
        elif threat.validation_status == ValidationStatus.SUPPORTED:
            threat.event_status = EventStatus.UNDER_REVIEW
            threat.verification_status = f"SUPPORTED CLAIM; SCM ROLE UNVERIFIED ({threat.event_freshness.value}){audit_suffix}"
        elif threat.validation_status == ValidationStatus.PARTIALLY_SUPPORTED:
            threat.event_status = EventStatus.UNDER_REVIEW
            threat.verification_status = f"PARTIALLY SUPPORTED ({threat.event_freshness.value} | Manual Review Required){audit_suffix}"
        else:
            threat.confidence_level = ConfidenceLevel.LOW
            threat.event_status = EventStatus.UNDER_REVIEW
            threat.verification_status = f"UNVERIFIED ({threat.event_freshness.value} | {threat.validation_status.value}){audit_suffix}"

        if threat.validation_status == ValidationStatus.PARTIALLY_SUPPORTED and threat.causal_support_status == "HYPOTHETICAL_ONLY":
            threat.threat_description = (
                f"Source excerpt: {(threat.fact_check_quote or '')[:220]}. "
                "Claimed operational impacts require verification."
            )

        if (
                threat.threat_score >= 8
                and threat.confidence_level == ConfidenceLevel.HIGH
                and threat.validation_status == ValidationStatus.SUPPORTED
                and threat.program_relevance == "DIRECT_KIT_MATCH"
                and is_fresh
                and not is_sibling_watchlist
        ):
            threat.escalation_level = EscalationStatus.CRITICAL_CONFIRMED_ALERT
            threat.urgency = UrgencyLevel.HIGH
        elif threat.program_relevance == "PROGRAM_UNVERIFIED":
            threat.escalation_level = EscalationStatus.PRIORITY_VERIFICATION_REQUIRED
            threat.urgency = UrgencyLevel.LOW
        elif is_sibling_watchlist or not is_fresh:
            threat.escalation_level = EscalationStatus.ROUTINE_MONITORING
            threat.urgency = UrgencyLevel.MEDIUM if threat.threat_score >= 6 else UrgencyLevel.LOW
        elif threat.threat_score >= 7 or threat.event_status == EventStatus.UNDER_REVIEW:
            threat.escalation_level = EscalationStatus.PRIORITY_VERIFICATION_REQUIRED
            threat.urgency = UrgencyLevel.HIGH if threat.threat_score >= 7 else UrgencyLevel.MEDIUM
        elif threat.threat_score >= 4:
            threat.escalation_level = EscalationStatus.ROUTINE_MONITORING
            threat.urgency = UrgencyLevel.MEDIUM
        else:
            threat.escalation_level = EscalationStatus.ARCHIVED_LOW_RELEVANCE
            threat.urgency = UrgencyLevel.LOW

        if (
                risk_type_value == "REGULATORY"
                and matched_doc.get("source_id") == "SRC_001"
                and threat.corroboration_summary.get("FAA Lifecycle Verified") == "YES"
        ):
            # Apply source-specific legal and operational caveats to final risk classification.
            stage = threat.corroboration_summary.get("Regulatory Stage", "UNKNOWN")
            quote_str = threat.fact_check_quote or ""

            impact_in_quote = bool(
                re.search(
                    r"\b(?:production (?:halt|stoppage)|deliver(?:y|ies) delays?|ground(?:ing|ed) of aircraft)\b",
                    quote_str, flags=re.I,
                )
            )
            threat.score_rationale = (
                    f"Official FAA action ({stage}) is evidenced by the cited document. "
                    f"Potential severity: {threat.threat_score}/10; "
                    f"deterministic urgency: {threat.urgency.value}; "
                    f"escalation: {threat.escalation_level.value}. "
                    + (
                        "Any additional downstream impacts require separate evidence."
                        if impact_in_quote
                        else "The cited quotation does not establish grounding, production stoppage, delivery delays, or an immediate compliance deadline."
                    )
            )

            cited_impact = bool(
                re.search(
                    r"\b(?:production (?:halt|stoppage)|delivery delays?|grounded aircraft|aircraft grounding)\b",
                    quote_str, re.I,
                )
            )
            if not cited_impact:
                threat.adversarial_scenario = (
                    "HYPOTHETICAL SCENARIO — NOT EVIDENCED: "
                    "Applicable FAA inspection requirements could increase maintenance workload if capacity "
                    "constraints arise. Actual grounding, production stoppage and delivery disruption are not "
                    "established by the cited evidence."
                )
                if stage in {"EFFECTIVE", "FINAL_ISSUED"}:
                    threat.analytical_interpretation = (
                        "The FAA airworthiness directive establishes regulatory inspection requirements. "
                        "Potential effects on maintenance capacity, aircraft availability, production or deliveries "
                        "remain hypothetical until supported by additional operational evidence."
                    )

        if (
                matched_doc.get("origin_type") == "PRIMARY_OFFICIAL_INDEX_METADATA"
                and threat.validation_status in {ValidationStatus.SUPPORTED, ValidationStatus.PARTIALLY_SUPPORTED}
        ):
            threat.validation_status = ValidationStatus.PARTIALLY_SUPPORTED
            threat.confidence_level = ConfidenceLevel.LOW
            threat.event_status = EventStatus.UNDER_REVIEW
            easa_title = str(matched_doc.get("title") or "EASA directive").strip()
            threat.threat_description = (
                                            f"Official EASA index records: {easa_title}. The complete directive text was not analyzed."
                                        )[:800]
            threat.confirmed_facts = (
                f"Official EASA index entry: {easa_title}. Publication date: {canonical_doc_date}."
            )
            threat.analytical_interpretation = (
                "Official metadata confirm the publication and its stated subject. "
                "Exact inspection intervals, compliance duties and operational effects require verification "
                "against the full directive."
            )
            threat.corroboration_summary["Evidence Scope"] = (
                "PUBLICATION_VERIFIED; TECHNICAL_CONTENT_NOT_READ; OPERATIONAL_IMPACT_NOT_VERIFIED"
            )
            threat.score_rationale = (
                f"Potential severity: {threat.threat_score}/10. "
                "Official index metadata verify the publication but do not independently establish additional "
                "maintenance workload, aircraft grounding, delivery delays or immediate compliance duties."
            )
            # Enforce deterministic restrictions on unsupported critical alerts and watchlist events.
            threat.escalation_level = EscalationStatus.PRIORITY_VERIFICATION_REQUIRED

        threat.kiq_ids = match_kiqs_for_threat(threat, catalog)

        allowed_kiq_ids = {item["kiq_id"] for item in catalog}
        if threat.intelligence_gap:
            current_gap_kiq = str(threat.intelligence_gap.affected_kiq_id or "").strip()
            if current_gap_kiq not in allowed_kiq_ids or (
                    threat.kiq_ids and current_gap_kiq not in threat.kiq_ids
            ):
                threat.intelligence_gap.affected_kiq_id = threat.kiq_ids[0] if threat.kiq_ids else ""

        if threat.missing_data and threat.missing_data.strip().lower() in {"none", "null", "n/a", "not available",
                                                                           "unspecified", ""}:
            threat.missing_data = None

        if is_sibling_watchlist:
            threat.missing_data = (
                f"Prove concrete shared-supplier or shared-component impact mechanism from {threat.affected_program} onto {sorted(kit_target_variants)}."
            )
        elif audit_notes and not threat.missing_data:
            threat.missing_data = f"Verification required: {'; '.join(audit_notes[:2])}."
        elif not threat.missing_data:
            if threat.publication_time == "DATE_UNKNOWN":
                threat.missing_data = "Exact publication or incident date is missing from source metadata."
            elif threat.confidence_level == ConfidenceLevel.LOW:
                threat.missing_data = f"Independent primary corroboration required for {threat.company_affected} ({threat.affected_program})."
            elif independent_source_count == 1 and threat.threat_score >= 7 and not is_official_domain:
                threat.missing_data = f"Single secondary source for {threat.company_affected} ({threat.affected_program}); independent confirmation needed."

        if threat.missing_data and not threat.intelligence_gap:
            threat.intelligence_gap = IntelligenceGap(
                what_is_missing=threat.missing_data,
                why_important=f"Needed to confirm {threat.propagation_effect.value} impact on {threat.company_affected} ({threat.affected_program}).",
                affected_kiq_id=threat.kiq_ids[0] if threat.kiq_ids else "",
                recommended_source="FAA / EASA / Official OEM Pressroom",
                can_auto_scan=True,
                status="OPEN",
            )

        threat.corroboration_summary.update({
            "Severity": f"{threat.threat_score}/10 (potential impact, not verification)",
            "Confidence": threat.confidence_level.value,
            "Verification": threat.validation_status.value,
            "Current Status": threat.event_status.value,
        })
        threat.is_critical = is_confirmed_critical(threat)
        (watchlist_threats if is_sibling_watchlist else validated_threats).append(threat)

    report.threats = validated_threats
    report.related_program_watchlist = watchlist_threats

    if not report.kiq_answers:
        generated_answers: List[KIQAnswer] = []
        for item in catalog:
            kid = item["kiq_id"]
            rel_threats = [t for t in validated_threats if kid in t.kiq_ids]
            if not rel_threats:
                continue
            ev_ids = list(dict.fromkeys(eid for t in rel_threats for eid in t.evidence_ids))
            high_conf = any(
                t.confidence_level == ConfidenceLevel.HIGH and t.validation_status == ValidationStatus.SUPPORTED
                for t in rel_threats
            )
            ans_parts = []
            for t in rel_threats[:2]:
                prog = f" ({t.affected_program})" if t.affected_program and not t.affected_program.lower().startswith(
                    "unknown") else ""
                body = (t.confirmed_facts or t.fact_check_quote or t.threat_description or "").strip().rstrip(".")
                did = f" [{t.evidence_ids[0]}]" if t.evidence_ids else ""
                ans_parts.append(f"For {t.company_affected}{prog}, available evidence notes: {body}{did}.")
            ans_text = " ".join(ans_parts)
            missing_list = [t.missing_data for t in rel_threats if t.missing_data]
            generated_answers.append(
                KIQAnswer(
                    kiq_id=kid,
                    question=item["question"],
                    answer_status="PARTIALLY_ANSWERED",
                    answer=ans_text[:450],
                    related_event_ids=[t.event_id for t in rel_threats],
                    evidence_ids=ev_ids,
                    verification_status="Event evidence evaluated; complete KIQ coverage not established",
                    uncertainty_level=ConfidenceLevel.MEDIUM if high_conf else ConfidenceLevel.LOW,
                    recommended_next_step="Verify remaining KIQ facets before marking fully answered.",
                    missing_information=missing_list[0] if missing_list else "Completeness of required KIQ facets not verified.",
                )
            )
        report.kiq_answers = generated_answers

    for answer in report.kiq_answers:
        if str(getattr(answer.answer_status, "value", answer.answer_status)).upper() == "ANSWERED" and not any(
            answer.kiq_id in threat.kiq_ids
            and threat.program_relevance == "DIRECT_KIT_MATCH"
            and threat.validation_status == ValidationStatus.SUPPORTED
            for threat in validated_threats
        ):
            answer.answer_status = "PARTIALLY_ANSWERED"
            answer.missing_information = (answer.missing_information
                                          or "No fully supported direct evidence for this KIQ.")

    direct_validated = [t for t in validated_threats if t.program_relevance == "DIRECT_KIT_MATCH"]
    fully_supported_count = sum(t.validation_status == ValidationStatus.SUPPORTED for t in direct_validated)
    partial_count = sum(t.validation_status == ValidationStatus.PARTIALLY_SUPPORTED for t in direct_validated)
    ongoing_count = sum(t.event_freshness == EventFreshness.ONGOING_ISSUE for t in direct_validated)

    previous_qa = str(report.qa_audit_summary or "").strip()
    event_doc_ids = {eid for t in validated_threats + watchlist_threats for eid in (t.evidence_ids or [])}
    kiq_doc_ids = {eid for answer in report.kiq_answers for eid in (answer.evidence_ids or [])}
    disposition = {
        d["doc_id"]: (
            "USED_IN_KIQ_ANSWER" if d["doc_id"] in kiq_doc_ids
            else "REFERENCED_BY_EVENT_NOT_KIQ" if d["doc_id"] in event_doc_ids
            else "NOT_REFERENCED_BY_ANALYST_RELEVANCE_UNDETERMINED"
        ) for d in docs if isinstance(d, dict) and d.get("doc_id")
    }
    grounding_summary = (
        f"Five-Dimensional Grounding (Technical, Claim, Causal, Independent Verification, Freshness) completed. | "
        f"[Harness Guard]: {fully_supported_count}/{len(direct_validated)} direct signals SUPPORTED, "
        f"{partial_count} PARTIALLY_SUPPORTED, {ongoing_count} classified as ONGOING_ISSUE, "
        f"{len(watchlist_threats)} moved to RELATED_PROGRAM_WATCHLIST, "
        f"{flagged_unverified} flagged for manual HITL verification."
    )
    provenance_summary = " | Evidence disposition (not a filtering verdict): " + "; ".join(
        f"{doc_id}={reason}" for doc_id, reason in disposition.items()
    ) if disposition else ""
    report.qa_audit_summary = " | ".join(filter(None, (previous_qa, grounding_summary))) + provenance_summary
    return report, validation_errors