# =============================================================================
# aviation_ci_app | Deterministic evidence, technical-identity, and alert validation
#
# Responsibility: Verify source provenance, quotation alignment, aircraft/engine identity,
#   event freshness, corroboration, and impact assertions.
# Design boundary: Confirmed critical escalation requires source-supported findings,
#   direct KIT relevance, and adequate confidence.
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
    _detect_engine_models, _engine_models_match, _detect_specific_variants,
    _detect_exact_variants, _detect_aircraft_families,
)
from aero_ews.domain.identity_patterns import (
    ENGINE_MODEL_PATTERNS, SPECIFIC_AIRCRAFT_VARIANT_PATTERNS, AIRCRAFT_FAMILY_PATTERNS,
    COMPONENT_KEYWORDS_MAP, HYPOTHETICAL_IN_FACTS_REGEX, CAUSAL_CLAIM_REGEX,
    EVENT_LOCATION_EVIDENCE_MAP, _EVENT_LOCATION_PATTERN, _LOCATION_TO_REGION,
    _WIRE_PATTERNS, _PRIOR_PERIOD_CAUSE_RE, _CURRENT_PERIOD_RE, _CLAIM_CAUSE_RE,
    _EXACT_VARIANT_RE, AIRLINE_AND_REGULATOR_PATTERN, REGISTRY_TIER_MAP,
    ONGOING_OR_RECONFIRMED_PATTERNS, HISTORICAL_RECAP_PATTERNS,
    _GTF_SPECIFIC_MODELS, _LEAP_SPECIFIC_MODELS,
)

# Trusted official domain sets (preserved verbatim).
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

_CAUSAL_CONNECTOR = re.compile(
    r"\b(?:due\s+to|because\s+of|because|caused\s+by|prompted\s+by|caus(?:ed|ing|es)|"
    r"(?:led|leading)\s+to|result(?:ed|ing)\s+in|contribut(?:ed|ing)\s+to|"
    r"triggered|forced|stemming\s+from|attributable\s+to|as\s+a\s+result\s+of)\b", re.I,
)
_REVERSE_CAUSAL_CONNECTORS = {
    "due to", "because of", "because", "caused by",
    "prompted by", "stemming from", "attributable to", "as a result of",
}

# Shared internal patterns (Czech exclusion terms "kromě"/"vyjma" retained for bilingual parity).
_EXCLUSION_RE = re.compile(r"\b(?:exclude|excluding|except(?:\s+for)?|without|not\s+including|kromě|vyjma)\b", re.I)
_LEGAL_SUFFIX_RE = re.compile(r"\s+(?:S\.?\s*A\.?|Inc\.?|Ltd\.?|LLC|GmbH|Corp\.?|PLC)$", re.I)
_REGISTRY_CLEAN_RE = re.compile(
    r"^The\s+|\s*\([^)]*\)|\s+(?:Company|S\.?p\.?A\.?|S\.?A\.?|SE|Inc\.?|Ltd\.?|LLC|Corp\.?|Holdings|Corporation)$", re.I,
)
_AUTHORITY_DOMAINS = {
    "FAA": {"faa.gov", "federalregister.gov"}, "EASA": {"easa.europa.eu"}, "NTSB": {"ntsb.gov"},
    "CAA": {"caa.co.uk"}, "TCCA": {"tc.canada.ca"}, "TSB": {"tsb.gc.ca"},
    "CAAC": {"caac.gov.cn"}, "ANAC": {"anac.gov.br"}, "CASA": {"casa.gov.au"}, "BEA": {"bea.aero"},
}
_NON_SUBSTANTIVE_STATUSES = {"METADATA_ONLY", "UNAVAILABLE", "STRUCTURED_DATA"}
_MATERIAL_GROUPS = (
    (r"\b(?:carbon[ -]?fib(?:er|re)|carbon[ -]?composites?)\b", r"\b(?:carbon[ -]?fib(?:er|re)|carbon[ -]?composites?)\b"),
    (r"\bcomposites?\b", r"\bcomposites?\b"),
    (r"\btitanium\b", r"\btitanium\b"),
    (r"\bforgings?\b", r"\bforg(?:e|ed|es|ing|ings)\b"),
    (r"\balumini?um\b", r"\balumini?um\b"),
    (r"\b(?:superalloys?|nickel(?:\s+alloys?)?)\b", r"\b(?:superalloys?|nickel(?:\s+alloys?)?)\b"),
    (r"\bcastings?\b", r"\bcast(?:ing|ings|ed)?\b"),
    (r"\bfasteners?\b", r"\bfasteners?\b"),
    (r"\b(?:semiconductors?|avionics)\b", r"\b(?:semiconductors?|avionics)\b"),
)
_FACT_STOPWORDS = {
    "source", "states", "confirmed", "reports", "aircraft", "airline", "company",
    "january", "february", "march", "april", "june", "july", "august",
    "september", "october", "november", "december",
    "that", "this", "with", "from", "which", "were", "have", "been", "under",
    "also", "into", "their", "these", "those", "such", "when", "where",
    "between", "within", "about", "after", "before", "during", "through",
    "including", "regarding", "following", "according", "based", "certain",
    "specific", "other", "more", "than", "some", "will", "would",
}
_KIT_SKIP_WORDS = {
    "airbus", "boeing", "embraer", "comac", "aerospace", "aircraft", "engine", "engines",
    "supply", "chain", "shortage", "supplier", "suppliers", "carbon", "fiber", "fibre",
    "composite", "composites", "material", "materials", "production", "technical", "problems",
    "issues", "monitor", "review", "compare", "competitive", "intelligence", "risk", "risks",
    "fleet", "capacity", "constraints", "aviation", "impact", "delivery", "the", "and", "for", "from", "with",
}
_MONTH_NAMES = "january february march april may june july august september october november december".split()


def _strip_exclusions(query: str) -> str:
    """Return the positive KIT text preceding any exclusion clause."""
    return _EXCLUSION_RE.split(str(query or ""), maxsplit=1)[0].strip()


def _norm_model_hyphens(text: str) -> str:
    """Normalize hyphenated letter-digit model codes (e.g. C-919 -> C919) without altering dates or dockets."""
    return re.sub(r"\b([A-Za-z]{1,3})-(?!19\d{2}\b|20\d{2}\b)(\d{3,4}[A-Za-z0-9]*)\b", r"\1\2", str(text or ""))


def _is_short_snippet(doc: Dict[str, Any]) -> bool:
    """Treat a record as headline/snippet-only only when substantive text is genuinely short or metadata-only."""
    text = str(doc.get("text") or "").strip()
    status = str(doc.get("content_status") or "").upper()
    if status in {"METADATA_ONLY", "SOURCE_METADATA_ONLY", "SUMMARY_ONLY", "UNAVAILABLE"}:
        return True
    if "[NEWSAPI_METADATA_ONLY:" in text or "[EXA_METADATA_ONLY]" in text:
        return True
    if len(text) >= 320 and len(re.findall(r"\b\w+\b", text)) >= 45:
        return False
    return _is_snippet_only(doc)


def _doc_full_text(doc: Dict[str, Any]) -> str:
    """Combine document title and body text for grounding checks."""
    return f"{doc.get('title', '')} {doc.get('text', '')}"


def _segments_in_corpus(quote_text: str, corpus_norm: str) -> bool:
    """Verify every non-ellipsis segment (>=6 normalized chars) appears in the source corpus."""
    segs = [n for seg in re.split(r"\.{3,}|…", quote_text or "") if len(n := _normalize_for_quote_match(seg)) >= 6]
    return bool(segs) and all(seg in corpus_norm for seg in segs)


def _faa_docket_from_text(text: str) -> str:
    """Extract the labeled FAA docket identifier from a Federal Register record body."""
    m = re.search(r"(?im)^FAA Docket:\s*(FAA-\d{4}-\d+)\s*$", text or "")
    return m.group(1) if m else ""


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


def is_unverified_signal(threat: ThreatAssessment) -> bool:
    """Return True when the validation status does not establish a verified event."""
    return threat.validation_status in {
        ValidationStatus.UNSUPPORTED, ValidationStatus.CONTRADICTED, ValidationStatus.UNVERIFIED_COMMUNITY,
    }


def kit_direct_relevance_gap(kit_query: str, source_text: str) -> str:
    """Return a conservative reason when a source lacks a requested shortage facet."""
    kit, source = str(kit_query or ""), str(source_text or "")
    if not re.search(r"\b(?:shortag\w*|scarcity|supply\s+(?:constraints?|shortfalls?)|material\s+shortfalls?)\b", kit, re.I):
        return ""
    if not re.search(
        r"\b(?:shortag\w*|scarcity|scarce|bottleneck\w*|supply\s+(?:constraints?|shortfalls?|disruptions?)|"
        r"material\s+(?:shortfalls?|constraints?)|unable\s+to\s+meet\s+demand|allocation\s+restrictions?)\b",
        source, re.I,
    ):
        return "RELATED_CONTEXT: the source does not establish the shortage or supply constraint specified in the KIT."
    req_materials = [ev for req, ev in _MATERIAL_GROUPS if re.search(req, kit, re.I)]
    if req_materials and not any(re.search(ev, source, re.I) for ev in req_materials):
        return "RELATED_CONTEXT: the source does not identify the material specified in the KIT."

    # Match non-OEM suppliers named in the registry; ignore numeric model aliases.
    matched = [
        (entry.get("official_name", ""), names)
        for entry in AEROSPACE_SUPPLIER_REGISTRY if entry.get("default_tier") != "OEM (Final Assembler)"
        for names in [[n for n in (entry.get("official_name", ""), *entry.get("aliases", [])) if len(n) >= 4 and not re.search(r"\d", n)]]
        if any(re.search(rf"(?<!\w){re.escape(n)}(?!\w)", kit, re.I) for n in names)
    ]
    if len(matched) == 1:
        supplier, names = matched[0]
        if not any(re.search(rf"(?<!\w){re.escape(n)}(?!\w)", source, re.I) for n in names):
            return f"RELATED_CONTEXT: the cited source does not identify the KIT-specific supplier {supplier}."
    elif not matched:
        oem_tokens = {
            tok.lower() for entry in AEROSPACE_SUPPLIER_REGISTRY if entry.get("default_tier") == "OEM (Final Assembler)"
            for name in (entry.get("official_name", ""), *(entry.get("aliases") or []))
            for tok in re.findall(r"\b[a-z]{3,}\b", name.lower())
        }
        unknown = {name for name in re.findall(r"\b[A-Z][a-z]{3,}\b", kit) if name.lower() not in (oem_tokens | _KIT_SKIP_WORDS)}
        if len(unknown) == 1 and not re.search(rf"(?<!\w){re.escape(supplier := next(iter(unknown)))}(?!\w)", source, re.I):
            return f"RELATED_CONTEXT: the source does not identify named KIT entity {supplier}."
    return ""


def extract_effective_publisher_domain(url: str) -> str:
    """Extract the normalized publisher hostname without leading 'www.'."""
    netloc = urlparse(url).netloc.lower() if url else ""
    return netloc[4:] if netloc.startswith("www.") else netloc


def is_exact_or_subdomain(domain: str, trusted_set: set[str]) -> bool:
    """Require an exact trusted domain or a genuine subdomain boundary."""
    return bool(domain) and any(domain == td or domain.endswith("." + td) for td in trusted_set)


def _source_mentions(value: str, text: str) -> bool:
    """Check whether a non-placeholder value appears in text across punctuation boundaries."""
    val = str(value or "").strip()
    if not val or val.lower().startswith(("unknown", "not specified")):
        return False
    terms = re.findall(r"[a-z0-9]+", val.lower())
    return bool(terms and re.search(r"(?<!\w)" + r"[\W_]*".join(map(re.escape, terms)) + r"(?!\w)", (text or "").lower()))


def _extract_component_and_program(
    doc_raw_full: str, quote_text: str = "", proposed_component: str = "", proposed_program: str = "",
) -> Tuple[str, str]:
    """Resolve the component and aircraft program directly supported by the cited quotation."""
    unknown, quote = "Unknown / Not specified in source", (quote_text or "").strip()
    quoted = _detect_specific_variants(quote)
    return (
        proposed_component if _source_mentions(proposed_component, quote) else unknown,
        ", ".join(sorted(quoted)) if quoted else (proposed_program if _source_mentions(proposed_program, quote) else unknown),
    )


def _resolve_geography_dimensions(threat: ThreatAssessment, doc_raw_full: str) -> Tuple[str, str]:
    """Separate the incident epicenter from fleet-wide geographic impact."""
    regions = {_LOCATION_TO_REGION[loc.lower()] for loc in _EVENT_LOCATION_PATTERN.findall(doc_raw_full or "") if loc.lower() in _LOCATION_TO_REGION}
    return (next(iter(regions)) if len(regions) == 1 else "Unknown"), "Unknown (Requires Operator/Fleet Mapping)"


def _split_affected_entities(company_affected: str) -> List[str]:
    """Split compound organization names while keeping 'Pratt & Whitney' and legal suffixes intact."""
    if not company_affected:
        return []
    protected = re.sub(r"pratt\s*&\s*whitney", "Pratt_And_Whitney", company_affected, flags=re.I)
    protected = re.sub(r",(?=\s*(?:S\.?\s*A\.?|Inc\.?|Ltd\.?|LLC|GmbH|Corp\.?|PLC)\s*(?:$|[,;/|]))", "", protected, flags=re.I)
    entities = [p.replace("Pratt_And_Whitney", "Pratt & Whitney").strip() for p in re.split(r"[,;/|]+|\band\b", protected, flags=re.I)]
    return [e for e in entities if len(e) >= 2 and not re.fullmatch(r"(?:S\.?\s*A\.?|Inc\.?|Ltd\.?|LLC|GmbH|Corp\.?|PLC)", e, re.I)] or ["Unknown"]


def _sanitize_conflicting_scm_text(text: str, entity_roles: List[Tuple[str, SCMTier, Optional[Dict[str, Any]]]]) -> str:
    """Correct contradictory tier labels in prose to match validated registry roles."""
    cleaned = text or ""
    for ent_name, ent_tier, _ in entity_roles:
        if ent_tier == SCMTier.OEM:
            cleaned = re.sub(r"\b(?:tier[- ]?[123]\s+(?:supplier|manufacturer)s?\s+)?" + re.escape(ent_name) + r"\s*\(\s*tier[- ]?[123][^)]*\)", f"{ent_name} ({SCMTier.OEM.value})", cleaned, flags=re.I)
        elif ent_tier == SCMTier.REGULATOR_AIRLINE:
            cleaned = re.sub(r"\(\s*Tier\s*[123][^)]*\)", f"({SCMTier.REGULATOR_AIRLINE.value})", cleaned, flags=re.I)
    return cleaned


def _resolve_scm_roles_and_impact_path(
    threat: ThreatAssessment, doc_raw_full: str,
) -> Tuple[SCMTier, str, List[str], bool]:
    """Derive SCM tier, registry basis, and structured impact path from evidenced entities."""
    doc_low = (doc_raw_full or "").lower()
    entity_roles: List[Tuple[str, SCMTier, Optional[Dict[str, Any]]]] = []
    role_descs: List[str] = []
    has_unknown = False

    for ent in _split_affected_entities(threat.company_affected):
        reg = lookup_supplier_in_registry(_LEGAL_SUFFIX_RE.sub("", ent), exact=True)
        if not reg and "(" in ent and ")" in ent:
            outer = re.sub(r"\s*\([^)]*\)", "", ent).strip()
            for cand in (outer, _LEGAL_SUFFIX_RE.sub("", outer).strip(), *re.findall(r"\(([^)]+)\)", ent)):
                if cand and (reg := lookup_supplier_in_registry(cand.strip(), exact=True)):
                    break
        is_airline_reg = bool(AIRLINE_AND_REGULATOR_PATTERN.search(ent.lower()))
        if reg and not is_airline_reg:
            tier = REGISTRY_TIER_MAP.get(reg["default_tier"], SCMTier.UNKNOWN)
            entity_roles.append((reg["official_name"], tier, reg))
            role_descs.append(f"Company: {reg['official_name']} -> Role: {tier.value} (Registry Source: {reg['source_ref']})")
        elif is_airline_reg:
            entity_roles.append((ent, SCMTier.REGULATOR_AIRLINE, None))
            role_descs.append(f"Company/Authority: {ent} -> Role: {SCMTier.REGULATOR_AIRLINE.value}")
        else:
            has_unknown = True
            entity_roles.append((ent, SCMTier.UNKNOWN, None))
            role_descs.append(f"Company: {ent} -> Role: {SCMTier.UNKNOWN.value}")

    known_tiers = [r[1] for r in entity_roles if r[1] != SCMTier.UNKNOWN]
    primary_tier = entity_roles[0][1] if (len(entity_roles) == 1 or entity_roles[0][1] != SCMTier.UNKNOWN) else (known_tiers[0] if known_tiers else SCMTier.UNKNOWN)
    comp, prog = _extract_component_and_program(doc_raw_full, threat.fact_check_quote or "", threat.affected_component or "", threat.affected_program or "")
    threat.affected_component, threat.affected_program = comp, prog
    hyp_deps = list(dict.fromkeys(p for _, _, info in entity_roles if info for p in info.get("programs", []) if p.lower() not in prog.lower()))
    threat.hypothetical_dependencies = hyp_deps

    for field in ("threat_description", "confirmed_facts", "analytical_interpretation"):
        setattr(threat, field, _sanitize_conflicting_scm_text(getattr(threat, field), entity_roles))
    dep_note = f" (Hypothetical shared-OEM/supplier dependencies not evidenced in source: {', '.join(hyp_deps[:3])})" if hyp_deps else ""
    threat.hypothetical_scenario = f"Hypothetical {threat.propagation_effect.value} scenario affecting {', '.join(f'{n} ({t.value})' for n, t, _ in entity_roles)} on source-evidenced program {prog}.{dep_note}"

    path = []
    for n, t, _ in entity_roles:
        ev_tag = "[Evidenced Entity]" if any(tok in doc_low for tok in re.findall(r"\b[a-z0-9]{3,}\b", n.lower())) else "[Unconfirmed Entity]"
        path.append(f"{ev_tag} {n} -> Role: {t.value}")
    path.extend([f"[Source-Evidenced Component] {comp}", f"[Source-Evidenced Program] {prog}"])
    if hyp_deps:
        path.append(f"[Hypothetical Shared-Supplier Dependencies - NOT Evidenced in Source] {', '.join(hyp_deps[:3])}")
    path.append(f"[Hypothetical Propagation Mechanism] {threat.propagation_effect.value}")
    return primary_tier, f"{' | '.join(role_descs)} || Source-Evidenced Component: {comp} || Source-Evidenced Program: {prog}", path, has_unknown


def _count_independent_confirmations(corroborating_docs: List[Dict[str, Any]]) -> Tuple[int, bool, bool]:
    """Count distinct publishing origins after syndication and wire-service deduplication."""
    clusters: List[Tuple[str, str, Optional[str]]] = []
    has_reg = has_oem = False
    for doc in corroborating_docs:
        fp, title_norm = doc.get("syndication_fingerprint") or "", _normalize_for_quote_match(doc.get("title", ""))
        wire = next((w for w, pat in _WIRE_PATTERNS.items() if pat.search(_doc_full_text(doc))), None)
        if not any((fp and fp == ef) or (wire and ew and wire == ew) or (title_norm and et and SequenceMatcher(None, title_norm, et).ratio() >= 0.65) for ef, et, ew in clusters):
            clusters.append((fp, title_norm, wire))
        domain = extract_effective_publisher_domain(doc.get("url", ""))
        if domain and "news.google.com" not in domain:
            is_reg = is_exact_or_subdomain(domain, _PRIMARY_REGULATOR_DOMAINS)
            has_reg |= is_reg
            has_oem |= (not is_reg) and is_exact_or_subdomain(domain, _PRIMARY_OEM_AND_TIER1_DOMAINS)
    return len(clusters), has_reg, has_oem


def _certification_model_ids(text: str) -> set[str]:
    """Normalize exact technical models, including 737-10 / 737 MAX 10 aliases."""
    from aero_ews.collection.queries import _model_tokens

    codes = {
        f"737max{m.group(1)}" if (m := re.fullmatch(r"737(?:max)?(\d{1,2})", c)) else c
        for tok in _model_tokens(text or "") if (c := re.sub(r"[^a-z0-9]", "", tok.lower()))
    }
    return {c for c in codes if not re.fullmatch(r"\d{3}", c)}

def _claim_instant(claim: Dict[str, Any]) -> Optional[datetime]:
    """Extract an exact UTC timestamp when two states occurred on the same calendar day."""
    for field in ("state_as_of", "event_date", "regulatory_decision_date"):
        raw = str(claim.get(field) or "")
        if "T" in raw or " " in raw:
            try:
                ts = datetime.fromisoformat(raw.replace("Z", "+00:00"))
                return ts.replace(tzinfo=timezone.utc) if ts.tzinfo is None else ts.astimezone(timezone.utc)
            except ValueError:
                continue
    return None


def _verified_faa_publication(claim: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Verify a Federal Register publication independently of docket lifecycle checks."""
    if claim.get("source_id") != "SRC_001":
        return None
    url, src_url = str(claim.get("url") or "").strip(), str(claim.get("source_url") or "").strip()
    if url and src_url:
        try:
            o, r = urlparse(url), urlparse(src_url)
            if (o.scheme, o.hostname, o.path.rstrip("/")) != (r.scheme, r.hostname, r.path.rstrip("/")):
                return None
        except ValueError:
            return None
    return inspect_official_faa_publication({**claim, "url": url or src_url})


def _claim_authority(claim: Dict[str, Any]) -> str:
    """Identify official regulatory authorship from HTTPS domain and metadata."""
    parsed = urlparse(str(claim.get("source_url") or claim.get("url") or ""))
    if parsed.scheme != "https" or str(claim.get("evidence_authority") or "").upper() in {"SEC_EDGAR", "OFFICIAL_ISSUER_IR", "SECONDARY_MEDIA", "FILING_INDEX_METADATA"}:
        return ""
    host = (parsed.hostname or "").lower()
    explicit = str(claim.get("regulatory_authority") or claim.get("authority") or "").upper()
    if is_exact_or_subdomain(host, {"federalregister.gov"}):
        return "" if explicit in (set(_AUTHORITY_DOMAINS) - {"FAA"}) else ("FAA" if _verified_faa_publication(claim) else "")
    explicit = explicit if explicit in _AUTHORITY_DOMAINS else ""
    return next((auth for auth, doms in _AUTHORITY_DOMAINS.items() if explicit in {"", auth} and is_exact_or_subdomain(host, doms)), "")


def _reference_day(as_of_date: str, query: str = "") -> Optional[date]:
    """Parse an explicit historical cutoff; month-only resolves to its last calendar day."""
    month_end = lambda y, m: date(y, m, calendar.monthrange(y, m)[1])
    if as_of_date:
        try:
            raw = str(as_of_date).strip()
            return month_end(*map(int, raw.split("-"))) if re.fullmatch(r"20\d{2}-\d{2}", raw) else date.fromisoformat(raw[:10])
        except ValueError:
            return None
    q = query or ""
    if m := re.search(r"\bas\s+of\s+(20\d{2}-\d{2}-\d{2})\b", q, re.I):
        try:
            return date.fromisoformat(m.group(1))
        except ValueError:
            return None
    if m := re.search(r"\bas\s+of\s+(" + "|".join(_MONTH_NAMES) + r")\s+(20\d{2})\b", q, re.I):
        return month_end(int(m.group(2)), _MONTH_NAMES.index(m.group(1).lower()) + 1)
    if (m := re.search(r"\bas\s+of\s+(20\d{2})-(\d{2})(?!-\d)", q, re.I)) and 1 <= int(m.group(2)) <= 12:
        return month_end(int(m.group(1)), int(m.group(2)))
    return None


def _document_date(doc: Dict[str, Any], key: str) -> str:
    """Format a specific document date field without substituting other date dimensions."""
    try:
        return date.fromisoformat(str(doc[key])[:10]).isoformat() if doc.get(key) else "DATE_UNKNOWN"
    except ValueError:
        return "DATE_UNKNOWN"


def _verified_filing_passage(doc: Dict[str, Any], quote: str) -> bool:
    """Require validated hash-verified filing excerpts for SEC/ESEF sources."""
    if doc.get("source_id") not in {"SRC_027", "SRC_031"}:
        return True
    shash = str(doc.get("source_content_sha256") or "")
    needle = _normalize_for_quote_match(quote)
    return bool(
        needle and doc.get("content_status") in {"PARTIAL_TEXT", "FULL_TEXT"}
        and re.fullmatch(r"[0-9a-f]{64}", shash) and doc.get("evidence_verified") is True
        and any(
            isinstance(p, dict) and p.get("validated") is True and isinstance(p.get("text"), str)
            and hashlib.sha256(p["text"].encode("utf-8")).hexdigest() == p.get("passage_sha256")
            and needle in _normalize_for_quote_match(p["text"])
            and p.get("source_content_sha256") == shash
            and p.get("source_url") == doc.get("source_url", doc.get("url"))
            and (doc.get("source_id") != "SRC_027" or p.get("issuer_cik"))
            for p in doc.get("evidence_passages") or []
        )
    )


def _kit_fact_audit(query: str, quote: str, doc: Dict[str, Any], cutoff: Optional[date]) -> Dict[str, str]:
    """Tri-state checks of only the fact dimensions explicitly constrained by a KIT."""
    checks = dict.fromkeys(("ENTITY", "PROGRAM", "VARIANT", "COMPONENT", "ISSUE", "STATUS", "AUTHORITY", "DATE", "CAUSE", "IMPACT"), "NOT_REQUIRED")
    query, quote = _strip_exclusions(query), str(quote or "")
    sm = re.search(r"(?im)^Official Summary:\s*(.+)$", str(doc.get("text") or "")) if doc.get("source_id") == "SRC_001" else None
    context = f"{doc.get('title') or ''} {doc.get('issuer_name') or ''} {quote} {sm.group(1).strip() if sm else ''}"

    names = [
        (aliases, list(e.get("programs") or []) if e.get("default_tier") == "OEM (Final Assembler)" else [])
        for e in AEROSPACE_SUPPLIER_REGISTRY
        for aliases in [[e.get("official_name", ""), *(e.get("aliases") or [])]]
        if any(len(a) >= 4 and _source_mentions(a, query) for a in aliases)
    ]
    if names:
        q_vars = _detect_exact_variants(query) | _detect_specific_variants(query)
        c_vars = _detect_exact_variants(context) | _detect_specific_variants(context)
        checks["ENTITY"] = "POSITIVE" if any(
            any(_source_mentions(a, context) for a in aliases) or (
                progs and (q_vars & c_vars)
                and bool(q_vars & (_detect_exact_variants(" ".join(progs)) | _detect_specific_variants(" ".join(progs))))
                and bool(c_vars & (_detect_exact_variants(" ".join(progs)) | _detect_specific_variants(" ".join(progs))))
            ) for aliases, progs in names
        ) else "UNKNOWN"

    if req_models := _detect_engine_models(query):
        obs_models = _detect_engine_models(context)
        checks["PROGRAM"] = "POSITIVE" if (_engine_models_match(query, context) or (req_models & obs_models)) else ("NEGATIVE" if obs_models else "UNKNOWN")

    q_norm, c_norm = _norm_model_hyphens(query), _norm_model_hyphens(context)
    req_ex = _detect_exact_variants(query) | _detect_exact_variants(q_norm)
    req_sp = _detect_specific_variants(query) | _detect_specific_variants(q_norm)
    obs_ex = _detect_exact_variants(context) | _detect_exact_variants(c_norm)
    obs_sp = _detect_specific_variants(context) | _detect_specific_variants(c_norm)
    if req_ex:
        checks["VARIANT"] = "POSITIVE" if (req_ex & obs_ex) else ("NEGATIVE" if obs_ex and req_ex.isdisjoint(obs_ex) else ("NOT_REQUIRED" if checks["PROGRAM"] == "POSITIVE" else "UNKNOWN"))
    elif req_sp:
        checks["VARIANT"] = "POSITIVE" if (req_sp & obs_sp) else ("NEGATIVE" if (obs_sp or obs_ex) else ("NOT_REQUIRED" if checks["PROGRAM"] == "POSITIVE" else "UNKNOWN"))

    comp_keys = set(COMPONENT_KEYWORDS_MAP) | {"gearbox"}
    if comps := {k for k in comp_keys if re.search(rf"\b{re.escape(k)}\b", query, re.I)}:
        obs_c = {k for k in comp_keys if re.search(rf"\b{re.escape(k)}\b", context, re.I)}
        checks["COMPONENT"] = "POSITIVE" if (comps & obs_c) else ("NEGATIVE" if obs_c else "UNKNOWN")

    if re.search(r"\binspect\w*\s+(?:requirements?|mandates?|intervals?)\b", query, re.I):
        checks["ISSUE"] = "POSITIVE" if re.search(r"\binspect\w*\b", quote, re.I) and re.search(r"\b(?:requir\w*|mandat\w*|shall|must|compliance)\b", quote, re.I) else "UNKNOWN"
    elif re.search(r"\b(?:shortag\w*|scarcity|supply\s+constraints?)\b", query, re.I):
        checks["ISSUE"] = "POSITIVE" if not kit_direct_relevance_gap(query, quote) else "UNKNOWN"

    if re.search(r"\b(?:certification|approval|production|delivery)\s+status\b", query, re.I):
        checks["STATUS"] = "POSITIVE" if re.search(
            r"\b(?:pending|delayed|ongoing|issued|certified|approved|completed|suspended|resumed|withdrawn|revoked|effective)\b|"
            r"\b(?:achieved|granted|received|obtained|secured)\s+(?:amended\s+)?(?:type\s+)?certif\w*", quote, re.I,
        ) else "UNKNOWN"

    if auths := {a.upper() for a in re.findall(r"\b(?:FAA|EASA|NTSB|CAA|TCCA|TSB|CAAC|ANAC|CASA|BEA)\b", query, re.I)}:
        actual = _claim_authority(doc)
        checks["AUTHORITY"] = "POSITIVE" if actual in auths else ("NEGATIVE" if actual else "UNKNOWN")
    if cutoff:
        pub = _document_date(doc, "published_at")
        checks["DATE"] = "UNKNOWN" if pub == "DATE_UNKNOWN" else ("NEGATIVE" if pub > cutoff.isoformat() else "POSITIVE")
    if re.search(r"\b(?:why|causes?|caused|causality|due\s+to|drivers?)\b", query, re.I):
        checks["CAUSE"] = "POSITIVE" if _causal_roles(quote) else "UNKNOWN"
    if target := re.search(r"\bimpact\s+(?:on|of)\s+(?:\w+\s+){0,2}(deliver\w*|produc\w*)\b", query, re.I):
        stem = "deliver" if target.group(1).lower().startswith("deliver") else "produc"
        checks["IMPACT"] = "POSITIVE" if re.search(rf"\b{stem}\w*\b", quote, re.I) and re.search(r"\b(?:impact\w*|affect\w*|disrupt\w*|delay\w*)\b", quote, re.I) else "UNKNOWN"
    return checks


def _claim_model_ids(text: str) -> set[str]:
    """Return the most specific normalized model codes mentioned in text."""
    codes = _certification_model_ids(text)
    return {c for c in codes if not any(c != other and other.startswith(c) for other in codes)}

def _source_age_days(publication_time: str, as_of_date: str = "") -> Optional[int]:
    """Compute source age in days relative to the analysis reference date."""
    try:
        ref = date.fromisoformat(str(as_of_date)[:10]) if as_of_date else datetime.now(timezone.utc).date()
        return (ref - date.fromisoformat(str(publication_time or "")[:10])).days
    except (TypeError, ValueError):
        return None


def _evaluate_event_freshness(
    threat: ThreatAssessment, doc_raw_full: str, is_already_in_db: bool = False,
    as_of_date: str = "", event_date: str = "",
) -> EventFreshness:
    """Classify current developments separately from historical context and unknown dates."""
    age = _source_age_days(threat.publication_time, as_of_date)
    if age is not None and age > 90:
        return EventFreshness.HISTORICAL_CONTEXT
    combined = f"{threat.confirmed_facts} {threat.threat_description} {threat.fact_check_quote} {doc_raw_full}"
    hist_years = [int(y) for y in re.findall(
        r"\b(?:in|im|on|during)\s+(?:january|february|march|april|may|june|july|august|september|october|november|december|"
        r"januar|februar|märz|mai|juni|juli|oktober|dezember)\s+(20\d{2})\b", threat.fact_check_quote or "", flags=re.I,
    )]
    ref_year = int(as_of_date[:4]) if re.match(r"^20\d{2}", as_of_date or "") else datetime.now(timezone.utc).year
    if hist_years and max(hist_years) < ref_year:
        return EventFreshness.HISTORICAL_CONTEXT
    if ONGOING_OR_RECONFIRMED_PATTERNS.search(combined):
        return EventFreshness.ONGOING_ISSUE
    if HISTORICAL_RECAP_PATTERNS.search(threat.fact_check_quote or "") and not any(k in combined.lower() for k in ("today", "this week", "newly")):
        return EventFreshness.HISTORICAL_CONTEXT
    if is_already_in_db:
        return EventFreshness.ONGOING_ISSUE
    if age is None or age < 0 or age > 30 or threat.claim_support_status == "UNSUPPORTED":
        return EventFreshness.EVENT_DATE_UNKNOWN
    ev_day = _document_date({"event_date": event_date}, "event_date")
    if ev_day == "DATE_UNKNOWN":
        return EventFreshness.EVENT_DATE_UNKNOWN
    ev_age = ((_reference_day(as_of_date) or datetime.now(timezone.utc).date()) - date.fromisoformat(ev_day)).days
    return EventFreshness.EVENT_DATE_UNKNOWN if ev_age < 0 else (EventFreshness.HISTORICAL_CONTEXT if ev_age > 90 else threat.event_freshness)


def _causal_roles(text: str) -> Optional[Tuple[set[str], set[str]]]:
    """Extract normalized cause and effect token sets when one sentence explicitly links them."""
    stop = {"that", "this", "with", "from", "which", "were", "have", "been", "their"}
    words = lambda v: {
        "directive" if w in {"ad", "pad"} else (w[:-3] + "y" if w.endswith("ies") else (w[:-1] if len(w) > 5 and w.endswith("s") else w))
        for w in set(re.findall(r"\b(?:ad|pad|aog|mel|mmel|hpc|hpt|gtf|ifsd|[a-z0-9]{4,})\b", v.lower())) - stop
    }
    for sent in re.split(r"(?<=[.!?])\s+|\n+", text or ""):
        if not (m := _CAUSAL_CONNECTOR.search(sent)):
            continue
        before, after = sent[:m.start()], sent[m.end():]
        cause, effect = ((after, before) if words(before) else (after.split(",", 1) if "," in after else (after, before))) if m.group().lower() in _REVERSE_CAUSAL_CONNECTORS else (before, after)
        if (cw := words(cause)) and (ew := words(effect)):
            return cw, ew
    return None


def _causal_quote_support(threat: ThreatAssessment, doc: Dict[str, Any], grounded_text: str = "") -> Tuple[bool, str]:
    """Require the cited assertion to express the same participants, cause, and effect."""
    quote, stmt = str(grounded_text or threat.fact_check_quote or ""), f"{threat.confirmed_facts or ''} {threat.threat_description or ''}"
    cited_roles, claimed_roles = _causal_roles(quote), _causal_roles(stmt)
    if not cited_roles or not claimed_roles:
        return False, "CAUSAL_LINK_NOT_EXPLICIT_IN_CITED_PASSAGE"
    if not all(src & clm for src, clm in zip(cited_roles, claimed_roles)):
        return False, "CAUSE_OR_EFFECT_PARTICIPANTS_NOT_ALIGNED"
    context, body = f"{doc.get('title') or ''} {doc.get('issuer_name') or ''} {quote}", str(doc.get("text") or "")
    if quote and (pos := body.find(quote)) >= 0:
        end = body.find("\n\n", pos + len(quote))
        context += " " + body[body.rfind("\n\n", 0, pos) + 2:end if end >= 0 else len(body)][:800]
    actors = [n for n in _split_affected_entities(threat.company_affected) if n.lower() != "unknown"]
    if actors and not any(_source_mentions(n, context) for n in actors):
        return False, "CAUSAL_ENTITY_NOT_ESTABLISHED"
    if target := str(threat.affected_program or ""):
        exact, obs_ex = _detect_exact_variants(target), _detect_exact_variants(context)
        models, obs_m = _claim_model_ids(target), _claim_model_ids(context)
        if (_detect_engine_models(target) and not _engine_models_match(target, context)) or (exact and obs_ex and (not exact.issubset(obs_ex) or (obs_ex - exact))) or (models and not (models & obs_m)):
            return False, "CAUSAL_PROGRAM_NOT_ESTABLISHED"
    comp = str(getattr(threat, "affected_component", "") or "").strip()
    if comp and not re.search(r"\b(?:unknown|not specified|n/a)\b", comp, re.I) and not re.search(rf"\b{re.escape(comp)}\b", context, re.I):
        return False, "CAUSAL_COMPONENT_NOT_ESTABLISHED"
    cy, qy = set(re.findall(r"\b20\d{2}\b", stmt)), set(re.findall(r"\b20\d{2}\b", quote))
    return (False, "CAUSAL_TIME_PERIOD_CONFLICT") if (cy and qy and cy.isdisjoint(qy)) else (True, "CAUSE_EFFECT_STATED_TOGETHER_IN_VERIFIED_QUOTE")


def _evaluate_claim_and_causal_support(
    threat: ThreatAssessment, matched_doc: Dict[str, Any],
    full_quote_verified: bool, is_unverified_or_community_source: bool,
) -> Tuple[str, str, List[str]]:
    """Separate stated source facts from speculative causal explanations."""
    from aero_ews.collection.queries import get_program_engine_domain

    doc_text = (matched_doc.get("text") or "").strip()
    doc_raw_full = f"{(matched_doc.get('title') or '').strip()} {doc_text}"
    claim_comb = f"{threat.company_affected} {threat.threat_description} {threat.confirmed_facts}"

    doc_norm_models = _norm_model_hyphens(doc_raw_full)
    claim_norm_models = _norm_model_hyphens(claim_comb)
    c_engs = _detect_engine_models(claim_comb) | _detect_engine_models(claim_norm_models)
    d_engs = _detect_engine_models(doc_raw_full) | _detect_engine_models(doc_norm_models)
    c_vars = _detect_specific_variants(claim_comb) | _detect_specific_variants(claim_norm_models)
    d_vars = _detect_specific_variants(doc_raw_full) | _detect_specific_variants(doc_norm_models)

    if c_vars and c_vars.isdisjoint(d_vars):
        eng_links_variant = False
        if not d_vars and d_engs and (not c_engs or _engine_models_match(claim_comb, doc_raw_full)):
            dom_engines = _detect_engine_models(" ".join(
                eng for v in c_vars for eng in get_program_engine_domain(v).get("engine_models", ())
            ))
            eng_links_variant = bool(dom_engines & d_engs)
        if not eng_links_variant:
            return "UNSUPPORTED", "UNSUPPORTED", [f"Variant mismatch: {sorted(c_vars)} vs source {sorted(d_vars)}"]

    c_fams = _detect_aircraft_families(claim_comb) | _detect_aircraft_families(claim_norm_models)
    d_fams = _detect_aircraft_families(doc_raw_full) | _detect_aircraft_families(doc_norm_models)
    if c_fams and d_fams and not (c_fams & d_fams):
        return (
            "UNSUPPORTED",
            "UNSUPPORTED",
            [f"Aircraft family mismatch: Claim references {sorted(c_fams)} vs source {sorted(d_fams)}"],
        )

    if c_engs and d_engs and not _engine_models_match(claim_comb, doc_raw_full):
        return "UNSUPPORTED", "UNSUPPORTED", [f"Engine mismatch: Claim references {sorted(c_engs)} vs source {sorted(d_engs)}"]
    if not full_quote_verified:
        return "UNSUPPORTED", "UNSUPPORTED", ["Full verbatim quote could not be verified in source document"]
    if matched_doc.get("content_status") in _NON_SUBSTANTIVE_STATUSES:
        return "UNSUPPORTED", "HYPOTHETICAL_ONLY", ["CONTENT_QUALITY_GUARD: Metadata/structured facts cannot verify a narrative event or cause."]

    sid = matched_doc.get("source_id")
    if sid == "SRC_027" and (matched_doc.get("document_type") == "SEC_FILING_METADATA_ONLY" or matched_doc.get("content_status") == "METADATA_ONLY" or "[SEC_METADATA_ONLY]" in doc_raw_full or "FULL_TEXT_UNAVAILABLE:" in doc_raw_full):
        return "PARTIALLY_STATED_IN_SOURCE", "HYPOTHETICAL_ONLY", ["SEC_METADATA_ONLY_GUARD: Verified filing metadata cannot establish substantive financial results, operational disruptions or causal explanations."]
    if sid == "SRC_031" and (matched_doc.get("document_type") == "ESEF_FILING_METADATA_ONLY" or matched_doc.get("content_status") == "METADATA_ONLY" or "[ESEF_FILING_METADATA_ONLY]" in doc_raw_full):
        return "UNSUPPORTED", "HYPOTHETICAL_ONLY", ["ESEF_METADATA_ONLY_GUARD: Filing index metadata cannot establish financial losses, disruptions or causality."]

    notes: List[str] = []
    is_snippet = _is_short_snippet(matched_doc) and not (sid in {"SRC_027", "SRC_031"} and _verified_filing_passage(matched_doc, threat.fact_check_quote))
    doc_norm = _normalize_for_quote_match(doc_raw_full)
    matched_did = str(matched_doc.get("doc_id") or "")
    quotes = [threat.fact_check_quote or ""]

    for p in getattr(threat, "evidence_passages", None) or []:
        p_doc = str(getattr(p, "document_id", "") or (p.get("document_id", "") if isinstance(p, dict) else ""))
        p_txt = str(getattr(p, "passage_text", "") or (p.get("passage_text", "") if isinstance(p, dict) else ""))
        if (not matched_did or not p_doc or p_doc == matched_did) and _segments_in_corpus(p_txt, doc_norm):
            quotes.append(p_txt)
    if full_quote_verified and not is_snippet and not is_unverified_or_community_source:
        q_toks = re.findall(r"\w+", threat.fact_check_quote or "")
        if len(q_toks) >= 6 and (anc := re.search(r"\W+".join(map(re.escape, q_toks[:10])), doc_raw_full, re.I)):
            quotes.append(doc_raw_full[max(0, anc.start() - 250):min(len(doc_raw_full), anc.end() + 400)].strip())
        for c_obj in getattr(threat, "evidence_claims", None) or []:
            c_doc, c_q = str(getattr(c_obj, "document_id", "") or ""), str(getattr(c_obj, "quote", "") or "")
            if (not matched_did or not c_doc or c_doc == matched_did) and _segments_in_corpus(c_q, doc_norm):
                quotes.append(c_q)
    if full_quote_verified and sid == "SRC_001" and (hdr := doc_text.split("Official Full Text:", 1)[0].strip()):
        quotes.append(hdr)
    grounded_text = " ".join(q for q in quotes if q)

    fact_src = (threat.confirmed_facts or "").strip() or (threat.threat_description or "").strip()
    fact_words = [w for w in re.findall(r"\b[a-z0-9]{4,}\b", _normalize_for_quote_match(fact_src)) if w not in _FACT_STOPWORDS]
    corpus = doc_norm if (full_quote_verified and not is_snippet and not is_unverified_or_community_source) else _normalize_for_quote_match(grounded_text)
    word_ok = lambda w: w in corpus or (len(w) >= 6 and any(w.endswith(s) and len(w) - len(s) >= 4 and w[:-len(s)] in corpus for s in ("ings", "ing", "ied", "ies", "ed", "es", "s")))
    overlap = (sum(1 for w in fact_words if word_ok(w)) / len(fact_words)) if fact_words else 0.0

    has_causality = bool(CAUSAL_CLAIM_REGEX.search(f"{threat.confirmed_facts} {threat.threat_description}"))
    c_ok, c_reason = _causal_quote_support(threat, matched_doc, grounded_text) if has_causality else (False, "")
    if has_causality and c_ok and overlap >= 0.50:
        causal_status = "CLAIMED_IN_UNVERIFIED_SOURCE" if (is_unverified_or_community_source or is_snippet) else "EVIDENCED_IN_VERIFIED_SOURCE"
        if causal_status == "CLAIMED_IN_UNVERIFIED_SOURCE":
            notes.append("Causality is stated in an unverified/community or snippet source (not objectively proven)")
    elif has_causality:
        causal_status = "HYPOTHETICAL_ONLY"
        notes.append(f"{'INSUFFICIENT_FACT_OVERLAP_FOR_CAUSAL_CLAIM' if c_ok else (c_reason or 'CAUSAL_CLAIM_NOT_GROUNDED')}: downstream causality is not verified")
    else:
        causal_status = "NOT_ASSERTED"

    if is_snippet:
        notes.append("Source record contains only a headline or short snippet; confirms headline publication only")
        claim_status = "PARTIALLY_STATED_IN_SOURCE" if overlap >= 0.45 else "UNSUPPORTED"
    elif overlap >= 0.55:
        claim_status = "STATED_IN_SOURCE"
    elif overlap >= 0.35:
        notes.append("Source states only part of the claim details")
        claim_status = "PARTIALLY_STATED_IN_SOURCE"
    else:
        notes.append("Claim extrapolates beyond what is stated in the source document")
        claim_status = "UNSUPPORTED"

    if has_causality and causal_status != "EVIDENCED_IN_VERIFIED_SOURCE":
        claim_status = "PARTIALLY_STATED_IN_SOURCE" if claim_status == "STATED_IN_SOURCE" else claim_status
        notes.append("Unverified causal interpretation cannot be included among confirmed facts.")
    if (re.search(r"\b(?:certified|approved|completed|resumed|restored|issued|effective|delivered)\b", claim_comb, re.I)
            and re.search(r"\b(?:not\s+yet|never|without|pending|expect\w*|anticipat\w*|plan\w*|propos\w*|await\w*|may|might|could)\b", threat.fact_check_quote or "", re.I)
            and not re.search(r"\b(?:has|have|was|were)\s+(?:already\s+)?(?:been\s+)?(?:certified|approved|completed|resumed|restored|issued|delivered)\b", threat.fact_check_quote or "", re.I)):
        claim_status = "PARTIALLY_STATED_IN_SOURCE" if claim_status == "STATED_IN_SOURCE" else claim_status
        notes.append("ACTUAL_STATUS_UNVERIFIED: forecast, proposal or negation cannot establish completed action")
    if _PRIOR_PERIOD_CAUSE_RE.search(doc_raw_full) and _CURRENT_PERIOD_RE.search(claim_comb) and _CLAIM_CAUSE_RE.search(claim_comb):
        claim_status, causal_status = "PARTIALLY_STATED_IN_SOURCE", "HYPOTHETICAL_ONLY"
        notes.append("TEMPORAL_SCOPE_MISMATCH: Causal attribution belongs to the prior comparison period, not demonstrably to the current period")

    imp_re = r"\b(delay|shortag|disrupt|impact|affect|threaten|ground|halt|caus|trigger|intensif|increas|pressur|strain|bottleneck|constrain|allocat)\w*\b"
    imp_corpus = f"{grounded_text} {doc_raw_full}" if (
                full_quote_verified and not is_snippet and not is_unverified_or_community_source) else grounded_text
    if {m.lower() for m in re.findall(imp_re, f"{threat.threat_description or ''} {threat.confirmed_facts or ''}", re.I)} - {m.lower() for m in re.findall(imp_re, imp_corpus, re.I)}:
        causal_status = "HYPOTHETICAL_ONLY"
        claim_status = "PARTIALLY_STATED_IN_SOURCE" if claim_status == "STATED_IN_SOURCE" else claim_status
        notes.append("Claimed operational impact is not supported by the cited quotation.")
    return claim_status, causal_status, notes


def _mark_untraced_threat(threat: ThreatAssessment) -> ThreatAssessment:
    """Downgrade an event whose cited document cannot be traced to the collected dataset."""
    threat.technical_grounding_status = "FAIL"
    threat.claim_support_status = threat.causal_support_status = "UNSUPPORTED"
    threat.independent_verification_status = "UNVERIFIED_SINGLE_SOURCE"
    threat.validation_status, threat.confidence_level = ValidationStatus.UNSUPPORTED, ConfidenceLevel.LOW
    threat.event_status, threat.escalation_level = EventStatus.UNDER_REVIEW, EscalationStatus.PRIORITY_VERIFICATION_REQUIRED
    threat.evidence_citation, threat.source_urls, threat.evidence_ids = "", [], []
    threat.affected_program = threat.affected_component = "Unknown / Not specified in source"
    threat.geographic_epicenter = "Unknown"
    threat.verification_status = "UNVERIFIED: Cited DOC_ID/URL not found in collected OSINT documents (Manual HITL Review Required)"
    threat.missing_data = "Source document could not be traced in collected dataset; manual verification required."
    threat.intelligence_gap = IntelligenceGap(
        what_is_missing=threat.missing_data, why_important="Cannot confirm claim without a traceable primary/secondary OSINT document.",
        affected_kiq_id=threat.kiq_ids[0] if threat.kiq_ids else "", recommended_source="Manual Analyst Verification", can_auto_scan=True, status="OPEN",
    )
    threat.confirmed_facts = ""
    threat.threat_description = "Unverified intelligence claim: the cited source could not be traced to the collected OSINT dataset."
    threat.analytical_interpretation = "No source-grounded interpretation is possible until the source reference is verified."
    return threat


def _apply_regulatory_checks(
    threat: ThreatAssessment, matched_doc: Dict[str, Any], matched_text: str, full_quote_verified: bool,
    faa_pub: Optional[Dict[str, Any]], faa_pub_ver: bool, faa_lifecycle_ver: bool,
    age: Optional[int], as_of_date: str, audit_notes: List[str],
) -> None:
    """Validate regulatory stage, FAA docket metadata, and proposal/withdrawal caveats."""
    reg_ev = f"{matched_doc.get('title', '')} {threat.fact_check_quote or ''}"
    if sm := re.search(r"(?im)^Regulatory Stage:\s*(EFFECTIVE|FINAL_ISSUED|WITHDRAWN|PROPOSED|UNKNOWN)\s*$", matched_text):
        stage = sm.group(1)
    elif re.search(r"\b(?:withdrawn|withdrawal of (?:an? )?nprm)\b", reg_ev, re.I):
        stage = "WITHDRAWN"
    elif re.search(r"\b(?:final rule|adopt(?:s|ed|ing) an? (?:new )?airworthiness directive)\b", reg_ev, re.I):
        stage = "FINAL_ISSUED"
    elif re.search(r"\b(?:propos(?:e|es|ed|ing|al)|notice of proposed rulemaking|NPRM)\b", reg_ev, re.I):
        stage = "PROPOSED"
    else:
        stage = "UNKNOWN"

    if not _claim_authority(matched_doc) or not full_quote_verified:
        stage = "UNKNOWN"
        audit_notes.append("REGULATORY_AUTHORITY_NOT_VERIFIED: issuer or media statements do not establish an agency decision")
    if (lm := re.search(r"(?im)^Regulatory Lifecycle Check:\s*(VERIFIED|UNVERIFIED)\s*$", matched_text)) and lm.group(1) == "UNVERIFIED":
        audit_notes.append("FAA docket lifecycle search unavailable; latest regulatory status not independently checked.")
    if stage in {"FINAL_ISSUED", "EFFECTIVE"} and (off := re.search(r"(?im)^Official Summary:\s*(.+)$", matched_text)):
        actual = off.group(1).strip()[:350]
        if re.search(r"\bpropos(?:e|es|ed|ing)\b", threat.threat_description or "", re.I):
            threat.threat_description = actual
        if re.search(r"\bpropos(?:e|es|ed|ing)\b", threat.confirmed_facts or "", re.I):
            threat.confirmed_facts = actual

    if matched_doc.get("source_id") == "SRC_001":
        docket = _faa_docket_from_text(matched_text)
        older = re.search(r"(?im)^Related earlier document:\s*(https://\S+)", matched_text)
        eff_m = re.search(r"(?im)^Effective Date:\s*(\d{4}-\d{2}-\d{2})\s*$", matched_text)
        eff_date = "" if (ed := _document_date({"v": eff_m.group(1)}, "v") if eff_m else "DATE_UNKNOWN") == "DATE_UNKNOWN" else ed
        if (meta_eff := str(matched_doc.get("regulatory_effective_date") or "")[:10]) and eff_date and meta_eff != eff_date:
            eff_date = ""
            audit_notes.append("FAA_EFFECTIVE_DATE_CONFLICT: official label and metadata disagree")
        eff_reached = bool(eff_date and date.fromisoformat(eff_date) <= (_reference_day(as_of_date) or datetime.now(timezone.utc).date()))
        if stage == "EFFECTIVE" and not eff_date:
            stage = "FINAL_ISSUED"
            audit_notes.append("EFFECTIVE_DATE_UNKNOWN: final issuance does not prove current legal effectiveness")
        elif stage == "EFFECTIVE" and eff_date and not eff_reached:
            stage = "FINAL_ISSUED"

        if faa_pub_ver and docket:
            cs = threat.corroboration_summary
            cs.update({
                "FAA Publication Verified": "YES", "FAA Document Number": faa_pub["document_number"],
                "FAA Docket": docket.upper(), "FAA Publication Date": faa_pub["publication_date"],
                "FAA Lifecycle Verified": "YES" if faa_lifecycle_ver else "NO",
                "FAA Supersession Status": "CHECKED" if faa_lifecycle_ver else "UNKNOWN",
                "FAA Effective Date Established": "YES" if eff_date else "NO",
                "FAA Effective As Of Date": "NO" if eff_date and not eff_reached else ("YES" if eff_reached and faa_lifecycle_ver and stage == "EFFECTIVE" else "UNKNOWN"),
            })
            if eff_date:
                cs["effective_date"] = cs["FAA Effective Date"] = eff_date
            if not faa_lifecycle_ver and threat.confidence_level == ConfidenceLevel.HIGH:
                threat.confidence_level = ConfidenceLevel.MEDIUM
            if faa_lifecycle_ver:
                cs["FAA Compliance Deadline"] = matched_doc.get("regulatory_compliance_deadline") or "NOT_ESTABLISHED"
                if older:
                    cs["FAA Prior Document"] = older.group(1)
                if stage in {"FINAL_ISSUED", "EFFECTIVE"} and age is not None:
                    threat.event_freshness = EventFreshness.NEW_DEVELOPMENT if 0 <= age <= 90 else (EventFreshness.HISTORICAL_CONTEXT if age > 90 else threat.event_freshness)
                    cs["5. Event Freshness"] = threat.event_freshness.value

    threat.corroboration_summary["Regulatory Stage"] = stage
    if stage == "WITHDRAWN":
        threat.analytical_interpretation = "The cited NPRM was withdrawn; this document does not establish an enforceable new compliance obligation. " + (threat.analytical_interpretation or "")
        audit_notes.append("Withdrawn NPRM; no new binding compliance requirement from this notice.")
    if stage == "PROPOSED":
        threat.analytical_interpretation = "Regulatory proposal identified; legal effectiveness and implementation obligations are not established by this evidence. " + (threat.analytical_interpretation or "")
        if re.search(r"\b(?:mandat(?:e|es|ed|ory)|requires?|in force|effective)\b", threat.score_rationale or "", flags=re.I):
            threat.score_rationale = f"Potential severity: {threat.threat_score}/10. The cited regulatory measure is a proposal. Binding obligations and downstream operational impacts require additional evidence."
        audit_notes.append("Regulatory proposal detected; binding implementation requirements must not be assumed.")


def _resolve_source_doc(
    threat: ThreatAssessment, explicit_docs: List[Dict[str, Any]], docs_by_url: Dict[str, Dict[str, Any]],
    llm_url: str, active_kit: str, kit_exact: set[str], audit_notes: List[str],
) -> Tuple[Optional[Dict[str, Any]], str, bool]:
    """Match the cited document and perform conservative official-headline recovery if needed."""
    quote_norm = _normalize_for_quote_match(threat.fact_check_quote)
    quote_hits = [ed for ed in explicit_docs if quote_norm and quote_norm in _normalize_for_quote_match(_doc_full_text(ed))]
    matched = (
        next((ed for ed in quote_hits if llm_url and ed.get("url") == llm_url), max(quote_hits, key=lambda ed: str(ed.get("published_at") or "")))
        if quote_hits else next((ed for ed in explicit_docs if llm_url and ed.get("url") == llm_url), explicit_docs[0] if explicit_docs else None)
    )
    recovered = False
    if matched and not quote_hits and (exact_kit := _detect_exact_variants(active_kit)):
        primary = next((
            d for d in explicit_docs
            if (_detect_exact_variants(d.get("title", "")) & exact_kit)
            and re.search(r"\b(?:certif\w*|approv\w*|airworth\w*)\b", d.get("title", ""), re.I)
            and 6 <= len(d.get("title", "").split()) <= 25 and len(d.get("title", "")) <= 400
            and is_exact_or_subdomain(extract_effective_publisher_domain(d.get("url", "")), _PRIMARY_REGULATOR_DOMAINS | _PRIMARY_OEM_AND_TIER1_DOMAINS)
        ), None)
        if primary:
            matched, threat.fact_check_quote, recovered = primary, primary["title"].strip(), True
            quote_norm = _normalize_for_quote_match(threat.fact_check_quote)
            audit_notes.append("Original quote not found; using exact official headline. Operational impacts remain unverified.")

    orig_q = threat.fact_check_quote or ""
    if (matched and (reg_m := re.search(r"\b(?:FAA|EASA)\b", orig_q, re.I)) and kit_exact
            and matched.get("source_id") in {"SRC_004", "SRC_007", "SRC_008"}
            and (matched.get("source_id") != "SRC_004" or quote_norm not in _normalize_for_quote_match(_doc_full_text(matched)))
            and re.search(r"\b(?:certif\w*|approv\w*|clear\w*|grant\w*)\b", orig_q, re.I)
            and not re.search(r"\b(?:pending|propos\w*|await\w*|expect\w*|could|might|deni\w*|reject\w*|revok\w*|suspend\w*|withdraw\w*|not\s+yet)\b", orig_q, re.I)):
        for doc in explicit_docs:
            t_str = (doc.get("title") or "").strip()
            if (doc.get("source_id") == "SRC_004" and not _is_snippet_only(doc) and "[NEWSAPI_METADATA_ONLY:" not in (doc.get("text") or "")
                    and 5 <= len(t_str.split()) <= 25 and _detect_exact_variants(t_str) == kit_exact
                    and re.search(rf"\b{reg_m.group()}\b", t_str, re.I) and re.search(r"\b(?:certif\w*|approv\w*|clear\w*|grant\w*)\b", t_str, re.I)
                    and not re.search(r"\b(?:pending|propos\w*|await\w*|expect\w*|deni\w*|reject\w*|revok\w*|suspend\w*)\b", t_str, re.I)
                    and threat.company_affected.lower() in t_str.lower()):
                matched, threat.fact_check_quote, quote_norm, recovered = doc, t_str, _normalize_for_quote_match(t_str), True
                audit_notes.append("Original LLM quote replaced with exact full-text source title; broader claims remain unverified.")
                break

    if not matched and llm_url and llm_url in docs_by_url:
        matched = docs_by_url[llm_url]
        audit_notes.append("DOC_ID missing or invalid; matched via exact collected URL")
    return matched, quote_norm, recovered


def deterministic_harness_validation(
    report: EWSReport, raw_data: str, collected_docs: Optional[List[Dict[str, Any]]] = None,
    user_query: str = "", as_of_date: str = "",
) -> Tuple[EWSReport, int]:
    """Five-Dimensional Grounding, Source-Evidenced Program Guard, Event Freshness & Watchlist Validator."""
    docs = collected_docs if collected_docs is not None else get_collected_documents()
    docs_by_id = {d["doc_id"]: d for d in docs if isinstance(d, dict) and d.get("doc_id")}
    docs_by_url = {d["url"]: d for d in docs if isinstance(d, dict) and d.get("url")}

    active_kit = user_query or (report.run_metadata or {}).get("query", "")
    ref_date = _reference_day(as_of_date, active_kit)
    invalid_ref = bool(as_of_date and not ref_date)
    if ref_date:
        as_of_date = ref_date.isoformat()

    pos_kit = _strip_exclusions(active_kit)
    kit_variants, kit_exact, kit_engines = _detect_specific_variants(pos_kit), _detect_exact_variants(pos_kit), _detect_engine_models(pos_kit)
    kit_components = {lbl for kw, lbl in COMPONENT_KEYWORDS_MAP.items() if re.search(rf"\b{re.escape(kw)}\b", pos_kit, re.I)}
    filing_specific_kit = bool(re.search(r"\b(?:sec|edgar|esef|xbrl|10-[kq]|20-f|6-k)\b", active_kit, re.I))

    entity_names = tuple(dict.fromkeys(
        [*(_REGISTRY_CLEAN_RE.sub("", e.get("official_name", "")).strip() for e in AEROSPACE_SUPPLIER_REGISTRY if
           e.get("official_name")), "Pratt & Whitney", "Aequs"]))
    oem_programs = {_REGISTRY_CLEAN_RE.sub("", e.get("official_name", "")).strip().lower(): e.get("programs") or [] for
                    e in AEROSPACE_SUPPLIER_REGISTRY if
                    e.get("default_tier") == "OEM (Final Assembler)" and e.get("official_name")}
    entity_aliases = {
        _REGISTRY_CLEAN_RE.sub("", e.get("official_name", "")).strip().lower(): [
            a for a in (e.get("aliases") or []) if len(a) >= 4 and not re.search(r"\d", a)
        ]
        for e in AEROSPACE_SUPPLIER_REGISTRY if e.get("official_name")
    }

    def _entity_mentioned(name: str, text: str, *, allow_program_inference: bool = True) -> bool:
        pat = r"(?<!\w)pratt\s*(?:&|and)\s*whitney(?!\w)" if name == "Pratt & Whitney" else rf"(?<!\w){re.escape(name)}(?!\w)"
        if re.search(pat, text or "", re.I):
            return True
        if any(re.search(rf"(?<!\w){re.escape(alias)}(?!\w)", text or "", re.I) for alias in
               entity_aliases.get(name.lower(), ())):
            return True
        if allow_program_inference and (progs := oem_programs.get(name.lower())):
            return bool((_detect_exact_variants(text) | _detect_specific_variants(text)) & (
                        _detect_exact_variants(" ".join(progs)) | _detect_specific_variants(" ".join(progs))))
        return False

    catalog = get_active_kiq_catalog()
    allowed_kiqs = {item["kiq_id"] for item in catalog}
    validated_threats: List[ThreatAssessment] = []
    watchlist_threats: List[ThreatAssessment] = []
    validation_errors = flagged_unverified = 0

    for threat in report.threats:
        llm_url = re.sub(r"^(?:SOURCE_URL:|LINK:|Link:|SOURCE:|URL:)\s*", "", (threat.evidence_citation or "").strip(), flags=re.I).rstrip(".,;)")
        explicit_docs = [docs_by_id[eid.strip().upper()] for eid in (threat.evidence_ids or []) if eid.strip().upper() in docs_by_id]
        audit_notes: List[str] = []
        matched_doc, full_quote_norm, quote_recovered = _resolve_source_doc(threat, explicit_docs, docs_by_url, llm_url, active_kit, kit_exact, audit_notes)
        if not matched_doc:
            validation_errors += 1
            flagged_unverified += 1
            validated_threats.append(_mark_untraced_threat(threat))
            continue

        canonical_url, canonical_date = matched_doc["url"], matched_doc.get("published_at") or "DATE_UNKNOWN"
        url_ok = not (llm_url and llm_url != canonical_url)
        if not url_ok:
            audit_notes.append(f"LLM URL differed from {matched_doc['doc_id']} metadata; overwritten with canonical document URL")
        llm_date = normalize_date_str(threat.publication_time)
        date_ok = not (canonical_date != "DATE_UNKNOWN" and llm_date and llm_date != canonical_date)
        if not date_ok:
            audit_notes.append(f"LLM date ({llm_date}) differed from {matched_doc['doc_id']} date ({canonical_date}); corrected")

        threat.evidence_citation, threat.publication_time = canonical_url, canonical_date
        corroborating = [matched_doc] + [ed for ed in explicit_docs if ed["doc_id"] != matched_doc["doc_id"]]
        if matched_doc.get("source_id") == "SRC_001" and (pd := _faa_docket_from_text(matched_doc.get("text", ""))):
            filtered = [d for d in corroborating if d.get("source_id") != "SRC_001" or _faa_docket_from_text(d.get("text", "")) == pd]
            if len(filtered) < len(corroborating):
                audit_notes.append("Evidence from different FAA dockets removed.")
            corroborating = filtered

        threat.evidence_ids = list(dict.fromkeys(d["doc_id"] for d in corroborating))
        threat.source_urls = list(dict.fromkeys(d["url"] for d in corroborating if d.get("url")))
        doc_raw_full = _doc_full_text(matched_doc)
        corpus_norm = _normalize_for_quote_match(doc_raw_full)

        threat.scm_tier, threat.supplier_registry_basis, threat.impact_path, has_unknown_scm = _resolve_scm_roles_and_impact_path(threat, doc_raw_full)
        threat.geographic_epicenter, threat.geographic_impact_scope = _resolve_geography_dimensions(threat, doc_raw_full)
        indep_count, _, _ = _count_independent_confirmations(corroborating)

        domain = extract_effective_publisher_domain(canonical_url)
        is_official = urlparse(canonical_url).scheme == "https" and is_exact_or_subdomain(domain, _PRIMARY_REGULATOR_DOMAINS | _PRIMARY_OEM_AND_TIER1_DOMAINS | {"sec.gov"})
        has_comm = any(d.get("source_type") in {"COMMUNITY_SOCIAL", "VIDEO_MEDIA"} for d in corroborating)
        has_media = any(d.get("source_type") in {"MEDIA_AGGREGATOR", "INDUSTRY_EVENT", "GEOGRAPHIC_SIGNAL"} or "news.google.com" in extract_effective_publisher_domain(d.get("url", "")) for d in corroborating)
        is_social_video = is_exact_or_subdomain(domain, UNVERIFIED_SOCIAL_VIDEO_DOMAINS) or (has_comm and not is_official and not has_media)
        threat.independent_verification_status = (
            "CORROBORATED_INDEPENDENTLY" if (indep_count >= 2 or (is_official and has_media))
            else "SINGLE_PRIMARY_SOURCE" if is_official else "SINGLE_SECONDARY_SOURCE" if (has_media and not is_social_video) else "UNVERIFIED_SINGLE_SOURCE"
        )

        full_quote_verified = bool(
            full_quote_norm and len(full_quote_norm) >= 12 and _segments_in_corpus(threat.fact_check_quote or "",
                                                                                   corpus_norm))
        # If the short summary quote slightly abbreviated a term (e.g. "FAA" for "Federal Aviation Administration (FAA)"),
        # check whether one of the event's own extracted evidence_claims for the same DOC_ID carries the verbatim passage.
        if (not full_quote_verified or not _verified_filing_passage(matched_doc, threat.fact_check_quote)):
            matched_did = str(matched_doc.get("doc_id") or "")
            for c_obj in getattr(threat, "evidence_claims", None) or []:
                c_did = str(getattr(c_obj, "document_id", "") or "")
                c_q = str(getattr(c_obj, "quote", "") or "").strip()
                c_norm = _normalize_for_quote_match(c_q)
                if (not c_did or c_did == matched_did) and len(c_norm) >= 20 and _segments_in_corpus(c_q,
                                                                                                     corpus_norm) and _verified_filing_passage(
                        matched_doc, c_q):
                    threat.fact_check_quote, full_quote_norm, full_quote_verified = c_q, c_norm, True
                    break
        if not _verified_filing_passage(matched_doc, threat.fact_check_quote):
            full_quote_verified = False
            audit_notes.append("FILING_PASSAGE_UNVERIFIED: source-exact filing excerpt or stored hash is missing")
        threat.technical_grounding_status = "PASS" if full_quote_verified else "FAIL"

        matched_text = str(matched_doc.get("text") or "")
        faa_pub = _verified_faa_publication(matched_doc)
        faa_pub_ver, faa_lifecycle_ver = bool(faa_pub), bool(faa_pub and re.search(r"(?im)^Regulatory Lifecycle Check:\s*VERIFIED\s*$", matched_text))

        # Recover verbatim FAA abstract or NewsAPI exact title when the LLM paraphrased slightly.
        if faa_pub_ver and not full_quote_verified and (am := re.search(r"(?is)Official Summary:\s*(.+)", matched_text)):
            if spans := list(re.finditer(r"\S+", ab := am.group(1).strip())):
                cand_q = ab[:spans[min(25, len(spans)) - 1].end()].strip()
                if len(cand_n := _normalize_for_quote_match(cand_q)) >= 30 and cand_n in corpus_norm:
                    threat.fact_check_quote, full_quote_norm, full_quote_verified, quote_recovered = cand_q, cand_n, True, True
                    threat.technical_grounding_status = "PASS"
                    audit_notes.append("Original LLM quote was not traceable; replaced by a literal excerpt of the stored FAA abstract. This does not verify unquoted operational effects.")

        m_title = (matched_doc.get("title") or "").strip()
        if (not full_quote_verified and matched_doc.get("source_id") == "SRC_004" and not _is_snippet_only(matched_doc)
                and 10 <= len(m_title) <= 400 and len(m_title.split()) <= 25
                and SequenceMatcher(None, full_quote_norm, _normalize_for_quote_match(m_title)).ratio() >= 0.90):
            threat.fact_check_quote, full_quote_norm, full_quote_verified, quote_recovered = m_title, _normalize_for_quote_match(m_title), True, True
            threat.technical_grounding_status = "PASS"
            audit_notes.append("LLM near-quote replaced with exact stored source title; broader claims remain unverified.")

        if faa_pub_ver and full_quote_verified:
            imp_pat = r"\b(?:ground\w*|production|deliver\w*|capacity|bottleneck\w*|shortag\w*|disrupt\w*)\b"
            if re.search(imp_pat, f"{threat.threat_description} {threat.confirmed_facts}", re.I) and not re.search(imp_pat, threat.fact_check_quote or "", re.I):
                threat.analytical_interpretation = ("Possible downstream effects are hypothetical and require independent operational evidence. " + (threat.analytical_interpretation or ""))[:800]
                threat.threat_description, threat.confirmed_facts = (threat.fact_check_quote or "")[:800], (threat.fact_check_quote or "")[:400]
                audit_notes.append("FAA regulatory fact kept separate from unverified downstream effects.")

        if is_official and full_quote_verified and (sf := str(threat.fact_check_quote or "").strip()) and not str(threat.confirmed_facts or "").strip() and not _is_short_snippet(matched_doc) and matched_doc.get("content_status") not in _NON_SUBSTANTIVE_STATUSES:
            threat.confirmed_facts = sf[:400]
            audit_notes.append("Source-exact statement retained as confirmed fact; unquoted operational consequences remain unverified.")

        threat.claim_support_status, threat.causal_support_status, content_notes = _evaluate_claim_and_causal_support(threat, matched_doc, full_quote_verified, is_unverified_or_community_source=is_social_video)
        claim_text = f"{threat.confirmed_facts} {threat.threat_description}"
        cited_corpus = " ".join(_doc_full_text(d) for d in corroborating)
        if unsup_ents := [
            n for n in entity_names
            if _entity_mentioned(n, claim_text, allow_program_inference=False)
               and not _entity_mentioned(n, cited_corpus, allow_program_inference=True)
        ]:
            threat.claim_support_status = "PARTIALLY_STATED_IN_SOURCE" if threat.claim_support_status == "STATED_IN_SOURCE" else threat.claim_support_status
            threat.causal_support_status = "HYPOTHETICAL_ONLY"
            audit_notes.append(f"Entity relationship requires verification: {', '.join(unsup_ents)} not explicitly identified in cited source.")

        if any(n.startswith("TEMPORAL_SCOPE_MISMATCH") for n in content_notes):
            threat.threat_description = re.sub(r",?\s+(?:mainly|primarily|mostly|largely)\s+(?:due\s+to|because\s+of)\b.*$", "", threat.threat_description, flags=re.I).rstrip(" ,.;") + "."
            threat.confirmed_facts = re.sub(r";?\s*(?:primary|main)\s+cause\s*:\s*.*$", "", threat.confirmed_facts, flags=re.I).rstrip(" ,.;") + "."
            threat.analytical_interpretation = "The source attributes a cause to the prior comparison period. The cause of the current-period result requires separate evidence."
            threat.missing_data = "Verify current-period causality in an independent primary financial or regulatory disclosure."
        audit_notes.extend(content_notes)

        threat.event_freshness = _evaluate_event_freshness(threat, doc_raw_full, as_of_date=as_of_date, event_date=matched_doc.get("event_date") or "")
        age = _source_age_days(threat.publication_time, as_of_date)
        if age is not None and age > 90:
            audit_notes.append(f"Source published {age} days before reference date; historical source alone does not prove a new event or current disruption")
        elif age is not None and age < 0:
            audit_notes.append("Publication date is later than analysis reference date; temporal integrity review required")
        if threat.event_freshness == EventFreshness.ONGOING_ISSUE:
            audit_notes.append("Classified as ONGOING_ISSUE (reconfirmation of previously known schedule/issue, not a newly announced deterioration)")
        elif threat.event_freshness == EventFreshness.HISTORICAL_CONTEXT:
            audit_notes.append("Classified as HISTORICAL_CONTEXT (older event referenced in recent source)")

        # Evaluate KIT technical scope alignment and sibling-program watchlist routing.
        ev_vars, src_exact = _detect_specific_variants(threat.affected_program or ""), _detect_exact_variants(threat.fact_check_quote or "")
        ev_scope = f"{threat.affected_component or ''} {threat.affected_program or ''} {threat.fact_check_quote or ''}"
        ev_engines = _detect_engine_models(ev_scope)
        ev_comps = {lbl for kw, lbl in COMPONENT_KEYWORDS_MAP.items() if re.search(rf"\b{re.escape(kw)}\b", ev_scope, re.I)}
        exact_mis, var_mis = bool(kit_exact and src_exact and kit_exact.isdisjoint(src_exact)), bool(kit_variants and ev_vars and kit_variants.isdisjoint(ev_vars))
        eng_mis, comp_mis = bool(kit_engines and ev_engines and not _engine_models_match(active_kit, ev_scope)), bool(kit_components and ev_comps and kit_components.isdisjoint(ev_comps))
        is_sibling = exact_mis or var_mis or eng_mis or comp_mis
        missing_facet = ((((kit_variants and not ev_vars) or (kit_exact and not src_exact)) and not (kit_engines and ev_engines and not eng_mis))
                         or (kit_engines and not ev_engines and not ((kit_exact and src_exact and not exact_mis) or (kit_variants and ev_vars and not var_mis)))
                         or (kit_components and not ev_comps))

        if is_sibling:
            threat.program_relevance = "RELATED_PROGRAM_WATCHLIST"
            mis_reasons = [r for cond, r in ((exact_mis or var_mis, f"program {sorted(ev_vars or src_exact)} vs KIT {sorted(kit_variants or kit_exact)}"), (eng_mis, f"propulsion {sorted(ev_engines)} vs KIT {sorted(kit_engines)}"), (comp_mis, f"component {sorted(ev_comps)} vs KIT {sorted(kit_components)}")) if cond]
            audit_notes.append(f"Classified as RELATED_PROGRAM_WATCHLIST: Event evidence conflicts with constraining KIT facet(s) ({'; '.join(mis_reasons)}); direct cross-program or cross-configuration impact is not established")
        elif missing_facet:
            threat.program_relevance = "PROGRAM_UNVERIFIED"
            audit_notes.append("All constraining technical facets of the KIT (aircraft program and/or specific propulsion/component scope) could not be simultaneously verified from event evidence. Direct KIT relevance remains unconfirmed.")
        else:
            threat.program_relevance = "DIRECT_KIT_MATCH"

        if filing_specific_kit and matched_doc.get("source_id") not in {"SRC_027", "SRC_031"}:
            threat.program_relevance = "RELATED_CONTEXT" if threat.program_relevance == "DIRECT_KIT_MATCH" else threat.program_relevance
            audit_notes.append("FINANCIAL_SOURCE_SCOPE: non-filing source cannot directly evidence a filing-specific KIT")
        if (issue_gap := kit_direct_relevance_gap(active_kit, doc_raw_full)) and not is_sibling:
            threat.program_relevance, threat.causal_support_status = "RELATED_CONTEXT", "HYPOTHETICAL_ONLY"
            threat.claim_support_status = "PARTIALLY_STATED_IN_SOURCE" if full_quote_verified else "UNSUPPORTED"
            audit_notes.append(issue_gap)

        fact_audit = _kit_fact_audit(active_kit, threat.fact_check_quote, matched_doc, ref_date)
        if unverified_facets := {k: v for k, v in fact_audit.items() if v in {"NEGATIVE", "UNKNOWN"}}:
            audit_notes.append("KIT_FACT_GAP: " + ", ".join(f"{k}={v}" for k, v in unverified_facets.items()))
            only_auth_unknown = unverified_facets == {"AUTHORITY": "UNKNOWN"}
            if any(fact_audit[k] == "NEGATIVE" for k in ("PROGRAM", "VARIANT", "COMPONENT")):
                is_sibling, threat.program_relevance = True, "RELATED_PROGRAM_WATCHLIST"
            elif any(fact_audit[k] == "UNKNOWN" for k in
                     ("ENTITY", "PROGRAM", "VARIANT", "COMPONENT")) and not is_sibling:
                threat.program_relevance = "PROGRAM_UNVERIFIED"
            elif not is_sibling and not only_auth_unknown and threat.program_relevance == "DIRECT_KIT_MATCH":
                threat.program_relevance = "RELATED_CONTEXT"

        # Assign validation status and confidence; contradictions cannot be proven by isolated negative words.
        has_spec = bool(SPECULATIVE_DISINFO_MARKERS.search(f"{threat.threat_description} {threat.fact_check_quote} {threat.adversarial_scenario}"))
        if is_social_video:
            threat.validation_status, threat.confidence_level = ValidationStatus.UNVERIFIED_COMMUNITY, ConfidenceLevel.LOW
            flagged_unverified += 1
        elif threat.technical_grounding_status == "PASS" and threat.claim_support_status == "STATED_IN_SOURCE" and threat.causal_support_status in {"EVIDENCED_IN_VERIFIED_SOURCE", "NOT_ASSERTED"} and not is_sibling:
            threat.validation_status = ValidationStatus.SUPPORTED
            threat.confidence_level = ConfidenceLevel.HIGH if ((is_official or indep_count >= 2) and url_ok and date_ok and not has_spec) else ConfidenceLevel.MEDIUM
        elif threat.technical_grounding_status == "PASS" and threat.claim_support_status in {"STATED_IN_SOURCE", "PARTIALLY_STATED_IN_SOURCE"}:
            threat.validation_status, threat.confidence_level = ValidationStatus.PARTIALLY_SUPPORTED, (ConfidenceLevel.MEDIUM if is_official else ConfidenceLevel.LOW)
            flagged_unverified += 1
        else:
            threat.validation_status, threat.confidence_level = ValidationStatus.UNSUPPORTED, ConfidenceLevel.LOW
            validation_errors += 1
            flagged_unverified += 1

        if quote_recovered and threat.validation_status == ValidationStatus.SUPPORTED:
            threat.validation_status, threat.confidence_level = ValidationStatus.PARTIALLY_SUPPORTED, ConfidenceLevel.LOW
            audit_notes.append("Recovered quotation establishes a source statement; further factual verification is required.")
        if matched_doc.get("source_id") == "SRC_004" and "[NEWSAPI_METADATA_ONLY:" in matched_text:
            if threat.validation_status == ValidationStatus.SUPPORTED:
                threat.validation_status = ValidationStatus.PARTIALLY_SUPPORTED
                flagged_unverified += 1
            threat.confidence_level = ConfidenceLevel.LOW
            audit_notes.append("NEWSAPI_METADATA_ONLY: Full publisher article was unavailable; the summary cannot independently establish the claim.")
        if matched_doc.get("evidence_authority") == "OFFICIAL_ISSUER_IR" and matched_doc.get("evidence_issuer_identity_verified") is not True:
            threat.validation_status = ValidationStatus.PARTIALLY_SUPPORTED if threat.validation_status == ValidationStatus.SUPPORTED else threat.validation_status
            threat.confidence_level = ConfidenceLevel.LOW
            audit_notes.append("IR_ISSUER_IDENTITY_UNKNOWN: quoted page is verified, issuer attribution is not")
        if "SCHEMA_RECOVERY_MALFORMED_CONFIRMED_FACTS" in (threat.missing_data or ""):
            flagged_unverified += int(threat.validation_status == ValidationStatus.SUPPORTED)
            if threat.validation_status in {ValidationStatus.SUPPORTED, ValidationStatus.PARTIALLY_SUPPORTED}:
                validation_errors += 1
                threat.validation_status = ValidationStatus.UNSUPPORTED
            threat.confidence_level, threat.claim_support_status, threat.causal_support_status = ConfidenceLevel.LOW, "UNSUPPORTED", "UNSUPPORTED"
            audit_notes.append("Analyst confirmed_facts contained malformed JSON; its factual assertions were discarded and cannot support escalation without fresh source verification")

        ev_date_str = _document_date(matched_doc, "event_date")
        if (age is not None and age < 0) or (ref_date and ev_date_str != "DATE_UNKNOWN" and ev_date_str > ref_date.isoformat()) or (ref_date and canonical_date == "DATE_UNKNOWN") or invalid_ref:
            threat.validation_status, threat.confidence_level, threat.claim_support_status = ValidationStatus.UNSUPPORTED, ConfidenceLevel.LOW, "UNSUPPORTED"
            flagged_unverified += 1
            validation_errors += 1
            audit_notes.append("HISTORICAL_AS_OF_GUARD: source availability or actual event timing cannot be established at cutoff")
        if threat.causal_support_status != "EVIDENCED_IN_VERIFIED_SOURCE" and CAUSAL_CLAIM_REGEX.search(f"{threat.confirmed_facts} {threat.threat_description}"):
            threat.confirmed_facts = (threat.fact_check_quote or "")[:600] if full_quote_verified else ""
            audit_notes.append("Unverified cause removed from confirmed facts; source wording retained only as a quotation")

        if is_unverified_signal(threat):
            if threat.confirmed_facts:
                audit_notes.append("LLM-proposed confirmed_facts were withheld because the claim did not pass Harness validation.")
            threat.confirmed_facts = ""
            threat.analytical_interpretation = "The available evidence does not establish the event's asserted causes or consequences. Independent verification is required."
            src_title = str(matched_doc.get("title") or threat.fact_check_quote or "Unknown claim").strip()
            threat.threat_description = f"Unverified source claim ({matched_doc.get('doc_id', 'UNKNOWN')}): {src_title[:550]}. The reported event and its operational impacts have not been independently confirmed."[:800]
        elif threat.validation_status == ValidationStatus.PARTIALLY_SUPPORTED:
            if threat.claim_support_status != "STATED_IN_SOURCE" and full_quote_verified:
                threat.confirmed_facts = f"Source statement (event not fully verified): {threat.fact_check_quote or ''}"[:600]
            if _is_short_snippet(matched_doc) and (src_title := str(matched_doc.get("title") or "").strip()):
                did = matched_doc.get("doc_id", "UNKNOWN")
                threat.confirmed_facts = f"{did}: A source headline was published (underlying claim not independently verified): {src_title}"
                threat.threat_description = f"Preliminary source report ({did}): {src_title}"[:800]
                threat.analytical_interpretation = "A headline or short excerpt alone cannot establish the alleged cause, financial impact, or downstream operational consequences. Additional evidence is required."
                audit_notes.append("Headline-only source: headline recorded, substantive claims and causal implications not independently verified")

        if has_unknown_scm:
            flagged_unverified += 1
            threat.confidence_level = ConfidenceLevel.LOW
            audit_notes.append(f"Unclassified SCM entity in '{threat.company_affected}' set to Unknown (Verification Required)")

        doc_auth = _claim_authority(matched_doc)
        is_primary_origin = is_official and str(matched_doc.get("origin_type") or "").startswith("PRIMARY")
        threat.corroboration_summary = {
            "1. Technical Grounding": f"{threat.technical_grounding_status} (Full Quote & URL Match: {'YES' if full_quote_verified else 'NO'})",
            "2. Claim Support": threat.claim_support_status, "3. Causal Support": threat.causal_support_status,
            "4. Independent Verification": f"{threat.independent_verification_status} ({indep_count} non-syndicated source(s))",
            "5. Event Freshness": threat.event_freshness.value, "Program Relevance Scope": threat.program_relevance,
            "Source-Evidenced Program": threat.affected_program,
            "Hypothetical Shared Dependencies": ", ".join(threat.hypothetical_dependencies) if threat.hypothetical_dependencies else "None",
            "Event Epicenter": threat.geographic_epicenter,
            "Evidence Authority": str(matched_doc.get("evidence_authority") or ("FAA_FEDERAL_REGISTER" if faa_pub_ver else f"{doc_auth}_OFFICIAL_SOURCE" if doc_auth else "SEC_EDGAR" if is_exact_or_subdomain(domain, {"sec.gov"}) else "OEM_OFFICIAL_RELEASE" if is_primary_origin else "UNDETERMINED")),
            "Claim Authority": str(matched_doc.get("claim_authority") or ("REGULATOR_OFFICIAL_PUBLICATION" if (faa_pub_ver or doc_auth) else "ISSUER_REPORTED" if is_primary_origin else "UNDETERMINED")),
            "Regulatory Decision Verified": "YES" if (full_quote_verified and doc_auth and matched_doc.get("regulator_decision_verified") is True) else "NO_OR_UNKNOWN",
            "KIT Fact Dimensions": ", ".join(f"{k}={v}" for k, v in fact_audit.items()),
            "publication_date": _document_date(matched_doc, "published_at"), "event_date": ev_date_str,
            "effective_date": _document_date(matched_doc, "effective_date"),
            "deadline": _document_date({"deadline": matched_doc.get("deadline") or matched_doc.get("regulatory_compliance_deadline")}, "deadline"),
        }

        scm_label = getattr(threat.scm_tier, "value", str(threat.scm_tier))
        c_tier, e_tier = re.search(r"\bTier\s*[- ]?\s*([123])\b", threat.score_rationale or "", re.I), re.search(r"\bTier\s*[- ]?\s*([123])\b", scm_label, re.I)
        if c_tier and (not e_tier or c_tier.group(1) != e_tier.group(1)):
            threat.score_rationale = re.sub(r"[^.!?]*\bTier\s*[- ]?\s*[123]\b[^.!?]*[.!?]?", "", threat.score_rationale or "", flags=re.I).strip() or f"Potential severity: {threat.threat_score}/10. Supplier-tier contribution requires verification."
            threat.corroboration_summary["SCM Scoring Consistency"] = f"Conflicting supplier-tier assertion removed from score rationale. Validated classification: {scm_label}."
            audit_notes.append("Scoring rationale contained a supplier-tier assertion inconsistent with validated SCM classification.")

        risk_type_val = getattr(threat.risk_type, "value", str(threat.risk_type))
        if risk_type_val == "REGULATORY":
            _apply_regulatory_checks(threat, matched_doc, matched_text, full_quote_verified, faa_pub, faa_pub_ver, faa_lifecycle_ver, age, as_of_date, audit_notes)

        # Derive final event status, escalation level, and urgency.
        audit_suffix = f" [{' | '.join(audit_notes)}]" if audit_notes else ""
        is_fresh = threat.event_freshness in {EventFreshness.NEW_EVENT, EventFreshness.NEW_DEVELOPMENT}
        if is_sibling:
            threat.event_status = EventStatus.RELATED_PROGRAM_WATCHLIST
            threat.verification_status = f"RELATED PROGRAM WATCHLIST ({threat.affected_program}): Awaiting proof of shared-supplier impact on {sorted(kit_variants)}{audit_suffix}"
        elif threat.validation_status == ValidationStatus.SUPPORTED and threat.program_relevance != "DIRECT_KIT_MATCH":
            threat.event_status, threat.verification_status = EventStatus.UNDER_REVIEW, f"SUPPORTED SOURCE; DIRECT KIT RELEVANCE UNVERIFIED ({threat.event_freshness.value}){audit_suffix}"
        elif threat.validation_status == ValidationStatus.SUPPORTED and not has_unknown_scm:
            lbl = (f"Verified Issuer Filing Statement ({threat.event_freshness.value})" if is_exact_or_subdomain(domain, {"sec.gov"})
                   else f"Verified Primary Source ({threat.event_freshness.value} | 5-Step Grounding PASS)" if is_official
                   else f"Verified Secondary Source ({threat.event_freshness.value} | {indep_count} independent source(s))")
            threat.verification_status = f"{lbl}{audit_suffix}"
            threat.event_status = EventStatus.CRITICAL_RISK if (threat.threat_score >= 8 and threat.confidence_level == ConfidenceLevel.HIGH and is_fresh) else (EventStatus.ELEVATED_RISK if threat.threat_score >= 5 else EventStatus.CONFIRMED_EVENT)
        elif threat.validation_status == ValidationStatus.SUPPORTED:
            threat.event_status, threat.verification_status = EventStatus.UNDER_REVIEW, f"SUPPORTED CLAIM; SCM ROLE UNVERIFIED ({threat.event_freshness.value}){audit_suffix}"
        elif threat.validation_status == ValidationStatus.PARTIALLY_SUPPORTED:
            threat.event_status, threat.verification_status = EventStatus.UNDER_REVIEW, f"PARTIALLY SUPPORTED ({threat.event_freshness.value} | Manual Review Required){audit_suffix}"
        else:
            threat.confidence_level, threat.event_status = ConfidenceLevel.LOW, EventStatus.UNDER_REVIEW
            threat.verification_status = f"UNVERIFIED ({threat.event_freshness.value} | {threat.validation_status.value}){audit_suffix}"

        if threat.validation_status == ValidationStatus.PARTIALLY_SUPPORTED and threat.causal_support_status == "HYPOTHETICAL_ONLY":
            threat.threat_description = f"Source excerpt: {(threat.fact_check_quote or '')[:220]}. Claimed operational impacts require verification."

        if threat.threat_score >= 8 and threat.confidence_level == ConfidenceLevel.HIGH and threat.validation_status == ValidationStatus.SUPPORTED and threat.program_relevance == "DIRECT_KIT_MATCH" and is_fresh and not is_sibling:
            threat.escalation_level, threat.urgency = EscalationStatus.CRITICAL_CONFIRMED_ALERT, UrgencyLevel.HIGH
        elif threat.program_relevance == "PROGRAM_UNVERIFIED":
            threat.escalation_level, threat.urgency = EscalationStatus.PRIORITY_VERIFICATION_REQUIRED, UrgencyLevel.LOW
        elif is_sibling or not is_fresh:
            threat.escalation_level, threat.urgency = EscalationStatus.ROUTINE_MONITORING, (UrgencyLevel.MEDIUM if threat.threat_score >= 6 else UrgencyLevel.LOW)
        elif threat.threat_score >= 7 or threat.event_status == EventStatus.UNDER_REVIEW:
            threat.escalation_level, threat.urgency = EscalationStatus.PRIORITY_VERIFICATION_REQUIRED, (UrgencyLevel.HIGH if threat.threat_score >= 7 else UrgencyLevel.MEDIUM)
        elif threat.threat_score >= 4:
            threat.escalation_level, threat.urgency = EscalationStatus.ROUTINE_MONITORING, UrgencyLevel.MEDIUM
        else:
            threat.escalation_level, threat.urgency = EscalationStatus.ARCHIVED_LOW_RELEVANCE, UrgencyLevel.LOW

        if risk_type_val == "REGULATORY" and matched_doc.get("source_id") == "SRC_001" and threat.corroboration_summary.get("FAA Lifecycle Verified") == "YES":
            stage, q_str = threat.corroboration_summary.get("Regulatory Stage", "UNKNOWN"), threat.fact_check_quote or ""
            imp_in_q = bool(re.search(r"\b(?:production (?:halt|stoppage)|deliver(?:y|ies) delays?|ground(?:ing|ed) of aircraft)\b", q_str, re.I))
            threat.score_rationale = f"Official FAA action ({stage}) is evidenced by the cited document. Potential severity: {threat.threat_score}/10; deterministic urgency: {threat.urgency.value}; escalation: {threat.escalation_level.value}. " + ("Any additional downstream impacts require separate evidence." if imp_in_q else "The cited quotation does not establish grounding, production stoppage, delivery delays, or an immediate compliance deadline.")
            if not re.search(r"\b(?:production (?:halt|stoppage)|delivery delays?|grounded aircraft|aircraft grounding)\b", q_str, re.I):
                threat.adversarial_scenario = "HYPOTHETICAL SCENARIO — NOT EVIDENCED: Applicable FAA inspection requirements could increase maintenance workload if capacity constraints arise. Actual grounding, production stoppage and delivery disruption are not established by the cited evidence."
                if stage in {"EFFECTIVE", "FINAL_ISSUED"}:
                    threat.analytical_interpretation = "The FAA airworthiness directive establishes regulatory inspection requirements. Potential effects on maintenance capacity, aircraft availability, production or deliveries remain hypothetical until supported by additional operational evidence."

        if matched_doc.get("origin_type") == "PRIMARY_OFFICIAL_INDEX_METADATA" and threat.validation_status in {ValidationStatus.SUPPORTED, ValidationStatus.PARTIALLY_SUPPORTED}:
            threat.validation_status, threat.confidence_level, threat.event_status = ValidationStatus.PARTIALLY_SUPPORTED, ConfidenceLevel.LOW, EventStatus.UNDER_REVIEW
            easa_title = str(matched_doc.get("title") or "EASA directive").strip()
            threat.threat_description = f"Official EASA index records: {easa_title}. The complete directive text was not analyzed."[:800]
            threat.confirmed_facts = f"Official EASA index entry: {easa_title}. Publication date: {canonical_date}."
            threat.analytical_interpretation = "Official metadata confirm the publication and its stated subject. Exact inspection intervals, compliance duties and operational effects require verification against the full directive."
            threat.corroboration_summary["Evidence Scope"] = "PUBLICATION_VERIFIED; TECHNICAL_CONTENT_NOT_READ; OPERATIONAL_IMPACT_NOT_VERIFIED"
            threat.score_rationale = f"Potential severity: {threat.threat_score}/10. Official index metadata verify the publication but do not independently establish additional maintenance workload, aircraft grounding, delivery delays or immediate compliance duties."
            threat.escalation_level = EscalationStatus.PRIORITY_VERIFICATION_REQUIRED

        # Map KIQ IDs, populate missing-data gaps, and finalize corroboration summary.
        threat.kiq_ids = match_kiqs_for_threat(threat, catalog)
        if threat.intelligence_gap and ((cg := str(threat.intelligence_gap.affected_kiq_id or "").strip()) not in allowed_kiqs or (threat.kiq_ids and cg not in threat.kiq_ids)):
            threat.intelligence_gap.affected_kiq_id = threat.kiq_ids[0] if threat.kiq_ids else ""
        if threat.missing_data and threat.missing_data.strip().lower() in {"none", "null", "n/a", "not available", "unspecified", ""}:
            threat.missing_data = None
        if is_sibling:
            threat.missing_data = f"Prove concrete shared-supplier or shared-component impact mechanism from {threat.affected_program} onto {sorted(kit_variants)}."
        elif audit_notes and not threat.missing_data:
            threat.missing_data = f"Verification required: {'; '.join(audit_notes[:2])}."
        elif not threat.missing_data:
            threat.missing_data = (
                "Exact publication or incident date is missing from source metadata." if threat.publication_time == "DATE_UNKNOWN"
                else f"Independent primary corroboration required for {threat.company_affected} ({threat.affected_program})." if threat.confidence_level == ConfidenceLevel.LOW
                else f"Single secondary source for {threat.company_affected} ({threat.affected_program}); independent confirmation needed." if (indep_count == 1 and threat.threat_score >= 7 and not is_official) else None
            )
        if threat.missing_data and not threat.intelligence_gap:
            threat.intelligence_gap = IntelligenceGap(
                what_is_missing=threat.missing_data, why_important=f"Needed to confirm {threat.propagation_effect.value} impact on {threat.company_affected} ({threat.affected_program}).",
                affected_kiq_id=threat.kiq_ids[0] if threat.kiq_ids else "", recommended_source="FAA / EASA / Official OEM Pressroom", can_auto_scan=True, status="OPEN",
            )
        threat.corroboration_summary.update({
            "Severity": f"{threat.threat_score}/10 (potential impact, not verification)", "Confidence": threat.confidence_level.value,
            "Verification": threat.validation_status.value, "Current Status": threat.event_status.value,
        })
        threat.is_critical = is_confirmed_critical(threat)
        (watchlist_threats if is_sibling else validated_threats).append(threat)

    report.threats, report.related_program_watchlist = validated_threats, watchlist_threats
    if not report.kiq_answers:
        report.kiq_answers = [
            KIQAnswer(
                kiq_id=item["kiq_id"], question=item["question"], answer_status="PARTIALLY_ANSWERED",
                answer=" ".join(
                    f"For {t.company_affected}{f' ({t.affected_program})' if t.affected_program and not t.affected_program.lower().startswith('unknown') else ''}, available evidence notes: {(t.confirmed_facts or t.fact_check_quote or t.threat_description or '').strip().rstrip('.')}{f' [{t.evidence_ids[0]}]' if t.evidence_ids else ''}."
                    for t in rel[:2]
                )[:450],
                related_event_ids=[t.event_id for t in rel],
                evidence_ids=list(dict.fromkeys(eid for t in rel for eid in t.evidence_ids)),
                verification_status="Event evidence evaluated; complete KIQ coverage not established",
                uncertainty_level=ConfidenceLevel.MEDIUM if any(t.confidence_level == ConfidenceLevel.HIGH and t.validation_status == ValidationStatus.SUPPORTED for t in rel) else ConfidenceLevel.LOW,
                recommended_next_step="Verify remaining KIQ facets before marking fully answered.",
                missing_information=next((t.missing_data for t in rel if t.missing_data), "Completeness of required KIQ facets not verified."),
            )
            for item in catalog if (rel := [t for t in validated_threats if item["kiq_id"] in t.kiq_ids])
        ]

    for answer in report.kiq_answers:
        if str(getattr(answer.answer_status, "value", answer.answer_status)).upper() == "ANSWERED" and not any(
            answer.kiq_id in t.kiq_ids and t.program_relevance == "DIRECT_KIT_MATCH" and t.validation_status == ValidationStatus.SUPPORTED for t in validated_threats
        ):
            answer.answer_status = "PARTIALLY_ANSWERED"
            answer.missing_information = answer.missing_information or "No fully supported direct evidence for this KIQ."

    direct_val = [t for t in validated_threats if t.program_relevance == "DIRECT_KIT_MATCH"]
    event_dids = {eid for t in validated_threats + watchlist_threats for eid in (t.evidence_ids or [])}
    kiq_dids = {eid for a in report.kiq_answers for eid in (a.evidence_ids or [])}
    disposition = {d["doc_id"]: ("USED_IN_KIQ_ANSWER" if d["doc_id"] in kiq_dids else "REFERENCED_BY_EVENT_NOT_KIQ" if d["doc_id"] in event_dids else "NOT_REFERENCED_BY_ANALYST_RELEVANCE_UNDETERMINED") for d in docs if isinstance(d, dict) and d.get("doc_id")}
    grounding_summary = (
        f"Five-Dimensional Grounding (Technical, Claim, Causal, Independent Verification, Freshness) completed. | "
        f"[Harness Guard]: {sum(t.validation_status == ValidationStatus.SUPPORTED for t in direct_val)}/{len(direct_val)} direct signals SUPPORTED, "
        f"{sum(t.validation_status == ValidationStatus.PARTIALLY_SUPPORTED for t in direct_val)} PARTIALLY_SUPPORTED, "
        f"{sum(t.event_freshness == EventFreshness.ONGOING_ISSUE for t in direct_val)} classified as ONGOING_ISSUE, "
        f"{len(watchlist_threats)} moved to RELATED_PROGRAM_WATCHLIST, {flagged_unverified} flagged for manual HITL verification."
    )
    prov_summary = (" | Evidence disposition (not a filtering verdict): " + "; ".join(f"{k}={v}" for k, v in disposition.items())) if disposition else ""
    report.qa_audit_summary = " | ".join(filter(None, (str(report.qa_audit_summary or "").strip(), grounding_summary))) + prov_summary
    return report, validation_errors