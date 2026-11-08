# =============================================================================
# aviation_ci_app | Deterministic evidence, technical-identity, and alert validation
#
# Responsibility: Verify source provenance, quotation alignment, aircraft/engine identity, event
#   freshness, corroboration, and impact assertions.
# Design boundary: Confirmed critical escalation requires source-supported findings, direct KIT relevance,
#   and adequate confidence.
# =============================================================================

"""Deterministic checks for source grounding, event identity, and alert eligibility."""

from datetime import date, datetime, timezone

from ews_database import get_active_kiq_catalog
from ews_kiq import match_kiqs_for_threat
from ews_state import (
    Any, CONTRADICTION_MARKERS, ConfidenceLevel, Dict, EWSReport,
    EscalationStatus, EventFreshness, EventStatus, IntelligenceGap,
    KIQAnswer, List, Optional, SCMTier, SPECULATIVE_DISINFO_MARKERS,
    SequenceMatcher, ThreatAssessment, Tuple, UNVERIFIED_SOCIAL_VIDEO_DOMAINS,
    UrgencyLevel, ValidationStatus, get_collected_documents,
    lookup_supplier_in_registry, normalize_date_str, re, urlparse,
)


# Check the full evidence, confidence, relevance, and escalation conditions for critical alerts.
def is_confirmed_critical(threat: ThreatAssessment) -> bool:
    """A confirmed critical alert requires both high severity and sufficient evidence."""
    return (
            threat.threat_score >= 8
            and threat.validation_status == ValidationStatus.SUPPORTED
            and threat.confidence_level == ConfidenceLevel.HIGH
            and threat.escalation_level == EscalationStatus.CRITICAL_CONFIRMED_ALERT
            and threat.program_relevance == "DIRECT_KIT_MATCH"
    )


# Detect assessment states that do not establish a verified event.
def is_unverified_signal(threat: ThreatAssessment) -> bool:
    return threat.validation_status in {
        ValidationStatus.UNSUPPORTED,
        ValidationStatus.CONTRADICTED,
        ValidationStatus.UNVERIFIED_COMMUNITY,
    }


# Canonicalize punctuation and spacing before source-grounding comparisons.
def normalize_text(text: str) -> str:
    if not text:
        return ""
    text = re.sub(r"[\u2010-\u2015]", "-", text)
    text = re.sub(r"[\u2018-\u201B\u00B4\u0060]", "'", text)
    text = re.sub(r"[\u201C-\u201F]", '"', text)
    return re.sub(r"\s+", " ", text).strip()


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


# Technical identity dictionaries are lexical hints; they are not installation or applicability proof.
ENGINE_MODEL_PATTERNS: Dict[str, re.Pattern] = {

    # ============================================================
    # CFM International engine names (family labels remain distinct from variant identities).
    # ============================================================

    "CFM56": re.compile(
        r"\bcfm[\s-]?56\b", re.I
    ),

    "LEAP-1A": re.compile(
        r"\bleap[\s-]*1a\b", re.I
    ),

    "LEAP-1B": re.compile(
        r"\bleap[\s-]*1b\b", re.I
    ),

    "LEAP-1C": re.compile(
        r"\bleap[\s-]*1c\b", re.I
    ),

    "LEAP": re.compile(
        r"\bleap\b", re.I
    ),

    # ============================================================
    # Pratt & Whitney models; GTF is a broad family term, not synonymous with PW1100G.
    # ============================================================

    "PW1100G_GTF": re.compile(
        r"\bpw11\d{2}g(?:[\s-]*jm)?\b", re.I
    ),

    "PW1500G_GTF": re.compile(
        r"\bpw15\d{2}g\b", re.I
    ),

    "PW1900G_GTF": re.compile(
        r"\bpw19\d{2}g\b", re.I
    ),

    "GTF": re.compile(
        r"\b(?:gtf|geared[ -]turbofan)\b", re.I
    ),

    "PW4000": re.compile(
        r"\bpw[\s-]*4000\b", re.I
    ),

    "PW2000": re.compile(
        r"\bpw[\s-]*2000\b", re.I
    ),

    # ============================================================
    # GE Aerospace and Engine Alliance model identifiers.
    # ============================================================

    "GE90": re.compile(
        r"\bge[\s-]?90\b", re.I
    ),

    "GE9X": re.compile(
        r"\bge[\s-]?9x\b", re.I
    ),

    "GENX": re.compile(
        r"\bge[\s-]?nx\b", re.I
    ),

    "CF34": re.compile(
        r"\bcf[\s-]?34\b", re.I
    ),

    "CF6": re.compile(
        r"\bcf[\s-]?6\b", re.I
    ),

    "GP7000": re.compile(
        r"\bgp[\s-]?7000\b", re.I
    ),

    # ============================================================
    # Rolls-Royce engine families and named variants.
    # ============================================================

    "TRENT_1000": re.compile(
        r"\btrent[\s-]*1000\b", re.I
    ),

    "TRENT_7000": re.compile(
        r"\btrent[\s-]*7000\b", re.I
    ),

    "TRENT_700": re.compile(
        r"\btrent[\s-]*700\b", re.I
    ),

    "TRENT_900": re.compile(
        r"\btrent[\s-]*900\b", re.I
    ),

    "TRENT_XWB": re.compile(
        r"\btrent[\s-]*xwb(?:[\s-]*\d+)?\b", re.I
    ),

    "RB211": re.compile(
        r"\brb[\s-]*211\b", re.I
    ),

    # ============================================================
    # International Aero Engines and other historically monitored engine models.
    # ============================================================

    "V2500": re.compile(
        r"\bv[\s-]?2500\b", re.I
    ),

    "AE3007": re.compile(
        r"\bae[\s-]*3007\b", re.I
    ),
}

SPECIFIC_AIRCRAFT_VARIANT_PATTERNS: Dict[str, re.Pattern] = {
    "777X": re.compile(r"\b(?:777xs?|777-8|777-9|b777x)\b", re.I),
    "777F": re.compile(r"\b(?:777f|777\s+freighter|b777f)\b", re.I),
    "777_LEGACY": re.compile(r"\b(?:777-200|777-300(?:er)?)\b", re.I),
    "737_MAX": re.compile(r"\b(?:737[\s_-]*max|737-7|737-8|737-9|737-10|max\s*[789]|max\s*10)\b", re.I),
    "737_NG": re.compile(r"\b(?:737\s*ng|737-700|737-800|737-900)\b", re.I),
    "787": re.compile(r"\b(?:787|787-8|787-9|787-10|dreamliner)\b", re.I),
    "767": re.compile(r"\b(?:767|767-300f?)\b", re.I),
    "A321XLR": re.compile(r"\ba321\s*xlr\b", re.I),
    "A320NEO_FAMILY": re.compile(
        r"\b(?:"
        r"a3(?:19|20|21)[\s-]*neo"
        r"|a3(?:19|20|21)-\d{3}n[a-z]?"
        r"|a320neo_family"
        r")\b",
        re.I,
    ),
    "A320CEO_FAMILY": re.compile(r"\ba3(?:18|19|20|21)\s*ceo\b", re.I),
    "A350F": re.compile(r"\ba350f\b", re.I),
    "A350": re.compile(r"\ba350(?:-\d{3})?\b", re.I),
    "A330NEO": re.compile(r"\ba330\s*neo|a330-900\b", re.I),
    "A220": re.compile(r"\ba220(?:-[13]00)?\b", re.I),
    "C919": re.compile(r"\bc919\b", re.I),
    "C909": re.compile(
        r"\b(?:c909|arj[\s-]?21)\b",
        re.I,
    ),

    "EJET_E2": re.compile(
        r"\be(?:175|190|195)[\s-]?e2\b",
        re.I,
    ),
}

AIRCRAFT_FAMILY_PATTERNS: Dict[str, re.Pattern] = {

    # Airbus aircraft-family aliases for lexical program identification.
    "A220": re.compile(
        r"\ba220(?:-\d{3})?\b", re.I
    ),

    "A320_FAMILY": re.compile(
        r"\ba3(?:18|19|20|21)"
        r"(?:[\s-]?(?:neo|ceo|xlr|lr)|-\d{3}[a-z]{0,2})?\b",
        re.I,
    ),

    "A330": re.compile(
        r"\ba330(?:[\s-]?neo|-\d{3}[a-z]?)?\b", re.I
    ),

    "A350": re.compile(
        r"\ba350(?:-\d{3}|f)?\b", re.I
    ),

    "A380": re.compile(
        r"\ba380(?:-\d{3})?\b", re.I
    ),

    "A400M": re.compile(
        r"\ba400m\b", re.I
    ),

    # Boeing aircraft-family aliases for lexical program identification.
    "B737": re.compile(
        r"\b(?:b\s*)?737(?:[\s-]?(?:max|ng|\d{1,4}))?\b",
        re.I,
    ),

    "B747": re.compile(
        r"\b(?:b\s*)?747(?:-\d{3}[a-z]?)?\b",
        re.I,
    ),

    "B757": re.compile(
        r"\b(?:b\s*)?757(?:-\d{3})?\b",
        re.I,
    ),

    "B767": re.compile(
        r"\b(?:b\s*)?767(?:-\d{3}[a-z]?)?\b",
        re.I,
    ),

    "B777": re.compile(
        r"\b(?:b\s*)?777(?:x|-[0-9]{1,3}[a-z]?)?\b",
        re.I,
    ),

    "B787": re.compile(
        r"\b(?:b\s*)?787(?:-\d{1,2})?\b|\bdreamliner\b",
        re.I,
    ),

    # COMAC: C919 and C909/ARJ21 remain distinct programs.
    "C919": re.compile(
        r"\bc919\b", re.I
    ),

    "C909": re.compile(
        r"\b(?:c909|arj[\s-]?21)\b", re.I
    ),

    # Embraer regional-jet family aliases.
    "E_JETS": re.compile(
        r"\b(?:e[\s-]?(?:170|175|190|195)"
        r"(?:[\s-]?e2)?|"
        r"erj[\s-]?(?:170|175|190|195))\b",
        re.I,
    ),

    # Other regional aircraft families.
    "ATR": re.compile(
        r"\batr[\s-]?(?:42|72)(?:-\d{3})?\b",
        re.I,
    ),

    "CRJ": re.compile(
        r"\bcrj[\s-]?(?:200|700|900|1000)\b",
        re.I,
    ),

    "Q400": re.compile(
        r"\b(?:dash[\s-]?8[\s-]?q400|q400)\b",
        re.I,
    ),
}

# Central aerospace component vocabulary used in deterministic evidence checks.
# Aliases share a canonical label; a text match does not independently verify a defect.

COMPONENT_KEYWORDS_MAP: Dict[str, str] = {

    # ============================================================
    # ENGINE & PROPULSION SYSTEMS
    # ============================================================

    "fire switch": "Engine Fire Switch / Cockpit Fire Panel",

    "powder metal": "High-Pressure Turbine Discs (Powder Metal)",
    "powdered metal": "High-Pressure Turbine Discs (Powder Metal)",

    "fan blade": "Engine Fan Blades",
    "fan blades": "Engine Fan Blades",

    "turbine blade": "Engine Turbine Blades",
    "turbine blades": "Engine Turbine Blades",

    "compressor blade": "Engine Compressor Blades",
    "compressor blades": "Engine Compressor Blades",

    "combustor": "Engine Combustion System",
    "combustion chamber": "Engine Combustion System",

    # ============================================================
    # FUEL & HYDRAULIC SYSTEMS
    # ============================================================

    "hydraulic pump": "Hydraulic Pump",
    "hydraulic pumps": "Hydraulic Pump",

    "fuel pump": "Fuel Pump",
    "fuel pumps": "Fuel Pump",

    "fuel tank": "Aircraft Fuel Tank",
    "fuel tanks": "Aircraft Fuel Tank",

    # ============================================================
    # AVIONICS & ELECTRICAL SYSTEMS
    # ============================================================

    "avionics": "Flight Deck Avionics System",

    "wiring harness": "Electrical Wiring Harness",
    "wiring harnesses": "Electrical Wiring Harness",

    "flight management system": "Flight Management System",
    "flight management computer": "Flight Management System",

    # ============================================================
    # AIRCRAFT STRUCTURES
    # ============================================================

    "fuselage": "Aircraft Fuselage Structure",

    "door plug": "Fuselage Door Plug",
    "door plugs": "Fuselage Door Plug",

    "wing spar": "Wing Spar",
    "wing spars": "Wing Spar",

    "engine pylon": "Engine Pylon",
    "engine pylons": "Engine Pylon",

    "slotted nut": "Wing Thrust Spigot Slotted Nuts",

    "trailing-edge rib kit": "Wing Trailing-Edge Rib Kit",

    # ============================================================
    # FLIGHT CONTROL SYSTEMS
    # ============================================================

    "flight control actuator": "Flight Control Actuator",
    "flight control actuators": "Flight Control Actuator",

    "hydraulic actuator": "Hydraulic Actuator",
    "hydraulic actuators": "Hydraulic Actuator",

    # ============================================================
    # LANDING GEAR & BRAKING
    # ============================================================

    "landing gear": "Landing Gear System",

    "brake assembly": "Aircraft Brake Assembly",
    "brake assemblies": "Aircraft Brake Assembly",

    # ============================================================
    # SAFETY & EMERGENCY SYSTEMS
    # ============================================================

    "evacuation slide": "Door Emergency Evacuation Slide System",

    # ============================================================
    # MATERIALS & MANUFACTURING
    # ============================================================

    "titanium": "Aerospace Titanium Forgings / Raw Material",

    "casting": "Precision Turbine Castings",
}

HYPOTHETICAL_IN_FACTS_REGEX = re.compile(
    r"\b(?:could|might|would|potentially|hypothetical\w*|speculat\w*|if\s+this|may\s+lead\s+to|threatens\s+to)\b", re.I
)
CAUSAL_CLAIM_REGEX = re.compile(
    r"\b(?:caus(?:es|ed|ing)|lead(?:s|ing)\s+to|result(?:s|ed|ing)\s+in|forc(?:es|ed|ing)|trigger(?:s|ed|ing)|due\s+to|because\s+of|prompted\s+by|delays?\s+delivery)\b",
    re.I,
)

EVENT_LOCATION_EVIDENCE_MAP: Dict[str, re.Pattern] = {
    "North America (USA / Canada)": re.compile(
        r"\b(?:united\s+states|u\.s\.|usa|faa|ntsb|federal\s+register|renton|everett|charleston|wichita|"
        r"seattle|connecticut|east\s+hartford|clayville|goodyear|arizona|dallas|detroit|mobile,\s+alabama|"
        r"canada|mirabel|montreal|toronto)\b", re.I
    ),
    "Europe (EU / UK / France / Germany)": re.compile(
        r"\b(?:europe\w*|easa|toulouse|hamburg|farnborough|paris|france|germany|united\s+kingdom|u\.k\.|"
        r"britain|london|derby|filton|bremen|madrid|spain|italy|dublin|hungary|warsaw|istanbul|turkish)\b", re.I
    ),
    "Asia-Pacific (China / Singapore / Japan / India)": re.compile(
        r"\b(?:china|shanghai|beijing|tianjin|singapore|india|new\s+delhi|mumbai|japan|tokyo|south\s+korea|"
        r"seoul|taiwan|taipei|australia|sydney|melbourne)\b", re.I
    ),
    "Middle East (UAE / Qatar / Saudi Arabia)": re.compile(
        r"\b(?:dubai|uae|united\s+arab\s+emirates|abu\s+dhabi|qatar|doha|saudi\s+arabia|riyadh|jeddah)\b", re.I
    ),
}

_EVENT_LOCATION_PATTERN = re.compile(
    r"\b(?:production|assembly|manufacturing|factory|plant|facility|incident|disruption|"
    r"strike|accident|ground test|stoppage|production halt)\b.{0,90}?\b(?:in|at|near)\s+"
    r"(Everett|Seattle|Renton|Wichita|Florida|Washington|Charleston|Toulouse|Hamburg|Bremen|"
    r"Derby|Farnborough|Shanghai|Tianjin|Singapore|Montreal|Mirabel|Dubai|Doha)\b",
    re.I | re.S,
)

_LOCATION_TO_REGION = {
    **{k: "North America (USA / Canada)" for k in
       ("everett", "seattle", "renton", "wichita", "florida", "washington", "charleston", "montreal", "mirabel")},
    **{k: "Europe (EU / UK / France / Germany)" for k in ("toulouse", "hamburg", "bremen", "derby", "farnborough")},
    **{k: "Asia-Pacific (China / Singapore / Japan / India)" for k in ("shanghai", "tianjin", "singapore")},
    **{k: "Middle East (UAE / Qatar / Saudi Arabia)" for k in ("dubai", "doha")},
}

_WIRE_PATTERNS = {
    "REUTERS": re.compile(r"\breuters\b", re.I),
    "ASSOCIATED_PRESS": re.compile(r"\b(?:associated press|ap news)\b", re.I),
    "AGENCE_FRANCE_PRESSE": re.compile(r"\b(?:agence france.presse|afp)\b", re.I),
}

_PRIOR_PERIOD_CAUSE_RE = re.compile(
    r"\b(?:year[- ]ago|prior[- ]year|previous[- ]year)\b.{0,100}\b(?:mostly|mainly|primarily|largely)\s+(?:from|due to|because of)\b",
    re.I | re.S,
)
_CURRENT_PERIOD_RE = re.compile(r"\b(?:q[1-4]\s*20\d{2}|20\d{2}\s+q[1-4])\b", re.I)
_CLAIM_CAUSE_RE = re.compile(
    r"\b(?:primary\s+cause\s*:|(?:mainly|primarily|mostly|largely)\s+(?:due\s+to|from|because\s+of))", re.I)

_EXACT_VARIANT_RE = re.compile(
    r"(?<!\w)(?:[AB]\s*)?(\d{3})(?:[\s_-]*(max|neo|ceo|xlr|lr|er)(?:[\s_-]*(\d{1,3}))?|[\s_-]+(\d{1,3}))?(?!\w)",
    re.I,
)

AIRLINE_AND_REGULATOR_PATTERN = re.compile(
    r"\b(?:airlines?|airways|air\s+canada|qantas|indigo|wizz(?:\s*air)?|lufthansa|ryanair|delta|"
    r"united|american\s+airlines|jetblue|easyjet|emirates|etihad|qatar|flydubai|starlux|aegean|"
    r"iberia|klm|air\s+france|turkish|spirit\s+airlines|cyprus|aircastle|aer\s+lingus|korean\s+air|"
    r"asiana|jeju\s+air|jin\s+air|hainan|volotea|condor|norwegian|swiss|austrian|flyone|ajet|"
    r"faa|easa|ntsb|caa|icao|iata|federal\s+aviation|safety\s+agency|ministry|regulator\w*)\b",
    re.I,
)

REGISTRY_TIER_MAP: Dict[str, SCMTier] = {
    "OEM (Final Assembler)": SCMTier.OEM,
    "Tier 1 (Systems/Engines)": SCMTier.TIER_1,
    "Tier 2 (Subcomponents)": SCMTier.TIER_2,
    "Tier 3 (Raw Materials)": SCMTier.TIER_3,
    "Regulator / Airline": SCMTier.REGULATOR_AIRLINE,
}

ONGOING_OR_RECONFIRMED_PATTERNS = re.compile(
    r"\b(?:reaffirm\w*|reconfirm\w*|reiterat\w*|previously\s+(?:announced|delayed|pushed)|"
    r"contin(?:ues|ued)\s+to\s+(?:expect|anticipate|target)|still\s+expects?|"
    r"maintains?\s+(?:its\s+)?(?:20\d{2}|schedule|target)|on\s+track\s+for\s+20\d{2}|remains?\s+scheduled)\b",
    re.I,
)

HISTORICAL_RECAP_PATTERNS = re.compile(r"\b(?:in\s+20\d{2}|years\s+ago|history\s+of|documentary)\b", re.I)

# Identify explicit engine names; generic family labels must not override specific variants.
_GTF_SPECIFIC_MODELS = frozenset({
    "PW1100G_GTF",
    "PW1500G_GTF",
    "PW1900G_GTF",
})

_LEAP_SPECIFIC_MODELS = frozenset({
    "LEAP-1A",
    "LEAP-1B",
    "LEAP-1C",
})


def _detect_engine_models(text: str) -> set[str]:
    """
    Detect explicit engine identities.

    Specific models take precedence over generic engine families.
    """

    detected = {
        engine
        for engine, pattern in ENGINE_MODEL_PATTERNS.items()
        if pattern.search(text or "")
    }

    # Suppress generic family names when a specific engine identifier appears in the same text.
    if detected & _LEAP_SPECIFIC_MODELS:
        detected.discard("LEAP")

    if detected & _GTF_SPECIFIC_MODELS:
        detected.discard("GTF")

    return detected


def _engine_models_match(
        query: str,
        evidence: str,
) -> bool:
    """
    Determine whether engine identities are compatible.

    Rules:
    - Exact model match is accepted.
    - Generic family in KIT may match a specific family member.
    - Specific KIT model cannot be confirmed by generic family alone.
    - Different specific variants must not match.
    """

    wanted = _detect_engine_models(query)
    found = _detect_engine_models(evidence)

    if not wanted or not found:
        return False

    # Prefer an exact engine variant over a generic family overlap.
    if wanted & found:
        return True

    # A generic LEAP KIT includes its explicit variant identifiers.
    if (
            "LEAP" in wanted
            and found & _LEAP_SPECIFIC_MODELS
    ):
        return True

    # A generic GTF KIT includes its explicit variant identifiers.
    if (
            "GTF" in wanted
            and found & _GTF_SPECIFIC_MODELS
    ):
        return True

    return False


# Identify aircraft program variants; engine identity is checked separately.
def _detect_specific_variants(text: str) -> set[str]:
    return {var for var, pat in SPECIFIC_AIRCRAFT_VARIANT_PATTERNS.items() if pat.search(text or "")}


# Keep exact type designations separate from broad aircraft-family mentions.
def _detect_exact_variants(text: str) -> set[str]:
    return {
        f"{base}:{'' if kind.lower() == 'max' else kind.upper()}{num or tail}"
        for base, kind, num, tail in _EXACT_VARIANT_RE.findall(text or "")
        if num or tail or (kind and kind.lower() != "max")
    }


# Normalize aircraft references into controlled program families.
def _detect_aircraft_families(text: str) -> set[str]:
    return {fam for fam, pat in AIRCRAFT_FAMILY_PATTERNS.items() if pat.search(text or "")}


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
def _normalize_for_quote_match(text: str) -> str:
    norm = re.sub(r"[^\w\s]", " ", normalize_text(text).lower())
    return re.sub(r"\s+", " ", norm).strip()


# Recognize source records whose limited text cannot support a factual finding.
def _is_snippet_only(doc: Dict[str, Any]) -> bool:
    text = str(doc.get("text") or "").strip()
    title = str(doc.get("title") or "").strip()

    return (
            len(text) < 220
            or str(doc.get("origin_type") or "").endswith(
        "RSS_METADATA_ONLY"
    )
            or "[OFFICIAL_RSS_METADATA_ONLY:" in text
            or "[NEWSAPI_METADATA_ONLY:" in text
            or _normalize_for_quote_match(text)
            == _normalize_for_quote_match(title)
            or doc.get("source_id") == "SRC_009"
    )


# Split and normalize multiple organizations named in one event.
def _split_affected_entities(company_affected: str) -> List[str]:
    if not company_affected:
        return []
    protected = re.sub(r"pratt\s*&\s*whitney", "Pratt_And_Whitney", company_affected, flags=re.I)
    entities = [
        p.replace("Pratt_And_Whitney", "Pratt & Whitney").strip()
        for p in re.split(r"[,;/|]+|\band\b", protected, flags=re.I)
    ]
    return [e for e in entities if len(e) >= 2] or [company_affected.strip()]


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
        reg_match = lookup_supplier_in_registry(ent, exact=True)
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
        if is_exact_or_subdomain(domain, {"federalregister.gov", "easa.europa.eu", "ntsb.gov", "faa.gov", }):
            has_true_primary_regulator = True
        elif is_exact_or_subdomain(domain, {"airbus.com", "boeing.com", "boeing.mediaroom.com", "comac.cc"}):
            has_true_primary_oem = True

    return len(distinct_clusters), has_true_primary_regulator, has_true_primary_oem


def find_superseding_faa_certification(
        threat,
        documents,
        as_of_date="",
):
    claim = (
        f"{threat.fact_check_quote or ''} "
        f"{threat.threat_description or ''}"
    )

    if not re.search(
            r"\b(?:certif\w*|faa approval)\b",
            claim,
            re.I,
    ):
        return None

    if not re.search(
            r"\b(?:imminent|pending|await\w*|expect\w*|"
            r"could come|may come|soon|still in review)\b",
            claim,
            re.I,
    ):
        return None

    variants = _detect_exact_variants(claim)

    if not variants:
        return None

    reference = str(
        as_of_date or datetime.now(timezone.utc).date()
    )[:10]

    for doc in documents:
        domain = extract_effective_publisher_domain(
            doc.get("url") or ""
        )

        if not is_exact_or_subdomain(
                domain,
                {"faa.gov"},
        ):
            continue

        if (
                _is_snippet_only(doc)
                or "RSS_METADATA_ONLY" in str(
            doc.get("origin_type") or ""
        )
        ):
            continue

        doc_date = str(
            doc.get("published_at") or ""
        )[:10]

        if (
                not re.fullmatch(
                    r"20\d{2}-\d{2}-\d{2}",
                    doc_date,
                )
                or doc_date > reference
        ):
            continue

        title = str(doc.get("title") or "")

        if not (
                variants & _detect_exact_variants(title)
        ):
            continue

        if not re.search(
                r"\b(?:faa|federal aviation administration)\b",
                title,
                re.I,
        ):
            continue

        if not re.search(
                r"\b(?:certif(?:ies|ied)|"
                r"certification\s+(?:issued|granted|completed)|"
                r"issues?\s+(?:type\s+)?certification)\b",
                title,
                re.I,
        ):
            continue

        if re.search(
                r"\b(?:pending|planned|expected|proposed|"
                r"imminent|seeks?|awaiting|denied|"
                r"revoked|suspended)\b",
                title,
                re.I,
        ):
            continue

        return doc

    return None


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
        threat: ThreatAssessment, doc_raw_full: str, is_already_in_db: bool = False, as_of_date: str = ""
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
    if age is None or age > 30 or threat.claim_support_status == "UNSUPPORTED":
        return EventFreshness.EVENT_DATE_UNKNOWN

    return threat.event_freshness


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
    doc_norm = _normalize_for_quote_match(doc_raw_full)
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

    is_snippet_only = _is_snippet_only(matched_doc)
    fact_words = [
        w for w in re.findall(r"\b[a-z0-9]{4,}\b", _normalize_for_quote_match(threat.confirmed_facts))
        if w not in {"source", "states", "confirmed", "reports", "aircraft", "airline", "company"}
    ]
    fact_overlap = (sum(1 for w in fact_words if w in doc_norm) / len(fact_words)) if fact_words else 0.0

    claim_has_causality = bool(CAUSAL_CLAIM_REGEX.search(f"{threat.confirmed_facts} {threat.threat_description}"))
    doc_has_causality = bool(CAUSAL_CLAIM_REGEX.search(doc_raw_full))

    if claim_has_causality and doc_has_causality and fact_overlap >= 0.65:
        if is_unverified_or_community_source or is_snippet_only:
            causal_status = "CLAIMED_IN_UNVERIFIED_SOURCE"
            notes.append("Causality is stated in an unverified/community or snippet source (not objectively proven)")
        else:
            causal_status = "EVIDENCED_IN_VERIFIED_SOURCE"
    elif claim_has_causality:
        causal_status = "HYPOTHETICAL_ONLY"
        notes.append("Causal link or downstream impact is analytical/hypothetical")
    else:
        causal_status = (
            "CLAIMED_IN_UNVERIFIED_SOURCE"
            if is_unverified_or_community_source
            else ("EVIDENCED_IN_VERIFIED_SOURCE" if not is_snippet_only else "HYPOTHETICAL_ONLY")
        )

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
    claimed = set(re.findall(impact_re, f"{threat.threat_description or ''} {threat.confirmed_facts or ''}", re.I))
    cited = set(re.findall(impact_re, threat.fact_check_quote or "", re.I))

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
    docs_by_id: Dict[str, Dict[str, Any]] = {d["doc_id"]: d for d in docs}
    docs_by_url: Dict[str, Dict[str, Any]] = {d["url"]: d for d in docs if d.get("url")}

    active_kit_query = user_query or (report.run_metadata or {}).get("query", "")
    kit_target_variants = _detect_specific_variants(active_kit_query)
    kit_exact = _detect_exact_variants(active_kit_query)
    kit_engines = _detect_engine_models(active_kit_query)
    kit_components = {
        comp_label for kw, comp_label in COMPONENT_KEYWORDS_MAP.items()
        if re.search(rf"\b{re.escape(kw)}\b", active_kit_query, re.I)
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

        matched_doc = next(
            (
                ed for ed in explicit_docs
                if full_quote_norm and full_quote_norm in _normalize_for_quote_match(
                f"{ed.get('title', '')} {ed.get('text', '')}")
            ),
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
                {"faa.gov", "boeing.mediaroom.com", "boeing.com",
                 "airbus.com", "easa.europa.eu"}
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
            threat.evidence_citation = "https://unverified-source.local/manual-review-required"
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
        is_official_domain = has_true_primary_regulator or has_true_primary_oem

        domain = extract_effective_publisher_domain(canonical_doc_url)
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
        # Check quotation provenance and avoid treating generated prose as an exact source quote.
        threat.technical_grounding_status = "PASS" if full_quote_verified else "FAIL"

        matched_text_str = str(matched_doc.get("text") or "")
        faa_verified = (
                matched_doc.get("source_id") == "SRC_001"
                and "federalregister.gov/documents/" in canonical_doc_url
                and re.search(r"(?im)^Regulatory Lifecycle Check:\s*VERIFIED\s*$", matched_text_str)
                and re.search(r"(?im)^FAA Docket:\s*FAA-\d{4}-\d+\s*$", matched_text_str)
        )

        quote_recovered_from_faa_abstract = False
        if faa_verified and not full_quote_verified:
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

        if faa_verified and full_quote_verified:
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

        # Evaluate factual statements and causal interpretations separately.
        threat.claim_support_status, threat.causal_support_status, content_notes = _evaluate_claim_and_causal_support(
            threat, matched_doc, full_quote_verified, is_unverified_or_community_source=is_social_or_video
        )

        claim_text = f"{threat.confirmed_facts} {threat.threat_description}"
        entity_names = (
            "Airbus", "Boeing", "Safran", "Aequs", "Pratt & Whitney",
            "GE Aerospace", "Spirit AeroSystems", "Collins Aerospace",
        )

        # Match company mentions against the source rather than inferred relationships.
        def _entity_mentioned(name: str, text: str) -> bool:
            pat = r"(?<!\w)pratt\s*(?:&|and)\s*whitney(?!\w)" if name == "Pratt & Whitney" else rf"(?<!\w){re.escape(name)}(?!\w)"
            return bool(re.search(pat, text or "", re.I))

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

        threat.event_freshness = _evaluate_event_freshness(threat, doc_raw_full, as_of_date=as_of_date)
        age = _source_age_days(threat.publication_time, as_of_date)
        if age is not None and age > 90:
            audit_notes.append(
                f"Source published {age} days before reference date; historical source alone "
                "does not prove a new event or current disruption"
            )
        elif age is not None and age < -1:
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
        missing_program_facet = bool((kit_target_variants and not event_variants) or (kit_exact and not source_exact))
        missing_technical_subfacet = bool(
            (kit_engines and not event_engines) or (kit_components and not event_components))

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

        combined_claim = f"{threat.threat_description} {threat.fact_check_quote} {threat.adversarial_scenario}"
        has_speculation = bool(SPECULATIVE_DISINFO_MARKERS.search(combined_claim))
        has_contradiction = bool(
            CONTRADICTION_MARKERS.search(doc_raw_full.lower())
            and not CONTRADICTION_MARKERS.search(combined_claim.lower())
        )

        if has_contradiction:
            threat.validation_status = ValidationStatus.CONTRADICTED
            threat.claim_support_status = "CONTRADICTED"
            threat.confidence_level = ConfidenceLevel.LOW
            validation_errors += 1
            flagged_unverified += 1
        elif is_social_or_video:
            threat.validation_status = ValidationStatus.UNVERIFIED_COMMUNITY
            threat.confidence_level = ConfidenceLevel.LOW
            flagged_unverified += 1
        elif (
                threat.technical_grounding_status == "PASS"
                and threat.claim_support_status == "STATED_IN_SOURCE"
                and threat.causal_support_status == "EVIDENCED_IN_VERIFIED_SOURCE"
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

        if age is not None and age < -1:
            threat.validation_status = ValidationStatus.UNSUPPORTED
            threat.confidence_level = ConfidenceLevel.LOW
            threat.claim_support_status = "UNSUPPORTED"
            flagged_unverified += 1
            validation_errors += 1

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
            if stage_match := re.search(r"(?im)^Regulatory Stage:\s*(EFFECTIVE|FINAL_ISSUED|PROPOSED|UNKNOWN)\s*$",
                                        matched_text_str):
                regulatory_stage = stage_match.group(1)
            elif re.search(r"\b(?:final rule|adopt(?:s|ed|ing) an? (?:new )?airworthiness directive)\b",
                           regulatory_evidence, re.I):
                regulatory_stage = "FINAL_ISSUED"
            elif re.search(r"\b(?:propos(?:e|es|ed|ing|al)|notice of proposed rulemaking|NPRM)\b", regulatory_evidence,
                           re.I):
                regulatory_stage = "PROPOSED"
            else:
                regulatory_stage = "UNKNOWN"

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
                verified = bool(lifecycle_match and lifecycle_match.group(1) == "VERIFIED")
                docket_match = re.search(r"(?im)^FAA Docket:\s*(FAA-\d{4}-\d+)\s*$", matched_text_str)
                older_match = re.search(r"(?im)^Related earlier document:\s*(https://\S+)", matched_text_str)
                effective_match = re.search(r"(?im)^Effective Date:\s*(\d{4}-\d{2}-\d{2})\s*$", matched_text_str)
                effective_date = effective_match.group(1) if effective_match else ""
                ref_date = (as_of_date or "")[:10]

                if regulatory_stage == "EFFECTIVE" and effective_date and ref_date and effective_date > ref_date:
                    regulatory_stage = "FINAL_ISSUED"

                if verified and docket_match:
                    threat.corroboration_summary["FAA Lifecycle Verified"] = "YES"
                    threat.corroboration_summary["FAA Docket"] = docket_match.group(1).upper()
                    if older_match:
                        threat.corroboration_summary["FAA Prior Document"] = older_match.group(1)
                    if effective_date:
                        threat.corroboration_summary["FAA Effective Date"] = effective_date

                    if regulatory_stage in {"FINAL_ISSUED", "EFFECTIVE"} and age is not None:
                        if 0 <= age <= 90:
                            threat.event_freshness = EventFreshness.NEW_DEVELOPMENT
                        elif age > 90:
                            threat.event_freshness = EventFreshness.HISTORICAL_CONTEXT
                        threat.corroboration_summary["5. Event Freshness"] = threat.event_freshness.value

            threat.corroboration_summary["Regulatory Stage"] = regulatory_stage

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
                f"Verified Primary Source ({threat.event_freshness.value} | 5-Step Grounding PASS)"
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
            ans_text = " ".join(
                f"{t.company_affected} ({t.affected_program} | {t.event_freshness.value}): {t.confirmed_facts}"
                for t in rel_threats[:2]
            )
            missing_list = [t.missing_data for t in rel_threats if t.missing_data]
            generated_answers.append(
                KIQAnswer(
                    kiq_id=kid,
                    question=item["question"],
                    answer_status="ANSWERED" if high_conf and not missing_list else "PARTIALLY_ANSWERED",
                    answer=ans_text[:450],
                    related_event_ids=[t.event_id for t in rel_threats],
                    evidence_ids=ev_ids,
                    verification_status="Verified via primary/independent sources" if high_conf else "Requires additional corroboration",
                    uncertainty_level=ConfidenceLevel.HIGH if high_conf else ConfidenceLevel.MEDIUM,
                    recommended_next_step="Monitor downstream OEM schedule adjustments." if high_conf else "Execute Targeted KIQ Scan to close intelligence gaps.",
                    missing_information=missing_list[0] if missing_list else None,
                )
            )
        report.kiq_answers = generated_answers

    direct_validated = [t for t in validated_threats if t.program_relevance == "DIRECT_KIT_MATCH"]
    fully_supported_count = sum(t.validation_status == ValidationStatus.SUPPORTED for t in direct_validated)
    partial_count = sum(t.validation_status == ValidationStatus.PARTIALLY_SUPPORTED for t in direct_validated)
    ongoing_count = sum(t.event_freshness == EventFreshness.ONGOING_ISSUE for t in direct_validated)

    report.qa_audit_summary = (
        f"Five-Dimensional Grounding (Technical, Claim, Causal, Independent Verification, Freshness) completed. | "
        f"[Harness Guard]: {fully_supported_count}/{len(direct_validated)} direct signals SUPPORTED, "
        f"{partial_count} PARTIALLY_SUPPORTED, {ongoing_count} classified as ONGOING_ISSUE, "
        f"{len(watchlist_threats)} moved to RELATED_PROGRAM_WATCHLIST, "
        f"{flagged_unverified} flagged for manual HITL verification."
    )
    return report, validation_errors
