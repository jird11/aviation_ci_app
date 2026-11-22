# =============================================================================
# aviation_ci_app | Two-stage KIT-relevance screening and audit trail
#
# Responsibility: Apply deterministic document gates, model-assisted semantic decisions, conservative
#   context checks, and analyst batching.
# Design boundary: A rejected or unavailable source must not be misrepresented as proof that no relevant
#   event exists.
# =============================================================================

"""Document relevance screening, audit logging, and analyst input batching."""

import hashlib
from inspect import signature
from urllib.parse import urlsplit
from ews_agent_support import call_external_llm_tracked, call_tracked_llm
from ews_database import get_active_kiq_catalog
from ews_evidence_contract import assess_official_faa_fact
try:
    from ews_evidence_contract import inspect_official_faa_publication
except ImportError:  # Older deployments expose only assess_official_faa_fact.
    inspect_official_faa_publication = None
from ews_kiq import build_catalog_prompt_context
from ews_state import (
    Any, DB_LOCK, Dict, GEMINI_API_KEY, List, PROMPT_VERSION, SQLITE_DB,
    Tuple, datetime, fast_llm, genai, is_date_within_scope, json, logger,
    os, re, sqlite3, timezone,
)
from ews_validation import (
    _detect_aircraft_families,
    _detect_exact_variants,
    _detect_engine_models,
    _engine_models_match,
    kit_direct_relevance_gap,
)

# Deterministic screening patterns and relevance-cache configuration.
OBVIOUS_NOISE_REGEX = re.compile(
    r"\b(?:1:200|1:400|scale\s+model|diecast|unboxing|flight\s+simulator|msfs\s*202\d|x-plane|infinite\s+flight)\b",
    re.I,
)
_SEMANTIC_CACHE_VERSION = "FR03-RELEVANCE-14"
_FR03_RULES_VERSION = "FR03-MULTILEVEL-10"
_FAA_DOCKET_PATTERN = re.compile(r"(?<![A-Z0-9])FAA-20\d{2}-\d{3,7}(?!\d)", re.I)
_FEDERAL_REGISTER_NUMBER = re.compile(r"(?<![A-Z0-9])20\d{2}-\d{5,6}(?!\d)", re.I)
_LIMITED_CONTENT = {
    "METADATA_ONLY", "SOURCE_METADATA_ONLY", "TRUNCATED", "SUMMARY_ONLY",
    "SOURCE_ACCESS_BLOCKED", "CONTENT_UNAVAILABLE_OR_BLOCKED",
    "FILING_BLOCKED_OR_UNAVAILABLE", "ESEF_REPORT_UNAVAILABLE_OR_BLOCKED",
}
_AUTHORITIES = ("FAA", "EASA", "NTSB", "SEC", "CAA", "TCCA", "TSB", "CAAC", "ANAC", "CASA", "BEA")
_ISSUE_CONCEPTS = {
    "CERTIFICATION": (
        r"\b(?:certif\w*|type\s+approv\w*|regulatory\s+approv\w*|approval|airworthiness\s+approv\w*|"
        r"type\s+certificate|clearance\s+for\s+passenger\s+service|cleared\s+to\s+fly|"
        r"musterzulassung|zulassung|zugelassen|homologation)\b"
    ),
    "DELAY": r"\b(?:delay\w*|postpon\w*|reschedul\w*|slipp?\w*|push(?:ed)?\s+back|behind\s+schedule|setback\w*|defer\w*)\b",
    "DEFECT": r"\b(?:defect\w*|fault\w*|failure\w*|crack\w*|malfunction\w*|nonconform\w*|quality\s+issue\w*|durabilit\w*)\b",
    "INSPECTION": r"\b(?:inspect\w*|audit\w*|airworthiness\s+directive|\bAD\b|service\s+bulletin)\b",
    "PRODUCTION": r"\b(?:produc\w*|manufactur\w*|assembly|output|capacity|factory|line\s+rate|ramp[ -]?up)\b",
    "SUPPLY": (
        r"\b(?:supply\w*|shortag\w*|bottleneck\w*|scarcity|supplier\w*|backlog\w*|"
        r"export\s+(?:control\w*|licen[cs]e\w*|restrict\w*)|control\s+measures?|constraint\w*)\b"
    ),
    "DELIVERY": r"\b(?:deliver\w*|handover\w*|shipment\w*|fulfill\w*)\b",
    "GROUNDING": r"\b(?:ground(?:ed|ing)?|suspend\w*\s+(?:operations|flights)|out\s+of\s+service)\b",
    "ORDER": (
        r"\b(?:order\w*|contract\w*|purchas\w*|cancell\w*|leasing|fleet\s+acquisit\w*|"
        r"firmed?\s+up|commit(?:ment|ted|s)?|s['’]engage\w*|commande\w*|bestell\w*)\b"
    ),
    "REGULATION": r"\b(?:regulat\w*|rulemaking|legislat\w*|compliance|mandat\w*|directive\w*)\b",
    "STRIKE": r"\b(?:strik\w*|walkout\w*|labor\s+disput\w*|labour\s+disput\w*|work\s+stoppage\w*)\b",
}
# The process affected by an action must match the monitored issue. In particular,
# completing an inspection does not resolve a defect or certify an aircraft.
_PROCESS_COMPLETED = {
    "CERTIFICATION": r"\b(?:certif\w*|type\s+approv\w*|type\s+certificat\w*)\s+"
                     r"(?:was\s+|has\s+been\s+)?(?:achieved|obtained|granted|issued|completed|secured)\b|"
                     r"\b(?:achieved|obtained|received|secured)\s+(?:\w+\s+){0,3}"
                     r"(?:certification|type\s+approval|type\s+certificate)\b|"
                     r"\b(?:obtained|received)\s+(?:FAA\s+|EASA\s+)?approval\s+for\s+"
                     r"(?:type\s+)?certification\b|"
                     r"\b(?:FAA|EASA|Federal\s+Aviation\s+Administration|"
                     r"European\s+Union\s+Aviation\s+Safety\s+Agency)\s+"
                     r"(?:has\s+)?certif(?:ied|ies)\b|"
                     r"\b(?:was|has\s+been)\s+certified\s+by\s+(?:the\s+)?"
                     r"(?:FAA|EASA|Federal\s+Aviation\s+Administration|"
                     r"European\s+Union\s+Aviation\s+Safety\s+Agency)\b|"
                     r"\b(?:certif(?:ied|ication)|type\s+approval)\s+"
                     r"(?:has\s+been\s+|was\s+)?(?:granted|issued|completed|achieved)\b",
    "INSPECTION": r"\b(?:inspect\w*|audit)\s+(?:was\s+|has\s+been\s+)?(?:completed|finished|cleared)\b|"
                  r"\bcompleted\s+(?:\w+\s+){0,2}(?:inspection|audit)\b",
    "PRODUCTION": r"\b(?:restored|resumed|restarted)\s+(?:\w+\s+){0,2}(?:production|manufacturing|assembly)\b|"
                  r"\b(?:production|manufacturing|assembly)\s+(?:has\s+)?(?:resumed|restarted)\b",
    "DELIVERY": r"\b(?:restored|resumed|restarted)\s+(?:\w+\s+){0,2}(?:deliveries|shipments)\b|"
                r"\b(?:deliveries|shipments)\s+(?:have\s+)?resumed\b",
    "GROUNDING": r"\b(?:resumed|restored|restarted)\s+(?:\w+\s+){0,2}(?:operations|flights)\b|"
                 r"\b(?:grounding|flight\s+restriction)\s+(?:was\s+)?lifted\b",
    "SUPPLY": r"\b(?:shortag\w*|supply\s+disruption\w*)\s+(?:was\s+)?(?:resolved|eliminated|ended)\b",
    "DEFECT": r"\b(?:defect\w*|fault\w*|crack\w*|nonconform\w*)\s+(?:was\s+)?(?:fixed|rectified|resolved|eliminated)\b",
    "REGULATION": r"\b(?:regulatory\s+restriction|rule|directive)\s+(?:was\s+)?lifted\b",
}
_PROCESS_IMPROVED = {
    "SUPPLY": r"\b(?:shortag\w*|bottleneck\w*|supply\s+disruption\w*)\s+(?:has\s+)?(?:eased|reduced|improved)\b",
    "DELAY": r"\b(?:delay\w*|backlog\w*)\s+(?:has\s+)?(?:eased|reduced|shortened)\b",
    "PRODUCTION": r"\b(?:production|manufacturing|output)\s+(?:has\s+)?(?:recovered|increased)\b",
    "DELIVERY": r"\b(?:deliveries|shipments)\s+(?:have\s+)?(?:recovered|increased)\b",
    "GROUNDING": r"\b(?:received|obtained)\s+(?:FAA\s+|EASA\s+)?clearance\s+to\s+"
                 r"(?:resume\s+(?:operations|flights)|return\s+to\s+service)\b",
}
_STATUS_TRANSITIONS = {
    "ISSUE_WITHDRAWN": r"\b(?:withdrawn|withdrew|revoked|rescinded|superseded|repealed|cancelled)\b",
    "ISSUE_WORSENED": r"\b(?:worsen\w*|escalat\w*|deteriorat\w*|further\s+delay\w*|additional\s+shortag\w*|"
                      r"delay\w*\s+(?:grew|increased|extended))\b",
    "ISSUE_ONGOING": r"\b(?:remains?|continues?|still|ongoing|persists?|unresolved)\b",
    "ISSUE_EMERGED": r"\b(?:new(?:ly)?|first|began|started|emerged|surfaced|identified|detected)\b",
}
_WITHDRAWN_TARGETS = {
    "CERTIFICATION": r"certif\w*|approv\w*|type\s+certificate",
    "REGULATION": r"directive|regulation|rule|restriction",
    "INSPECTION": r"inspection\s+requirement|inspection\s+mandate",
    "ORDER": r"order|contract",
    "GROUNDING": r"grounding|flight\s+restriction",
}
_SOURCE_TYPE_SCORES = {
    "REGULATORY": 100,
    "OEM_PR": 80,
    "INDUSTRY_EVENT": 60,
    "MEDIA_AGGREGATOR": 50,
    "GEOGRAPHIC_SIGNAL": 50,
}
_CONCRETE_EVENT = re.compile(
    r"\b(?:shortag\w*|disrupt\w*|bottleneck\w*|delay\w*|defect\w*|fault\w*|"
    r"failur\w*|ground\w*|restrict\w*|mandat\w*|requir\w*|issued|granted|"
    r"approved|achieved|completed|restored|resumed|recovered|reported|confirmed|"
    r"increased|decreased|reduced|cancelled|withdrawn|updated|identified|detected)\b", re.I,
)

# Normalize text for stable identity and overlap comparisons.
def _alnum_norm(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", str(text or "").lower()).strip()


def _contains_entity(text: str, entity: str) -> bool:
    """Whole-word identity match, including a short trade name in a legal issuer name."""
    name, haystack = _alnum_norm(entity), _alnum_norm(text)
    return bool(name and re.search(rf"(?<!\w){re.escape(name)}(?!\w)", haystack))


def _verified_sec_issuer(doc: Dict[str, Any]) -> str:
    """Trust SEC issuer metadata only when CIK agrees with a genuine SEC filing URL."""
    issuer = str(doc.get("sec_company") or "").strip()
    cik = re.sub(r"\D", "", str(doc.get("sec_cik") or ""))
    if not issuer or not cik:
        return ""
    parsed = urlsplit(str(doc.get("url") or ""))
    if parsed.scheme != "https" or (parsed.hostname or "").lower() not in {
        "www.sec.gov", "sec.gov", "data.sec.gov",
    }:
        return ""
    match = re.search(r"(?i)/(?:Archives/edgar/data/|submissions/CIK|api/xbrl/companyfacts/CIK)(\d+)",
                      parsed.path)
    return issuer if match and int(match.group(1)) == int(cik) else ""


_SEC_ISSUER_EQUIVALENTS = (
    ("general electric", "ge aerospace", "ge aviation", "ge"),
    ("rtx", "raytheon", "pratt whitney", "pratt and whitney", "collins aerospace"),
    ("boeing", "the boeing company", "boeing co"),
    ("embraer", "embraer sa"),
    ("howmet", "howmet aerospace", "arconic"),
    ("ati", "ati inc", "allegheny technologies"),
    ("alaska air", "alaska airlines", "alaska air group"),
    ("general dynamics", "gulfstream"),
    ("textron", "cessna", "beechcraft", "bell"),
)

_ENTITY_SYNONYMS = {
    "faa": ("faa", "federal aviation administration", "us aviation body", "us regulators", "us regulator"),
    "easa": ("easa", "european union aviation safety agency", "european regulators"),
    "ntsb": ("ntsb", "national transportation safety board"),
    "cfm": ("cfm", "cfm international", "american french partnership"),
    "ge aerospace": ("ge aerospace", "general electric", "ge aviation", "ge"),
    "rolls royce deutschland": ("rolls royce deutschland", "rolls royce"),
}


def _split_entity_candidates(entity: str) -> List[str]:
    if not entity:
        return []
    protected = re.sub(r"pratt\s*&\s*whitney", "Pratt_And_Whitney", str(entity), flags=re.I)
    parts = [
        p.replace("Pratt_And_Whitney", "Pratt & Whitney").strip()
        for p in re.split(r"\s*[/|;,]+\s*|\s+\band\b\s+", protected, flags=re.I)
    ]
    return [p for p in parts if len(p) >= 2] or [str(entity).strip()]


def _sec_issuer_matches(issuer: str, entity: str) -> bool:
    if not issuer or not entity:
        return False
    if _contains_entity(issuer, entity) or _contains_entity(entity, issuer):
        return True
    iss_norm, ent_norm = _alnum_norm(issuer), _alnum_norm(entity)
    for group in _SEC_ISSUER_EQUIVALENTS:
        if any(g in iss_norm for g in group) and any(g in ent_norm for g in group):
            return True
    return False


def _entity_in_text(text: str, candidate: str) -> bool:
    if _contains_entity(text, candidate):
        return True
    norm = _alnum_norm(candidate)
    for alias in _ENTITY_SYNONYMS.get(norm, ()):
        if _contains_entity(text, alias):
            return True
    return False


def _entity_provenance(doc: Dict[str, Any], entity: str, quote: str, context: str) -> str:
    """Keep publisher identity separate from incidental mentions in media articles."""
    if not entity:
        return "NOT_CLAIMED"
    candidates = _split_entity_candidates(entity)
    issuer = _verified_sec_issuer(doc)
    if issuer and any(_sec_issuer_matches(issuer, cand) for cand in candidates):
        named_subject = re.match(
            r"^([A-Z][a-z][A-Za-z-]*(?:\s+[A-Z][a-z]+)?)\s+"
            r"(?:has|had|is|was|were|said|reported|announced|experienced|faces|suffered)\b",
            quote.strip(),
        )
        if (named_subject and named_subject.group(1).lower() not in {"we", "it", "they", "the", "company"}
                and not _sec_issuer_matches(issuer, named_subject.group(1))
                and not _issue_categories(named_subject.group(1))):
            return "UNVERIFIED_ENTITY"
        return "VERIFIED_SEC_ISSUER"

    title = str(doc.get("title") or "")
    body_context = context or quote
    if any(_entity_in_text(quote, cand) for cand in candidates):
        return "CITED_ENTITY"
    occurrence = re.search(re.escape(quote[:min(55, len(quote))]), body_context, re.I) if quote else None
    if occurrence:
        start = max(body_context.rfind(mark, 0, occurrence.start()) for mark in ".!?\n") + 1
        end_positions = [body_context.find(mark, occurrence.end()) for mark in ".!?\n"]
        end = min((pos for pos in end_positions if pos >= 0), default=len(body_context))
        if any(_entity_in_text(body_context[start:end], cand) for cand in candidates):
            return "LOCAL_CONTEXT_ENTITY"
        preceding = body_context[:start]
        previous_sentence = [part for part in re.split(r"[.!?\n]", preceding) if part.strip()][-1:]
        if (previous_sentence and any(_entity_in_text(previous_sentence[-1], cand) for cand in candidates)
                and re.search(r"\b(?:said|reported|stated|announced|confirmed)\b", previous_sentence[-1], re.I)
                and re.search(r"\b(?:we|it|the company|the manufacturer)\b", quote, re.I)):
            return "LOCAL_CONTEXT_ATTRIBUTION"
    if any(_entity_in_text(body_context, cand) for cand in candidates):
        return "LOCAL_CONTEXT_ENTITY"
    if (str(doc.get("origin_type") or "").upper().startswith("PRIMARY_OFFICIAL")
            and any(_entity_in_text(title, cand) for cand in candidates) and body_context):
        return "OFFICIAL_DOCUMENT_HEADING"
    if title and any(_entity_in_text(title, cand) for cand in candidates) and quote:
        return "LOCAL_CONTEXT_ENTITY"
    return "UNVERIFIED_ENTITY"


def _issue_categories(text: str) -> set[str]:
    return {name for name, pattern in _ISSUE_CONCEPTS.items() if re.search(pattern, text, re.I)}


def _positive_kit(query: str) -> str:
    """Excluded programs are negative constraints, not additional requested matches."""
    return re.split(r"\b(?:exclude|excluding|except(?:\s+for)?|without|not\s+including|kromě|vyjma)\b",
                    query or "", maxsplit=1, flags=re.I)[0].strip()


def _excluded_kit(query: str) -> str:
    parts = re.split(r"\b(?:exclude|excluding|except(?:\s+for)?|without|not\s+including|kromě|vyjma)\b",
                     query or "", maxsplit=1, flags=re.I)
    return parts[1].strip() if len(parts) > 1 else ""


def _detect_engine_models_ext(text: str) -> set[str]:
    """Extend base engine detector with FAA/EASA certified sub-model designations."""
    found = set(_detect_engine_models(text or ""))
    raw = str(text or "")
    extra_patterns = (
        (r"\bPW11\d{2}G(?:[- ]?JM|[- ]?\d[A-Z]?)?\b", "PW1100G_GTF"),
        (r"\bPW15\d{2}G(?:[- ]?[A-Z0-9]+)?\b", "PW1500G_GTF"),
        (r"\bPW19\d{2}G(?:[- ]?[A-Z0-9]+)?\b", "PW1900G_GTF"),
        (r"\bPW14\d{2}G(?:[- ]?[A-Z0-9]+)?\b", "PW1400G_GTF"),
        (r"\bLEAP[- ]?1A\b", "LEAP-1A"),
        (r"\bLEAP[- ]?1B\b", "LEAP-1B"),
        (r"\bLEAP[- ]?1C\b", "LEAP-1C"),
        (r"\bTRENT[- ]?XWB(?:[- ]?(?:75|84|97))?\b", "TRENT_XWB"),
        (r"\bGE9X\b", "GE9X"),
        (r"\bPW127(?:XT|M|F|G|E)?\b", "PW127"),
        (r"\bPW150A?\b", "PW150"),
    )
    for pat, label in extra_patterns:
        if re.search(pat, raw, re.I):
            found.add(label)
    return found


def _engine_models_compatible(query_text: str, doc_text: str) -> bool:
    """True when the document evidences at least one requested engine model."""
    q_eng = _detect_engine_models_ext(query_text)
    if not q_eng:
        return True
    d_eng = _detect_engine_models_ext(doc_text)
    if q_eng & d_eng:
        return True
    if not d_eng:
        return _engine_models_match(query_text, doc_text)
    return False


def _detect_exact_variants_ext(text: str) -> set[str]:
    """Include legal FAA/EASA type-certificate codes (BD-500-1A10/11, A350-941/-1041)."""
    found = set(_detect_exact_variants(text or ""))
    raw = str(text or "")
    if re.search(r"\bBD-?500-?1A10\b", raw, re.I):
        found.add("220:100")
    if re.search(r"\bBD-?500-?1A11\b", raw, re.I):
        found.add("220:300")
    if re.search(r"\bA350-?1041\b|\bA350-?941\s*(?:,|and|&)\s*-?1041\b", raw, re.I):
        found.add("350:1000")
    if re.search(r"\bA350-?941\b", raw, re.I):
        found.add("350:900")
    return found


def _detect_aircraft_families_ext(text: str) -> set[str]:
    found = set(_detect_aircraft_families(text or ""))
    raw = str(text or "")
    if re.search(r"\bBD-?500-?1A1[01]\b|\bCS(?:100|300)\b|\bC\s*Series\b", raw, re.I):
        found.add("A220")
    return found


_COMPONENT_KNOWN_PATTERNS = (
    (r"\bfuel\s+manifold\b", "fuel manifold"),
    (r"\bdoor\s+plug\b", "door plug"),
    (r"\blanding\s+gear\b", "landing gear"),
    (r"\bthrust\s+link\b", "thrust link"),
    (r"\bfan\s+blades?\b", "fan blade"),
    (r"\bgear[ -]?box\b", "gearbox"),
    (r"\bcompressor\b|\bhpc\b", "compressor"),
    (r"\bavionic\w*\b", "avionics"),
    (r"\bfuselage\b", "fuselage"),
    (r"\btitanium\b", "titanium"),
    (r"\bforgings?\b", "forging"),
    (r"\bcastings?\b", "casting"),
    (r"\bairfoils?\b", "airfoil"),
    (r"\bfasteners?\b", "fastener"),
)

_COMPONENT_NOISE_WORDS = {
    "a", "an", "the", "and", "or", "by", "of", "from", "with", "for", "to", "in", "on",
    "caused", "due", "delays", "delay", "issue", "issues", "shortage", "shortages",
    "critical", "affected", "specific", "aircraft", "supplier", "some", "component",
    "components", "part", "parts", "supply", "production", "manufacturing", "delivery",
    "certification", "engine", "engines", "technology", "mandatory", "new", "durability",
    "airbus", "boeing", "embraer", "comac", "rolls", "royce", "trent", "pratt", "whitney",
    "safran", "collins", "spirit", "aerosystems", "howmet", "aerospace", "ati", "ge",
    "dreamliner", "max", "neo", "xlr", "gtf", "leap", "airlines", "alaska",
}


def _component_requirements(query: str) -> set[str]:
    """Extract clean atomic KIT components without swallowing OEMs or aircraft names."""
    q = _positive_kit(query)
    anchors = {label for pat, label in _COMPONENT_KNOWN_PATTERNS if re.search(pat, q, re.I)}
    if anchors:
        return anchors

    heads = r"components?|parts?|modules?|systems?|assembl(?:y|ies)|software|hardware"
    matches = re.findall(rf"\b((?:[a-z0-9-]+\s+){{1,3}}(?:{heads}))\b", q, re.I)
    matches += re.findall(
        r"\b((?:[a-z0-9-]+\s+){1,2}[a-z0-9-]+)\s+"
        r"(?:cracks?|defects?|failures?|faults?|shortages?|inspections?|malfunctions?)\b",
        q, re.I,
    )
    for value in matches:
        for chunk in re.split(r"\b(?:and|or)\b|[,/]", value, flags=re.I):
            words = [
                w for w in chunk.lower().split()
                if w not in _COMPONENT_NOISE_WORDS and not re.search(r"\d", w)
            ]
            if len(words) >= 2:
                anchors.add(" ".join(words[-2:]))
    for match in re.finditer(
        r"\b((?:[a-z0-9-]+\s+){0,2}[a-z][a-z0-9-]*)\s+"
        r"(?:inspection|testing|maintenance|repair|replacement)\s+requirements?\b", q, re.I,
    ):
        words = [
            w for w in match.group(1).lower().split()
            if w not in _COMPONENT_NOISE_WORDS and not re.search(r"\d", w)
        ]
        if words:
            anchors.add(" ".join(words[-2:]))
    return anchors


def _component_matched(component: str, text: str) -> bool:
    norm_c = _alnum_norm(component)
    norm_t = _alnum_norm(text)
    if not norm_c or not norm_t:
        return False
    if norm_c in norm_t:
        return True
    stem_map = {
        "forging": r"\bforg(?:e|ed|es|ing|ings)\b",
        "casting": r"\bcast(?:ing|ings|ed)?\b",
        "compressor": r"\b(?:compressor\w*|hpc)\b",
        "gearbox": r"\b(?:gear[ -]?box|reduction\s+gear\w*)\b",
        "avionics": r"\bavionic\w*\b",
        "fuel manifold": r"\bfuel\s+(?:manifold|hose\s+assembly|line)\b",
    }
    if norm_c in stem_map:
        return bool(re.search(stem_map[norm_c], text or "", re.I))
    return False


def _requested_authorities(query: str) -> set[str]:
    names = {
        "FAA": r"\bFederal\s+Aviation\s+Administration\b",
        "EASA": r"\bEuropean\s+Union\s+Aviation\s+Safety\s+Agency\b",
        "NTSB": r"\bNational\s+Transportation\s+Safety\s+Board\b",
        "SEC": r"\bSecurities\s+and\s+Exchange\s+Commission\b",
        "CAA": r"\bCivil\s+Aviation\s+Authority\b",
        "TCCA": r"\bTransport\s+Canada\b",
        "TSB": r"\bTransportation\s+Safety\s+Board\b",
        "CAAC": r"\bCivil\s+Aviation\s+Administration\s+of\s+China\b",
        "ANAC": r"\bAg[eê]ncia\s+Nacional\s+de\s+Avia[cç][aã]o\s+Civil\b",
        "CASA": r"\bCivil\s+Aviation\s+Safety\s+Authority\b",
        "BEA": r"\bBureau\s+d['’]Enqu[eê]tes\s+et\s+d['’]Analyses\b",
    }
    return {a for a in _AUTHORITIES if re.search(rf"\b{a}\b", query, re.I)
            or (a in names and re.search(names[a], query, re.I))}

def _requested_document_ids(query: str) -> set[str]:
    return ({m.group().upper() for m in _FAA_DOCKET_PATTERN.finditer(query)}
            | {m.group().upper() for m in _FEDERAL_REGISTER_NUMBER.finditer(query)})


def _document_identifiers(doc: Dict[str, Any]) -> set[str]:
    """Only source-origin regulatory identifiers; never an incidental prose citation."""
    numbers = _document_dockets(doc)
    for key in ("federal_register_document", "federal_register_document_number",
                "document_number", "regulatory_document_id"):
        value = str(doc.get(key) or "")
        numbers.update(m.group().upper() for m in _FEDERAL_REGISTER_NUMBER.finditer(value))
    parsed = urlsplit(str(doc.get("url") or ""))
    if (parsed.scheme == "https" and (parsed.hostname or "").lower() in
            {"federalregister.gov", "www.federalregister.gov"}):
        match = re.search(r"/documents/\d{4}/\d{2}/\d{2}/(20\d{2}-\d{5,6})(?:/|$)",
                          parsed.path, re.I)
        if match:
            numbers.add(match.group(1).upper())
    return numbers


def _requested_event_dates(query: str) -> set[str]:
    numeric = set(re.findall(r"\b20\d{2}-\d{2}-\d{2}\b", query))
    named = re.findall(
        r"\b(?:\d{1,2}\s+)?(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|"
        r"Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|"
        r"Nov(?:ember)?|Dec(?:ember)?)\s+20\d{2}\b", query, re.I,
    )
    return numeric | {value.lower() for value in named}


def _valid_publication_date(value: Any) -> bool:
    try:
        datetime.strptime(str(value)[:10], "%Y-%m-%d")
        return True
    except (TypeError, ValueError):
        return False


def _source_authority(doc: Dict[str, Any]) -> str:
    """Only a regulator's HTTPS site can establish its own official authorship."""
    parsed = urlsplit(str(doc.get("url") or ""))
    host = (parsed.hostname or "").lower()
    domains = {
        "FAA": "faa.gov", "EASA": "easa.europa.eu", "NTSB": "ntsb.gov",
        "SEC": "sec.gov", "FEDERAL_REGISTER": "federalregister.gov",
        "CAA": "caa.co.uk", "TCCA": "tc.canada.ca", "TSB": "tsb.gc.ca",
        "CAAC": "caac.gov.cn", "ANAC": "anac.gov.br", "CASA": "casa.gov.au",
        "BEA": "bea.aero",
    }
    for authority, domain in domains.items():
        if parsed.scheme == "https" and (host == domain or host.endswith("." + domain)):
            return authority
    return ""


def _claim_authority_scope(doc: Dict[str, Any]) -> str:
    """A submitted issuer report is not a confirmed regulatory finding."""
    if _verified_sec_issuer(doc):
        return "ISSUER_REPORTED"
    if _source_authority(doc) in (set(_AUTHORITIES) - {"SEC"}) | {"FEDERAL_REGISTER"}:
        return "REGULATORY_PUBLICATION"
    return "SOURCE_REPORTED"


_GENERIC_ENTITY_STOPWORDS = {
    "what", "which", "when", "how", "why", "where", "who", "current", "latest", "status",
    "show", "tell", "provide", "identify", "analyze", "analyse", "find", "monitor",
    "aerospace", "aviation", "aircraft", "airline", "airlines", "supplier", "suppliers",
    "supply", "chain", "commercial", "global", "industry", "market", "production",
    "delivery", "deliveries", "engine", "engines", "labor", "labour", "strike",
    "impact", "official", "report", "reports", "airshow", "what is",
}


def _extract_kit_entities(positive: str) -> set[str]:
    raw_names = set(re.findall(r"\b[A-Z][a-z]{2,}\b|\b[A-Z]{2,5}\b", positive or ""))
    auths = _requested_authorities(positive)
    cleaned = set()
    for name in raw_names:
        if name.lower() in _GENERIC_ENTITY_STOPWORDS or name.upper() in auths:
            continue
        if name.upper() in {"MAX", "NEO", "XLR", "XWB", "GTF", "AD", "AOG", "MRO", "OEM", "SEC", "ESEF"}:
            continue
        cleaned.add(name)
    return cleaned


def _query_precision(query: str) -> Dict[str, List[str]]:
    """Expose hard identity constraints separately from topic and background terms."""
    positive = _positive_kit(query)
    excluded_text = _excluded_kit(query)
    variants = _detect_exact_variants_ext(positive)
    engines = _detect_engine_models_ext(positive)
    required = (
        [f"PROGRAM:{value}" for value in sorted(variants)]
        + [f"ENGINE:{value}" for value in sorted(engines)]
        + [f"COMPONENT:{value}" for value in sorted(_component_requirements(positive))]
        + [f"AUTHORITY:{value}" for value in sorted(_requested_authorities(positive))]
        + [f"DOCUMENT_ID:{value}" for value in sorted(_requested_document_ids(positive))]
        + [f"EVENT_DATE:{value}" for value in sorted(_requested_event_dates(positive))]
    )
    if not variants and not engines:
        required += [f"AIRCRAFT_FAMILY:{value}"
                     for value in sorted(_detect_aircraft_families_ext(positive))]
    if not required or (not variants and not engines and not _detect_aircraft_families_ext(positive)):
        entities = _extract_kit_entities(positive)
        for name in sorted(entities):
            tag = f"ENTITY:{name}"
            if tag not in required:
                required.append(tag)
    preferred = sorted(_issue_categories(positive))
    required_words = set(re.findall(r"\b[a-z0-9]{2,}\b",
                                    _alnum_norm(" ".join(required))))
    contextual = sorted(set(re.findall(r"\b[a-z0-9]{4,}\b", _alnum_norm(positive)))
                        - {"aircraft", "aviation", "industry", "aerospace"}
                        - required_words)
    contextual = [word for word in contextual if not any(
        re.search(pattern, word, re.I) for pattern in _ISSUE_CONCEPTS.values()
    )]
    out: Dict[str, List[str]] = {"REQUIRED": required, "PREFERRED": preferred, "CONTEXTUAL": contextual}
    if excluded_text:
        excl = (
            [f"PROGRAM:{v}" for v in sorted(_detect_exact_variants_ext(excluded_text))]
            + [f"AIRCRAFT_FAMILY:{f}" for f in sorted(_detect_aircraft_families_ext(excluded_text))]
            + [f"ENGINE:{e}" for e in sorted(_detect_engine_models_ext(excluded_text))]
        )
        if excl:
            out["EXCLUDED"] = excl
    return out


def _program_disclaimed(query: str, source: str) -> bool:
    """A model named only to disclaim applicability is not a positive match."""
    requested = _detect_exact_variants_ext(_positive_kit(query))
    if not requested:
        return False
    for hit in re.finditer(
        r"\b(?:not|unrelated\s+to|different\s+from|excluding|"
        r"does\s+not\s+(?:apply\s+to|concern)|not\s+applicable\s+to)\b",
        source, re.I,
    ):
        following = source[hit.end():hit.end() + 80]
        if not requested.intersection(_detect_exact_variants_ext(following)):
            continue
        if hit.group().lower() == "not" and re.search(
            r"\b(?:yet|certif\w*|approv\w*|delayed|delivered|completed|produced|"
            r"resolved|affected)\b", following[:45], re.I
        ):
            continue
        return True
    return False


def _identity_checks(query: str, doc: Dict[str, Any], passage: str = "") -> Dict[str, Any]:
    """Exact identifiers are mandatory; multi-target KITs accept any requested target."""
    q = _positive_kit(query)
    excl = _excluded_kit(query)
    source = f"{doc.get('title') or ''} {doc.get('text') or ''}"
    local = f"{doc.get('title') or ''} {passage}" if passage else source
    q_variants, d_variants = _detect_exact_variants_ext(q), _detect_exact_variants_ext(source)
    local_variants = _detect_exact_variants_ext(local)
    q_engines, d_engines = _detect_engine_models_ext(q), _detect_engine_models_ext(source)
    q_families, d_families = _detect_aircraft_families_ext(q), _detect_aircraft_families_ext(source)
    passed, failed, unverified = [], [], []

    # Enforce explicit negative exclusions when the local text targets only the excluded scope.
    if excl:
        ex_variants = _detect_exact_variants_ext(excl) - q_variants
        ex_families = _detect_aircraft_families_ext(excl) - q_families
        ex_engines = _detect_engine_models_ext(excl) - q_engines
        check_scope = passage or str(doc.get("title") or "") or source
        hit_excl = bool(
            (ex_variants & _detect_exact_variants_ext(check_scope))
            or (ex_families & _detect_aircraft_families_ext(check_scope))
            or (ex_engines & _detect_engine_models_ext(check_scope))
        )
        hit_pos = bool(
            (q_variants & _detect_exact_variants_ext(check_scope))
            or (q_families & _detect_aircraft_families_ext(check_scope))
            or (q_engines and _engine_models_compatible(q, check_scope))
        )
        if hit_excl and not hit_pos:
            failed.append("PROGRAM_CONFLICT")

    if q_variants:
        if q_variants & local_variants:
            passed.append("REQUIRED_PROGRAM")
        elif d_variants and not (q_variants & d_variants):
            failed.append("PROGRAM_CONFLICT")
        else:
            unverified.append("REQUIRED_PROGRAM")
        if passage and (_detect_exact_variants_ext(passage) - q_variants):
            if not (q_variants & _detect_exact_variants_ext(passage)):
                failed.append("PROGRAM_CONFLICT")
        if (d_variants - q_variants) and _program_disclaimed(q, source):
            failed.append("PROGRAM_CONFLICT")
            if "REQUIRED_PROGRAM" in passed:
                passed.remove("REQUIRED_PROGRAM")
    elif q_families:
        if q_families & d_families:
            passed.append("REQUIRED_AIRCRAFT_FAMILY")
        elif d_families and not (q_engines and _engine_models_compatible(q, source)):
            failed.append("PROGRAM_CONFLICT")
        else:
            unverified.append("REQUIRED_AIRCRAFT_FAMILY")

    if q_engines:
        if _engine_models_compatible(q, local):
            passed.append("REQUIRED_ENGINE")
        elif d_engines and not _engine_models_compatible(q, source):
            if not (q_families and (q_families & d_families)) and not (q_variants and (q_variants & d_variants)):
                failed.append("PROGRAM_CONFLICT")
            else:
                unverified.append("REQUIRED_ENGINE")
        else:
            unverified.append("REQUIRED_ENGINE")

        # U kombinovaných KITů (drak + motor) neblokuj motorový dokument kvůli absenci kódu draku (a naopak),
        # pokud v dokumentu není žádný konfliktní typ letadla/motoru.
    if "PROGRAM_CONFLICT" not in failed:
        if "REQUIRED_ENGINE" in passed and "REQUIRED_PROGRAM" in unverified:
            unverified.remove("REQUIRED_PROGRAM")
        if "REQUIRED_ENGINE" in passed and "REQUIRED_AIRCRAFT_FAMILY" in unverified:
            unverified.remove("REQUIRED_AIRCRAFT_FAMILY")
        if ("REQUIRED_PROGRAM" in passed or "REQUIRED_AIRCRAFT_FAMILY" in passed) and "REQUIRED_ENGINE" in unverified:
            unverified.remove("REQUIRED_ENGINE")

    req_auths = _requested_authorities(q)
    matched_auths = {
        a for a in req_auths
        if a in _requested_authorities(local) or _source_authority(doc) == a
    }
    for authority in sorted(matched_auths):
        passed.append(f"REQUIRED_AUTHORITY:{authority}")
    non_reg_kit_issues = _issue_categories(q) - {"CERTIFICATION", "REGULATION", "INSPECTION"}
    local_non_reg = _issue_categories(local) & non_reg_kit_issues
    if req_auths and not matched_auths and not local_non_reg:
        for authority in sorted(req_auths):
            unverified.append(f"REQUIRED_AUTHORITY:{authority}")

    for identifier in _requested_document_ids(q):
        recorded = _document_identifiers(doc)
        if identifier in recorded:
            passed.append(f"REQUIRED_DOCUMENT_ID:{identifier}")
        elif recorded:
            failed.append("DOCUMENT_ID_CONFLICT")
        else:
            unverified.append(f"REQUIRED_DOCUMENT_ID:{identifier}")
    for date in _requested_event_dates(q):
        if date in (passage or str(doc.get("text") or "")).lower():
            passed.append(f"REQUIRED_EVENT_DATE:{date}")
        else:
            unverified.append(f"REQUIRED_EVENT_DATE:{date}")

    if not (q_variants or q_engines or q_families):
        named = {n.lower() for n in _extract_kit_entities(q)}
        if named:
            issuer = _verified_sec_issuer(doc)
            if (issuer and any(_sec_issuer_matches(issuer, name) for name in named)
                    and (not passage or any(_contains_entity(passage, name) for name in named)
                         or re.search(r"\b(?:we|our|us|the\s+company)\b", passage, re.I))):
                passed.append("REQUIRED_ENTITY")
            elif passage and any(_contains_entity(local, name) for name in named):
                passed.append("REQUIRED_ENTITY")
            elif passage:
                unverified.append("REQUIRED_ENTITY")
            elif issuer and any(_contains_entity(source, name) for name in named):
                unverified.extend(("REQUIRED_ENTITY", "ENTITY_ISSUER_DIFFERENT"))
            elif any(_contains_entity(source, name) for name in named):
                passed.append("REQUIRED_ENTITY")
            else:
                if issuer:
                    failed.append("ENTITY_CONFLICT")
                else:
                    unverified.append("REQUIRED_ENTITY")
    return {"passed": sorted(set(passed)), "failed": sorted(set(failed)),
            "unverified": sorted(set(unverified)),
            "hard_conflict": bool({"PROGRAM_CONFLICT", "ENTITY_CONFLICT", "DOCUMENT_ID_CONFLICT"} & set(failed))}


def _quote_context(doc: Dict[str, Any], quote: str) -> str:
    """Use the containing paragraph and heading, never distant independent claims."""
    body = str(doc.get("text") or "")
    words = re.findall(r"\w+", quote)
    if not words:
        return ""
    found = re.search(r"\W+".join(map(re.escape, words)), body, re.I)
    if not found:
        return quote if _alnum_norm(quote) in _alnum_norm(str(doc.get("title") or "")) else ""
    if "\n\n" in body[found.start():found.end()]:
        return ""  # A citation must not splice separate paragraphs together.
    beginning = max(body.rfind("\n\n", 0, found.start()) + 2, found.start() - 350)
    end_of_para = body.find("\n\n", found.end())
    ending = min(end_of_para if end_of_para >= 0 else len(body), found.end() + 350)
    return body[beginning:ending].strip()


def _relevance_checks(query: str, doc: Dict[str, Any], excerpt: str = "") -> Dict[str, Any]:
    identity = _identity_checks(query, doc, excerpt)
    passed, failed, unverified = (list(identity[k]) for k in ("passed", "failed", "unverified"))
    body = str(doc.get("text") or "")
    source = f"{doc.get('title') or ''} {body}"
    issues = _issue_categories(_positive_kit(query))
    quote_issues = _issue_categories(excerpt) if excerpt else _issue_categories(source)
    if issues and issues & quote_issues:
        passed.append("ISSUE_EVIDENCED")
    elif issues:
        (failed if doc.get("content_status") in {"FULL_TEXT", "FULL_TEXT_RETRIEVED"}
         and len(body.strip()) >= 70 else unverified).append("ISSUE_NOT_EVIDENCED")

    req_components = _component_requirements(query)
    comp_haystack = f"{doc.get('title') or ''} {excerpt}" if excerpt else source
    matched_components = {c for c in req_components if _component_matched(c, comp_haystack)}
    for component in sorted(matched_components):
        passed.append(f"REQUIRED_COMPONENT:{component}")
    full_dual_identity = (
            ("REQUIRED_PROGRAM" in passed or "REQUIRED_AIRCRAFT_FAMILY" in passed)
            and "REQUIRED_ENGINE" in passed
            and "ISSUE_EVIDENCED" in passed
            and doc.get("source_id") != "SRC_001"
    )
    if req_components and not matched_components and not full_dual_identity:
        for component in sorted(req_components):
            unverified.append(f"REQUIRED_COMPONENT:{component}")

    if len(body.strip()) < 70 or doc.get("content_status") in _LIMITED_CONTENT:
        failed.append("INSUFFICIENT_SOURCE_TEXT")
    else:
        passed.append("SUBSTANTIVE_SOURCE_TEXT")
    if excerpt:
        if _quote_context(doc, excerpt):
            passed.append("QUOTATION_GROUNDED")
        else:
            failed.append("QUOTATION_NOT_GROUNDED")
    return {"passed": sorted(set(passed)), "failed": sorted(set(failed)),
            "unverified": sorted(set(unverified)),
            "hard_conflict": identity["hard_conflict"]}


def _mandatory_gaps(checks: Dict[str, Any]) -> List[str]:
    """Required identity, applicability and component gaps cannot prove a direct KIT claim."""
    return [item for item in checks["unverified"] if item.startswith(
        ("REQUIRED_", "PROGRAM_ISSUE_LINK_", "ENTITY_ISSUE_LINK_")
    ) or item == "ENTITY_ISSUER_DIFFERENT"]


def _secondary_evidence_check(
    query: str, doc: Dict[str, Any], change: tuple[str, str] | None = None,
) -> tuple[str, str, str]:
    """Recheck LLM negatives against local, contiguous passages; never infer event truth."""
    if doc.get("content_status") in _LIMITED_CONTENT or len(str(doc.get("text") or "").strip()) < 70:
        return "REVIEW", "", "SOURCE_TEXT_UNAVAILABLE"
    if _regulatory_relevance_gap(query, doc):
        return "REVIEW", "", "REGULATORY_APPLICABILITY_UNVERIFIED"
    checks = _relevance_checks(query, doc)
    if checks["hard_conflict"]:
        return "REJECT", "", "HARD_IDENTITY_CONFLICT"
    if change:
        excerpt = change[1]
        checks = _relevance_checks(query, doc, excerpt)
        if _quote_context(doc, excerpt) and not checks["hard_conflict"] and not _mandatory_gaps(checks):
            return "CONFIRMED", excerpt, "STATUS_CHANGE_PASSAGE_MATCHED"
    required_issues = _issue_categories(_positive_kit(query))
    terms = set(_query_precision(query)["CONTEXTUAL"])
    passages = (
        re.sub(r"^\s*\]?\s*\[E\d+\s+[A-Z_]+(?:\s+offset=\d+)?\]\s*", "", part).strip()[:450]
        for part in re.split(r"(?<=[.!?])\s+|\n+", str(doc.get("text") or ""))
    )
    shortlisted = [p for p in passages if len(p) >= 40 and _CONCRETE_EVENT.search(p)
                   and (not required_issues or bool(required_issues & _issue_categories(p)))]
    shortlisted.sort(key=lambda p: sum(t in _alnum_norm(p) for t in terms), reverse=True)
    for excerpt in shortlisted[:64]:
        checks = _relevance_checks(query, doc, excerpt)
        if (checks["hard_conflict"] or _mandatory_gaps(checks)
                or "INSUFFICIENT_SOURCE_TEXT" in checks["failed"]
                or not _quote_context(doc, excerpt)):
            continue
        if not required_issues and not set(_query_precision(query)["CONTEXTUAL"]) & set(
            re.findall(r"\b[a-z0-9]{4,}\b", _alnum_norm(excerpt))
        ):
            continue
        return "CONFIRMED", excerpt, "DIRECT_PASSAGE_MATCHED"
    return "REVIEW", "", "DIRECT_KIT_PASSAGE_NOT_ESTABLISHED"


def _issuer_status_passage(query: str, doc: Dict[str, Any]) -> str:
    """Find an attributed SEC issuer statement, without certifying a regulator's act.

    Only the *authority* gate may remain unverified. Model, requested document
    identity, component, and any explicitly requested date remain mandatory.
    """
    if (_source_authority(doc) != "SEC" or not _verified_sec_issuer(doc)
            or doc.get("content_status") in _LIMITED_CONTENT):
        return ""
    body = str(doc.get("text") or "")
    if len(body.strip()) < 70 or not _requested_authorities(query):
        return ""
    issues = _issue_categories(query)
    for match in re.finditer(r"[^.!?\n]{30,450}(?:[.!?]|$)", body):
        quote = match.group().strip()
        if not _quote_context(doc, quote):
            continue
        checks = _relevance_checks(query, doc, quote)
        gaps = _mandatory_gaps(checks)
        if (checks["hard_conflict"] or not gaps
                or any(not item.startswith("REQUIRED_AUTHORITY:") for item in gaps)
                or not issues.intersection(_issue_categories(quote))):
            continue
        if re.search(r"\b(?:expect\w*|plan\w*|intend\w*|may|might|could|would|will|"
                     r"pending|not\s+(?:yet\s+)?(?:certif\w*|approv\w*))\b", quote, re.I):
            continue
        if any(issue in issues and re.search(pattern, quote, re.I)
               for issue, pattern in _PROCESS_COMPLETED.items()):
            return quote
    return ""


def _status_change_evidence(query: str, doc: Dict[str, Any]) -> tuple[str, str] | None:
    """Find a dated, process-specific passage; never infer resolution of other impacts."""
    source = str(doc.get("text") or "")
    published = str(doc.get("published_at") or "")[:10]
    if (len(source.strip()) < 70 or doc.get("content_status") in _LIMITED_CONTENT
            or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", published)):
        return None
    try:
        datetime.strptime(published, "%Y-%m-%d")
    except ValueError:
        return None
    kit = _positive_kit(query)
    issues = _issue_categories(kit)
    variants = _detect_exact_variants_ext(kit)
    families = _detect_aircraft_families_ext(kit)
    engines = _detect_engine_models_ext(kit)
    if not issues:
        return None
    if variants and not (variants & _detect_exact_variants_ext(source + " " + str(doc.get("title") or ""))):
        return None

    requested_agencies = _requested_authorities(kit)
    for sentence_match in re.finditer(r"[^.!?\n]+(?:[.!?]|$)", source):
        sentence = sentence_match.group().strip()
        for clause in re.split(r"\s+(?:but|whereas|although|while)\s+|;", sentence, flags=re.I):
            excerpt = re.sub(
                r"^\s*\]?\s*\[E\d+\s+[A-Z_]+(?:\s+offset=\d+)?\]\s*", "", clause
            ).strip()[:450]
            if re.search(r"\b(?:planned|plans?|expects?|expected|scheduled|pending|awaiting|"
                         r"forecast|proposed|may|might|could|would|will|if|whether|rumou?red)\b", excerpt, re.I):
                continue
            if re.search(r"\b(?:not|never|no|without|hasn't|hadn't)\b(?:\W+\w+){0,5}\W+"
                         r"(?:certif\w*|approv\w*|achiev\w*|obtain\w*|complet\w*|resolv\w*|"
                         r"resum\w*|restor\w*|lift\w*|eas\w*)\b", excerpt, re.I):
                continue
            if re.search(r"\b(?:status|outcome|decision)\s+(?:remains?|is)\s+"
                         r"(?:unknown|unclear|unconfirmed|undetermined)\b", excerpt, re.I):
                continue
            local_identity = f"{doc.get('title') or ''} {excerpt}"
            if (variants and (not (variants & _detect_exact_variants_ext(local_identity))
                              or (_detect_exact_variants_ext(excerpt) - variants
                                  and not (variants & _detect_exact_variants_ext(excerpt))))
                    or families and not variants and not families.intersection(
                        _detect_aircraft_families_ext(local_identity))
                    or engines and not _engine_models_compatible(kit, local_identity)):
                continue
            explicit_change = any(issue in issues and re.search(pattern, excerpt, re.I)
                                  for patterns in (_PROCESS_COMPLETED, _PROCESS_IMPROVED)
                                  for issue, pattern in patterns.items())
            if not explicit_change and not (
                issues.intersection(_issue_categories(excerpt))
                and any(re.search(pattern, excerpt, re.I) for pattern in _STATUS_TRANSITIONS.values())
            ):
                continue
            checks = _relevance_checks(kit, doc, excerpt)
            if (checks["hard_conflict"] or any(
                term.startswith(("REQUIRED_COMPONENT:", "REQUIRED_AUTHORITY:",
                                 "REQUIRED_DOCUMENT_ID:", "REQUIRED_EVENT_DATE:"))
                or term in {"REQUIRED_PROGRAM", "REQUIRED_ENGINE", "REQUIRED_ENTITY"}
                for term in checks["unverified"]
            )):
                continue
            actual_agencies = _requested_authorities(excerpt)
            if requested_agencies and actual_agencies and not requested_agencies.intersection(actual_agencies):
                continue

            for issue, pattern in _PROCESS_COMPLETED.items():
                completed = re.search(pattern, excerpt, re.I) if issue in issues else None
                if not completed:
                    continue
                if issue == "CERTIFICATION" and requested_agencies and not (
                    requested_agencies & actual_agencies
                ):
                    continue  # A regulator-specific final decision needs local attribution.
                local_action = excerpt[max(0, completed.start() - 30):completed.end() + 25]
                partial = re.search(r"\b(?:partially|partly|limited|phased|in\s+part)\b", local_action, re.I)
                return ("ISSUE_PARTIALLY_RESOLVED" if partial else "ISSUE_RESOLVED"), excerpt

            if any(issue in issues and re.search(pattern, excerpt, re.I)
                   for issue, pattern in _PROCESS_IMPROVED.items()):
                return "ISSUE_IMPROVED", excerpt

            if not issues.intersection(_issue_categories(excerpt)):
                continue
            for status, pattern in _STATUS_TRANSITIONS.items():
                hit = re.search(pattern, excerpt, re.I)
                if not hit:
                    continue
                if status == "ISSUE_WITHDRAWN":
                    vicinity = excerpt[max(0, hit.start() - 55):hit.end() + 55]
                    if not any(issue in issues and re.search(pattern, vicinity, re.I)
                               for issue, pattern in _WITHDRAWN_TARGETS.items()):
                        continue
                if status == "ISSUE_EMERGED" and not re.search(
                    r"\b(?:new(?:ly)?|first|began|started)\b.{0,70}"
                    r"\b(?:delay\w*|defect\w*|shortag\w*|failur\w*|restrict\w*)\b|"
                    r"\b(?:delay\w*|defect\w*|shortag\w*|failur\w*)\b.{0,50}"
                    r"\b(?:identified|detected|reported|occurred|found)\b", excerpt, re.I,
                ):
                    continue
                return status, excerpt
    return None


def _potential_status_change(query: str, doc: Dict[str, Any]) -> bool:
    """Uncertain status developments remain reviewable even without local model proof."""
    source = f"{doc.get('title') or ''} {doc.get('text') or ''}"
    if not _issue_categories(query).intersection(_issue_categories(source)):
        return False
    if _identity_checks(query, doc)["hard_conflict"]:
        return False
    issues = _issue_categories(query)
    return (any(re.search(pattern, source, re.I) for pattern in _STATUS_TRANSITIONS.values())
            or any(issue in issues and re.search(pattern, source, re.I)
                   for patterns in (_PROCESS_COMPLETED, _PROCESS_IMPROVED)
                   for issue, pattern in patterns.items()))


def _document_dockets(doc: Dict[str, Any]) -> set[str]:
    """Use document identity fields, not incidental docket mentions in article prose."""
    values = [doc.get("faa_docket_id"), doc.get("docket_id"), doc.get("docket_ids")]
    identified = set()
    for value in values:
        for item in (value if isinstance(value, list) else [value]):
            identified.update(m.group().upper() for m in _FAA_DOCKET_PATTERN.finditer(str(item or "")))
    if not identified:
        # Older collector records encode the original docket in a labeled provenance line.
        text = str(doc.get("text") or "")
        identified.update(m.group(1).upper() for m in re.finditer(
            r"(?im)^FAA\s+Docket:\s*(FAA-20\d{2}-\d{3,7})\b", text
        ))
    return identified


def _regulatory_relevance_gap(query: str, doc: Dict[str, Any]) -> str:
    requested = _requested_document_ids(query)
    if doc.get("source_id") != "SRC_001":
        return ""
    recorded = _document_identifiers(doc)
    if requested and not requested.intersection(recorded):
        return "RELATED_REGULATORY_CONTEXT: FAA document does not verify the requested docket identifier."
    variants = _detect_exact_variants(query)
    if variants and not variants.intersection(_detect_exact_variants(
        f"{doc.get('title') or ''} {doc.get('text') or ''}"
    )):
        return "REGULATORY_APPLICABILITY_UNCONFIRMED: docket matches, but exact variant applicability is not evidenced."
    return ""


def _program_claim_grounded(program: str, source: str) -> bool:
    """Is the program named by the model actually present in the source text?

    A family-level claim ("Boeing 787") is grounded by a source that names the
    family in any of its normal spellings ("Model 787-8, 787-9", "787 Dreamliner").
    A variant-level claim ("787-9") is never grounded by the family alone.
    """
    if not program:
        return True
    claimed_variants = _detect_exact_variants(program)
    if claimed_variants:
        return claimed_variants.issubset(_detect_exact_variants(source))
    if _detect_engine_models(program) and _engine_models_match(program, source):
        return True
    families = _detect_aircraft_families(program)
    if families:
        return families.issubset(_detect_aircraft_families(source))
    return bool(_alnum_norm(program) and _alnum_norm(program) in _alnum_norm(source))


def _faa_publication_audit(query: str, doc: Dict[str, Any]) -> Dict[str, Any]:
    """Verify FAA *record identity* separately from issue, model and legal effect.

    This is a cross-check of collected official-source data, not a fresh online
    authentication or proof that the regulation is already effective.
    """
    if doc.get("source_id") != "SRC_001":
        return {}

    url = urlsplit(str(doc.get("url") or ""))
    match = (re.fullmatch(r"/documents/(20\d{2})/(\d{2})/(\d{2})/(20\d{2}-\d{5})(?:/[^?#]*)?",
                          url.path, re.I)
             if url.scheme == "https" and (url.hostname or "").lower() in
             {"federalregister.gov", "www.federalregister.gov"} else None)
    document_no = match.group(4).upper() if match else ""
    path_date = "-".join(match.group(i) for i in (1, 2, 3)) if match else ""
    source = f"{doc.get('title') or ''}\n{doc.get('text') or ''}"
    headings = re.findall(
        r"(?im)^(?:Official Summary|Applicability|Affected (?:Aircraft|Models|Products)|"
        r"Manufacturer|Models?)\s*:\s*(.+)$", str(doc.get("text") or "")
    )
    scope = "\n".join([str(doc.get("title") or ""), *headings])
    if not headings:
        scope = source  # Older records may have no structured summary field.

    failed, unverified = [], []
    if not match:
        failed.append("FAA_OFFICIAL_URL_INVALID")
    recorded = set()
    for key in ("federal_register_document", "federal_register_document_number",
                "document_number", "regulatory_document_id"):
        recorded.update(m.group().upper() for m in _FEDERAL_REGISTER_NUMBER.finditer(str(doc.get(key) or "")))
    recorded.update(m.group(1).upper() for m in re.finditer(
        r"(?im)^Federal Register Document:\s*(20\d{2}-\d{5})\b", str(doc.get("text") or "")
    ))
    if recorded and document_no not in recorded:
        failed.append("FAA_DOCUMENT_NUMBER_CONFLICT")
    elif not recorded:
        unverified.append("FAA_DOCUMENT_NUMBER_IN_SOURCE_UNVERIFIED")

    requested = _requested_document_ids(_positive_kit(query))
    requested_numbers = {x for x in requested if _FEDERAL_REGISTER_NUMBER.fullmatch(x)}
    requested_dockets = {x for x in requested if _FAA_DOCKET_PATTERN.fullmatch(x)}
    if requested_numbers and document_no not in requested_numbers:
        failed.append("FAA_REQUESTED_DOCUMENT_CONFLICT")
    dockets = _document_dockets(doc)
    if requested_dockets and not requested_dockets.issubset(dockets):
        (failed if dockets else unverified).append("FAA_REQUESTED_DOCKET_MISMATCH" if dockets
                                                    else "FAA_REQUESTED_DOCKET_UNVERIFIED")

    published = str(doc.get("published_at") or "")[:10]
    publication_verified = bool(path_date and _valid_publication_date(published)
                                and published == path_date)
    if path_date and _valid_publication_date(published) and published != path_date:
        failed.append("FAA_PUBLICATION_DATE_CONFLICT")
    elif not publication_verified:
        unverified.append("FAA_PUBLICATION_DATE_UNVERIFIED")

    positive = _positive_kit(query)
    requested_variants, scoped_variants = _detect_exact_variants_ext(positive), _detect_exact_variants_ext(scope)
    requested_families, scoped_families = (_detect_aircraft_families_ext(positive),
                                           _detect_aircraft_families_ext(scope))
    if requested_variants:
        if scoped_variants and requested_variants.isdisjoint(scoped_variants):
            failed.append("FAA_EXACT_VARIANT_MISMATCH")
        elif not scoped_variants:
            unverified.append("FAA_EXACT_VARIANT_UNVERIFIED")
    elif requested_families:
        if scoped_families and not requested_families.intersection(scoped_families):
            failed.append("FAA_AIRCRAFT_FAMILY_MISMATCH")
        elif not scoped_families:
            unverified.append("FAA_AIRCRAFT_FAMILY_UNVERIFIED")

    # A brand mention in body text is insufficient: prefer official title/summary.
    airframe_manufacturers = (
        "Boeing", "Airbus", "Airbus Canada", "Airbus Helicopters",
        "Embraer", "COMAC", "Bombardier", "ATR", "De Havilland",
        "Gulfstream", "Textron", "Cessna", "Beechcraft", "Bell",
        "Dassault", "Pilatus", "Lockheed Martin", "Sikorsky", "Leonardo",
        "Ilyushin", "Sukhoi", "Antonov", "Tupolev",
    )
    engine_groups = {
        "PW_RTX_IAE": ("Pratt & Whitney", "International Aero Engines", "RTX", "Collins Aerospace"),
        "GE_CFM_SAFRAN": ("GE Aerospace", "General Electric", "CFM International", "Safran"),
        "ROLLS_ROYCE": ("Rolls-Royce",),
        "HONEYWELL": ("Honeywell",),
        "WILLIAMS": ("Williams International",),
    }
    wanted_airframe = {m for m in airframe_manufacturers if _contains_entity(positive, m)}
    actual_airframe = {m for m in airframe_manufacturers if _contains_entity(scope, m)}
    wanted_engine_groups = {
        grp for grp, names in engine_groups.items()
        if any(_contains_entity(positive, n) for n in names)
    }
    actual_engine_groups = {
        grp for grp, names in engine_groups.items()
        if any(_contains_entity(scope, n) for n in names)
    }
    actual_engine_names = {
        n for names in engine_groups.values() for n in names
        if _contains_entity(scope, n)
    }
    named_maker = str(doc.get("manufacturer") or doc.get("manufacturer_name") or "")
    metadata_airframe = {m for m in airframe_manufacturers if _contains_entity(named_maker, m)}
    metadata_engine_groups = {
        grp for grp, names in engine_groups.items()
        if any(_contains_entity(named_maker, n) for n in names)
    }
    actual_makers = actual_airframe | actual_engine_names

    if wanted_airframe and actual_airframe and not wanted_airframe.intersection(actual_airframe):
        failed.append("FAA_MANUFACTURER_MISMATCH")
    elif wanted_airframe and metadata_airframe and not wanted_airframe.intersection(metadata_airframe):
        failed.append("FAA_MANUFACTURER_METADATA_CONFLICT")
    elif wanted_engine_groups and actual_engine_groups and not wanted_engine_groups.intersection(actual_engine_groups):
        failed.append("FAA_MANUFACTURER_MISMATCH")
    elif wanted_engine_groups and metadata_engine_groups and not wanted_engine_groups.intersection(
            metadata_engine_groups):
        failed.append("FAA_MANUFACTURER_METADATA_CONFLICT")
    elif (wanted_airframe and not actual_airframe) or (wanted_engine_groups and not actual_engine_groups):
        unverified.append("FAA_MANUFACTURER_UNVERIFIED")
    if _detect_engine_models_ext(positive):
        if _detect_engine_models_ext(scope) and not _engine_models_compatible(positive, scope):
            failed.append("FAA_ENGINE_MODEL_MISMATCH")
        elif not _engine_models_compatible(positive, scope):
            unverified.append("FAA_ENGINE_MODEL_UNVERIFIED")
        elif "FAA_EXACT_VARIANT_MISMATCH" not in failed and "FAA_AIRCRAFT_FAMILY_MISMATCH" not in failed:
            if "FAA_EXACT_VARIANT_UNVERIFIED" in unverified:
                unverified.remove("FAA_EXACT_VARIANT_UNVERIFIED")
            if "FAA_AIRCRAFT_FAMILY_UNVERIFIED" in unverified:
                unverified.remove("FAA_AIRCRAFT_FAMILY_UNVERIFIED")

    requested_issues = _issue_categories(positive)
    scoped_issues = _issue_categories(scope)
    passage = _source_evidence_quote(doc, positive)
    req_components = _component_requirements(positive)
    matched_comp = {c for c in req_components if _component_matched(c, source)}
    missing_components = set() if matched_comp else req_components
    kit_named_entities = (
        _extract_kit_entities(positive)
        if not (requested_variants or requested_families or _detect_engine_models_ext(positive))
        else set()
    )
    entity_ok = (not kit_named_entities) or any(_contains_entity(source, e) for e in kit_named_entities)
    non_regulatory_commercial = bool(
        requested_issues and requested_issues <= {"ORDER", "STRIKE"}
    )
    exact_doc_hit = bool(requested and (requested & _document_identifiers(doc)))
    engine_match_hit = bool(
        _detect_engine_models_ext(positive)
        and _engine_models_compatible(positive, source)
    )
    issue_verified = bool(
        requested_issues and requested_issues.intersection(scoped_issues)
        and passage and _quote_context(doc, passage)
        and entity_ok and not non_regulatory_commercial
        and (not missing_components or bool(requested) or engine_match_hit)
    ) or bool(
        exact_doc_hit
        and requested_issues and requested_issues.intersection(scoped_issues)
        and passage and not non_regulatory_commercial
    )
    if not issue_verified:
        unverified.append("FAA_ISSUE_PASSAGE_UNVERIFIED")
    unverified.extend(f"REQUIRED_COMPONENT:{c}" for c in sorted(missing_components))

    # Consult the dedicated contract if present; negative contract results
    # never become affirmative merely because the URL looks plausible.
    contract = {}
    if inspect_official_faa_publication is not None:
        try:
            arguments = list(signature(inspect_official_faa_publication).parameters)
            inspected = (inspect_official_faa_publication(doc) if len(arguments) == 1 else
                         inspect_official_faa_publication(doc, query)
                         if arguments and arguments[0].lower() in {"doc", "document", "record", "publication"}
                         else inspect_official_faa_publication(query, doc))
        except (TypeError, ValueError, KeyError, AttributeError) as exc:
            logger.warning("[FAA IDENTITY] Inspection unavailable: %s", exc)
            inspected = None
        if isinstance(inspected, dict):
            contract = inspected
            if contract.get("document_identity_verified") is False:
                failed.append("FAA_CONTRACT_IDENTITY_REJECTED")
            if contract.get("document_publication_verified") is False:
                publication_verified = False
                unverified.append("FAA_CONTRACT_PUBLICATION_UNVERIFIED")
            if contract.get("issue_relevance_verified") is False:
                issue_verified = False
                unverified.append("FAA_CONTRACT_ISSUE_UNVERIFIED")
            if contract.get("aircraft_applicability_verified") is False:
                unverified.append("FAA_AIRCRAFT_APPLICABILITY_UNVERIFIED")
        elif inspected is False:
            failed.append("FAA_CONTRACT_IDENTITY_REJECTED")

    identity_verified = bool(match and recorded and publication_verified and not failed)
    text = str(doc.get("text") or "")
    lifecycle_checked = bool(re.search(r"(?im)^Regulatory Lifecycle Check:\s*VERIFIED\s*$", text))
    stage = re.search(r"(?im)^Regulatory Stage:\s*(PROPOSED|FINAL_ISSUED|EFFECTIVE)\s*$", text)
    effective_date = re.search(r"(?im)^Effective Date:\s*(20\d{2}-\d{2}-\d{2})\s*$", text)
    lifecycle_verified = bool(lifecycle_checked and stage)
    if not lifecycle_verified:
        unverified.append("FAA_REGULATORY_LIFECYCLE_UNVERIFIED")
    if not effective_date or not _valid_publication_date(effective_date.group(1)):
        unverified.append("FAA_EFFECTIVE_DATE_UNVERIFIED")

    return {
        "document_identity_verified": identity_verified,
        "document_publication_verified": publication_verified,
        "issue_relevance_verified": issue_verified and not bool(failed),
        "applicable_variants": sorted(scoped_variants),
        "applicable_families": sorted(scoped_families),
        "applicable_manufacturers": sorted(actual_makers),
        "document_issue_categories": sorted(scoped_issues),
        "aircraft_applicability_verified": not any(x.startswith(("FAA_EXACT_VARIANT_", "FAA_AIRCRAFT_",
                                                                 "FAA_MANUFACTURER_", "FAA_ENGINE_"))
                                                    for x in failed + unverified),
        "regulatory_lifecycle_verified": lifecycle_verified,
        "technical_requirement_verified": False,
        "effective_date_verified": bool(lifecycle_verified and stage.group(1) == "EFFECTIVE"
                                        and effective_date and _valid_publication_date(effective_date.group(1))),
        "official_document_number": document_no,
        "official_document_passage": passage if issue_verified else "",
        "identity_evidence_basis": "OFFICIAL_SOURCE_CROSSCHECK",
        "failed": sorted(set(failed)), "unverified": sorted(set(unverified)),
    }


def _validate_semantic_decision(query: str, doc: Dict[str, Any], decision: Dict[str, Any]) -> Dict[str, Any]:
    """Check a model's cited fact, its local context and the KIT's hard constraints."""
    result = dict(decision)
    source = f"{doc.get('title') or ''}\n{doc.get('text') or ''}"
    quote = str(result.get("evidence_excerpt") or "").strip().strip('"\'')[:450]
    faa = _faa_publication_audit(query, doc)
    result["official_faa_audit"] = faa
    result["evidence_recovered"] = False
    if (faa.get("document_identity_verified") and faa.get("issue_relevance_verified")
            and not _quote_context(doc, quote)):
        replacement = faa.get("official_document_passage") or ""
        if replacement and _quote_context(doc, replacement):
            quote, result["evidence_recovered"] = replacement, True
    result.update(
        evidence_excerpt=quote, rules_version=_FR03_RULES_VERSION,
        decision_rationale=str(result.get("decision_rationale") or result.get("rationale") or "")[:600],
    )
    result["rationale"] = result["decision_rationale"]
    for field in ("matched_entity", "matched_program", "matched_issue"):
        result[field] = str(result.get(field) or "")[:160]

    context = _quote_context(doc, quote) if quote else ""
    checks = _relevance_checks(query, doc, context or quote)
    failed, unverified = set(checks["failed"]), set(checks["unverified"])
    identity_basis = _entity_provenance(doc, result["matched_entity"], quote, context)
    identity_unverified = identity_basis == "UNVERIFIED_ENTITY"
    result["entity_identity_basis"] = identity_basis
    result["identity_review_reason"] = (
        ("SEC_ISSUER_METADATA_UNVERIFIED" if doc.get("sec_company") else
         "ENTITY_ATTRIBUTION_UNVERIFIED") if identity_unverified else ""
    )
    result["conditions_met"] = checks["passed"]
    result["conditions_unmet"] = checks["failed"]
    result["conditions_unverified"] = checks["unverified"]
    result["evidence_validated"] = False
    result["evidence_validation_reason"] = "NOT_ACCEPTED"
    if not result.get("is_relevant"):
        candidate = (not checks["hard_conflict"] and (
            _potential_status_change(query, doc)
            or identity_unverified and bool(context)
        ))
        result["filter_decision"] = (
            "REJECT_CONFIRMED_MISMATCH" if checks["hard_conflict"] else
            "REVIEW_POTENTIALLY_RELEVANT" if candidate else "CONTEXT_ONLY"
        )
        result["relevance_level"] = (
            "IRRELEVANT" if checks["hard_conflict"] else
            "POTENTIAL_KIT_SIGNAL" if candidate else "RELATED_CONTEXT"
        )
        return result

    query_entities = [item.split(":", 1)[1] for item in _query_precision(query)["REQUIRED"]
                      if item.startswith("ENTITY:")]
    quote_norm = _alnum_norm(quote)
    if len(quote_norm) < 25 or not context:
        reason = "EVIDENCE_EXCERPT_NOT_FOUND"
    elif (result["matched_program"] and not _program_claim_grounded(result["matched_program"], source)
          and not (faa.get("document_identity_verified") and faa.get("issue_relevance_verified")
                   and faa.get("aircraft_applicability_verified"))):
        reason = "PROGRAM_CLAIM_NOT_GROUNDED"
    elif identity_unverified and not faa.get("document_identity_verified"):
        reason = "ENTITY_IDENTITY_UNVERIFIED"
    elif (result["matched_entity"] and query_entities and not faa.get("document_identity_verified") and not any(
        _sec_issuer_matches(cand, name) or _entity_in_text(cand, name)
        for cand in _split_entity_candidates(result["matched_entity"])
        for name in query_entities
    )):
        reason = "KIT_ENTITY_MISMATCH"
    elif faa.get("failed") or (not faa and _regulatory_relevance_gap(query, doc)):
        reason = "REGULATORY_IDENTITY_OR_APPLICABILITY_GAP"
    elif checks["hard_conflict"]:
        reason = "PROGRAM_CONFLICT"
    elif "INSUFFICIENT_SOURCE_TEXT" in failed:
        reason = "INSUFFICIENT_SOURCE_TEXT"
    else:
        reason = ""

    issues = _issue_categories(_positive_kit(query))
    local_issues = _issue_categories(context or quote)
    change = _status_change_evidence(query, doc)
    change_grounded = bool(change and (
        _alnum_norm(quote) in _alnum_norm(change[1])
        or _alnum_norm(change[1]) in _alnum_norm(context)
    ))
    claimed_issue_cats = _issue_categories(result["matched_issue"]) if result["matched_issue"] else set()
    if (claimed_issue_cats
            and not (claimed_issue_cats & local_issues)
            and not change_grounded):
        reason = reason or "MATCHED_ISSUE_NOT_GROUNDED"
    if issues and not local_issues.intersection(issues) and not change_grounded:
        reason = reason or "ISSUE_NOT_EVIDENCED"
    if ({"REQUIRED_PROGRAM", "REQUIRED_ENGINE", "PROGRAM_ISSUE_LINK_UNCLEAR"} & unverified):
        reason = reason or "PROGRAM_ISSUE_LINK_NOT_EVIDENCED"
    if {"REQUIRED_ENTITY", "ENTITY_ISSUER_DIFFERENT"} & unverified:
        reason = reason or "ENTITY_ISSUE_LINK_UNVERIFIED"
    if missing := _mandatory_gaps(checks):
        reason = reason or ("COMPONENT_EVIDENCE_MISSING" if any(
            item.startswith("REQUIRED_COMPONENT:") for item in missing
        ) else "REQUIRED_IDENTITY_OR_SCOPE_UNVERIFIED")
    if not issues and not set(re.findall(r"\b[a-z0-9]{4,}\b", _alnum_norm(_positive_kit(query)))).intersection(
        set(re.findall(r"\b[a-z0-9]{4,}\b", _alnum_norm(context or quote)))
    ):
        reason = reason or "KIT_ANCHOR_MISSING"

    complete = not issues or bool(issues & local_issues)
    if reason:
        level = "RELATED_CONTEXT" if checks["hard_conflict"] else "POTENTIAL_KIT_SIGNAL"
        outcome = "REJECT_CONFIRMED_MISMATCH" if checks["hard_conflict"] else "REVIEW_POTENTIALLY_RELEVANT"
    elif change_grounded and (not complete or change[0] in {
        "ISSUE_RESOLVED", "ISSUE_PARTIALLY_RESOLVED", "ISSUE_IMPROVED", "ISSUE_WITHDRAWN",
    }):
        level, outcome = "STATUS_CHANGE_KIT_EVIDENCE", "ACCEPT_STATUS_CHANGE"
    elif complete:
        level, outcome = "DIRECT_KIT_EVIDENCE", "ACCEPT_DIRECT"
    else:
        level, outcome = "POTENTIAL_KIT_SIGNAL", "REVIEW_POTENTIALLY_RELEVANT"

    result.update(
        relevance_level=level, filter_decision=outcome,
        evidence_validated=not bool(reason),
        evidence_validation_reason=reason or "VERIFIED_IN_SOURCE",
    )
    return result

def _source_evidence_quote(doc: Dict[str, Any], query: str) -> str:
    """Select an actual contiguous passage for audited official-source fallback."""
    source = str(doc.get("text") or "")
    concepts = _issue_categories(query)
    for sentence in re.split(r"(?<=[.!?])\s+|\n+", source):
        if len(sentence) >= 45 and _issue_categories(sentence).intersection(concepts):
            if len(sentence) > 350:
                first_issue = next((re.search(pattern, sentence, re.I)
                                    for name, pattern in _ISSUE_CONCEPTS.items() if name in concepts
                                    and re.search(pattern, sentence, re.I)), None)
                start = max(0, (first_issue.start() if first_issue else 0) - 100)
                return sentence[start:start + 350].strip()
            return sentence.strip()
    return source[:300].strip() if len(source.strip()) >= 45 else ""


def _review_reasons(query: str, doc: Dict[str, Any], sem: Dict[str, Any] | None = None) -> List[str]:
    quote = str((sem or {}).get("evidence_excerpt") or "")
    checks = _relevance_checks(query, doc, _quote_context(doc, quote) if quote else "")
    reasons = list(checks["failed"])
    reasons.extend(item for item in checks["unverified"] if item in {
        "ISSUE_NOT_EVIDENCED", "REQUIRED_PROGRAM", "REQUIRED_ENGINE",
        "REQUIRED_ENTITY", "PROGRAM_ISSUE_LINK_UNCLEAR",
    })
    if any(item.startswith("REQUIRED_COMPONENT:") for item in checks["unverified"]):
        reasons.append("COMPONENT_EVIDENCE_MISSING")
    if "INSUFFICIENT_SOURCE_TEXT" in reasons:
        reasons.append("SOURCE_TEXT_INSUFFICIENT")  # Legacy audit consumer.
    if sem is None:
        reasons.append("UNCLASSIFIED")
    elif sem.get("is_relevant") and not sem.get("evidence_validated"):
        reasons.append(str(sem.get("evidence_validation_reason") or "EVIDENCE_UNVERIFIED"))
    elif (sem.get("is_relevant") is False and not checks["hard_conflict"]
          and _issue_categories(query).intersection(_issue_categories(
              f"{doc.get('title') or ''} {doc.get('text') or ''}"
          ))):
        reasons.append("POSSIBLE_FALSE_NEGATIVE")
    if (not sem or not sem.get("is_relevant")) and _status_change_evidence(query, doc):
        reasons.extend(("STATUS_CHANGE_CANDIDATE", "POSSIBLE_FALSE_NEGATIVE"))
    elif (not sem or not sem.get("is_relevant")) and _potential_status_change(query, doc):
        reasons.append("STATUS_CHANGE_CANDIDATE")
    if gap := _regulatory_relevance_gap(query, doc):
        reasons.append(gap.split(":", 1)[0])
    return list(dict.fromkeys(reasons))

# Select a bounded source excerpt emphasizing KIT terms and operational risk indicators.
def relevant_excerpt(text: str, query: str, limit: int = 1500) -> str:
    """Prioritize KIT-specific and risk-related passages under a bounded context budget."""
    terms = set(re.findall(r"\b[a-z0-9]{3,}\b", query.lower()))
    risks = {"delay", "shortage", "defect", "recall", "grounded", "disruption", "inspection",
             "certified", "approved", "granted", "cleared", "resolved", "improved",
             "withdrawn", "superseded", "replaced", "lifted"}

    pattern = "|".join(re.escape(x) for x in terms | risks)
    matches = list(re.finditer(r"\b(?:" + pattern + r")\b", text, re.I))

    snippets = [text[max(0, m.start() - 200):m.end() + 350] for m in matches]
    snippets.sort(
        key=lambda s: sum(3 for w in terms if w in s.lower()) + sum(2 for w in risks if w in s.lower()),
        reverse=True,
    )
    return (text[:250] + "\n...\n" + "\n...\n".join(snippets[:2]))[:limit]

# Identify documents that share background context but do not support the specific KIT issue.
# Record why contextual overlap was insufficient for a direct KIT signal.
def _kit_context_reason(
    query: str, doc: Dict[str, Any], status_change: tuple[str, str] | None = None,
) -> str:
    """Keep broad company overlap separate from proof of the requested issue."""
    text = f"{doc.get('title') or ''} {doc.get('text') or ''}"
    checks = _relevance_checks(query, doc)
    if checks["hard_conflict"]:
        return "RELATED_CONTEXT: explicitly requested entity, model or engine conflicts with the source."
    if any(item.startswith("REQUIRED_COMPONENT:") for item in checks["unverified"]):
        return "RELATED_CONTEXT: the source does not establish the explicitly requested component."
    if status_change or _status_change_evidence(query, doc):
        return ""
    requested, observed = _issue_categories(query), _issue_categories(text)
    if requested and not requested.intersection(observed):
        return "RELATED_CONTEXT: the required issue is not evidenced; entity overlap alone is insufficient."
    operational = {"SUPPLY", "DEFECT", "INSPECTION", "GROUNDING", "DELAY"}
    if requested & operational and "ORDER" in observed and not re.search(
        r"\b(?:shortag\w*|disrupt\w*|constraint\w*|defect\w*|fault\w*|"
        r"inspect\w*|ground\w*|delay\w*|resum\w*|restor\w*)\b", text, re.I
    ):
        return "RELATED_CONTEXT: commercial transaction without the monitored operational issue."
    return ""
def _official_easa_interim_direct_match(doc: Dict[str, Any], kit: str) -> bool:
    """Conservative fallback for official EASA AD index records."""
    if doc.get("source_id") != "SRC_002" or doc.get("origin_type") != "PRIMARY_OFFICIAL_INDEX_METADATA":
        return False

    text = f"{doc.get('title') or ''} {doc.get('text') or ''}".lower()
    query = kit.lower()

    if not re.search(r"\beasa\s+ad\s+20\d{2}-\d{4}", text):
        return False

    if not _detect_engine_models(query):
        return False

    if not _engine_models_match(query, text):
        return False

    # Require issue-specific evidence in official metadata.
    if re.search('\\binspect\\w*', query) and (not re.search('\\binspect\\w*', text)):
        return False

    required_components = _component_requirements(query)
    if required_components and not any(
        _alnum_norm(component) in _alnum_norm(text)
        for component in required_components
    ):
        return False

    return True

# Ask the LLM to classify a batch while distinguishing events, weak signals, and general noise.
# Rejected classifications must retain their reason for subsequent manual review.
def _run_batch_semantic_llm_filter(
    candidates: List[Dict[str, Any]], user_query: str, _retry_split: bool = True
) -> Dict[str, Dict[str, Any]]:
    # Request a structured batch response and keep the semantic categories distinct.
    """Classify candidate sources for KIT relevance in a single model-assisted batch."""
    if not candidates:
        return {}

    if len(candidates) > 5:
        combined = {}
        for start in range(0, len(candidates), 5):
            combined.update(_run_batch_semantic_llm_filter(candidates[start:start + 5], user_query))
        return combined

    catalog_ctx = build_catalog_prompt_context(user_query)
    items_payload = [
        {
            "doc_id": d["doc_id"],
            "source_type": d.get("source_type", "MEDIA"),
            "published_at": d.get("published_at", "DATE_UNKNOWN"),
            "title": d.get("title", "")[:160],
            "excerpt": relevant_excerpt(d.get("text", ""), user_query, limit=900),
            "official_issuer": _verified_sec_issuer(d),
            "sec_cik": d.get("sec_cik") if _verified_sec_issuer(d) else "",
            "evidence_passages": str(d.get("evidence_passages") or "")[:1200],
        }
        for d in candidates
    ]

    prompt = (
        f"You are a Competitive Intelligence semantic pre-filter for the aerospace Early Warning System.\n"
        f"Target Key Intelligence Topic (KIT): '{user_query}'\n"
        f"Active KIQ Context:\n{catalog_ctx}\n\n"
        "Evaluate EACH document in the JSON array below and classify it strictly:\n"
        "- Reject (`is_relevant: false`, `signal_type: \"GENERAL_NOISE\"`) if the document is about a DIFFERENT aircraft family "
        "(compare exact models and variants rather than assuming compatibility) "
        "unless it directly concerns a shared supplier bottleneck requested in the KIT.\n"
        "- Reject routine airline PR, hobbyist/model reviews, or general background noise without a concrete event or warning indicator.\n"
        "- Reject purely historical background, aircraft specifications "
        "and documentaries unless they describe a NEW development "
        "within the monitoring period that directly matches the KIT.\n"
        "- Label RELATED_CONTEXT (is_relevant=false) for orders "
        "or other events involving the same entity but not "
        "the KIT issue.\n"
        "- Do NOT reject a document solely because its claims are unverified.\n"
        "- Track the entire KIT lifecycle: confirmation, deterioration, improvement, resolution, "
        "and withdrawal or supersession. Completion of a delayed certification, restored supply, "
        "or lifting of a restriction is KIT-relevant even though it is positive news.\n"
        "- Classify a documented change as ISSUE_EMERGED, ISSUE_ONGOING, ISSUE_WORSENED, "
        "ISSUE_IMPROVED, ISSUE_PARTIALLY_RESOLVED, ISSUE_RESOLVED, or ISSUE_WITHDRAWN when appropriate. "
        "Do not confuse a completed event with a proposal, expectation, or conditional approval.\n"
        "- Identify the exact process affected by a change. Completed inspections do not prove "
        "defect resolution; aircraft certification does not prove delivery resumption.\n"
        "- Use the publication date and wording to distinguish a new status change from historical "
        "background. A newer update may supersede an older risk signal without proving all downstream effects.\n"
        "- Retain relevant technical anomalies as WEAK_SIGNAL when they match the KIT.\n"
        "- When evidence is ambiguous, prefer WEAK_SIGNAL over GENERAL_NOISE.\n"
        "- Accept (`is_relevant: true`) for a KIT-matching RELEVANT_EVENT, lifecycle status change, "
        "or WEAK_SIGNAL (early community/operational anomaly). Relevance does not verify the claim.\n\n"
        "- For competitive KITs, retain concrete new aircraft orders, "
        "cancellations, contracts and market-position changes.\n"
        "- For SAF/environmental KITs, retain concrete certification decisions, "
        "regulatory changes and new compliance obligations.\n"
        "- These must directly match the KIT; reject unrelated routine PR.\n"
        "- For any accepted decision, copy a contiguous 40-240 character evidence_excerpt VERBATIM "
        "from that document's title or excerpt (never paraphrase or borrow another document's evidence).\n"
        "- Distinguish the explicitly evidenced entity, program/aircraft/engine and monitored issue. "
        "A relevant brand alone does not prove a certification, defect or delay.\n"
        "- SEC issuer identity may be established by the official_issuer and SEC CIK when provided; "
        "a filing's first-person 'we' can refer to that issuer. Do not apply this assumption to media.\n"
        "- Extract separate locally cited relevant_claims if a document supports several facts, "
        "each with evidence_excerpt, claim_type and matched_kiq_id. Never combine unrelated passages.\n"
        "- Treat an explicitly requested exact model or engine variant as REQUIRED (e.g. different "
        "variants cannot be substituted). Treat broad topic synonyms as PREFERRED and surrounding "
        "industry context as CONTEXTUAL; never invent a model missing from the KIT.\n"
        "- A publication about restored deliveries may be a new development even when the older "
        "shortage wording is absent. Do not infer that the root shortage itself was resolved "
        "unless the source explicitly establishes the causal link and resolution.\n"
        "- A citation is one contiguous verified passage. The title or immediately neighboring "
        "sentences may identify its subject, but unrelated sections cannot be combined into a claim.\n"
        "- Never convert missing source content or an inaccessible semantic model into an irrelevant finding.\n"
        "- Do not require every KIT word literally; recognize equivalent event descriptions, "
        "but report uncertainty when program applicability or the monitored event is not established.\n"
        "Return ONLY a valid JSON array where each element has this exact schema:\n"
        "[\n"
        "  {\n"
        '    "doc_id": "DOC_001",\n'
        '    "is_relevant": true,\n'
        '    "matched_kiq_id": "",\n'
        '    "entities_models_tech": "Entities and technology explicitly named in the document",\n'
        '    "matched_entity": "Exact entity named in cited passage or empty",\n'
        '    "matched_program": "Exact program/model named in the source or empty",\n'
        '    "matched_issue": "Requested event/issue evidenced by the passage or empty",\n'
        '    "evidence_excerpt": "Verbatim contiguous source passage supporting the decision",\n'
        '    "relevant_claims": [{"evidence_excerpt": "Verbatim passage", "claim_type": "DIRECT_ISSUE", "matched_kiq_id": ""}],\n'
        '    "signal_type": "RELEVANT_EVENT",\n'
        '    "decision_rationale": "Why this passage addresses the KIT (or why the record is unrelated)."\n'
        "  }\n"
        "]\n\n"
        f"DOCUMENTS TO EVALUATE:\n{json.dumps(items_payload, ensure_ascii=False)}"
    )

    raw_response = ""
    if GEMINI_API_KEY:
        try:
            client = genai.Client(api_key=GEMINI_API_KEY)
            resp = call_external_llm_tracked(
                lambda: client.models.generate_content(model="gemini-3.5-flash-lite", contents=prompt),
                task_type="FR03_SEMANTIC_FILTER", model="gemini-3.5-flash-lite", provider="google",
            )
            raw_response = resp.text or ""
        except Exception as e:
            logger.debug(f"[SEMANTIC FILTER] Gemini batch call failed ({e}), falling back to fast_llm.")

    if not raw_response:
        try:
            res = call_tracked_llm(fast_llm, [{"role": "user", "content": prompt}],
                                   task_type="FR03_SEMANTIC_FILTER")
            raw_response = str(res or "")
        except Exception as e:
            logger.warning(f"[SEMANTIC FILTER] LLM batch call unavailable ({e}), using deterministic fallback.")
            return {}

    result_map: Dict[str, Dict[str, Any]] = {}
    allowed_docs = {str(d["doc_id"]).strip().upper(): d for d in candidates}
    repeated_ids: set[str] = set()

    # Parse model JSON defensively; an invalid response is not evidence of irrelevance.
    try:
        match = re.search(r"\[.*\]", raw_response, re.S)
        if not match:
            raise ValueError("Model response does not contain a JSON array")

        parsed_list = json.loads(match.group(0))
        if not isinstance(parsed_list, list):
            raise ValueError("Semantic response must be a JSON array")

        for item in parsed_list:
            if not isinstance(item, dict):
                continue
            doc_id = str(item.get("doc_id") or "").strip().upper()
            if doc_id in allowed_docs and type(item.get("is_relevant")) is bool:
                if doc_id in result_map:
                    repeated_ids.add(doc_id)
                else:
                    result_map[doc_id] = _validate_semantic_decision(user_query, allowed_docs[doc_id], item)
        for duplicate in repeated_ids:
            result_map.pop(duplicate, None)  # Ambiguous attribution: retry this record alone.
        if repeated_ids:
            logger.warning("[FR03 EVIDENCE] Duplicate document IDs in model batch: %s", sorted(repeated_ids))
    except (ValueError, TypeError) as exc:
        logger.warning("[SEMANTIC FILTER] Invalid batch JSON: %s", exc)

    missing = [d for d in candidates if str(d["doc_id"]).strip().upper() not in result_map]
    if missing and _retry_split:
        midpoint = max(1, len(missing) // 2)
        groups = [missing] if len(missing) == 1 else [missing[:midpoint], missing[midpoint:]]
        logger.warning(
            "[SEMANTIC FILTER RECOVERY] Retrying %d unclassified document(s) in %d smaller group(s)",
            len(missing), len(groups),
        )
        for group in groups:
            result_map.update(_run_batch_semantic_llm_filter(group, user_query, _retry_split=False))

    return result_map

# Reuse versioned semantic decisions and classify only uncached candidates.
# Cache reuse is versioned and keyed to avoid unnecessary model calls without silently changing old
#   decisions.
# Cache hits are version-scoped; unavailable classifications do not prove irrelevance.
def _cached_semantic_filter(
    candidates: List[Dict[str, Any]], user_query: str, revalidate_suspicious: bool = False,
) -> Dict[str, Dict[str, Any]]:
    # Reuse available cached classifications and classify the remaining documents.
    if not candidates:
        return {}

    catalog_context = build_catalog_prompt_context(user_query)
    kit = " ".join(user_query.lower().split())
    revalidate_suspicious = revalidate_suspicious or os.getenv("EWS_FR03_REVALIDATE_SUSPICIOUS", "0") == "1"

    # Build a stable cache key for a document and the active KIT.
    def stable_key(doc: Dict[str, Any]) -> str:
        payload = {
            "version": _SEMANTIC_CACHE_VERSION,
            "rules_version": _FR03_RULES_VERSION,
            "prompt_version": PROMPT_VERSION,
            "kit": kit,
            "catalog_context": catalog_context,
            "source_id": doc.get("source_id") or "",
            "source_type": doc.get("source_type") or "",
            "url": (doc.get("url") or "").strip(),
            "title": doc.get("title") or "",
            "text": doc.get("text") or "",
            "published_at": doc.get("published_at") or "",
            "sec_company": doc.get("sec_company") or "",
            "sec_cik": doc.get("sec_cik") or "",
            "sec_ticker": doc.get("sec_ticker") or "",
            "evidence_authority": doc.get("evidence_authority") or "",
            "evidence_passages": doc.get("evidence_passages") or [],
            "source_content_sha256": doc.get("source_content_sha256") or "",
        }
        return hashlib.sha256(json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()

    semantic_map, cache_keys, missing = {}, {}, []

    try:
        with DB_LOCK, sqlite3.connect(SQLITE_DB) as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS semantic_filter_cache (cache_key TEXT PRIMARY KEY, decision_json TEXT NOT NULL)"
            )
            for doc in candidates:
                doc_id = str(doc["doc_id"]).upper()
                key = stable_key(doc)
                cache_keys[doc_id] = key

                row = conn.execute("SELECT decision_json FROM semantic_filter_cache WHERE cache_key = ?", (key,)).fetchone()
                if row:
                    try:
                        decision = json.loads(row[0])
                        if (isinstance(decision, dict)
                                and type(decision.get("is_relevant")) is bool
                                and decision.get("rules_version") == _FR03_RULES_VERSION
                                and type(decision.get("evidence_validated")) is bool):
                            if not (revalidate_suspicious and decision["is_relevant"]
                                    and (not decision["evidence_validated"]
                                         or decision.get("relevance_level") == "POTENTIAL_KIT_SIGNAL")):
                                decision["doc_id"] = doc_id
                                semantic_map[doc_id] = _validate_semantic_decision(user_query, doc, decision)
                                continue
                    except (ValueError, TypeError):
                        pass
                missing.append(doc)
    except sqlite3.Error as exc:
        logger.warning("[FILTER CACHE] Unavailable: %s; using live filter", exc)
        missing = list(candidates)
        cache_keys = {str(d["doc_id"]).upper(): stable_key(d) for d in candidates}

    if missing:
        ordered = sorted(
            missing,
            key=lambda d: (str(d.get("url") or ""), str(d.get("title") or ""), str(d.get("doc_id") or "")),
        )
        new_decisions = _run_batch_semantic_llm_filter(ordered, user_query)
        docs_by_id = {str(d["doc_id"]).upper(): d for d in ordered}
        new_decisions = {
            doc_id: _validate_semantic_decision(user_query, docs_by_id[doc_id], decision)
            for doc_id, decision in new_decisions.items() if doc_id in docs_by_id
        }
        semantic_map.update(new_decisions)

        try:
            with DB_LOCK, sqlite3.connect(SQLITE_DB) as conn:
                for doc_id, decision in new_decisions.items():
                    if doc_id not in cache_keys or type(decision.get("is_relevant")) is not bool:
                        continue
                    payload = {k: v for k, v in decision.items() if k != "doc_id"}
                    conn.execute(
                        "INSERT OR REPLACE INTO semantic_filter_cache (cache_key, decision_json) VALUES (?, ?)",
                        (cache_keys[doc_id], json.dumps(payload, ensure_ascii=False)),
                    )
        except sqlite3.Error as exc:
            logger.warning("[FILTER CACHE] Could not save decisions: %s", exc)

    logger.info(
        "[FILTER CACHE] cached=%d fresh=%d total=%d",
        len(candidates) - len(missing),
        len(missing),
        len(candidates)
    )
    return semantic_map

# Persist accept/reject decisions for later false-negative and recall review.
# Keep both accepted and excluded classifications available for reproducible review.
def _save_filter_audit_records(audit_records: List[Dict[str, Any]], run_id: str, run_workspace: str) -> None:
    # Save audit records to the run workspace and available persistence backend.
    if not audit_records:
        return
    if run_workspace and os.path.isdir(run_workspace):
        try:
            with open(os.path.join(run_workspace, "semantic_filter_audit.json"), "w", encoding="utf-8") as f:
                json.dump(audit_records, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.debug(f"[SEMANTIC FILTER] Could not write workspace audit JSON: {e}")

    if not run_id:
        return
    with DB_LOCK, sqlite3.connect(SQLITE_DB) as conn:
        conn.executemany(
            """
            INSERT OR REPLACE INTO document_filter_log (
                run_id, doc_id, source_id, url, title, filter_stage,
                is_accepted, signal_type, entities_models_tech, matched_kiq_id,
                decision_rationale, evaluated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    run_id, rec["doc_id"], rec.get("source_id", ""), rec.get("url", ""), rec.get("title", ""),
                    rec["filter_stage"], 1 if rec["is_accepted"] else 0, rec["signal_type"],
                    rec.get("entities_models_tech", ""), rec.get("matched_kiq_id", ""),
                    rec["decision_rationale"], rec["evaluated_at"],
                )
                for rec in audit_records
            ],
        )
        conn.execute("""
            CREATE TABLE IF NOT EXISTS document_filter_evidence_audit (
                run_id TEXT NOT NULL, doc_id TEXT NOT NULL,
                rules_version TEXT NOT NULL, audit_json TEXT NOT NULL,
                PRIMARY KEY (run_id, doc_id)
            )
        """)
        conn.executemany(
            "INSERT OR REPLACE INTO document_filter_evidence_audit VALUES (?, ?, ?, ?)",
            [(run_id, str(rec["doc_id"]), _FR03_RULES_VERSION,
              json.dumps(rec, ensure_ascii=False, default=str)) for rec in audit_records],
        )
        conn.commit()


def _relevance_status(decision: str, stage: str, signal: str) -> str:
    if decision in {"ACCEPT_DIRECT", "ACCEPT_STATUS_CHANGE"}:
        return "RELEVANT"
    if decision == "REJECT_CONFIRMED_MISMATCH" or signal == "GENERAL_NOISE":
        return "IRRELEVANT"
    if stage.startswith("STAGE_1") or decision == "REVIEW_POTENTIALLY_RELEVANT":
        return "UNKNOWN"
    return "RELATED" if decision == "CONTEXT_ONLY" else "UNKNOWN"


def _claim_kiq_id(quote: str, user_query: str, catalog: List[Dict[str, Any]],
                  fallback: str = "") -> str:
    """Link an individual claim to the best matching known KIQ, not a guessed ID."""
    claim_words = set(re.findall(r"\b[a-z0-9]{5,}\b", _alnum_norm(quote)))
    claim_issues = _issue_categories(quote)
    scored = []
    for item in catalog:
        kiq = str(item.get("kiq_id") or "")
        question = str(next((item[k] for k in (
            "question", "kiq_question", "query", "description", "text", "title"
        ) if item.get(k)), ""))
        if not kiq or not question:
            continue
        if (_detect_exact_variants(question)
                and not _detect_exact_variants(question).issubset(
                    _detect_exact_variants(f"{user_query} {quote}"))):
            continue
        if _detect_engine_models(question) and not _engine_models_match(
            question, f"{user_query} {quote}"
        ):
            continue
        issue_overlap = claim_issues & _issue_categories(question)
        term_overlap = claim_words & set(re.findall(r"\b[a-z0-9]{5,}\b", _alnum_norm(question)))
        if issue_overlap or len(term_overlap) >= 2:
            scored.append((len(issue_overlap) * 4 + len(term_overlap), kiq))
    if scored:
        return sorted(scored, key=lambda value: (-value[0], value[1]))[0][1]
    return fallback if any(item.get("kiq_id") == fallback for item in catalog) else ""


def _extract_relevant_claims(query: str, doc: Dict[str, Any], sem: Dict[str, Any] | None,
                             status_change: tuple[str, str] | None,
                             catalog: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Preserve distinct source-backed KIT statements within one collected document."""
    candidates: List[tuple[str, str, str]] = []
    fallback_kiq = str((sem or {}).get("matched_kiq_id") or "")
    for claim in (sem or {}).get("relevant_claims") or []:
        if isinstance(claim, dict):
            candidates.append((str(claim.get("evidence_excerpt") or ""),
                               str(claim.get("claim_type") or ""),
                               str(claim.get("matched_kiq_id") or "")))
    if sem and sem.get("evidence_validated"):
        candidates.append((str(sem.get("evidence_excerpt") or ""), "DIRECT_ISSUE", fallback_kiq))
    if status_change:
        candidates.append((status_change[1], status_change[0], fallback_kiq))
    passages = doc.get("evidence_passages") or []
    if isinstance(passages, dict):
        passages = list(passages.values())
    if isinstance(passages, str):
        passages = [passages]
    for passage in passages[:30]:
        if isinstance(passage, dict):
            passage = next((passage[k] for k in ("passage", "evidence_excerpt", "excerpt", "text", "quote")
                            if passage.get(k)), "")
        candidates.append((str(passage), "", ""))
    if _issue_categories(query):
        for match in re.finditer(r"[^.!?\n]{45,420}(?:[.!?]|$)", str(doc.get("text") or "")):
            if _issue_categories(match.group()).intersection(_issue_categories(query)):
                candidates.append((match.group().strip(), "", ""))

    claims, seen = [], set()
    issuer_quote = _issuer_status_passage(query, doc)
    for excerpt, kind, kiq in candidates:
        excerpt = re.sub(
            r"^\s*\]?\s*\[E\d+\s+[A-Z_]+(?:\s+offset=\d+)?\]\s*", "", str(excerpt or "")
        ).strip().strip('"\'')[:450]
        normalized = _alnum_norm(excerpt)
        if len(normalized) < 25 or normalized in seen or not _quote_context(doc, excerpt):
            continue
        checks = _relevance_checks(query, doc, excerpt)
        gaps = _mandatory_gaps(checks)
        if (checks["hard_conflict"] or (gaps and not (
                issuer_quote and normalized == _alnum_norm(issuer_quote)
                and all(g.startswith("REQUIRED_AUTHORITY:") for g in gaps)))):
            continue
        status = (status_change if status_change and _alnum_norm(status_change[1]) == normalized else
                  _status_change_evidence(query, {**doc, "text": excerpt}))
        if (not _issue_categories(query).intersection(_issue_categories(excerpt)) and not status
                and (not sem or normalized != _alnum_norm(sem.get("evidence_excerpt") or ""))):
            continue
        kind = status[0] if status else (kind if kind.startswith("DIRECT_") else "DIRECT_ISSUE")
        entity = (str(_verified_sec_issuer(doc)) if issuer_quote and normalized == _alnum_norm(issuer_quote)
                  else str((sem or {}).get("matched_entity") or _verified_sec_issuer(doc) or ""))
        basis = _entity_provenance(doc, entity, excerpt, _quote_context(doc, excerpt))
        if basis == "UNVERIFIED_ENTITY":
            continue
        seen.add(normalized)
        claims.append({
            "claim_id": f"{doc.get('doc_id', 'DOC_UNK')}:C{len(claims) + 1:02d}",
            "doc_id": doc.get("doc_id", ""),
            "source_id": doc.get("source_id", ""),
            "source_url": doc.get("url", ""),
            "published_at": doc.get("published_at", ""),
            "event_at": doc.get("event_at") or doc.get("event_date") or "DATE_UNKNOWN",
            "claim_type": kind,
            "kiq_id": _claim_kiq_id(excerpt, query, catalog, kiq or fallback_kiq),
            "evidence_excerpt": excerpt,
            "evidence_status": ("PRELIMINARY" if issuer_quote and normalized == _alnum_norm(issuer_quote)
                                else "VERIFIED"),
            "source_authority": _source_authority(doc) or "UNVERIFIED",
            "claim_authority_scope": _claim_authority_scope(doc),
            "matched_entity": entity,
            "identity_basis": basis,
            "evidence_validated": True,  # Quotation integrity, not regulatory/event verification.
            "claim_verification": "NOT_VERIFIED",
        })
        if len(claims) >= 6:
            break
    return claims

# Apply two-stage relevance gates and arrange surviving source records into Analyst batches.
# All exclusion paths feed the filter audit so that rejected candidates remain reviewable.
# Store the reason behind every exclusion decision, including unavailable source content.
def prioritize_and_batch_documents(
    docs: List[Dict[str, Any]],
    user_query: str,
    max_chars_per_batch: int = 24000,
    run_id: str = "",
    run_workspace: str = "",
    filter_diagnostics: Dict[str, Any] | None = None,
) -> Tuple[List[str], int, int]:
    # Prepare counters, audit records, and bounded text budgets for this filtering run.
    """Apply deterministic and semantic filters, then batch retained documents."""
    if filter_diagnostics is not None:
        filter_diagnostics.clear()
        filter_diagnostics.update({
            "semantic_filter_missing_ids": [],
            "semantic_filter_unavailable_count": 0,
        })

    if not docs:
        return [], 0, 0

    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    query_precision = _query_precision(user_query)
    q_words = [w.lower() for w in re.findall(r"\b\w{3,}\b", user_query)]

    seen_urls: Dict[str, str] = {}
    seen_fingerprints: Dict[str, str] = {}
    stage1_survivors: List[Dict[str, Any]] = []
    audit_records: List[Dict[str, Any]] = []
    rejected_count = 0

    # Record this source’s decision without losing its provenance.
    def _record_audit(
        d: Dict[str, Any], stage: str, accepted: bool, sig_type: str,
        rationale: str, entities: str = "", kiq: str = "", **extra: Any,
    ) -> None:
        decision = extra.pop("filter_decision", "ACCEPT_DIRECT" if accepted else "REVIEW_POTENTIALLY_RELEVANT")
        conditions_met = extra.pop("conditions_met", [])
        conditions_unmet = extra.pop("conditions_unmet", [])
        conditions_unverified = extra.pop("conditions_unverified", [])
        quote = str(extra.get("evidence_excerpt") or "")
        evidence_status = extra.pop("evidence_status", (
            "UNAVAILABLE" if d.get("content_status") in _LIMITED_CONTENT or not str(d.get("text") or "").strip()
            else "VERIFIED" if quote and _quote_context(d, quote) else "UNVERIFIED"
        ))
        c_status = str(d.get("content_status", "TEXT_COMPLETENESS_UNVERIFIED") or "")
        has_full_text = c_status.upper() in {"FULL_TEXT", "FULL_TEXT_RETRIEVED"}
        stage_1_result = f"REJECT:{sig_type}" if stage.startswith("STAGE_1") else "PASS"
        stage_2_result = (
            "NOT_RUN" if stage.startswith("STAGE_1")
            else (f"PASS:{decision}" if accepted else f"REJECT:{decision}")
        )
        decision_basis = (
            "FILTER_UNAVAILABLE" if sig_type == "FILTER_UNAVAILABLE"
            else "INSUFFICIENT_EVIDENCE" if (c_status.upper() in _LIMITED_CONTENT or evidence_status == "UNAVAILABLE")
            else "HARD_IDENTITY_CONFLICT" if decision == "REJECT_CONFIRMED_MISMATCH"
            else "FACTUAL_CONTENT"
        )
        hay_score = f"{d.get('title', '')} {d.get('text', '')}".lower()
        lexical_score = (
                _SOURCE_TYPE_SCORES.get(d.get("source_type", ""), 20)
                + sum(10 for w in q_words if w in hay_score)
                + (15 if d.get("supplier_registry_match") else 0)
        )
        audit_records.append({
            "doc_id": d.get("doc_id", "DOC_UNK"),
            "original_kit": user_query,
            "source_id": d.get("source_id", ""),
            "connector_name": d.get("connector_name", ""),
            "url": (d.get("url") or "").strip() if stage.startswith("STAGE_1") else d.get("url", ""),
            "title": (d.get("title") or "").strip() if stage.startswith("STAGE_1") else d.get("title", ""),
            "filter_stage": stage,
            "stage_1_result": stage_1_result,
            "stage_2_result": stage_2_result,
            "is_accepted": accepted,
            "signal_type": sig_type,
            "entities_models_tech": entities,
            "matched_kiq_id": kiq,
            "decision_rationale": rationale,
            "decision_basis": decision_basis,
            "relevance_score": lexical_score,
            "has_full_text": has_full_text,
            "evaluated_at": now_iso,
            "content_status": c_status,
            "content_limit_reason": d.get("content_limit_reason", ""),
            "query_precision": query_precision,
            "filter_decision": decision,
            "internal_filter_status": extra.pop("internal_filter_status", (
                "ACCEPTED" if accepted and decision in {"ACCEPT_DIRECT", "ACCEPT_STATUS_CHANGE"}
                else "ACCEPTED_NEEDS_REVIEW" if accepted else "REJECTED"
            )),
            "relevance_status": extra.pop("relevance_status", _relevance_status(decision, stage, sig_type)),
            "evidence_status": evidence_status,
            "lifecycle_status": extra.pop("lifecycle_status", "STATUS_UNKNOWN"),
            "semantic_status": extra.pop("semantic_status", "NOT_RUN"),
            "reason_code": extra.pop("reason_code", sig_type),
            "matched_identity": extra.pop("matched_identity", ""),
            "matched_component": extra.pop("matched_component", ""),
            "source_authority": _source_authority(d) or "UNVERIFIED",
            "claim_authority_scope": _claim_authority_scope(d),
            "event_at": d.get("event_at") or d.get("event_date") or "DATE_UNKNOWN",
            "source_content_sha256": d.get("source_content_sha256") or d.get("content_sha256") or "",
            "conditions_met": conditions_met,
            "conditions_unmet": conditions_unmet,
            "conditions_unverified": conditions_unverified,
            **extra,
        })

    # Stage 1: exclude structurally unusable, duplicated, stale, or clearly mismatched source records.
    # Prefer a substantive copy over an earlier index/snippet of the same URL.
    ordered_docs = sorted(
        docs, key=lambda d: (
            str(d.get("content_status") or "").upper() in {"FULL_TEXT", "FULL_TEXT_RETRIEVED"},
            len(str(d.get("text") or "")),
        ), reverse=True,
    )
    for d in ordered_docs:
        url = (d.get("url") or "").strip()
        fp = (d.get("syndication_fingerprint") or "").strip()
        title = (d.get("title") or "").strip()
        text = (d.get("text") or "").strip()
        pub_date = d.get("published_at") or "DATE_UNKNOWN"
        combined_text = f"{title} {text}"
        faa = _faa_publication_audit(user_query, d)
        d["faa_publication_audit"] = faa
        faa_candidate = bool(faa.get("document_identity_verified") and
                             faa.get("issue_relevance_verified"))

        if faa.get("failed"):
            rejected_count += 1
            _record_audit(
                d, "STAGE_1_FAA_IDENTITY", False, "FAA_IDENTITY_MISMATCH",
                "Official FAA record fails source identity or requested applicability checks.",
                filter_decision="REJECT_CONFIRMED_MISMATCH",
                review_reasons=faa["failed"], conditions_unmet=faa["failed"],
                official_faa_audit=faa, internal_filter_status="REJECTED",
            )
            continue

        if d.get("content_status") in {
            "SOURCE_ACCESS_BLOCKED", "CONTENT_UNAVAILABLE_OR_BLOCKED",
            "FILING_BLOCKED_OR_UNAVAILABLE", "ESEF_REPORT_UNAVAILABLE_OR_BLOCKED",
        }:
            rejected_count += 1
            _record_audit(
                d, "STAGE_1_CONTENT_QUALITY", False, "SOURCE_ACCESS_BLOCKED",
                "Source access failed; KIT relevance remains unknown, not negative.",
                filter_decision="REVIEW_POTENTIALLY_RELEVANT",
                review_reasons=["SOURCE_ACCESS_BLOCKED"],
                conditions_unverified=["SUBSTANTIVE_SOURCE_TEXT"],
            )
            continue

        if ((len(combined_text) < 45 and not faa_candidate)
                or (d.get("prompt_injection_flagged") and len(text) < 80)):
            rejected_count += 1
            _record_audit(
                d, "STAGE_1_DETERMINISTIC", False, "EMPTY_OR_INJECTION",
                "Rejected in Stage 1: Document text is empty, too short, or flagged for prompt injection.",
                filter_decision="REVIEW_POTENTIALLY_RELEVANT",
                review_reasons=["INSUFFICIENT_SOURCE_TEXT", "SOURCE_TEXT_INSUFFICIENT"],
                conditions_unmet=["INSUFFICIENT_SOURCE_TEXT"],
            )
            continue

        if (not faa_candidate and d.get("content_status") in {
            "METADATA_ONLY", "SOURCE_METADATA_ONLY",
        }) or (not faa_candidate and d.get("document_type") in {
            "SEC_FILING_METADATA_ONLY", "ESEF_FILING_METADATA_ONLY",
            "STATISTICAL_METADATA_UPDATE",
        }):
            rejected_count += 1
            _record_audit(
                d, "STAGE_1_CONTENT_QUALITY", False, "SOURCE_METADATA_ONLY",
                "Metadata establish record identity/publication only; substantive KIT claims require source text.",
                filter_decision="REVIEW_POTENTIALLY_RELEVANT",
                content_status="METADATA_ONLY", retained_as_context=True,
                review_reasons=["INSUFFICIENT_SOURCE_TEXT", "SOURCE_TEXT_INSUFFICIENT"],
                conditions_unmet=["INSUFFICIENT_SOURCE_TEXT"],
            )
            continue

        if (url and url in seen_urls) or (fp and fp in seen_fingerprints):
            rejected_count += 1
            original = seen_urls.get(url) if url else None
            original = original or (seen_fingerprints.get(fp) if fp else None)
            _record_audit(
                d, "STAGE_1_DETERMINISTIC", False, "DUPLICATE",
                f"Rejected in Stage 1: Duplicate of document {original or 'UNKNOWN'}.",
                filter_decision="CONTEXT_ONLY",
                review_reasons=["DUPLICATE_OF_DOCUMENT"],
                conditions_unmet=["DUPLICATE_OF_DOCUMENT"],
                duplicate_of_document_id=original,
            )
            continue

        if not _valid_publication_date(pub_date):
            date_probe = f"{url} {text[:500]}"
            iso_hit = re.search(r"\b(20\d{2}-\d{2}-\d{2})\b", date_probe)
            if iso_hit and _valid_publication_date(iso_hit.group(1)):
                pub_date = iso_hit.group(1)
                d["published_at"] = pub_date
            else:
                named_hit = re.search(
                    r"\b(\d{1,2})\s+(Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|"
                    r"Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|"
                    r"Nov(?:ember)?|Dec(?:ember)?)\s+(20\d{2})\b", date_probe, re.I,
                )
                if named_hit:
                    for fmt in ("%d %B %Y", "%d %b %Y"):
                        try:
                            pub_date = datetime.strptime(" ".join(named_hit.groups()), fmt).strftime("%Y-%m-%d")
                            d["published_at"] = pub_date
                            break
                        except ValueError:
                            pass
        if not _valid_publication_date(pub_date):
            rejected_count += 1
            _record_audit(
                d, "STAGE_1_DATE_UNKNOWN", False, "PUBLICATION_DATE_UNVERIFIED",
                "Publication date is unavailable; temporal relevance cannot be established.",
                filter_decision="REVIEW_POTENTIALLY_RELEVANT",
                review_reasons=["PUBLICATION_DATE_UNVERIFIED"],
                conditions_unverified=["PUBLICATION_WITHIN_SCOPE"],
            )
            continue

        if not is_date_within_scope(pub_date):
            rejected_count += 1
            _record_audit(
                d, "STAGE_1_DETERMINISTIC", False, "OUT_OF_SCOPE",
                f"Rejected in Stage 1: Publication date ({pub_date}) is outside the active time window.",
                filter_decision="CONTEXT_ONLY",
                review_reasons=["OUTSIDE_REQUESTED_TIME"],
                conditions_unmet=["OUTSIDE_REQUESTED_TIME"],
            )
            continue

        if (OBVIOUS_NOISE_REGEX.search(title)
                and not _issue_categories(user_query).intersection(_issue_categories(text))):
            rejected_count += 1
            _record_audit(
                d, "STAGE_1_DETERMINISTIC", False, "GENERAL_NOISE",
                "Rejected in Stage 1: Hobbyist scale model or flight simulator content.",
                filter_decision="CONTEXT_ONLY",
                review_reasons=["ISSUE_NOT_EVIDENCED"],
                conditions_unmet=["ISSUE_NOT_EVIDENCED"],
            )
            continue

        identity = _identity_checks(user_query, d)
        if identity["hard_conflict"] and not (
            faa_candidate and set(identity["failed"]) <= {"PROGRAM_CONFLICT"}
            and faa.get("aircraft_applicability_verified")
        ):
            rejected_count += 1
            _record_audit(
                d, "STAGE_1_DETERMINISTIC", False,
                "ENTITY_MISMATCH" if "ENTITY_CONFLICT" in identity["failed"] else "MODEL_MISMATCH",
                "Rejected in Stage 1: Explicitly requested entity, program or engine "
                "conflicts with the retrieved document.",
                filter_decision="REJECT_CONFIRMED_MISMATCH",
                review_reasons=identity["failed"],
                conditions_met=identity["passed"], conditions_unmet=identity["failed"],
                conditions_unverified=identity["unverified"],
            )
            continue

        title_key, text_key = _alnum_norm(title), _alnum_norm(text)
        if title_key and (not text_key or text_key == title_key) and not faa_candidate:
            rejected_count += 1
            _record_audit(
                d, "STAGE_1_CONTENT_QUALITY", False, "SOURCE_METADATA_ONLY",
                "Title-only source record; no source-backed event can be verified.",
                filter_decision="REVIEW_POTENTIALLY_RELEVANT",
                review_reasons=["INSUFFICIENT_SOURCE_TEXT", "SOURCE_TEXT_INSUFFICIENT"],
                conditions_unmet=["INSUFFICIENT_SOURCE_TEXT"],
            )
            continue

        if url:
            seen_urls[url] = str(d.get("doc_id") or "")
        if fp:
            seen_fingerprints[fp] = str(d.get("doc_id") or "")
        stage1_survivors.append(d)

    # Stage 2: classify surviving documents against the full KIT using cached or fresh model decisions.
    logger.info(
        f"[SEMANTIC FILTER FR03] Stage 1 passed {len(stage1_survivors)}/{len(docs)} docs "
        f"(rejected {rejected_count}). Running Stage 2 batch LLM semantic check..."
    )
    # The second stage classifies the survivors; cache reuse does not bypass the deterministic stage.
    try:
        semantic_map = _cached_semantic_filter(stage1_survivors, user_query)
    except Exception:
        logger.exception("[FR03] Semantic filtering failed; holding unknown documents for deterministic review")
        semantic_map = {}
    missing_semantic_ids = [d["doc_id"] for d in stage1_survivors
                            if str(d["doc_id"]).upper() not in semantic_map]

    if filter_diagnostics is not None:
        filter_diagnostics["semantic_filter_missing_ids"] = missing_semantic_ids
        filter_diagnostics["semantic_filter_unavailable_count"] = len(missing_semantic_ids)

    kit_terms = {
        word for word in re.findall(r"\b[a-z0-9]{5,}\b", user_query.lower())
        if word not in {"aircraft", "aviation", "aerospace", "industry", "commercial"}
    }

    accepted_docs: List[Dict[str, Any]] = []
    kiq_catalog = get_active_kiq_catalog()
    valid_kiq_ids = {item["kiq_id"] for item in kiq_catalog}

    for d in stage1_survivors:
        doc_id = str(d["doc_id"]).upper()
        sem = semantic_map.get(doc_id)
        faa = d.get("faa_publication_audit") or {}
        faa_candidate = bool(faa.get("document_identity_verified")
                             and faa.get("issue_relevance_verified") and not faa.get("failed"))
        source = f"{d.get('title') or ''} {d.get('text') or ''}"
        status_change = _status_change_evidence(user_query, d)
        regulatory_gap = "" if faa_candidate else _regulatory_relevance_gap(user_query, d)
        issuer_quote = _issuer_status_passage(user_query, d)
        is_faa_direct = bool(faa_candidate and assess_official_faa_fact(user_query, d) is not None)
        context_reason = (kit_direct_relevance_gap(user_query, source)
                          or ("" if faa_candidate else _kit_context_reason(user_query, d, status_change)))
        if faa_candidate:
            context_reason = ""  # Valid FAA scope is stronger than a loose LLM label.
        if (sem and sem.get("evidence_validated") and
                sem.get("filter_decision") in {"ACCEPT_DIRECT", "ACCEPT_STATUS_CHANGE"}):
            # Whole-document context cannot erase a separately cited, validated claim.
            context_reason = ""
        is_rel = bool(sem and sem.get("is_relevant") and sem.get("evidence_validated")
                      and sem.get("relevance_level") in {
                          "DIRECT_KIT_EVIDENCE", "STATUS_CHANGE_KIT_EVIDENCE", "POTENTIAL_KIT_SIGNAL",
                      })
        level = str(sem.get("relevance_level") or "POTENTIAL_KIT_SIGNAL") if sem else "POTENTIAL_KIT_SIGNAL"
        sig_type = str(sem.get("signal_type") or "GENERAL_NOISE").upper() if sem else "FILTER_UNAVAILABLE"
        rationale = str(sem.get("decision_rationale") or sem.get("rationale") or "") if sem else (
            "Semantic classification missing; relevance not established."
        )
        quote = str(sem.get("evidence_excerpt") or "") if sem else ""
        evidence_verified = bool(sem and sem.get("evidence_validated"))
        secondary_status, secondary_quote, secondary_reason = (
            _secondary_evidence_check(user_query, d, status_change)
            if sem is None or not sem.get("evidence_validated") else ("NOT_NEEDED", "", "")
        )
        status_grounded = bool(status_change and (
            secondary_status == "CONFIRMED" if secondary_status != "NOT_NEEDED"
            else _secondary_evidence_check(user_query, d, status_change)[0] == "CONFIRMED"
        ))
        # Retrieval provenance plus a contiguous quoted passage may establish
        # source relevance even when the semantic LLM is unavailable. It does
        # not establish the external truth of that source's allegation.
        secondary_confirmed = secondary_status == "CONFIRMED"

        if faa_candidate:
            quote = secondary_quote or _source_evidence_quote(d, user_query)
            quote = (faa.get("official_document_passage") or quote)
            quote_checks = _relevance_checks(user_query, d, quote)
            evidence_verified = bool(quote and _quote_context(d, quote))
            is_rel = evidence_verified
            level = "POTENTIAL_KIT_SIGNAL" if is_rel else "RELATED_CONTEXT"
            sig_type = "REGULATORY_PRIMARY_ISSUE"
            rationale = ("Official FAA record identity and a relevant source passage are grounded; "
                         "legal effectiveness and technical obligations are assessed separately.")
        elif sem is None and _official_easa_interim_direct_match(d, user_query):
            is_rel, level, sig_type = False, "POTENTIAL_KIT_SIGNAL", "REGULATORY_INDEX_CONTEXT"
            rationale = "EASA index identifies a candidate record; its substantive content remains unverified."

        # A model rejection triggers a separate, source-grounded KIT check.
        # Its result confirms relevance of a quoted claim, not external event truth.
        # A failed LLM entity label must not veto independently checked local
        # evidence. The secondary checker already enforces KIT entity/program,
        # regulator and document identity directly against the source passage.
        recovered = bool(secondary_confirmed and not is_rel and not regulatory_gap)
        lifecycle_recovered = recovered and bool(status_change and secondary_quote == status_change[1])
        if recovered:
            quote, evidence_verified, is_rel = secondary_quote, True, True
            sig_type = status_change[0] if lifecycle_recovered else "RELEVANT_EVENT"
            level = "STATUS_CHANGE_KIT_EVIDENCE" if lifecycle_recovered else "DIRECT_KIT_EVIDENCE"
            rationale = f"Independent KIT passage check: {secondary_reason}; claim truth not established."
            context_reason = ""

        # A dated official SEC issuer claim is useful KIT evidence even if the
        # regulator's own decision cannot be retrieved. Keep that distinction
        # visible to the Analyst and KIQ evaluator; do not label it verified FAA.
        issuer_recovered = bool(issuer_quote and not is_rel and not regulatory_gap)
        if issuer_recovered:
            quote, evidence_verified, is_rel = issuer_quote, True, True
            sig_type, level = "ISSUER_REPORTED_STATUS", "POTENTIAL_KIT_SIGNAL"
            rationale = ("Exact issuer quotation from an official SEC filing; "
                         "regulator decision and event truth remain unverified.")
            context_reason = ""

        if regulatory_gap or (context_reason and not faa_candidate and not status_change
                              and not (sem and sem.get("evidence_validated")
                                       and sem.get("filter_decision") == "ACCEPT_DIRECT")):
            is_rel, level = False, "RELATED_CONTEXT"
            sig_type = "RELATED_REGULATORY_CONTEXT" if regulatory_gap else "RELATED_CONTEXT"
            rationale = regulatory_gap or context_reason
        elif (sem and sem.get("is_relevant") and not sem.get("evidence_validated")
              and not faa_candidate and not recovered and not issuer_recovered):
            is_rel = False
            sig_type = "UNVERIFIED_LLM_EVIDENCE"
            rationale = f"Source passage not verified: {sem.get('evidence_validation_reason')}. {rationale}"

        if len(_alnum_norm(str(d.get("text") or ""))) < 45:
            is_rel, evidence_verified = False, False
            level, sig_type = "IRRELEVANT", "SOURCE_METADATA_ONLY"
            rationale = "Insufficient substantive source text for a KIT event decision."

        checks = _relevance_checks(user_query, d, quote)
        hard_conflict = checks["hard_conflict"] or bool(
            regulatory_gap.startswith("RELATED_REGULATORY_CONTEXT")
        )
        semantic_outcome = str((sem or {}).get("filter_decision") or "")
        possible_change = _potential_status_change(user_query, d)
        if hard_conflict:
            filter_decision, level, is_rel = (
                "REJECT_CONFIRMED_MISMATCH", "IRRELEVANT", False
            )
        elif "INSUFFICIENT_SOURCE_TEXT" in checks["failed"]:
            filter_decision, level, is_rel = (
                "REVIEW_POTENTIALLY_RELEVANT", "POTENTIAL_KIT_SIGNAL", False
            )
        elif is_rel and semantic_outcome == "ACCEPT_DIRECT" and not context_reason:
            filter_decision, level = "ACCEPT_DIRECT", "DIRECT_KIT_EVIDENCE"
        elif (status_grounded and not regulatory_gap and evidence_verified
              and not (sem and sem.get("identity_review_reason"))):
            sig_type, quote = status_change
            direct_event = (
                status_change[0] == "ISSUE_WORSENED"
                and "DELAY" in _issue_categories(user_query)
                and "DELAY" in _issue_categories(quote)
            )
            filter_decision = "ACCEPT_DIRECT" if direct_event else "ACCEPT_STATUS_CHANGE"
            level, is_rel = (
                "DIRECT_KIT_EVIDENCE" if direct_event else "STATUS_CHANGE_KIT_EVIDENCE"
            ), True
            checks = _relevance_checks(user_query, d, quote)
            evidence_verified = True  # A source quotation, not independent claim verification.
            rationale = "Dated, locally scoped KIT status development; downstream effects remain unverified."
        elif is_rel and is_faa_direct:
            filter_decision, level = "ACCEPT_DIRECT", "DIRECT_KIT_EVIDENCE"
        elif is_rel and semantic_outcome in {"ACCEPT_DIRECT", "ACCEPT_STATUS_CHANGE"} and not context_reason:
            filter_decision = semantic_outcome
            level = ("DIRECT_KIT_EVIDENCE" if filter_decision == "ACCEPT_DIRECT"
                     else "STATUS_CHANGE_KIT_EVIDENCE")
        elif is_rel and (recovered or issuer_recovered):
            filter_decision = ("ACCEPT_STATUS_CHANGE" if lifecycle_recovered else "ACCEPT_DIRECT")
            level = ("STATUS_CHANGE_KIT_EVIDENCE" if lifecycle_recovered else
                     "POTENTIAL_KIT_SIGNAL" if issuer_recovered else "DIRECT_KIT_EVIDENCE")
        elif (possible_change or semantic_outcome == "REVIEW_POTENTIALLY_RELEVANT"
              or sem and sem.get("is_relevant") and not sem.get("evidence_validated")):
            filter_decision, level, is_rel = (
                "REVIEW_POTENTIALLY_RELEVANT", "POTENTIAL_KIT_SIGNAL", False
            )
        elif sem is None:
            filter_decision, level, is_rel = "REVIEW_POTENTIALLY_RELEVANT", "POTENTIAL_KIT_SIGNAL", False
        else:
            filter_decision, level, is_rel = "CONTEXT_ONLY", "RELATED_CONTEXT", False
        # Acceptance is impossible without a genuine local quotation and all
        # explicitly requested identity, component, authority, ID and date gates.
        checks = _relevance_checks(user_query, d, quote)
        evidence_verified = bool(quote and _quote_context(d, quote)
                                 and d.get("content_status") not in _LIMITED_CONTENT)
        mandatory_gaps = _mandatory_gaps(checks)
        permitted_issuer_gap = bool(
            issuer_recovered and _alnum_norm(quote) == _alnum_norm(issuer_quote)
            and mandatory_gaps
            and all(item.startswith("REQUIRED_AUTHORITY:") for item in mandatory_gaps)
        )
        if (filter_decision in {"ACCEPT_DIRECT", "ACCEPT_STATUS_CHANGE"}
                and (not evidence_verified or checks["hard_conflict"]
                     or (mandatory_gaps and not permitted_issuer_gap))):
            is_rel, filter_decision, level = False, "REVIEW_POTENTIALLY_RELEVANT", "POTENTIAL_KIT_SIGNAL"
            rationale = "Direct KIT evidence requires a verified passage and all mandatory scope constraints."

        # FAA identity and issue relevance can survive a hallucinated LLM quote.
        # Partial admission permits analysis, never regulatory-effect or technical
        # claims from missing evidence. The legacy filter_decision is preserved.
        faa_scope_conflict = bool(checks["hard_conflict"] and not (
            faa_candidate and faa.get("aircraft_applicability_verified")
            and set(checks["failed"]) & {"PROGRAM_CONFLICT"}
            and not set(checks["failed"]) & {"ENTITY_CONFLICT", "DOCUMENT_ID_CONFLICT"}
        ))
        faa_missing_core_identity = any(
            g.startswith(("REQUIRED_ENTITY", "REQUIRED_PROGRAM", "REQUIRED_ENGINE", "REQUIRED_COMPONENT"))
            for g in mandatory_gaps
        )
        exact_faa_doc_match = bool(
            faa.get("document_identity_verified")
            and not faa.get("failed")
            and (_requested_document_ids(user_query) & _document_identifiers(d))
            and _detect_engine_models_ext(user_query)
            and _engine_models_compatible(user_query, source)
        )
        if exact_faa_doc_match and not quote:
            quote = (faa.get("official_document_passage") or _source_evidence_quote(d, user_query) or str(
                d.get("title") or "")[:300]).strip()
        if (faa_candidate and evidence_verified and not faa_scope_conflict and not faa_missing_core_identity) or (
                exact_faa_doc_match and bool(quote)
        ):
            evidence_verified = True
            is_rel = True
            needs_review = bool(
                not is_faa_direct or not faa.get("aircraft_applicability_verified")
                or not faa.get("regulatory_lifecycle_verified")
                or not faa.get("effective_date_verified")
                or mandatory_gaps or (sem and not sem.get("evidence_validated"))
                or d.get("content_status") in _LIMITED_CONTENT
            )
            filter_decision = "REVIEW_POTENTIALLY_RELEVANT" if needs_review else "ACCEPT_DIRECT"
            level = "POTENTIAL_KIT_SIGNAL" if needs_review else "DIRECT_KIT_EVIDENCE"
            sig_type = "REGULATORY_PRIMARY_ISSUE"
            rationale = ("FAA publication identity and relevant original passage cross-checked; "
                         "unverified attributes remain separate from confirmed source facts.")

        internal_status = ("REJECTED" if not is_rel else
                           "ACCEPTED_NEEDS_REVIEW" if filter_decision == "REVIEW_POTENTIALLY_RELEVANT"
                           or issuer_recovered else "ACCEPTED")
        claim_sem = ({**(sem or {}), "evidence_excerpt": quote, "evidence_validated": True,
                      "matched_entity": _verified_sec_issuer(d) if issuer_recovered
                      else ""}
                     if recovered or issuer_recovered else sem)
        if faa_candidate and is_rel:
            # LLM model/entity names are not evidence. Only extracted passages
            # and source-verified identifiers can be passed to KIQ extraction.
            claim_sem = {"evidence_excerpt": quote, "evidence_validated": evidence_verified,
                         "matched_entity": "", "matched_program": "", "relevant_claims": [],
                         "matched_kiq_id": str((sem or {}).get("matched_kiq_id") or "")}
        relevant_claims = (_extract_relevant_claims(user_query, d, claim_sem, status_change, kiq_catalog)
                           if is_rel else [])
        if faa_candidate and is_rel:
            number_line = re.search(
                r"(?im)^Federal Register Document:\s*" +
                re.escape(faa["official_document_number"]) + r"\b[^\n]*",
                str(d.get("text") or ""),
            )
            if number_line:
                relevant_claims.insert(0, {
                    "claim_id": f"{doc_id}:FAA-ID", "doc_id": doc_id,
                    "source_id": d.get("source_id"), "source_url": d.get("url"),
                    "published_at": d.get("published_at"),
                    "claim_type": "OFFICIAL_DOCUMENT_IDENTITY",
                    "kiq_id": str((claim_sem or {}).get("matched_kiq_id") or ""),
                    "evidence_excerpt": number_line.group().strip(),
                    "evidence_status": "VERIFIED", "evidence_validated": True,
                    "claim_verification": "DOCUMENT_IDENTITY_ONLY",
                    "regulatory_lifecycle_verified": faa["regulatory_lifecycle_verified"],
                    "aircraft_applicability_verified": faa["aircraft_applicability_verified"],
                    "technical_requirement_verified": False,
                })

        d.update(
            semantic_signal_type=sig_type, semantic_relevance_level=level,
            semantic_relevance_status=_relevance_status(filter_decision, "STAGE_2_SEMANTIC", sig_type),
            semantic_evidence_status=("UNAVAILABLE" if d.get("content_status") in _LIMITED_CONTENT
                                      else "VERIFIED" if evidence_verified else "UNVERIFIED"),
            semantic_model_status="AVAILABLE" if sem is not None else "UNAVAILABLE",
            semantic_source_authority=_source_authority(d) or "UNVERIFIED",
            semantic_claim_authority_scope=_claim_authority_scope(d),
            semantic_query_precision=query_precision,
            semantic_filter_decision=filter_decision,
            semantic_conditions_met=checks["passed"],
            semantic_conditions_unmet=checks["failed"],
            semantic_conditions_unverified=checks["unverified"],
            semantic_entities=(', '.join(faa.get("applicable_variants") or
                                         faa.get("applicable_families") or [])
                               if faa_candidate else str(sem.get("entities_models_tech") or
                                                              d.get("supplier_registry_match") or "") if sem
                               else str(d.get("supplier_registry_match") or "")),
            semantic_kiq_id=(sem.get("matched_kiq_id") if sem and sem.get("matched_kiq_id") in valid_kiq_ids else ""),
            semantic_rationale=rationale, semantic_evidence_excerpt=quote,
            semantic_evidence_verified=evidence_verified, semantic_rules_version=_FR03_RULES_VERSION,
            semantic_claim_verification="NOT_VERIFIED",
            semantic_internal_filter_status=internal_status,
            semantic_official_faa_audit=faa,
            semantic_status_as_of=d.get("published_at") or "DATE_UNKNOWN",
            semantic_current_status_verified=False,
            semantic_matched_entity=(', '.join(faa.get("applicable_manufacturers") or [])
                                     if faa_candidate else str(sem.get("matched_entity") or "") if sem else ""),
            semantic_matched_program=(", ".join(faa.get("applicable_variants") or
                                                   faa.get("applicable_families") or [])
                                      if faa_candidate else str(sem.get("matched_program") or "") if sem else ""),
            semantic_matched_issue=(', '.join(sorted(_issue_categories(user_query) &
                                                  set(faa.get("document_issue_categories") or [])))
                                    if faa_candidate else str(sem.get("matched_issue") or "") if sem else ""),
            semantic_entity_identity_basis=str(sem.get("entity_identity_basis") or "") if sem else "",
            semantic_relevant_claims=relevant_claims,
            semantic_lifecycle_status=(status_change[0] if status_grounded else
                                       "ISSUER_REPORTED_STATUS" if issuer_recovered
                                       else "STATUS_UNKNOWN"),
        )
        review_reasons = _review_reasons(user_query, d, sem)
        if sem and sem.get("identity_review_reason"):
            review_reasons.append(str(sem["identity_review_reason"]))
        if sem is None:
            review_reasons.append("SEMANTIC_UNAVAILABLE")
        if recovered:
            review_reasons.append("SECONDARY_KIT_PASSAGE_RECOVERED")
        elif secondary_status == "REVIEW" and sem and not sem.get("is_relevant"):
            review_reasons.append(secondary_reason)
        if (sem and not sem.get("evidence_validated") and faa_candidate and is_rel):
            review_reasons.append("FAA_RELEVANCE_RECOVERED_FROM_OFFICIAL_PASSAGE")
        review_reasons.extend(faa.get("unverified") or [])
        if (not is_rel and status_change and (sem or {}).get("identity_review_reason")):
            review_reasons.append("POTENTIAL_FALSE_NEGATIVE_IDENTITY_UNVERIFIED")
        kit_matches = sorted(t for t in kit_terms if re.search(rf"(?<!\w){re.escape(t)}(?!\w)", source.lower()))
        q_variants, d_variants = _detect_exact_variants(user_query), _detect_exact_variants(source)
        identity_conflict = bool(q_variants and d_variants and not q_variants.intersection(d_variants))
        false_negative = bool(
            sem and not sem.get("is_relevant") and len(kit_matches) >= 2
            and len(str(d.get("text") or "")) >= 250 and not context_reason and not identity_conflict
            and _issue_categories(user_query).intersection(_issue_categories(source))
        )
        if false_negative and "POSSIBLE_FALSE_NEGATIVE" not in review_reasons:
            review_reasons.append("POSSIBLE_FALSE_NEGATIVE")
        suspicious_positive = bool(sem and sem.get("is_relevant") and not sem.get("evidence_validated"))
        manual_review = bool((internal_status == "ACCEPTED_NEEDS_REVIEW"
                              or filter_decision == "REVIEW_POTENTIALLY_RELEVANT"
                              or suspicious_positive or false_negative or recovered or sem is None
                              or "REGULATORY_APPLICABILITY_UNCONFIRMED" in review_reasons)
                             and not checks["hard_conflict"]
                             and not regulatory_gap.startswith("RELATED_REGULATORY_CONTEXT"))
        audit_extra = dict(
            relevance_level=level, filter_decision=filter_decision,
            relevance_status=_relevance_status(filter_decision, "STAGE_2_SEMANTIC", sig_type),
            evidence_status=("UNAVAILABLE" if d.get("content_status") in _LIMITED_CONTENT
                             else "VERIFIED" if evidence_verified else "UNVERIFIED"),
            lifecycle_status=status_change[0] if status_grounded else "STATUS_UNKNOWN",
            semantic_status="AVAILABLE" if sem is not None else "UNAVAILABLE",
            reason_code=("KIT_PASSAGE_VERIFIED" if is_rel else
                         "HARD_SCOPE_MISMATCH" if hard_conflict else
                         "SEMANTIC_UNAVAILABLE" if sem is None else
                         secondary_reason if secondary_status == "REVIEW" else
                         str((sem or {}).get("evidence_validation_reason") or sig_type)),
            matched_identity=str((d.get("semantic_matched_program") if faa_candidate else "") or
                                 (sem or {}).get("matched_program") or
                                 (sem or {}).get("matched_entity") or _verified_sec_issuer(d) or ""),
            matched_component=", ".join(sorted(c for c in _component_requirements(user_query)
                                               if _alnum_norm(c) in _alnum_norm(quote)))
                              if evidence_verified else "",
            conditions_met=checks["passed"], conditions_unmet=checks["failed"],
            conditions_unverified=checks["unverified"],
            rules_version=_FR03_RULES_VERSION,
            internal_filter_status=internal_status, official_faa_audit=faa,
            evidence_excerpt=quote, evidence_validated=evidence_verified,
            evidence_validation_reason=("LIFECYCLE_PASSAGE_GROUNDED"
                                        if filter_decision == "ACCEPT_STATUS_CHANGE" else
                                        sem.get("evidence_validation_reason") if sem else "DETERMINISTIC_FALLBACK"),
            claim_verification="NOT_VERIFIED",
            status_as_of=d.get("published_at") or "DATE_UNKNOWN",
            current_status_verified=False,
            matched_entity=d.get("semantic_matched_entity", ""),
            matched_program=d.get("semantic_matched_program", ""),
            matched_issue=d.get("semantic_matched_issue", ""),
            entity_identity_basis=sem.get("entity_identity_basis", "") if sem else "",
            identity_review_reason=sem.get("identity_review_reason", "") if sem else "",
            relevant_claims=relevant_claims,
            review_reasons=review_reasons, manual_review_candidate=manual_review,
            matched_kit_terms=kit_matches,
        )
        stage = "STAGE_2_SEMANTIC" if sem else "STAGE_2_DETERMINISTIC_FALLBACK"
        _record_audit(d, stage, is_rel, sig_type, rationale,
                      entities=d["semantic_entities"], kiq=d["semantic_kiq_id"], **audit_extra)
        if is_rel:
            accepted_docs.append(d)
        else:
            rejected_count += 1

    # Invariant: every Analyst input must have one corresponding accepted audit decision.
    accepted_ids = [str(doc["doc_id"]).upper() for doc in accepted_docs]
    audited_accepted_ids = [str(rec['doc_id']).upper() for rec in audit_records if rec['is_accepted']]
    if len(set(accepted_ids)) != len(accepted_ids) or set(accepted_ids) != set(audited_accepted_ids):
        raise RuntimeError(
            f"FR03_AUDIT_INTEGRITY: Analyst inputs {accepted_ids!r} "
            f"do not equal accepted audit records {audited_accepted_ids!r}"
        )
    if filter_diagnostics is not None:
        filter_diagnostics["accepted_document_ids"] = sorted(accepted_ids)
        filter_diagnostics["accepted_document_count"] = len(accepted_docs)
        filter_diagnostics["rejection_review_candidates"] = sum(
            bool(rec.get("manual_review_candidate")) and not rec["is_accepted"]
            for rec in audit_records
        )
        filter_diagnostics["accepted_review_candidates"] = sum(
            bool(rec.get("manual_review_candidate")) and rec["is_accepted"]
            for rec in audit_records
        )
        filter_diagnostics["rejection_stage_counts"] = {
            stage: sum(not rec["is_accepted"] and rec["filter_stage"] == stage for rec in audit_records)
            for stage in sorted({rec["filter_stage"] for rec in audit_records})
        }
        filter_diagnostics["relevance_level_counts"] = {
            level: sum(rec.get("relevance_level") == level for rec in audit_records)
            for level in ("DIRECT_KIT_EVIDENCE", "STATUS_CHANGE_KIT_EVIDENCE",
                          "POTENTIAL_KIT_SIGNAL", "RELATED_CONTEXT", "IRRELEVANT", "UNCLASSIFIED")
        }
        filter_diagnostics["filter_decision_counts"] = {
            state: sum(rec.get("filter_decision") == state for rec in audit_records)
            for state in ("ACCEPT_DIRECT", "ACCEPT_STATUS_CHANGE", "REVIEW_POTENTIALLY_RELEVANT",
                          "CONTEXT_ONLY", "REJECT_CONFIRMED_MISMATCH")
        }
        filter_diagnostics["internal_filter_status_counts"] = {
            status: sum(rec.get("internal_filter_status") == status for rec in audit_records)
            for status in ("ACCEPTED", "ACCEPTED_NEEDS_REVIEW", "REJECTED")
        }
        filter_diagnostics["review_document_ids"] = [
            rec["doc_id"] for rec in audit_records
            if rec.get("filter_decision") == "REVIEW_POTENTIALLY_RELEVANT"
        ]
        filter_diagnostics["review_reason_counts"] = {
            reason: sum(reason in rec.get("review_reasons", []) for rec in audit_records)
            for reason in sorted({r for rec in audit_records for r in rec.get("review_reasons", [])})
        }
        for name in ("relevance_status", "evidence_status", "semantic_status", "lifecycle_status"):
            filter_diagnostics[name + "_counts"] = {
                state: sum(rec.get(name) == state for rec in audit_records)
                for state in sorted({rec.get(name, "UNKNOWN") for rec in audit_records})
            }

    # Retain accepted and rejected decisions for later independent relevance review.
    _save_filter_audit_records(audit_records, run_id, run_workspace)
    if run_id:
        with DB_LOCK, sqlite3.connect(SQLITE_DB) as conn:
            stored = {
                row[0].upper() for row in conn.execute(
                    "SELECT doc_id FROM document_filter_log WHERE run_id=? AND is_accepted=1", (run_id,)
                ).fetchall()
            }
        if stored != set(accepted_ids):
            raise RuntimeError(
                f"FR03_PERSISTENCE_INTEGRITY: accepted={set(accepted_ids)!r} stored={stored!r}"
            )
    unavailable = sum(rec.get("signal_type") == "FILTER_UNAVAILABLE" for rec in audit_records)
    review_count = sum(rec.get("filter_decision") in {
        "REVIEW_POTENTIALLY_RELEVANT"
    } for rec in audit_records)
    logger.info(
        "[SEMANTIC FILTER COMPLETE] Accepted %d, excluded/held %d "
        "(%d require review, %d FILTER_UNAVAILABLE; unknown relevance is not irrelevance).",
        len(accepted_docs), rejected_count, review_count, unavailable,
    )

    # Compute the priority score used to order accepted source documents.
    def doc_priority_score(d: Dict[str, Any]) -> int:
        score = _SOURCE_TYPE_SCORES.get(d.get("source_type", ""), 20)
        if (d.get("semantic_signal_type") == "RELEVANT_EVENT"
                or str(d.get("semantic_signal_type") or "").startswith("ISSUE_")):
            score += 30
        hay = f"{d.get('title', '')} {d.get('text', '')}".lower()
        score += sum(10 for w in q_words if w in hay)
        if d.get("supplier_registry_match"):
            score += 15
        return score

    sorted_docs = sorted(
        accepted_docs,
        key=lambda d: (-doc_priority_score(d), str(d.get("url") or ""), str(d.get("title") or "")),
    )

    batches: List[str] = []
    current_batch_lines: List[str] = []
    current_len = 0
    analyzed_count = 0

    for d in sorted_docs:
        block = (
            f"<untrusted_osint_document id=\"{d['doc_id']}\" source_id=\"{d['source_id']}\" "
            f"origin=\"{d.get('origin_type', 'SECONDARY')}\">\n"
            f"DOC_ID: {d['doc_id']} | SOURCE_ID: {d['source_id']} ({d.get('connector_name', '')})\n"
            f"DATE: {d.get('published_at', 'DATE_UNKNOWN')} | COLLECTED_AT: {d.get('collected_at', '')}\n"
            f"CONTENT_STATUS: {d.get('content_status', 'SUMMARY_ONLY')} | "
            f"CONTENT_SHA256: {d.get('content_sha256', '')}\n"
            f"SEMANTIC_CLASSIFICATION: {d.get('semantic_signal_type', 'RELEVANT_EVENT')} | "
            f"RELEVANCE_LEVEL: {d.get('semantic_relevance_level', 'POTENTIAL_KIT_SIGNAL')} | "
            f"KIQ: {d.get('semantic_kiq_id', 'KIQ_1_1')} | ENTITIES/MODELS: {d.get('semantic_entities') or 'N/A'}\n"
            f"RELEVANCE_STATUS: {d.get('semantic_relevance_status', 'UNKNOWN')} | "
            f"EVIDENCE_STATUS: {d.get('semantic_evidence_status', 'UNVERIFIED')} | "
            f"FILTER_STATUS: {d.get('semantic_internal_filter_status', 'REJECTED')} | "
            f"MODEL_STATUS: {d.get('semantic_model_status', 'UNAVAILABLE')} | "
            f"LIFECYCLE_STATUS: {d.get('semantic_lifecycle_status', 'STATUS_UNKNOWN')}\n"
            f"SEMANTIC_RATIONALE: {d.get('semantic_rationale', '')}\n"
            f"MATCHED_ENTITY: {d.get('semantic_matched_entity', '')} | "
            f"PROGRAM: {d.get('semantic_matched_program', '')} | "
            f"ISSUE: {d.get('semantic_matched_issue', '')}\n"
            f"EVIDENCE_VERIFIED: {d.get('semantic_evidence_verified', False)} | "
            f"CLAIM_VERIFICATION: {d.get('semantic_claim_verification', 'NOT_VERIFIED')} | "
            f"STATUS_AS_OF: {d.get('semantic_status_as_of', 'DATE_UNKNOWN')} | "
            f"RULES_VERSION: {d.get('semantic_rules_version', '')}\n"
            f"EVIDENCE_EXCERPT: {d.get('semantic_evidence_excerpt', '')}\n"
            f"SOURCE_AUTHORITY: {d.get('semantic_source_authority', 'UNVERIFIED')} | "
            f"CLAIM_AUTHORITY_SCOPE: {d.get('semantic_claim_authority_scope', 'SOURCE_REPORTED')} | "
            f"EVENT_AT: {d.get('event_at') or d.get('event_date') or 'DATE_UNKNOWN'}\n"
            f"VERIFIED_OFFICIAL_ISSUER: {_verified_sec_issuer(d) or 'UNVERIFIED'}\n"
            f"RELEVANT_CLAIMS_JSON: {json.dumps(d.get('semantic_relevant_claims', []), ensure_ascii=False)}\n"
            f"OFFICIAL_FAA_AUDIT_JSON: {json.dumps(d.get('semantic_official_faa_audit', {}), ensure_ascii=False)}\n"
            f"TITLE: {d.get('title', '')}\n"
            f"SOURCE: {d.get('url', '')}\n"
            f"CONTENT: {relevant_excerpt(d.get('text', ''), user_query)}\n"
            f"</untrusted_osint_document>\n"
        )
        if current_len + len(block) > max_chars_per_batch and current_batch_lines:
            batches.append("\n".join(current_batch_lines))
            current_batch_lines = [block]
            current_len = len(block)
        else:
            current_batch_lines.append(block)
            current_len += len(block)
        analyzed_count += 1

    if current_batch_lines:
        batches.append("\n".join(current_batch_lines))

    return batches, analyzed_count, rejected_count


