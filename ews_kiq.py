# =============================================================================
# aviation_ci_app | Strategic KIT/KIQ mapping and runtime evidence coverage
#
# Responsibility: Map concrete intelligence findings to catalog questions and
#   account for answered, unresolved, or weakly evidenced KIQs.
# Design boundary: Issue-specific source evidence is required; generic aircraft
#   or company overlap is insufficient.
# =============================================================================

"""KIT/KIQ catalog mapping, evidence traceability, and question coverage."""

import hashlib
from datetime import date, datetime, timezone
from typing import Optional
from urllib.parse import urlparse, urlsplit

from aero_ews.collection.queries import get_program_engine_domain
from aero_ews.domain.evidence_text import SUPPORTED_EXTRACTION_METHODS, _is_snippet_only, assess_source_passage
from aero_ews.domain.identity import (
    _detect_aircraft_families, _detect_engine_models, _detect_exact_variants,
    _engine_models_match,
)
from ews_database import get_active_kiq_catalog
from ews_evidence_contract import (
    _consistent_date as _faa_consistent_date,
    _field as _faa_field,
    assess_official_faa_fact,
    inspect_official_faa_publication,
)
from ews_state import (
    Any, ConfidenceLevel, Dict, EWSReport, KIQAnswer, KIQPlan,
    List, RiskType, ThreatAssessment, ValidationStatus, re,
)
from tools import news_api_search_key

# Term extraction, strategic KIQ vocabularies, and evidence ontology (preserved verbatim).
_WORD_RE = re.compile(r"[a-z0-9]{4,}")
_QUERY_STOPWORDS = {"airbus", "boeing", "aviation", "aircraft", "aerospace", "industry"}
_DISTINCTIVE_TERMS = {
    "orders", "order", "contract", "contracts", "partnership", "shortage",
    "shortages", "production", "technology", "emissions", "regulation",
    "certification", "innovation", "materials",
}
_GENERIC_REG_TERMS = {
    "airbus", "boeing", "engine", "engines", "aircraft", "aviation", "faa", "easa",
    "directive", "directives", "airworthiness", "inspection", "inspections",
    "regulatory", "production", "supplier", "constraints", "airline", "impacts",
    "fleet", "requirements", "compliance",
}
_KIQ_ISSUE_GROUPS = (
    r"\b(?:engine\w*|gtf|pw1100g?|turbine\w*)\b",
    r"\b(?:airworthiness|directive\w*|inspect\w*|regulator\w*)\b",
    r"\b(?:certif\w*|approv\w*)\b",
    r"\b(?:order\w*|purchas\w*|contract\w*|leas\w*)\b",
    r"\b(?:shortag\w*|outage\w*|constraint\w*|production\s+(?:delay\w*|rate\w*|ramp\w*))\b",
    r"\b(?:accident\w*|crash\w*|runway\w*|incident\w*)\b",
)
_HISTORICAL_AGE_WARNING_RE = re.compile(
    r"Verification required: Source published \d+ days before reference date; "
    r"historical source alone does not prove a new event or current disruption; "
    r"Classified as HISTORICAL_CONTEXT \(older event referenced in recent source\)\.?",
    re.I,
)
_REQUIREMENT_RULES = (
    ("SUPPLY_DISRUPTION", "A documented supply disruption", r"\b(?:suppl\w*|shortag\w*|bottleneck\w*|dodáv\w*|nedostat\w*|výpad\w*)\b", "SUPPLY_EVENT"),
    ("AFFECTED_COMPONENT", "Identity of the affected part or engine", r"\b(?:engine\w*|motor\w*|component\w*|part\w*|součást\w*|komponent\w*|turbine\w*|fan\s+blade\w*)\b", "COMPONENT_IDENTITY"),
    ("PRODUCTION_IMPACT", "Demonstrated impact on production or capacity", r"\b(?:production|manufactur\w*|assembly|capacity|output|výrob\w*|kapacit\w*)\b", "PRODUCTION_OUTCOME"),
    ("DELIVERY_IMPACT", "Demonstrated impact on customer deliveries", r"\b(?:deliver\w*|handover\w*|předáv\w*|dodání|předání)\b", "DELIVERY_OUTCOME"),
    ("REGULATORY_EXISTENCE", "Existence of the requested regulatory action", r"\b(?:airworthiness|directive\w*|regulation\w*|regulatory\s+action|special\s+conditions?|AD|předpis\w*|nařízení|směrnic\w*)\b|\bFAA-\d{4}-\d+\b|\b20\d{2}-\d{5}\b", "OFFICIAL_REGULATION"),
    ("REGULATORY_PUBLICATION", "Official publication date", r"\b(?:publication\s+date|published\s+on|datum\s+zveřejnění|datum\s+publikace)\b", "PUBLICATION_DATE"),
    ("REGULATORY_EFFECTIVENESS", "Effective date and current regulatory stage", r"\b(?:effective\s+(?:date|on|from)|in\s+force|účinn\w*|platnost\w*)\b", "EFFECTIVE_DATE"),
    ("COMPLIANCE_DEADLINE", "Deadline for required compliance", r"\b(?:compliance\s+(?:date|deadline)|deadline|termín\s+(?:splnění|nápravy)|lhůt\w*)\b", "COMPLIANCE_DATE"),
    ("INSPECTION_REQUIREMENT", "Specific inspection or required corrective action", r"\b(?:inspect\w*|borescope|kontrol\w*|prohlídk\w*)\b", "INSPECTION_ACTION"),
    ("CERTIFICATION", "Completed certification or approval milestone", r"\b(?:certif\w*|type\s+approv\w*|certifik\w*|schválen\w*)\b", "CERTIFICATION_RECORD"),
    ("ORDER_CONTRACT", "Confirmed order or contractual commitment", r"\b(?:order\w*|purchas\w*|contract\w*|objednáv\w*|kontrakt\w*)\b", "COMMERCIAL_COMMITMENT"),
    ("ACCIDENT_INCIDENT", "Verified occurrence of the safety incident", r"\b(?:accident\w*|crash\w*|incident\w*|blowout|separation|nehod\w*)\b", "INCIDENT_RECORD"),
    ("INVESTIGATION_FINDING", "Documented investigation findings or technical cause",
     r"\b(?:investigat\w*|findings?|probable\s+cause|root\s+cause|technical\s+cause\w*|cause\w*\s+of|lapses?|recommendations?|vyšetřov\w*|zjištění|příčin\w*)\b",
     "INVESTIGATION_RECORD"),
    ("TECHNICAL_DEFECT", "Documented technical defect, durability or quality finding",
     r"\b(?:defect\w*|fault\w*|failure\w*|durabilit\w*|wear\s+and\s+tear|degradat\w*|erosion|corrosion|crack\w*|quality\s+control|missing\s+bolts?|poruch\w*|závad\w*|vad\w*)\b",
     "TECHNICAL_FINDING"),
    ("EMISSIONS", "Documented emissions or environmental claim", r"\b(?:emission\w*|decarbon\w*|sustainab\w*|emis\w*|udržitel\w*)\b", "ENVIRONMENTAL_EVIDENCE"),
    ("FINANCIAL_CLAIM", "The stated financial disclosure", r"\b(?:financial|revenue|earnings|cash\s+flow|10-[kq]|20-f|6-k|(?:sec|edgar|esef|xbrl|corporate|quarterly|annual)\s+filing\w*|tržb\w*|výnos\w*|zisk\w*)\b", "FILING_PASSAGE"),
)
_REQUIREMENT_PATTERN_BY_KEY = {name: pat for name, _, pat, _ in _REQUIREMENT_RULES}
_IMPACT_PROOF = {
    "PRODUCTION_IMPACT": r"(?:production|manufactur\w*|assembly|capacity|output|výrob\w*|kapacit\w*).{0,60}(?:delay\w*|reduc\w*|cut|halt\w*|disrupt\w*|slow\w*|impact\w*|affect\w*|constraint\w*|zpožd\w*|omezen\w*|pokles\w*|ovliv\w*)|(?:delay\w*|reduc\w*|disrupt\w*|zpožd\w*|ovliv\w*).{0,60}(?:production|manufactur\w*|capacity|výrob\w*|kapacit\w*)",
    "DELIVERY_IMPACT": r"(?:deliver\w*|handover\w*|předáv\w*|dodání).{0,60}(?:delay\w*|postpon\w*|miss\w*|slip\w*|late|push\w*|reduc\w*|zpožd\w*|posun\w*|ovliv\w*)|(?:delay\w*|postpon\w*|zpožd\w*|posun\w*).{0,60}(?:deliver\w*|handover\w*|předáv\w*|dodání)",
}
_SUPPLY_PROOF = r"\b(?:shortag\w*|supply\s+(?:disrupt\w*|delay\w*|constraint\w*|issue\w*)|bottleneck\w*|nedostat\w*|výpad\w*|problém\w*\s+dodáv\w*|zpožd\w*\s+dodáv\w*)\b"
_CAUSE_PROOF = r"\b(?:because|due\s+to|caus\w*|result\w*\s+in|led\s+to|affect\w*|impact\w*|kvůli|způsob\w*|důsled\w*|ovliv\w*)\b"
_CAUSE_SOURCES = {
    "SUPPLY_DISRUPTION": _SUPPLY_PROOF,
    "CERTIFICATION_DELAY": r"\bcertif\w*|\bcertifik\w*",
    "HISTORICAL_DELAY": r"\b(?:certif\w*|shortag\w*|strik\w*|defect\w*|failure\w*|disrupt\w*|supply\w*|závad\w*|stávk\w*)\b",
    "REGULATORY_EXISTENCE": r"\b(?:directive\w*|regulat\w*|předpis\w*|nařízení)\b",
    "TECHNICAL_DEFECT": r"\b(?:defect\w*|failure\w*|poruch\w*|závad\w*)\b",
    "ACCIDENT_INCIDENT": r"\b(?:accident\w*|incident\w*|nehod\w*)\b",
    "ORDER_CONTRACT": r"\b(?:order\w*|contract\w*|objednáv\w*)\b",
}
_COMPONENT_PATTERNS = {
    "ENGINE": r"\b(?:engine\w*|motor\w*)\b",
    "GEARBOX": r"\b(?:gearbox|gear\s+case|reduction\s+gear(?:box)?)\b",
    "TURBINE": r"\b(?:turbine\w*|turbín\w*)\b",
    "COMPRESSOR": r"\b(?:compressor\w*|kompresor\w*)\b",
    "FAN": r"\b(?:fan\s+(?:blade\w*|rotor\w*)|lopatk\w*)\b",
}
_LIFECYCLE_TOPICS = {
    "CERTIFICATION": r"\b(?:certif\w*|certifik\w*|type\s+approv\w*|approval\w*|musterzulassung)\b",
    "LABOR": r"\b(?:strik\w*|walkout\w*|stávk\w*)\b",
    "SUPPLY": r"\b(?:suppl\w*|shortag\w*|bottleneck\w*|nedostat\w*|dodavatel\w*)\b",
    "TECHNICAL": r"\b(?:defect\w*|fault\w*|failure\w*|inspect\w*|powder\s+metal|contaminat\w*|durabilit\w*|crack\w*|závad\w*|poruch\w*)\b",
    "REGULATORY": r"\b(?:regulat\w*|directive\w*|airworthiness|special\s+conditions?|předpis\w*|nařízení)\b",
    "PRODUCTION": r"\b(?:production|manufactur\w*|assembly|výrob\w*)\b",
    "DELIVERY": r"\b(?:deliver\w*|handover\w*|dodáv\w*|předáv\w*)\b",
    "OPERATIONS": r"\b(?:operat\w*|service|grounding|provoz\w*)\b",
}
_TOPIC_PRIORITY = ("CERTIFICATION", "LABOR", "SUPPLY", "TECHNICAL", "REGULATORY", "PRODUCTION", "DELIVERY", "OPERATIONS")
_ISSUE_WORDS = (
    r"delay\w*|pending|awaiting|postpon\w*|disrupt\w*|shortag\w*|halt\w*|"
    r"suspend\w*|fail\w*|defect\w*|strike\w*|zpožd\w*|odklad\w*|"
    r"nedostat\w*|výpad\w*|poruch\w*|závad\w*|stávk\w*|issues?|problem\w*|problém\w*"
)
_CURRENT_WORDS = (
    r"\b(?:current\w*|latest|status|update\w*|still|ongoing|now|"
    r"recent\w*|resolved|completed|resum\w*|aktuáln\w*|současn\w*|stav\w*|vyřešen\w*|obnoven\w*)\b"
)
_ISSUE_STATE_PATTERNS = {
    "CERTIFICATION": (
        r"\b(?:FAA|EASA|Federal\s+Aviation\s+Administration|European\s+Union\s+Aviation\s+Safety\s+Agency|"
        r"European\s+Aviation\s+Safety\s+Agency|authority|regulator)\b.{0,100}\b(?:certif(?:ied|ies)|approv(?:ed|es)|grant(?:ed|s))\b|"
        r"\bcertif\w*.{0,65}\b(?:granted|issued|complet\w*|approved|finished|obtained)\b|"
        r"\b(?:achiev\w*|secured|attain\w*|issued|granted|received|obtained|completed)\b.{0,65}\b(?:type\s+certificat\w*|certification|approval)\b|"
        r"\b(?:has\s+been|was|were|is)\s+(?:certified|approved)\b|\b(?:has|have)\s+(?:certified|approved)\b",
        r"\bcertif\w*.{0,70}\b(?:pending|delayed|awaiting|postponed|suspended|ongoing|in\s+progress|underway|not\s+yet\s+granted|validation|flight\s+test\w*|milestones?|testing|hold|acceleration)\b|"
        r"\b(?:pending|delayed|awaiting|pursuing|post|needs?|requiring|carried\s+out\s+test\s+flights|validation\s+activities|will\s+not\s+certificate)\b.{0,70}\b(?:certif\w*|approv\w*|validation)\b",
    ),
    "LABOR": (
        r"\b(?:strike|walkout|stávk\w*)\b.{0,45}\b(?:end\w*|settled|resolved|over|ukončen\w*|skončil\w*)\b|"
        r"\b(?:end\w*|settled|ukončen\w*)\b.{0,45}\b(?:strike|walkout|stávk\w*)\b|"
        r"\b(?:workers?|union)\b.{0,50}\b(?:return\w*\s+to\s+work|agreement\s+reached)\b",
        r"\b(?:strike|walkout|stávk\w*)\b.{0,45}\b(?:ongoing|continues|began|started|trvá\w*)\b",
    ),
    "SUPPLY": (
        r"\b(?:shortage|supply\s+(?:constraint|disruption)|nedostat\w*)\b.{0,60}\b(?:resolved|ended|eliminated|cleared|overcome|removed|vyřešen\w*)\b|"
        r"\b(?:supplier|dodavatel\w*)\b.{0,45}\b(?:output|capacity)\b.{0,35}\brestored\b",
        r"\b(?:shortage|supply\s+(?:constraint|disruption)|nedostat\w*)\b.{0,55}\b(?:continues|persists|ongoing|worsened|remains)\b",
    ),
    "TECHNICAL": (
        r"\b(?:defect|fault|failure|durabilit\w*|závad\w*|poruch\w*)\b.{0,55}\b(?:resolved|fixed|corrected|eliminated|repaired|vyřešen\w*)\b",
        r"\b(?:defect\w*|fault\w*|failure\w*|durabilit\w*|wear\s+and\s+tear|degradat\w*|crack\w*|erosion|mid[- ]?seal|závad\w*|poruch\w*)\b.{0,65}\b(?:continues|persists|ongoing|worsened|detected|remains|issue\w*|concern\w*|redesign\w*|upgrad\w*|testing|inspect\w*|enhanc\w*)\b",
    ),
    "REGULATORY": (
        r"\b(?:directive|regulation|rule|order|předpis\w*)\b.{0,55}\b(?:withdr\w*|repeal\w*|rescind\w*|revok\w*|revoked|zrušen\w*)\b|"
        r"\b(?:withdr\w*|repeal\w*|rescind\w*|revok\w*|revoked|zrušen\w*)\b.{0,55}\b(?:directive|regulation|rule|order|předpis\w*)\b",
        r"\b(?:directive|regulation|rule|order|special\s+conditions?)\b.{0,50}\b(?:effective|in\s+force|issued|enforced|published|superseding|mandat\w*|requir\w*)\b",
    ),
    "PRODUCTION": (
        r"\b(?:production|manufactur\w*|assembly|výrob\w*)\b.{0,50}\b(?:resum\w*|restor\w*|restart\w*|normaliz\w*|obnoven\w*)\b|"
        r"\b(?:resum\w*|restor\w*|restart\w*|obnoven\w*)\b.{0,50}\b(?:production|manufactur\w*|assembly|výrob\w*)\b",
        r"\b(?:production|manufactur\w*|assembly|output|ramp[- ]?up|výrob\w*)\b.{0,60}\b(?:halted|stopped|delayed|disrupted|suspended|struggl\w*|shortfall|shortag\w*|slowed|troubled|constrained|fell\s+short|behind|tight\w*)\b",
    ),
    "DELIVERY": (
        r"\b(?:deliver\w*|handover\w*|dodáv\w*)\b.{0,45}\b(?:resum\w*|restor\w*|complet\w*|caught\s+up|obnoven\w*)\b|"
        r"\b(?:resum\w*|restor\w*|complet\w*|obnoven\w*)\b.{0,45}\b(?:deliver\w*|handover\w*|dodáv\w*)\b",
        r"\b(?:deliver\w*|handover\w*|dodáv\w*)\b.{0,60}\b(?:delayed|halted|disrupted|suspended|fell\s+short|shortfall|slipp\w*|uncertain|below\s+(?:the\s+)?(?:initial|revised)?\s*target)\b",
    ),
    "OPERATIONS": (
        r"\b(?:operations?|service|flights?|provoz\w*)\b.{0,50}\b(?:resum\w*|restor\w*|restart\w*|obnoven\w*)\b|"
        r"\b(?:resum\w*|restor\w*|restart\w*|obnoven\w*)\b.{0,50}\b(?:operations?|service|flights?|provoz\w*)\b",
        r"\b(?:operations?|service|flights?|provoz\w*)\b.{0,50}\b(?:halted|suspended|disrupted|grounded)\b",
    ),
}
_FAA_DOC_NUMBER_RE = re.compile(r"(?<![A-Z0-9-])20\d{2}-\d{4,6}(?!\d)", re.I)
_FAA_DOCKET_RE = re.compile(r"(?<![A-Z0-9])FAA-20\d{2}-\d{3,7}(?!\d)", re.I)
_FAA_MANUFACTURERS = ("BOEING", "AIRBUS", "EMBRAER", "BOMBARDIER", "ATR")
_FAA_STAGES = {"PROPOSED", "FINAL_ISSUED", "EFFECTIVE", "WITHDRAWN"}
_FAA_FACT_KINDS = {
    "REGULATORY_EXISTENCE": "REGULATORY_DOCUMENT_IDENTITY",
    "REGULATORY_PUBLICATION": "REGULATORY_PUBLICATION_DATE",
    "REGULATORY_EFFECTIVENESS": "REGULATORY_EFFECTIVE_DATE",
    "EFFECTIVE_AS_OF_REFERENCE_DATE": "REGULATORY_EFFECTIVE_AS_OF_DATE",
    "COMPLIANCE_DEADLINE": "REGULATORY_COMPLIANCE_DATE",
    "PROGRAM_APPLICABILITY": "REGULATORY_PROGRAM_APPLICABILITY",
}
_SOURCE_GROUPS = {
    "MEDIA": ({"SRC_004", "SRC_005"}, {"news", "newsapi", "news api", "pr", "official pr releases", "press releases"}),
    "REG": ({"SRC_001", "SRC_002", "SRC_003", "SRC_019", "SRC_020", "SRC_021", "SRC_022", "SRC_023"},
            {"regulatory", "faa", "easa", "ntsb", "faa & easa regulations", "easa regulations", "ntsb investigations"}),
    "SOCIAL": ({"SRC_007", "SRC_008"}, {"bluesky", "bluesky social network", "youtube", "youtube videos"}),
    "AIRSHOW": ({"SRC_006"}, {"airshow", "airshow websites"}),
    "FIN": ({"SRC_027", "SRC_031"}, {"sec", "edgar", "esef", "xbrl", "financial", "oem & supplier pressroom"}),
}
_PRIMARY_SOURCES = set().union(_SOURCE_GROUPS["REG"][0], _SOURCE_GROUPS["FIN"][0])
_NON_FULL_TEXT = {
    "METADATA_ONLY", "SUMMARY_ONLY", "TRUNCATED", "SOURCE_POLICY_RESTRICTED",
    "CONTENT_UNAVAILABLE_OR_BLOCKED", "FILING_BLOCKED_OR_UNAVAILABLE", "ESEF_REPORT_UNAVAILABLE_OR_BLOCKED",
}
_ORDER_TOPIC_RE = re.compile(r"\b(?:order\w*|purchas\w*|contract\w*|backlog\w*|objednáv\w*|kontrakt\w*)\b", re.I)
_EXCLUSION_SPLIT_RE = re.compile(r"\b(?:exclude|excluding|except(?:\s+for)?|without|not\s+including|kromě|vyjma)\b", re.I)
_MONTHS_BILINGUAL = {
    "january": 1, "february": 2, "march": 3, "april": 4, "may": 5, "june": 6,
    "july": 7, "august": 8, "september": 9, "october": 10, "november": 11, "december": 12,
    "ledna": 1, "února": 2, "března": 3, "dubna": 4, "května": 5, "června": 6,
    "července": 7, "srpna": 8, "září": 9, "října": 10, "listopadu": 11, "prosince": 12,
}
_NAMED_SUBJECT_STOPWORDS = {
    "Compressor", "Rotor", "Stator", "Clashing", "Blade", "Blades", "Are", "Was", "Were", "Can", "Could",
    "Should", "Would", "Anti", "Ice", "Anti-Ice", "Trent", "Remaining", "Specific", "Hurdles", "System",
    "Systems", "Proposed", "Mandated", "Interval", "Intervals", "Durability", "Compliance", "What", "Which",
    "When", "How", "Does", "Will", "Current", "Status", "Latest", "Historical", "Documented", "Established",
    "Consequences", "Certification", "Production", "Delivery", "Deliveries", "Component", "Supply", "January",
    "February", "March", "April", "May", "June", "July", "August", "September", "October", "November",
    "December", "Issuer", "Direct", "Official", "Regulator", "Reported", "Confirmed", "The", "Airworthiness",
    "Directive", "Directives", "Regulatory", "Safety", "Federal", "Register", "Minimum", "Equipment", "List",
    "Master", "Engine", "Engines", "Turbine", "Pressure", "High", "Applicability", "Effective", "Date",
    "Notice", "Notices", "Inspection", "Inspections", "Aero", "International", "Has", "Have", "Docket",
    "Aircraft", "Ground", "Aerospace", "Fleet", "Airline", "Airlines", "Variant", "Variants", "Family",
    "Model", "Models", "Operations", "Operational", "Availability", "Technical", "Defects", "Concerns",
    "Execution", "Factory", "Facilities", "Facility", "Manufacturing", "Renton", "Mid", "Mid-Exit", "Exit",
    "Door", "Plug", "Fuselage", "Flight", "Blowout", "Corporation", "Company", "Group", "Holdings", "Gear",
    "Landing", "Avionics", "Controls", "Control", "Export", "Western", "Fuel", "Manifold", "Airways",
    "Pacific", "Investigation", "Findings", "Probable", "Cause", "Quality", "Labor", "Labour", "Strike",
    "Dispute", "Supplier", "Suppliers", "Program", "Timeline", "Requirements", "Exemption", "Exemptions",
    "Commercial", "Type", "Certificate", "Validation", "Progress", "Ramp", "Phase", "Plant", "Line",
    "Launch", "Update", "Updates", "Test", "Tests", "Testing", "Acceleration", "Redesign", "Upgrade",
    "Upgrades", "Operator", "Operators", "Environment", "Environments", "Hot", "Sandy", "Coating",
    "Coatings", "Blade", "European", "Chinese", "American", "Global", "Explicitly", "Requested", "Facts",
    "Tooling", "Assembly", "Capability", "Jean-Luc",
    "Special", "Conditions", "Condition", "Standards", "Standard",
    "Integration", "Folding", "Wingtips", "Wingtip", "Simulators", "Simulator",
    "Authorization",
}
_AUTHORITY_LABELS = {
    "REGULATOR": "official regulatory record",
    "ISSUER_DISCLOSURE": "official issuer filing",
    "ISSUER_RELEASE": "official company press release",
    "ANALYST_ASSESSMENT": "validated source record",
    "SECONDARY": "secondary media report",
}
_STATUS_PHRASES = {
    "ISSUE_RESOLVED": "Confirmed regulatory evidence indicates that the tracked milestone or issue has been resolved.",
    "ISSUE_REPORTED_RESOLVED": "Available filings and media reports indicate that the tracked milestone has been achieved, though direct confirmation from the regulator itself is still pending.",
    "ISSUE_ACTIVE": "Current evidence confirms that the issue remains active.",
    "ISSUE_REPORTED_ACTIVE": "Available reporting suggests the issue remains active, pending primary confirmation.",
    "ISSUE_PARTIALLY_RESOLVED": "Evidence points to partial resolution, with residual items still open.",
    "ISSUE_WORSENED": "Recent evidence indicates the situation has deteriorated.",
    "STATUS_CONFLICTED": "Sources from the same period present conflicting accounts that require reconciliation.",
    "NO_RELEVANT_EVENT": "No relevant event matching this question was found within the searched sources.",
}


def _norm_model_hyphens(text: str) -> str:
    """Normalize hyphenated letter-digit model codes (e.g. C-919 -> C919) without altering dates or dockets."""
    return re.sub(r"\b([A-Za-z]{1,3})-(?!19\d{2}\b|20\d{2}\b)(\d{3,4}[A-Za-z0-9]*)\b", r"\1\2", str(text or ""))


def _kiq_exact_variants(text: str) -> set[str]:
    raw = str(text or "")
    norm = _norm_model_hyphens(raw)
    return set(_detect_exact_variants(raw)) | (set(_detect_exact_variants(norm)) if norm != raw else set())


def _kiq_aircraft_families(text: str) -> set[str]:
    raw = str(text or "")
    norm = _norm_model_hyphens(raw)
    return set(_detect_aircraft_families(raw)) | (set(_detect_aircraft_families(norm)) if norm != raw else set())


def _kiq_engine_models(text: str) -> set[str]:
    raw = str(text or "")
    norm = _norm_model_hyphens(raw)
    return set(_detect_engine_models(raw)) | (set(_detect_engine_models(norm)) if norm != raw else set())


def _sha256_text(text: str) -> str:
    """Compute the lowercase SHA-256 hex digest of a UTF-8 string."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _iter_raw_passages(doc: Dict[str, Any]) -> List[tuple[Dict[str, Any], str]]:
    """Normalize heterogeneous evidence_passages containers into (metadata, text) pairs."""
    raw = doc.get("evidence_passages") or []
    if isinstance(raw, dict):
        raw = [raw] if any(k in raw for k in ("text", "passage", "quote", "excerpt")) else list(raw.values())
    if isinstance(raw, (str, dict)):
        raw = [raw]
    pairs = []
    for entry in raw if isinstance(raw, (list, tuple)) else []:
        meta = entry if isinstance(entry, dict) else {}
        excerpt = str(next((meta[k] for k in ("text", "passage", "quote", "excerpt", "content") if meta.get(k)), "") if meta else entry)
        pairs.append((meta, excerpt))
    return pairs


def _lifecycle_topics(query: str) -> set[str]:
    """Return all lifecycle topic domains triggered by the query."""
    return {name for name, pat in _LIFECYCLE_TOPICS.items() if re.search(pat, query, re.I)}


def _issue_state(text: str, query: str) -> str:
    """Identify a stated lifecycle change; never infer one from generic good news."""
    topics = _lifecycle_topics(query)
    if not topics or _is_forecast(text, query):
        return "STATUS_UNKNOWN"
    if "CERTIFICATION" in topics:
        if re.search(
            r"\b(?:certif\w*|approval\w*|authorization|type\s+certificate)\b.{0,65}\b(?:withdrawn|revoked|rescinded|cancelled|canceled|retracted)\b|"
            r"\b(?:withdrawn|revoked|rescinded|cancelled|canceled|retracted)\b.{0,65}\b(?:certif\w*|approval\w*|authorization)\b",
            text, re.I,
        ):
            return "ISSUE_WORSENED"
        if re.search(
            r"\b(?:certif\w*|approval\w*)\b.{0,40}\b(?:not|never)\s+(?:been\s+)?(?:granted|issued|received|obtained|approved|completed)\b|"
            r"\b(?:not|never)\s+(?:been\s+)?(?:certified|approved|granted)\b",
            text, re.I,
        ):
            return "ISSUE_ACTIVE"
    if "REGULATORY" in topics and re.search(r"\b(?:proposed|draft|proposal|NPRM|not\s+yet\s+effective)\b", text, re.I):
        return "STATUS_UNKNOWN"

    primary_topic = next(t for t in _TOPIC_PRIORITY if t in topics)
    issue = _LIFECYCLE_TOPICS[primary_topic]
    partial = (
        r"\b(?:partially|some|limited|částečn\w*)\b.{0,55}\b(?:resum\w*|restor\w*|resolv\w*|obnoven\w*)\b|"
        r"\b(?:resum\w*|restor\w*|resolv\w*|obnoven\w*)\b.{0,45}\b(?:partially|some|limited|částečn\w*)\b"
    )
    if re.search(issue, text, re.I) and re.search(partial, text, re.I):
        return "ISSUE_PARTIALLY_RESOLVED"
    det = r"\b(?:worsen\w*|escalat\w*|intensif\w*|zhoršen\w*)\b"
    if re.search(rf"{issue}.{{0,60}}{det}", text, re.I) or re.search(rf"{det}.{{0,60}}{issue}", text, re.I):
        return "ISSUE_WORSENED"
    resolved, active = _ISSUE_STATE_PATTERNS[primary_topic]
    if re.search(resolved, text, re.I) and not re.search(
        r"\b(?:not|never|without|pending|awaiting|expected|planned|proposed)\b.{0,40}\b(?:certif\w*|resolved|completed|approved|resumed)\b",
        text, re.I,
    ):
        return "ISSUE_RESOLVED"
    return "ISSUE_ACTIVE" if re.search(active, text, re.I) else "STATUS_UNKNOWN"


def _required_evidence_specs(query: str) -> List[Dict[str, str]]:
    """Decompose a compound KIQ into independently verifiable fact types."""
    models = sorted(_detect_exact_variants(query) | _detect_engine_models(query))
    families = sorted(_detect_aircraft_families(query))
    named_entities = sorted(_named_subjects(query))
    component = next((name for name, pat in _COMPONENT_PATTERNS.items() if re.search(pat, query, re.I)), "")
    requirements = [
        {"key": key, "required_fact": fact, "evidence_type": kind}
        for key, fact, trigger, kind in _REQUIREMENT_RULES
        if re.search(trigger, query, re.I) and (
            key != "AFFECTED_COMPONENT" or bool(
                _detect_engine_models(query) or component
                or re.search(r"\b(?:which|what|identify|affected|specific|jak\w*|kter\w*)\b.{0,45}\b(?:component|part|součást|komponent)\b", query, re.I)
            )
        )
    ]
    topics = _lifecycle_topics(query)
    issue_mentioned = bool(re.search(rf"\b(?:{_ISSUE_WORDS})\b", query, re.I))
    current_requested = bool(re.search(_CURRENT_WORDS, query, re.I))
    # A question about what an issuer disclosed does not require independent regulator issuance.
    issuer_question = bool(re.search(
        r"\b(?:what|which|how|co|jak|kdy)\b.{0,110}\b(?:say|said|state|stated|states|stating|statement\w*|report\w*|disclos\w*|uved\w*|sděl\w*)\b|"
        r"\b(?:according\s+to|as\s+(?:disclosed|reported)\s+in)\b.{0,80}\b(?:filing|sec|10-[kq])\b|"
        r"\b(?:sec|10-[kq]|20-f|filing)\b.{0,110}\b(?:state|stated|states|stating|statement\w*|disclos\w*|report\w*|said|say)\b",
        query, re.I,
    ))
    explicit_regulator = bool(re.search(r"\b(?:did|has|have|when\s+did)\s+(?:the\s+)?(?:FAA|EASA|regulat\w*)\b.{0,55}\b(?:certif\w*|approv\w*|grant\w*|issu\w*)\b", query, re.I))
    issuer_only = issuer_question and not explicit_regulator

    explicit_cert_completion = bool(re.search(
        r"\b(?:complet\w*|certified|granted|issued|approv\w*|"
        r"(?:has|have|did)\s+(?:the\s+)?(?:faa|easa|caac|tcca|regulat\w*)\s+(?:certified|approved|granted|issued|certif\w*|approv\w*))\b",
        query, re.I,
    ))
    if "CERTIFICATION" in topics and (issue_mentioned or not explicit_cert_completion):
        requirements = [r for r in requirements if r["key"] != "CERTIFICATION"]
    if "CERTIFICATION" in topics and issuer_only:
        fin_q = bool(
            re.search(r"\b(?:financial|revenue|earnings|cash\s+flow|profit|tržb\w*|výnos\w*|zisk\w*)\b", query, re.I))
        requirements = [r for r in requirements if
                        r["key"] != "CERTIFICATION" and (r["key"] != "FINANCIAL_CLAIM" or fin_q)]
        requirements.extend((
            {"key": "ISSUER_STATEMENT", "required_fact": "Issuer's dated certification statement",
             "evidence_type": "ISSUER_DISCLOSURE"},
            {"key": "SOURCE_PROVENANCE", "required_fact": "Verifiable issuer-source reference",
             "evidence_type": "SOURCE_REFERENCE"},
        ))
    elif "CERTIFICATION" in topics and explicit_cert_completion:
        requirements.extend((
            {"key": "REGULATOR_DECISION", "required_fact": "Direct certification decision by the responsible regulator",
             "evidence_type": "OFFICIAL_CERTIFICATION_RECORD"},
            {"key": "DECISION_DATE", "required_fact": "Date of the actual regulatory decision",
             "evidence_type": "DATED_REGULATOR_DECISION"},
            {"key": "SOURCE_PROVENANCE", "required_fact": "Verifiable primary-source reference",
             "evidence_type": "SOURCE_REFERENCE"},
        ))
    elif issuer_only:
        requirements.append({"key": "SOURCE_PROVENANCE", "required_fact": "Verifiable issuer-source reference",
                             "evidence_type": "SOURCE_REFERENCE"})

    if topics and issue_mentioned:
        requirements.append({"key": "HISTORICAL_DELAY", "required_fact": "Evidence of the historical issue or delay", "evidence_type": "HISTORICAL_ISSUE"})
    if topics and (current_requested or issue_mentioned) and not issuer_only:
        requirements.append({"key": "CURRENT_STATUS", "required_fact": "Latest dated, issue-specific status", "evidence_type": "DATED_STATUS"})
    if topics and re.search(r"\b(?:change\w*|develop\w*|since|transition\w*|změn\w*|vývoj\w*|od\s+kdy)\b", query, re.I):
        requirements.append({"key": "STATUS_CHANGE", "required_fact": "Dated transition between two evidenced states", "evidence_type": "STATUS_TRANSITION"})
    if topics and not issuer_only and re.search(r"\b(?:resolv\w*|complet\w*|certified|fixed|reopen\w*|resum\w*|vyřešen\w*|obnoven\w*)\b", query, re.I):
        requirements.append({"key": "RESOLUTION_EVIDENCE", "required_fact": "Direct proof of an issue's resolution", "evidence_type": "RESOLUTION_RECORD"})
    if topics and re.search(r"\b(?:remaining|residual|persist\w*|still|after\s+(?:resolution|recovery)|přetrváv\w*|zbývaj\w*)\b", query, re.I):
        requirements.append({"key": "REMAINING_IMPACT", "required_fact": "Explicitly evidenced residual consequences", "evidence_type": "RESIDUAL_IMPACT"})
    if models or re.search(
        r"\b(?:applicabilit\w*|applicable\s+(?:model\w*|aircraft|type\w*)|affected\s+(?:aircraft|model\w*|type\w*)|"
        r"aircraft\s+covered|which\s+(?:models?|aircraft|types?)|kter\w*\s+(?:model\w*|typ\w*|letadl\w*)|"
        r"na\s+jak\w*\s+(?:model\w*|typ\w*|letadl\w*)|vztahuje\s+se)\b", query, re.I,
    ):
        requirements.append({"key": "PROGRAM_APPLICABILITY", "required_fact": "Direct applicability to the named model or program", "evidence_type": "MODEL_APPLICABILITY"})
    if re.search(r"\b(?:already\s+effective|currently\s+effective|now\s+effective|in\s+force|has\s+(?:taken\s+effect|entered\s+into\s+force)|je\s+(?:již\s+)?účinn\w*|naby\w*\s+účinnost\w*)\b", query, re.I):
        requirements.append({"key": "EFFECTIVE_AS_OF_REFERENCE_DATE", "required_fact": "Whether the identified regulation is effective as of the reference date", "evidence_type": "DATED_REGULATORY_STATUS"})
    if (any(r["key"] in _CAUSE_SOURCES for r in requirements)
            and any(r["key"] in {"PRODUCTION_IMPACT", "DELIVERY_IMPACT"} for r in requirements)
            and re.search(r"\b(?:impact\w*|affect\w*|caus\w*|due\s+to|ovliv\w*|způsob\w*)\b", query, re.I)):
        requirements.append({"key": "CAUSAL_LINK", "required_fact": "Source-established causal link between supply and downstream impact", "evidence_type": "CAUSAL_EVIDENCE"})
    if not requirements:
        requirements.append({"key": "EVENT_EXISTENCE", "required_fact": "Verified occurrence of the requested event", "evidence_type": "SOURCE_EVENT"})

    deduped = list({r["key"]: r for r in requirements}.values())
    entity_model = ", ".join(dict.fromkeys([*models, *families, *named_entities]))
    for req in deduped:
        req["required_entity_model"], req["required_component"] = entity_model, component
    return deduped


def _proof_matches(
    key: str, text: str, question: str, component: str, causal_patterns: Optional[List[str]] = None,
) -> bool:
    """Check whether a text passage satisfies a specific atomic requirement key."""
    if key in {"REGULATORY_PUBLICATION", "REGULATORY_EFFECTIVENESS", "EFFECTIVE_AS_OF_REFERENCE_DATE",
               "COMPLIANCE_DEADLINE", "ISSUER_STATEMENT", "REGULATOR_DECISION", "DECISION_DATE",
               "SOURCE_PROVENANCE", "STATUS_CHANGE"}:
        return False
    if key in {"CURRENT_STATUS", "RESOLUTION_EVIDENCE"}:
        status = _issue_state(text, question)
        return status != "STATUS_UNKNOWN" and (key == "CURRENT_STATUS" or status == "ISSUE_RESOLVED")
    if key in {"HISTORICAL_DELAY", "CERTIFICATION_DELAY"}:
        if re.search(r"\b(?:no|without|zero|not|žádn\w*|bez)\b.{0,45}\b(?:issue\w*|problem\w*|delay\w*|shortag\w*|problém\w*)\b", text, re.I):
            return False
        return bool(re.search(rf"\b(?:{_ISSUE_WORDS})\b", text, re.I)
                    and any(re.search(_LIFECYCLE_TOPICS[t], text, re.I) for t in _lifecycle_topics(question)))
    if key == "REMAINING_IMPACT":
        return bool(re.search(r"\b(?:remaining|residual|persist\w*|still|přetrváv\w*|zbývaj\w*)\b", text, re.I)
                    and any(re.search(p, text, re.I) for p in _IMPACT_PROOF.values()))
    if key == "PROGRAM_APPLICABILITY":
        if re.search(r"\b(?:not\s+applicable|does\s+not\s+apply|unaffected|excluded|nevztahuje\s+se)\b", text, re.I):
            return False
        if variants := _kiq_exact_variants(question):
            if variants & _kiq_exact_variants(text):
                return True
        if _kiq_engine_models(question) and _engine_models_match(question, text):
            return True
        return bool((families := _kiq_aircraft_families(question)) and (families & _kiq_aircraft_families(text)))
    if key == "AFFECTED_COMPONENT":
        if _kiq_engine_models(question):
            if not _engine_models_match(question, text):
                return False
            if component not in {"", "ENGINE"} and not re.search(_COMPONENT_PATTERNS[component], text, re.I):
                return False
            return True
        if _kiq_engine_models(text) or re.search(
                r"\b(?:mid[- ]?seal|seal\w*|stator\s+vane\w*|compressor|turbine|durabilit\w*|crack\w*|thrust\s+link\w*|borescope)\b",
                text, re.I,
        ):
            return True
        return bool(component and component != "ENGINE" and re.search(_COMPONENT_PATTERNS[component], text, re.I))
    if key == "CAUSAL_LINK":
        sources = causal_patterns if causal_patterns is not None else [
            pat for issue, pat in _CAUSE_SOURCES.items() if any(req["key"] == issue for req in _required_evidence_specs(question))
        ]
        return bool(any(re.search(p, text, re.I) for p in sources)
                    and any(re.search(p, text, re.I) for p in _IMPACT_PROOF.values())
                    and re.search(_CAUSE_PROOF, text, re.I))
    if key == "SUPPLY_DISRUPTION":
        return bool(re.search(_SUPPLY_PROOF, text, re.I))
    if key in _IMPACT_PROOF:
        if re.search(_IMPACT_PROOF[key], text, re.I):
            return True
        if key == "PRODUCTION_IMPACT" and re.search(r"\b(?:production|manufactur\w*|assembly|output|ramp[- ]?up)\b",
                                                    text, re.I) and re.search(
                r"\b(?:\d+|rate|target|shortfall|shortag\w*|struggl\w*|workforce|capacity|per\s+(?:month|year))\b",
                text, re.I):
            return True
        if key == "DELIVERY_IMPACT" and re.search(r"\b(?:deliver\w*|handover\w*)\b", text, re.I) and re.search(
                r"\b(?:\d+|target|shortfall|fell\s+short|expect\w*|202\d)\b", text, re.I):
            return True
        return False
    if key == "EVENT_EXISTENCE":
        return True
    if key == "INVESTIGATION_FINDING":
        return bool(re.search(
            r"\b(?:ntsb|investigat\w*|findings?|probable\s+cause|root\s+cause|final\s+report|preliminary\s+report|"
            r"missing\s+(?:four\s+)?(?:key\s+)?bolts?|maintenance\s+lapse|human\s+error|wear\s+and\s+tear|"
            r"degradat\w*|erosion|cmas|thermal\s+barrier|coating\w*|cooling|sand|dust|durabilit\w*|"
            r"quality\s+control|audit|hearing|recommendations?|safety\s+board)\b", text, re.I,
        ))
    if key == "CERTIFICATION":
        return _issue_state(text, question) == "ISSUE_RESOLVED" and not _is_forecast(text, question)
    if key == "INSPECTION_REQUIREMENT" and re.search(r"\b(?:requirement\w*|mandatory|mandat\w*)\b", question, re.I):
        return bool(re.search(r"\b(?:must|shall|require\w*|mandat\w*)\b.{0,65}\binspect\w*\b|\binspect\w*\b.{0,65}\b(?:required|mandated|mandatory)\b", text, re.I))
    return bool(re.search(_REQUIREMENT_PATTERN_BY_KEY[key], text, re.I))


def _claim_strength(key: str, claim: Dict[str, Any], query: str) -> str:
    """Downgrade non-regulator claims to PRELIMINARY when regulator authority is required."""
    authority = claim.get("authority")
    if key in {"REGULATOR_DECISION", "DECISION_DATE"} and authority != "REGULATOR":
        return "PRELIMINARY"
    if "CERTIFICATION" in _lifecycle_topics(query) and authority != "REGULATOR":
        if key in {"RESOLUTION_EVIDENCE", "CERTIFICATION"}:
            return "PRELIMINARY"
        if key == "CURRENT_STATUS" and claim.get("state") == "ISSUE_RESOLVED":
            return "PRELIMINARY"
    return claim.get("strength", "PRELIMINARY")


def _faa_labeled_quote(text: str, field: str, expected: str = "") -> str:
    """Return the actual official field line, never a synthetic citation."""
    if not (match := re.search(rf"(?im)^[ \t]*{re.escape(field)}:[ \t]*[^\r\n]*", text)):
        return ""
    quote = match.group(0).strip()
    return quote if not expected or expected in quote else ""


def _faa_fact_claim(doc: Dict[str, Any], fact: Dict[str, Any], key: str, quote: str, reference: str) -> Dict[str, Any]:
    """Build provenance metadata for one verified FAA field."""
    doc_id, published = str(fact["document_id"]), str(fact.get("publication_date") or "")
    if quote and quote not in str(doc.get("text") or ""):
        raise ValueError("FAA field citation is absent from the collected document")
    return {
        "claim_id": f"FAA_{doc_id}_{key}", "doc_id": doc_id, "source_id": "SRC_001",
        "source_url": str(fact["source_url"]), "authority": "REGULATOR", "strength": "VERIFIED",
        "claim_type": _FAA_FACT_KINDS.get(key, key), "regulatory_fact_key": key,
        "quote": quote, "text": quote or str(doc.get("title") or ""),
        "publication_date": published, "date": published, "event_date": "",
        "date_basis": "PUBLICATION_DATE_ONLY", "state": "STATUS_UNKNOWN", "historical": False,
        "passage_hash": _sha256_text(quote) if quote else "",
        "source_hash": str(doc.get("source_content_sha256") or ""),
        "extraction_method": "OFFICIAL_LABELED_DOCUMENT_FIELD" if quote else "OFFICIAL_DOCUMENT_IDENTITY",
        "passage_validation_status": "PASSAGE_VERIFIED" if quote else "SOURCE_IDENTITY_VERIFIED",
        "verification_reason": "OFFICIAL_DOCUMENT_FIELD_VERIFIED" if quote else "OFFICIAL_DOCUMENT_IDENTITY_VERIFIED",
        "document_number": str(fact.get("document_number") or ""),
        "regulatory_stage": str(fact.get("stage") or ""),
        "effective_date": str(fact.get("effective_date") or ""),
        "effective_as_of_reference_date": fact.get("effective_as_of_reference_date"),
        "reference_date": reference,
        "lifecycle_verified": bool(fact.get("lifecycle_verified")),
        "supersession_status": str(fact.get("supersession_status") or "UNKNOWN"),
        "applicable_variants": list(fact.get("applicable_variants") or []),
    }


def _scoped_faa_publication_fact(question: str, doc: Dict[str, Any], reference: str = "") -> Optional[Dict[str, Any]]:
    """Accept verified Federal Register publication fields even when full lifecycle verification is absent."""
    source = {**doc, "url": doc.get("url") or doc.get("source_url") or ""}
    full_fact = assess_official_faa_fact(question, source)
    identity = inspect_official_faa_publication(source)
    if not identity or not identity.get("document_existence_verified") or not doc.get("doc_id"):
        return None

    pos_q = re.split(r"\b(?:exclude|excluding|except)\b", question, maxsplit=1, flags=re.I)[0]
    number = str(identity["document_number"])
    req_numbers = {m.upper() for m in _FAA_DOC_NUMBER_RE.findall(pos_q)}
    req_dockets = {m.upper() for m in _FAA_DOCKET_RE.findall(pos_q)}
    rec_dockets = {str(v).upper() for v in identity.get("docket_ids") or []}
    if (req_numbers and number not in req_numbers) or (req_dockets and not (req_dockets & rec_dockets)):
        return None
    if re.search(r"\bEASA\b", pos_q, re.I) and not re.search(r"\bFAA\b", pos_q, re.I):
        return None

    text, title = str(source.get("text") or ""), str(source.get("title") or "")
    src_status = str(source.get("content_status") or source.get("source_content_status") or "").upper()
    usable = src_status not in (_NON_FULL_TEXT | {"SOURCE_ACCESS_BLOCKED", "UNAVAILABLE"}) and source.get("content_truncated") is not True
    summary = _faa_field(text, "Official Summary") if usable else ""
    body = title + "\n" + summary

    wanted_makers = {m for m in _FAA_MANUFACTURERS if re.search(rf"\b{m}\b", pos_q, re.I)}
    w_vars, w_fams, w_engs = _detect_exact_variants(pos_q), _detect_aircraft_families(pos_q), _detect_engine_models(pos_q)
    f_vars, f_fams, f_engs = _detect_exact_variants(summary), _detect_aircraft_families(summary), _detect_engine_models(summary)
    eng_match = bool(w_engs and _engine_models_match(pos_q, summary))
    eng_ad_match = bool(usable and re.search(r"\bengines?\b", title, re.I) and eng_match)

    if wanted_makers and not eng_ad_match and not all(re.search(rf"\b{m}\b", body, re.I) for m in wanted_makers):
        return None
    if usable and ((w_engs and not eng_match)
                   or (w_vars and not (w_vars & f_vars) and (not eng_ad_match or bool(f_vars)))
                   or (w_fams and not (w_fams & f_fams) and (not eng_ad_match or bool(f_fams)))):
        return None
    if not usable and not (req_numbers or req_dockets):
        return None
    if re.search(r"\b(?:airworthiness\s+directives?|\bAD\b)\b", pos_q, re.I) and not re.search(r"\bairworthiness\s+directives?\b", body, re.I):
        return None
    if re.search(r"\b(?:minimum\s+equipment\s+list|\bMEL\b)\b", pos_q, re.I) and not re.search(r"\b(?:minimum\s+equipment\s+list|\bMEL\b)\b", body, re.I):
        return None
    if not any((req_numbers, req_dockets, w_vars, w_fams, w_engs)) and not _topic_matches(question, body):
        return None

    published = str(identity["publication_date"])
    fact = {
        **(full_fact or {}),
        "document_id": str(doc["doc_id"]), "document_number": number, "docket_ids": sorted(rec_dockets),
        "source_url": str(identity["source_url"]), "source_authority": "FAA_FEDERAL_REGISTER",
        "document_existence_verified": True, "requested_document_match": True,
        "requested_docket_match": True, "document_type_match": True, "publication_date": published,
        "lifecycle_verified": _faa_field(text, "Regulatory Lifecycle Check").upper() == "VERIFIED" and full_fact is not None,
        "supersession_status": str(full_fact.get("supersession_status") or "UNKNOWN") if full_fact is not None else "UNKNOWN",
        "program_unverified": bool(w_vars or w_fams or w_engs) and not bool(summary),
        "aircraft_or_engine_match": bool((w_vars & f_vars) or (w_fams & f_fams) or eng_match),
    }
    if not full_fact:
        fact.update(missing_evidence=["REGULATORY_LIFECYCLE_NOT_VERIFIED"], content_evidence_status="OFFICIAL_PUBLICATION_FIELDS_ONLY")

    stage = _faa_field(text, "Regulatory Stage").upper() if usable else ""
    doc_stage = str(doc.get("regulatory_stage") or "").upper()
    if stage and doc_stage and doc_stage != stage:
        return None
    if stage in _FAA_STAGES and (not doc_stage or doc_stage == stage):
        fact["stage"] = stage
    elif not full_fact:
        fact["stage"] = "UNKNOWN"

    effective, eff_conflict = _faa_consistent_date(_faa_field(text, "Effective Date") if usable else "", doc.get("regulatory_effective_date") if usable else "")
    deadline, dl_conflict = _faa_consistent_date(_faa_field(text, "Compliance Deadline") if usable else "", doc.get("regulatory_compliance_deadline") if usable else "")
    established = bool(effective and not eff_conflict and usable and _faa_field(text, "Effective Date") and fact.get("stage") in {"FINAL_ISSUED", "EFFECTIVE", "WITHDRAWN"})

    as_of = reference or _as_of_date(question) or datetime.now(timezone.utc).date().isoformat()
    as_of_day = date.fromisoformat(as_of)
    eff_as_of = bool(established and date.fromisoformat(effective) <= as_of_day and fact.get("stage") in {"FINAL_ISSUED", "EFFECTIVE"})
    observable = as_of_day <= datetime.now(timezone.utc).date()
    req_app = "PROGRAM_APPLICABILITY" in {r["key"] for r in _required_evidence_specs(question)}
    app_verified = bool(summary and ((w_vars & f_vars) or (w_fams & f_fams) or eng_match or (req_app and not any((w_vars, w_fams, w_engs)) and any((f_vars, f_fams, f_engs)))))

    fact.update(
        effective_date=effective if established else None,
        effective_date_established=established,
        compliance_deadline=deadline if not dl_conflict else None,
        effective_as_of_reference_date=eff_as_of if established and observable else None,
        reference_date=as_of,
        applicable_variants=sorted(f_vars),
        program_applicability_verified=app_verified,
    )
    if not full_fact:
        fact["regulatory_status"] = "WITHDRAWN" if fact.get("stage") == "WITHDRAWN" else ("EFFECTIVE" if eff_as_of and observable else str(fact.get("stage") or "UNKNOWN"))

    fields = {
        "REGULATORY_EXISTENCE": _faa_labeled_quote(text, "Federal Register Document", number),
        "REGULATORY_PUBLICATION": _faa_labeled_quote(text, "Publication Date", published),
    }
    if established:
        fields["REGULATORY_EFFECTIVENESS"] = _faa_labeled_quote(text, "Effective Date", effective)
        if observable:
            fields["EFFECTIVE_AS_OF_REFERENCE_DATE"] = fields["REGULATORY_EFFECTIVENESS"]
    if deadline and not dl_conflict:
        fields["COMPLIANCE_DEADLINE"] = _faa_labeled_quote(text, "Compliance Deadline", deadline)
    if app_verified:
        fields["PROGRAM_APPLICABILITY"] = _faa_labeled_quote(text, "Official Summary", summary)

    valid_keys = {"REGULATORY_EXISTENCE"} | {k for k in ("REGULATORY_PUBLICATION", "COMPLIANCE_DEADLINE", "PROGRAM_APPLICABILITY") if fields.get(k)}
    if established and fields.get("REGULATORY_EFFECTIVENESS"):
        valid_keys.add("REGULATORY_EFFECTIVENESS")
        if observable:
            valid_keys.add("EFFECTIVE_AS_OF_REFERENCE_DATE")

    fact["verified_fact_keys"] = sorted(valid_keys)
    fact["verified_field_claims"] = [_faa_fact_claim(source, fact, k, fields.get(k, ""), as_of) for k in fact["verified_fact_keys"]]
    if not fact.get("answer"):
        fact["answer"] = (
            f"FAA publication {number}, published {published}; stage {fact.get('stage') or 'UNKNOWN'}; "
            f"effective date {effective if established else 'NOT_ESTABLISHED'}; effective as of {as_of}: "
            f"{str(eff_as_of).upper() if established and observable else 'UNKNOWN'}. "
            "Later amendments and supersession have not been verified."
        )
    return fact


def build_atomic_kiq_requirements(
    query: str, kiq_id: str, supported: List[ThreatAssessment] = (),
    partially_supported: List[ThreatAssessment] = (), regulatory_facts: List[Dict[str, Any]] = (),
    official_confirmation: Optional[Dict[str, Any]] = None,
    eligible_document_ids: Optional[set[str]] = None, searched: bool = True,
    document_claims: Optional[List[Dict[str, Any]]] = None,
    required_keys: Optional[set[str]] = None,
) -> List[Dict[str, Any]]:
    """Return auditable atomic requirement records; contextual documents never verify downstream impacts."""
    facts = [f for f in regulatory_facts if f.get("requested_docket_match", True) and f.get("requested_document_match", True) and f.get("document_type_match", True)]
    allowed = eligible_document_ids
    specs = [s for s in _required_evidence_specs(query) if required_keys is None or s["key"] in required_keys]
    causal_patterns = [_CAUSE_SOURCES[r["key"]] for r in specs if r["key"] in _CAUSE_SOURCES]
    cutoff = _as_of_date(query)
    claims = [c for c in (document_claims or [])
              if (allowed is None or c["doc_id"] in allowed)
              and (not cutoff or (c.get("publication_date") and c["publication_date"] <= cutoff and c.get("date", "") <= cutoff))]
    cert_topic = "CERTIFICATION" in _lifecycle_topics(query)
    records = []

    for index, spec in enumerate(specs, 1):
        key = spec["key"]
        verified_ids, preliminary_ids, contributing = set(), set(), []

        for fact in facts:
            vkeys = set(fact.get("verified_fact_keys") or ())
            proof = {
                "REGULATORY_EXISTENCE": bool(fact.get("document_existence_verified")),
                "REGULATORY_PUBLICATION": bool(fact.get("publication_date")),
                "REGULATORY_EFFECTIVENESS": bool(fact.get("effective_date_established")),
                "EFFECTIVE_AS_OF_REFERENCE_DATE": fact.get("effective_as_of_reference_date") is not None,
                "COMPLIANCE_DEADLINE": bool(fact.get("compliance_deadline")),
                "PROGRAM_APPLICABILITY": bool(fact.get("program_applicability_verified")),
                "INSPECTION_REQUIREMENT": _proof_matches("INSPECTION_REQUIREMENT", str(fact.get("answer") or ""), query, spec["required_component"], causal_patterns),
                "CERTIFICATION": "CERTIFICATION" in str(fact.get("answer", "")).upper(),
            }.get(key, False)
            if vkeys:
                proof = proof and key in vkeys
            if proof and fact.get("document_id") and (allowed is None or fact["document_id"] in allowed):
                verified_ids.add(fact["document_id"])
                contributing.extend(c for c in fact.get("verified_field_claims") or [] if c.get("regulatory_fact_key") == key and c.get("doc_id") == fact["document_id"])

        if (official_confirmation and key in {"CERTIFICATION", "CURRENT_STATUS", "RESOLUTION_EVIDENCE", "PROGRAM_APPLICABILITY", "REGULATOR_DECISION", "SOURCE_PROVENANCE", "DECISION_DATE"}
                and (allowed is None or official_confirmation["doc_id"] in allowed)
                and (key != "DECISION_DATE" or _date_mentioned(official_confirmation.get("text", ""), official_confirmation.get("regulatory_decision_date")))):
            verified_ids.add(official_confirmation["doc_id"])

        if key not in {"REGULATORY_EFFECTIVENESS", "EFFECTIVE_AS_OF_REFERENCE_DATE", "COMPLIANCE_DEADLINE", "REGULATORY_PUBLICATION"}:
            for threat, target in [(t, verified_ids) for t in supported] + [(t, preliminary_ids) for t in partially_supported]:
                eids = set(threat.evidence_ids or [])
                if allowed is not None:
                    eids &= allowed
                if not eids:
                    continue
                if any(_proof_matches(key, str(p), query, spec["required_component"], causal_patterns) for p in (threat.fact_check_quote, threat.confirmed_facts) if p):
                    dest = preliminary_ids if (
                        (target is verified_ids and threat.claim_support_status != "STATED_IN_SOURCE")
                        or (key == "CAUSAL_LINK" and threat.causal_support_status != "EVIDENCED_IN_VERIFIED_SOURCE")
                        or (cert_topic and key in {"CERTIFICATION", "CURRENT_STATUS", "RESOLUTION_EVIDENCE"})
                    ) else target
                    dest.update(eids)

        for claim in claims:
            if claim.get("regulatory_fact_key") or (claim.get("claim_type") == "FORECAST" and key not in {"PROGRAM_APPLICABILITY", "ISSUER_STATEMENT"}):
                continue
            matched = (
                (key == "ISSUER_STATEMENT" and claim.get("authority") == "ISSUER_DISCLOSURE" and claim.get("issuer_matches_query") is True and bool(claim.get("publication_date")) and _topic_matches(query, claim["text"]))
                or (key == "SOURCE_PROVENANCE" and bool(urlsplit(str(claim.get("source_url") or "")).hostname) and claim.get("strength") == "VERIFIED")
                or (key == "DECISION_DATE" and claim.get("authority") == "REGULATOR" and _date_mentioned(claim.get("text", ""), claim.get("event_date")) and claim.get("strength") == "VERIFIED")
                or (key not in {"ISSUER_STATEMENT", "REGULATOR_DECISION", "DECISION_DATE", "SOURCE_PROVENANCE"} and _proof_matches(key, claim["text"] + " " + str(claim.get("section") or ""), query, spec["required_component"], causal_patterns))
            )
            if matched:
                dest = verified_ids if (_claim_strength(key, claim, query) == "VERIFIED" and (key != "CAUSAL_LINK" or claim.get("causal_link_verified") is True)) else preliminary_ids
                dest.add(claim["doc_id"])
                contributing.append(claim)

        if key in {"CURRENT_STATUS", "STATUS_CHANGE"}:
            states = sorted(
                (c for c in claims if c.get("state") != "STATUS_UNKNOWN" and c.get("date") and (key == "STATUS_CHANGE" or not c.get("historical"))),
                key=lambda c: c["date"],
                reverse=True,
            )
            if key == "CURRENT_STATUS":
                latest = [c for c in states if c["date"] == states[0]["date"]] if states else []
                stale_for_timeline = False
                if latest and re.search(r"\b(?:timeline|eis|entry[- ]into[- ]service|delay\w*|schedule\w*|slipp\w*)\b",
                                        query, re.I):
                    try:
                        top_day = date.fromisoformat(latest[0]["date"][:10])
                        newer_dates = [
                            c["date"][:10] for c in claims
                            if c.get("date") and len(str(c["date"])) >= 10
                               and (date.fromisoformat(str(c["date"])[:10]) - top_day).days >= 180
                        ]
                        stale_for_timeline = bool(newer_dates)
                    except ValueError:
                        stale_for_timeline = False
                valid = bool(latest and not stale_for_timeline and len({c["state"] for c in latest}) == 1)
                same_state = [c for c in states if valid and c["state"] == latest[0]["state"]] if valid else latest
                reg_conf = {official_confirmation["doc_id"]} if (
                            official_confirmation and not stale_for_timeline) else set()
                verified_ids = ({c["doc_id"] for c in same_state if
                                 _claim_strength(key, c, query) == "VERIFIED"} if valid else set()) | (
                                   reg_conf if valid or not latest else set())
                preliminary_ids = {c["doc_id"] for c in same_state if _claim_strength(key, c, query) != "VERIFIED"}
                if not valid:
                    verified_ids.clear()
                    preliminary_ids.update(c["doc_id"] for c in latest)
                contributing = same_state
            else:
                pairs = [(old, new) for old in states for new in states if old["date"] < new["date"] and old["state"] != new["state"]]
                verified_ids = set()
                if pairs:
                    old, new = pairs[0]
                    (verified_ids if all(_claim_strength(key, c, query) == "VERIFIED" and c.get("event_date") for c in (old, new)) else preliminary_ids).update((old["doc_id"], new["doc_id"]))
                else:
                    preliminary_ids.clear()
                contributing = list(pairs[0]) if pairs else []

        # Independent multi-source corroboration: >=2 distinct reputable non-social domains
        # agreeing on the same non-regulatory atomic fact elevate PRELIMINARY -> VERIFIED.
        _non_corroboratable = {
            "REGULATOR_DECISION", "DECISION_DATE", "REGULATORY_EXISTENCE",
            "REGULATORY_PUBLICATION", "REGULATORY_EFFECTIVENESS",
            "EFFECTIVE_AS_OF_REFERENCE_DATE", "COMPLIANCE_DEADLINE", "ISSUER_STATEMENT",
        }
        _cert_resolved_only = (
            cert_topic and (
                key in {"CERTIFICATION", "RESOLUTION_EVIDENCE"}
                or (key == "CURRENT_STATUS" and any(c.get("state") == "ISSUE_RESOLVED" for c in contributing))
            )
        )
        if not verified_ids and preliminary_ids and key not in _non_corroboratable and not _cert_resolved_only:
            from ews_state import UNVERIFIED_SOCIAL_VIDEO_DOMAINS
            corrob_domains: Dict[str, set[str]] = {}
            for c in contributing:
                if c.get("doc_id") not in preliminary_ids or c.get("source_id") in {"SRC_007", "SRC_008"}:
                    continue
                host = (urlsplit(str(c.get("source_url") or "")).hostname or "").lower().removeprefix("www.")
                if host and not any(host == sd or host.endswith("." + sd) for sd in UNVERIFIED_SOCIAL_VIDEO_DOMAINS):
                    corrob_domains.setdefault(host, set()).add(c["doc_id"])
            if len(corrob_domains) >= 2:
                verified_ids.update(did for dids in corrob_domains.values() for did in dids)

        state = "NOT_SEARCHED" if not searched else ("VERIFIED" if verified_ids else ("PRELIMINARY" if preliminary_ids else "MISSING"))
        if state == "VERIFIED":
            missing = []
        elif state == "NOT_SEARCHED":
            missing = ["No relevant source search was executed"]
        elif state == "PRELIMINARY":
            missing = ["Direct dated regulator certification decision" if key == "REGULATOR_DECISION"
                       else "Validated issuer passage with filing URL, identity and content integrity" if key == "ISSUER_STATEMENT"
                       else "Independent confirmation of the preliminary claim"]
        else:
            missing = ["Direct dated certification record from the competent regulator"] if key == "REGULATOR_DECISION" else [f"Verified source passage for: {spec['required_fact']}"]

        supporting = [
            {
                "doc_id": c["doc_id"], "claim": c["text"][:420], "claim_id": c.get("claim_id", ""),
                "kiq_id": kiq_id, "kit_id": c.get("kit_id", ""), "source_id": c.get("source_id", ""),
                "quote": c.get("quote", ""), "issuer_name": c.get("issuer_name", ""),
                "issuer_cik": c.get("issuer_cik", ""), "original_filing_url": c.get("original_filing_url", ""),
                "extraction_method": c.get("extraction_method", ""),
                "passage_validation_status": c.get("passage_validation_status", ""),
                "publication_date": c.get("publication_date", ""), "event_date": c.get("event_date", ""),
                "date_basis": c.get("date_basis", "PUBLICATION_DATE_ONLY"),
                "authority": c.get("authority", "UNSPECIFIED"), "strength": _claim_strength(key, c, query),
                "source_url": c.get("source_url", ""), "source_hash": c.get("source_hash", ""),
                "passage_hash": c.get("passage_hash", ""), "verification_reason": c.get("verification_reason", "UNSPECIFIED"),
                "claim_type": c.get("claim_type", "OBSERVED"), "claim_state": c.get("state", "STATUS_UNKNOWN"),
                "document_number": c.get("document_number", ""), "regulatory_stage": c.get("regulatory_stage", ""),
                "effective_date": c.get("effective_date", ""),
                "effective_as_of_reference_date": c.get("effective_as_of_reference_date"),
                "reference_date": c.get("reference_date", ""), "lifecycle_verified": c.get("lifecycle_verified"),
                "supersession_status": c.get("supersession_status", ""),
                "applicable_variants": c.get("applicable_variants", []),
            }
            for c in contributing if c["doc_id"] in (verified_ids | preliminary_ids)
        ][:3]
        if official_confirmation and official_confirmation["doc_id"] in verified_ids and key in {"REGULATOR_DECISION", "DECISION_DATE", "SOURCE_PROVENANCE", "PROGRAM_APPLICABILITY", "CERTIFICATION", "RESOLUTION_EVIDENCE"}:
            oq = str(official_confirmation.get("verified_quote") or "")
            d_date = _date_str(official_confirmation.get("regulatory_decision_date")) if _date_mentioned(official_confirmation.get("text", ""), official_confirmation.get("regulatory_decision_date")) else ""
            supporting = [{
                "doc_id": official_confirmation["doc_id"], "claim": oq[:420],
                "publication_date": _published_date(official_confirmation), "event_date": d_date,
                "date_basis": "EVENT_DATE" if d_date else "PUBLICATION_DATE_ONLY",
                "authority": "REGULATOR", "strength": "VERIFIED",
                "source_url": str(official_confirmation.get("url") or ""),
                "passage_hash": _sha256_text(oq), "verification_reason": "FAA_PRIMARY_FULL_TEXT",
            }]
        records.append({
            "id": f"{kiq_id}_REQ_{index:02d}", **spec, "verification_status": state,
            "doc_ids": sorted(verified_ids | preliminary_ids),
            "verified_doc_ids": sorted(verified_ids),
            "preliminary_doc_ids": sorted(preliminary_ids - verified_ids),
            "supporting_claims": supporting, "missing_information": missing,
        })
    return records


def _source_execution_status(
    query: str, enabled: bool, source_ids: set[str], retrieved: bool,
    searched_source_ids: Optional[set[str]], connector_telemetry: Optional[Dict[str, Any]],
    raw_document_count: Optional[int] = None, eligible_document_count: Optional[int] = None,
) -> str:
    """Distinguish nonexecution, connector failure, empty results, and FR03 rejection."""
    if not enabled:
        return "SOURCE_NOT_SELECTED"
    relevant = [e for e in (connector_telemetry or {}).values() if isinstance(e, dict) and e.get("source_id") in source_ids]
    query_confirmed = False
    if relevant and any(e.get("queries") for e in relevant):
        wanted = {_norm_q(query), news_api_search_key(query)}
        matched = [e for e in relevant if any(_norm_q(q) in wanted or news_api_search_key(q) in wanted for q in e.get("queries", []))]
        query_confirmed = bool(matched or (searched_source_ids is not None and (source_ids & searched_source_ids)))
        relevant = matched or relevant

    def _hard_unavailable(entry: Dict[str, Any]) -> bool:
        errs = [str(e).strip() for e in (entry.get("errors") or []) if str(e).strip()]
        if any(not e.upper().startswith("PARTIAL_COVERAGE") for e in errs):
            return True
        st = str(entry.get("operational_status", "")).upper()
        if st == "TEMPORARILY_UNAVAILABLE" and errs and int(entry.get("successful_responses") or 0) > 0:
            return False
        return st in {"RATE_LIMITED", "AUTHENTICATION_FAILED", "ACCESS_RESTRICTED", "TEMPORARILY_UNAVAILABLE", "FAILED", "ERROR", "TIMEOUT"}

    errors = any(_hard_unavailable(e) for e in relevant)
    if bool(retrieved or raw_document_count):
        return "RESULTS_FILTERED_OUT" if eligible_document_count == 0 else ("PARTIAL_RESULT" if errors else "RESULTS_RETRIEVED")
    if errors:
        return "SOURCE_UNAVAILABLE"
    if searched_source_ids is not None and not (source_ids & searched_source_ids):
        return "QUERY_NOT_EXECUTED"
    completed = {"SUCCESS", "SUCCEEDED", "COMPLETED", "OK", "AVAILABLE", "PARTIAL_COVERAGE", "NO_MATCH", "NO_RESULTS", "EMPTY"}
    if query_confirmed and relevant and all(str(e.get("operational_status") or "").upper() in completed for e in relevant):
        return "NO_MATCH"
    return "EXECUTION_UNVERIFIED"


def _compile_terms(*terms: str) -> re.Pattern:
    """Compile a strict word-boundary alternation regex for KIQ topic terms."""
    return re.compile(rf"(?<![a-z0-9])(?:{'|'.join(re.escape(t) for t in terms)})(?![a-z0-9])")


# Explicit strategic KIQ match rules (preserved verbatim).
_KIQ_MATCH_RULES = [
    ("KIQ_1_1", {RiskType.SUPPLY_CHAIN, RiskType.TECHNICAL_QUALITY, RiskType.FINANCIAL}, _compile_terms(
        "production delay", "production delays", "production disruption", "production disruptions",
        "delivery delay", "delivery delays", "delivery postponement", "delays to entry into service",
        "manufacturing disruption", "factory shutdown", "production halt", "production rate",
        "assembly disruption", "supplier production", "schedule slip",
    )),
    ("KIQ_1_2", {RiskType.SUPPLY_CHAIN, RiskType.TECHNICAL_QUALITY, RiskType.FINANCIAL}, _compile_terms(
        "component shortage", "engine shortage", "parts shortage", "spare parts shortage",
        "material shortage", "raw material", "titanium shortage", "forging shortage",
        "supplier insolvency", "supplier strike", "industrial strike", "labor strike",
        "work stoppage", "supply shortage", "critical components", "engine removal",
        "engine removals", "powder metal", "powdered metal", "mro bottleneck", "shop visit",
    )),
    ("KIQ_2_1", {RiskType.COMPETITIVE, RiskType.ENVIRONMENTAL_TECHNOLOGICAL}, _compile_terms(
        "strategic partnership", "strategic alliance", "product launch",
        "new aircraft", "new technology", "innovation partnership", "joint venture",
    )),
    ("KIQ_2_2", {RiskType.COMPETITIVE}, _compile_terms(
        "aircraft order", "fleet order", "firm order", "order cancellation",
        "purchase agreement", "fleet contract", "aircraft contract", "orderbook", "orders totaling",
    )),
    ("KIQ_3_1", {RiskType.REGULATORY, RiskType.TECHNICAL_QUALITY, RiskType.ENVIRONMENTAL_TECHNOLOGICAL}, _compile_terms(
        "sustainable aviation fuel", "saf certification", "saf technology",
        "emissions standard", "emissions regulation", "technology certification",
        "hydrogen propulsion", "electric propulsion", "alternative propulsion",
        "technology regulation", "environmental regulation",
        "airworthiness directive", "airworthiness directives", "airworthiness",
        "proposed ad", "notice of proposed rulemaking", "nprm",
        "type certification", "type certificate", "achieved certification",
        "faa certification", "easa certification", "minimum equipment list", "mmel",
        "borescope inspection", "mandatory inspection", "regulatory requirement",
        "regulatory directive", "faa ad", "easa ad",
    )),
]


def _norm_q(value: Any) -> str:
    """Normalize a KIT/KIQ string into lowercase alphanumeric words."""
    return re.sub(r"[^a-z0-9]+", " ", str(value or "").strip().lower()).strip()


def build_catalog_prompt_context(user_query: str) -> str:
    """Present catalog context only where it materially matches the user's actual KIT."""
    query_words = set(_WORD_RE.findall(user_query.lower())) - _QUERY_STOPWORDS
    lines = [
        f"- [{item['kiq_id']}] {item['question']} | Indicators: {'; '.join(item['indicators'])}"
        for item in get_active_kiq_catalog()
        if len(overlap := query_words & set(_WORD_RE.findall(f"{item['question']} {' '.join(item['indicators'])}".lower()))) >= 2
        or bool(overlap & _DISTINCTIVE_TERMS)
    ]
    return "\n".join(lines) if lines else "No direct match in the strategic KIQ catalog. Preserve the user-defined ad-hoc KIT without assigning an unrelated catalog identifier."


def match_kiqs_for_threat(threat: ThreatAssessment, catalog: List[Dict[str, Any]]) -> List[str]:
    """Conservative mapping to the thesis-aligned 5-KIQ strategic catalog."""
    evidence = f"{threat.threat_description or ''} {threat.confirmed_facts or ''} {threat.fact_check_quote or ''}".lower()
    allowed = {item["kiq_id"] for item in catalog}
    return [kid for kid, rtypes, pat in _KIQ_MATCH_RULES if kid in allowed and threat.risk_type in rtypes and pat.search(evidence)]


def _kiq_evidence_matches_topic(query: str, threat: ThreatAssessment) -> bool:
    """Require evidence of the specific issue, not generic aircraft overlap."""
    evidence = f"{threat.fact_check_quote or ''} {threat.confirmed_facts or ''}"
    if _detect_engine_models(query) and not _engine_models_match(query, evidence):
        return False
    reg_re = r"\bFAA-\d{4}-\d+\b|\b20\d{2}-\d{5}\b"
    wanted_ids = {v.upper() for v in re.findall(reg_re, query, re.I)}
    if wanted_ids and not wanted_ids.issubset({v.upper() for v in re.findall(reg_re, evidence, re.I)}):
        return False
    ad_nums = re.findall(r"\b20\d{2}-\d{4}(?:-[A-Z])?\b", query, re.I)
    if ad_nums and not all(re.search(rf"\b{re.escape(n)}\b", evidence, re.I) for n in ad_nums):
        return False
    requested = [pat for pat in _KIQ_ISSUE_GROUPS if re.search(pat, query, re.I)]
    return not requested or any(re.search(pat, evidence, re.I) for pat in requested)


def _is_matching_official_faa_doc(doc: Optional[Dict[str, Any]], specific_terms: set[str]) -> bool:
    """Check whether an official verified Federal Register document matches required terms."""
    if not doc or not specific_terms or doc.get("source_id") != "SRC_001":
        return False
    url, text = str(doc.get("url") or ""), str(doc.get("text") or "")
    if not url.startswith("https://www.federalregister.gov/documents/") or "Regulatory Lifecycle Check: VERIFIED" not in text or not re.search(r"(?m)^FAA Docket: FAA-\d{4}-\d+\s*$", text):
        return False
    combined = f"{doc.get('title') or ''} {text}".lower()
    return any(re.search(rf"\b{re.escape(tok)}\b", combined) for tok in specific_terms)


def _is_effective_faa_threat(t: ThreatAssessment) -> bool:
    """Return True when a threat carries a verified effective FAA lifecycle stage."""
    summary = t.corroboration_summary or {}
    return summary.get("FAA Lifecycle Verified") == "YES" and summary.get("Regulatory Stage") == "EFFECTIVE"


def _faa_certification_models(text: str) -> set[str]:
    """Normalize exact aircraft variants, including 737-10 / 737 MAX 10 aliases."""
    from aero_ews.collection.queries import _model_tokens

    cleaned = re.sub(r"\bFAA\s+(?=(?:B?737)[-\s])", "", text or "", flags=re.I)
    return {
        f"737-{m[1]}" if (m := re.fullmatch(r"B?737(?:MAX)?(\d{1,2})", code)) else code
        for tok in _model_tokens(cleaned) if (code := re.sub(r"[\s-]", "", tok.upper()))
    }


def find_official_faa_certification(
    query: str, docs: List[Dict[str, Any]], *, after_date: str = "", as_of_date: str = "",
):
    """Verify a dated FAA newsroom statement of issuance within optional date bounds."""
    if not re.search(r"\b(?:certif\w*|type\s+approv\w*)\b", query, re.I) or re.search(r"\b(?:EASA|TCCA|CAAC|CASA|ANAC|FAA[-\s]+20\d{2}[-\s]+\d+|20\d{2}-\d{5})\b", query, re.I):
        return None
    if not (requested := _faa_certification_models(query)):
        return None

    issuance = re.compile(
        r"\b(?:issued|granted|approved)\b.{0,90}\b(?:amended\s+)?type\s+certificat\w*\b|"
        r"\b(?:amended\s+)?type\s+certificat\w*\b.{0,90}\b(?:issued|granted|approved)\b|"
        r"\b(?:FAA|Federal Aviation Administration)\b.{0,90}\bcertif(?:ied|ies)\b|"
        r"\b(?:certification|type\s+approval)\b.{0,70}\b(?:completed|granted|approved|issued)\b|"
        r"\b(?:completed|granted|approved|issued)\b.{0,70}\b(?:certification|type\s+approval)\b", re.I,
    )
    negated = re.compile(r"\b(?:not|never|without|pending|expected|planned|proposed|awaiting|denied|revoked|suspended)\b.{0,55}\b(?:issued|granted|approved|certif\w*|type\s+certificate)\b", re.I)

    for doc in sorted(docs, key=lambda d: str(d.get("published_at") or ""), reverse=True):
        url = urlparse(str(doc.get("url") or ""))
        pub = str(doc.get("published_at") or "")
        if (url.scheme != "https" or url.hostname not in {"faa.gov", "www.faa.gov"} or not re.fullmatch(
                r"/newsroom/[a-z0-9-]+/?", url.path, re.I)
                or doc.get("source_id") not in {"SRC_001", "SRC_004"} or (
                        doc.get("source_id") == "SRC_004" and doc.get("verified_domain") is not True)
                or doc.get("content_status") not in {"FULL_TEXT", "FULL_TEXT_RETRIEVED"} or doc.get(
                    "content_truncated") is True or _is_snippet_only(doc)
                or not re.fullmatch(r"20\d{2}-\d{2}-\d{2}", pub) or not _date_str(pub)
                or (after_date and pub <= after_date) or (as_of_date and pub > as_of_date)):
            continue
        title, body = str(doc.get("title") or ""), str(doc.get("text") or "")
        if not requested.issubset(_faa_certification_models(body)):
            continue
        title_models = _faa_certification_models(title)
        for sent in re.split(r"(?<=[.!?])\s+|\n+", body):
            if not issuance.search(sent) or negated.search(sent):
                continue
            stated = _faa_certification_models(sent)
            if requested.issubset(stated) or (not stated and requested.issubset(title_models) and issuance.search(title)):
                return {**doc, "matched_models": sorted(requested), "verified_quote": sent.strip()}
    return None

_official_faa_certification_for_kiq = find_official_faa_certification

def _plan_queries(plan: KIQPlan) -> List[str]:
    """Collect deduplicated non-empty retrieval queries from a KIQPlan."""
    raw = [*(plan.media_and_pr_queries or []), *(plan.regulatory_and_ntsb_queries or []), *(plan.social_and_video_queries or []), plan.airshow_query]
    return list(dict.fromkeys(q.strip() for q in raw if isinstance(q, str) and q.strip()))


def _runtime_questions(user_query: str, plan: KIQPlan) -> List[Dict[str, Any]]:
    """Derive information requirements from the KIT, independently of connectors."""
    planned = []
    req_models = _detect_exact_variants(user_query) | _detect_engine_models(user_query)
    allowed_models = set(req_models)
    if re.search(r"\b(?:engine|engines|propulsion|turbine|gtf|leap)\b", user_query, re.I) and not _detect_engine_models(user_query):
        allowed_models |= _detect_engine_models(" ".join(get_program_engine_domain(user_query)["engine_models"]))

    plan_identities = list(dict.fromkeys(str(v).strip() for v in getattr(plan, "required_identity", []) or [] if v and _norm_q(v) in _norm_q(user_query)))
    user_req_keys = {s["key"] for s in _required_evidence_specs(user_query)}

    for req in getattr(plan, "information_requirements", []) or []:
        question = str(getattr(req, "question", "") or "").strip()
        if not question:
            continue
        q_models = _detect_exact_variants(question) | _detect_engine_models(question)
        if q_models and (not allowed_models or not q_models.issubset(allowed_models)):
            continue
        req_ids = list(dict.fromkeys(str(v).strip() for v in getattr(req, "required_identity", []) or [] if v and _norm_q(v) in _norm_q(user_query))) or plan_identities
        filt_ids = [v for v in req_ids if _norm_q(v) not in _norm_q(question) and (not q_models or not (_detect_exact_variants(v) - q_models))]
        query = " ".join([question, *filt_ids]).strip()
        scoped_models = _detect_exact_variants(query) | _detect_engine_models(query)
        if scoped_models and (not allowed_models or not scoped_models.issubset(allowed_models)):
            continue
        if req_models and not (scoped_models & req_models):
            query = f"{query} {user_query}"
        keys = {s["key"] for s in _required_evidence_specs(query)}
        purposes = {getattr(p, "value", p) for p in getattr(req, "search_purposes", []) or []}
        for p_flag, extra_keys in (("CAUSE", {"CAUSAL_LINK"}), ("CURRENT_STATUS", {"CURRENT_STATUS"}), ("RESOLUTION", {"RESOLUTION_EVIDENCE"}), ("IMPACT", {"PRODUCTION_IMPACT", "DELIVERY_IMPACT"} & user_req_keys)):
            if p_flag in purposes:
                keys |= extra_keys
        planned.append({"query": query, "keys": keys, "question": question})

    if planned:
        # Merge any uncovered explicit requirement keys into the first planned question
        # instead of spawning an extra broad fallback KIQ that dilutes answerability.
        covered = set().union(*(i["keys"] for i in planned))
        if uncovered := user_req_keys - covered:
            planned[0]["keys"] = set(planned[0]["keys"]) | uncovered
        return list({(_norm_q(i["question"]), tuple(sorted(i["keys"]))): i for i in planned}.values())

    seeds = [user_query.strip()] if user_query and user_query.strip() else _plan_queries(plan)
    result = []
    partitions = (
        ("Current status", {"CURRENT_STATUS", "RESOLUTION_EVIDENCE"}),
        ("Historical development", {"HISTORICAL_DELAY", "STATUS_CHANGE"}),
        ("Established cause", {"CAUSAL_LINK"}),
        ("Consequences", {"PRODUCTION_IMPACT", "DELIVERY_IMPACT", "REMAINING_IMPACT"}),
    )
    for query in dict.fromkeys(seeds):
        keys = {s["key"] for s in _required_evidence_specs(query)}
        app = keys & {"PROGRAM_APPLICABILITY"}
        assigned, groups = set(), []
        for label, wanted in partitions:
            if inc := keys & wanted:
                groups.append((label, inc | app))
                assigned |= inc
        if rem := keys - assigned - app:
            groups.append(("Documented facts", rem | app))
        for label, subset in (groups or [("Requested evidence", keys)]):
            result.append({"query": query, "keys": subset, "question": f"{label} for: {query}?"})
    return result


def _date_str(value: Any) -> str:
    """Parse an ISO YYYY-MM-DD prefix into a canonical date string, or empty string."""
    try:
        parsed = date.fromisoformat(str(value or "")[:10])
        return parsed.isoformat() if parsed.year >= 1900 else ""
    except (ValueError, TypeError):
        return ""


def _as_of_date(query: str) -> str:
    """Read an explicit point-in-time cutoff from the question, not arbitrary dates."""
    marker = r"\b(?:as\s+of|as\s+at|status\s+(?:on|at)|ke\s+dni|k\s+datu|stav\s+k|k)\s+"
    if m := re.search(marker + r"(20\d{2}-\d{2}-\d{2})\b", query, re.I):
        return _date_str(m[1])
    dmy = re.search(marker + r"(\d{1,2})\.?(?:\s+)([\wá-ž]+)\s+(20\d{2})", query, re.I)
    mdy = re.search(marker + r"([a-z]+)\s+(\d{1,2}),?\s+(20\d{2})", query, re.I)
    parts = (dmy[1], dmy[2], dmy[3]) if dmy else ((mdy[2], mdy[1], mdy[3]) if mdy else None)
    if parts and parts[1].lower() in _MONTHS_BILINGUAL:
        return _date_str(f"{parts[2]}-{_MONTHS_BILINGUAL[parts[1].lower()]:02d}-{int(parts[0]):02d}")
    return ""


def _published_date(doc: Dict[str, Any]) -> str:
    """Return the normalized publication date from standard document date fields."""
    return _date_str(doc.get("published_at") or doc.get("publication_time") or doc.get("publication_date"))


def _date_mentioned(text: str, value: Any) -> bool:
    """Return True if value's ISO or English long-form date appears in text."""
    if not (stamp := _date_str(value)):
        return False
    day = date.fromisoformat(stamp)
    low = str(text or "").casefold()
    return any(tok.casefold() in low for tok in (stamp, f"{day.strftime('%B')} {day.day}, {day.year}", f"{day.day} {day.strftime('%B')} {day.year}"))


def _available_as_of(doc: Dict[str, Any], cutoff: str) -> bool:
    """Verify a document was published (and its event occurred) on or before the cutoff."""
    pub, ev = _published_date(doc), _date_str(doc.get("event_date"))
    return not cutoff or bool(pub and pub <= cutoff and (not ev or ev <= cutoff))


def _named_subjects(query: str) -> set[str]:
    """Extract capitalized non-generic subject names from the positive query scope."""
    positive = _EXCLUSION_SPLIT_RE.split(str(query or ""), maxsplit=1)[0]
    return set(re.findall(r"\b[A-Z][a-z]{2,}(?:(?:\s*&\s*|-)[A-Z][a-z]{2,})?\b", positive)) - _NAMED_SUBJECT_STOPWORDS


def _issuer_matches_query(query: str, doc: Dict[str, Any]) -> bool:
    """Ensure a corporate disclosure belongs to an entity or product OEM named in the query."""
    issuer = str(next((doc[k] for k in ("sec_company", "issuer_name", "issuer", "company") if doc.get(k)), ""))
    if not issuer:
        return False
    core = set(_WORD_RE.findall(_norm_q(issuer))) - {"company", "corporation", "incorporated", "holding", "holdings", "group", "aerospace"}
    subjects = _named_subjects(query)
    if not subjects or any(_norm_q(s) in core for s in subjects):
        return True
    # Also accept an issuer when the query explicitly requests its engine/program (e.g. GE9X -> GE Aerospace).
    from ews_state import lookup_supplier_in_registry
    reg = lookup_supplier_in_registry(issuer, exact=False)
    if reg:
        q_models = _kiq_exact_variants(query) | _kiq_engine_models(query)
        reg_text = " ".join([reg.get("official_name", ""), *(reg.get("aliases") or []), *(reg.get("components") or [])])
        if q_models and (q_models & (_kiq_exact_variants(reg_text) | _kiq_engine_models(reg_text))):
            return True
    return False


def _scope_matches(
    query: str, passage: str, doc: Dict[str, Any], passage_meta: Optional[Dict[str, Any]] = None,
) -> bool:
    """Ground issuer in source metadata while verifying aircraft/engine in the local passage."""
    meta = passage_meta or {}
    identity = " ".join(str(doc.get(k) or "") for k in ("sec_company", "sec_cik", "sec_ticker", "issuer", "issuer_name", "company", "company_name", "ticker", "cik", "evidence_authority"))
    reference = " ".join(str(d.get(k) or "") for d in (doc, meta) for k in ("docket_id", "document_number", "url"))
    section = " ".join(str(d.get(k) or "") for d, ks in ((doc, ("section",)), (meta, ("section", "heading", "program", "affected_program", "component"))) for k in ks)

    ref_ids = re.findall(r"\bFAA-\d{4}-\d+\b|\b20\d{2}-\d{5}\b|\b20\d{2}-\d{4}-[A-Z]\b", query, re.I)
    if ref_ids and not all(re.search(re.escape(v), passage + " " + reference, re.I) for v in ref_ids):
        return False

    pos_q = _EXCLUSION_SPLIT_RE.split(str(query or ""), maxsplit=1)[0]
    pos_q = re.sub(r"^Remaining\s+explicitly\s+requested\s+facts\s*:\s*", "", pos_q, flags=re.I)
    doc_title = str(doc.get("title") or "")
    p_sec = f"{passage} {section}"
    p_ctx = f"{doc_title} {p_sec}"
    requested, local = _kiq_exact_variants(pos_q), _kiq_exact_variants(passage)
    families, local_fam = _kiq_aircraft_families(pos_q), _kiq_aircraft_families(p_ctx)
    engines, local_eng = _kiq_engine_models(pos_q), _kiq_engine_models(passage)
    if (requested and local and not (requested & local)) or (
            engines and local_eng and not _engine_models_match(pos_q, passage)):
        return False

    var_hit = bool(requested and (requested & (local | _kiq_exact_variants(f"{doc_title} {section}"))))
    fam_hit = bool(families and (families & local_fam))
    eng_hit = bool(engines and _engine_models_match(pos_q, p_ctx))
    airframe_req = bool(requested or families)
    airframe_hit = var_hit if requested else fam_hit
    if (airframe_req and engines and not (airframe_hit or eng_hit)) or (requested and not engines and not var_hit) or (
            engines and not airframe_req and not eng_hit):
        return False
    if any(re.search(pat, pos_q, re.I) and not re.search(pat, p_ctx, re.I) for name, pat in _COMPONENT_PATTERNS.items()
           if name != "ENGINE"):
        return False

    named = _named_subjects(pos_q)
    if airframe_req or engines:
        named -= {"Airbus", "Boeing", "Embraer", "COMAC", "Pratt & Whitney", "Safran", "Rolls-Royce", "Alaska"}
    return not named or any(re.search(rf"\b{re.escape(n)}\b", f"{p_ctx} {identity}", re.I) for n in named)


def _topic_matches(query: str, passage: str) -> bool:
    """Verify topical overlap between query lifecycle/order concepts and a passage."""
    topics, order_req = _lifecycle_topics(query), bool(_ORDER_TOPIC_RE.search(query))
    if topics or order_req:
        return any(re.search(_LIFECYCLE_TOPICS[t], passage, re.I) for t in topics) or (order_req and bool(_ORDER_TOPIC_RE.search(passage)))
    words = set(_WORD_RE.findall(_norm_q(query))) - _QUERY_STOPWORDS
    return not words or bool(words & set(_WORD_RE.findall(_norm_q(passage))))


def _is_forecast(text: str, query: str) -> bool:
    """Detect forward-looking expectations so plans are not treated as completed milestones."""
    topic = _LIFECYCLE_TOPICS["CERTIFICATION"] if "CERTIFICATION" in _lifecycle_topics(query) else r"\b(?:production|deliver\w*|suppl\w*|operations?)\b"
    exp = r"\b(?:expect\w*|anticipat\w*|forecast\w*|intend\w*|plan\w*|target\w*|project\w*|slat\w*|due)\b"
    fut = r"\b(?:will\s+(?:be\s+)?(?:certif\w*|complet\w*|receiv\w*|obtain\w*|approv\w*)|may\s+be\s+certif\w*)\b"
    return bool(re.search(
        rf"{exp}.{{0,90}}{topic}|{fut}.{{0,65}}{topic}|{topic}.{{0,35}}(?:(?:is|was|are|were|remains)\s+)?{exp}(?=\s+(?:to|by|for))|"
        rf"{topic}.{{0,55}}(?:{fut}|\bwill\s+be\b)|{topic}.{{0,45}}\b(?:is|are|was)\s+expected\s+(?:next\b|in\b|by\b|during\b|later\b|soon\b)",
        text, re.I,
    ))


def _filing_passage_assessment(doc: Dict[str, Any], meta: Dict[str, Any], excerpt: str) -> tuple[str, str]:
    """Validate SEC/ESEF excerpt provenance; missing cryptographic proof remains preliminary."""
    if not excerpt.strip() or doc.get("source_id") not in {"SRC_027", "SRC_031"}:
        return "UNVERIFIED", "SOURCE_OR_PASSAGE_MISSING"
    if doc["source_id"] == "SRC_027":
        return assess_source_passage(doc, meta, excerpt=excerpt)
    if doc.get("evidence_verified") is False or meta.get("issuer_identity_verified") is False:
        return "UNVERIFIED", "PRODUCER_REJECTED_EVIDENCE"

    locator = str(doc.get("evidence_url") or doc.get("source_url") or doc.get("url") or "")
    a, b, orig = urlsplit(locator), urlsplit(str(meta.get("source_url") or locator)), urlsplit(str(doc.get("sec_filing_url") or meta.get("original_filing_url") or locator))
    if a.scheme != "https" or not a.hostname or b._replace(fragment="") != a._replace(fragment="") or any((a.username, a.password, orig.username, orig.password)):
        return "UNVERIFIED", "SOURCE_URL_MISMATCH"

    issuer = str(doc.get("issuer_name") or doc.get("sec_company") or doc.get("issuer") or "")
    if not issuer or _norm_q(issuer) != _norm_q(str(meta.get("issuer_name") or meta.get("issuer") or issuer)):
        return "UNVERIFIED", "ISSUER_IDENTITY_MISMATCH"
    if not (doc.get("verified_domain") is True and (doc.get("lei") or doc.get("issuer_lei") or doc.get("registration_id"))):
        return "UNVERIFIED", "ESEF_ISSUER_NOT_VERIFIED"

    method = str(meta.get("extraction_method") or meta.get("offset_basis") or doc.get("extraction_method") or "").upper()
    start, end = meta.get("start"), meta.get("end")
    if method not in (SUPPORTED_EXTRACTION_METHODS | {"NORMALIZED_VISIBLE_TEXT", "FULL_TEXT", "HTML_VISIBLE_TEXT"}) or not isinstance(start, int) or not isinstance(end, int) or start < 0 or end <= start or end - start < len(excerpt.strip()):
        return "UNVERIFIED", "EXTRACTION_PROVENANCE_MISSING"

    src_hash, lnk_hash = str(doc.get("source_content_sha256") or "").lower(), str(meta.get("source_content_sha256") or "").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", src_hash) or src_hash != lnk_hash:
        return "UNVERIFIED", "SOURCE_HASH_MISMATCH_OR_MISSING"

    q_hash = str(meta.get("passage_sha256") or meta.get("excerpt_sha256") or "").lower()
    raw = doc.get("source_content_bytes") or doc.get("source_raw_bytes")
    if isinstance(raw, bytes):
        if hashlib.sha256(raw).hexdigest() != src_hash:
            return "UNVERIFIED", "SOURCE_HASH_MISMATCH"
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(raw, "html.parser")
        for node in soup(["script", "style", "nav", "footer", "noscript"]):
            node.decompose()
        if re.sub(r"\s+", " ", soup.get_text(" ", strip=True)).strip()[start:end].strip() != re.sub(r"\s+", " ", excerpt).strip():
            return "UNVERIFIED", "PASSAGE_NOT_IN_VERIFIED_SOURCE"
        return "VERIFIED", "FULL_SOURCE_AND_OFFSETS_VERIFIED"
    if q_hash and q_hash != _sha256_text(excerpt):
        return "UNVERIFIED", "PASSAGE_HASH_MISMATCH"
    if q_hash and meta.get("validated") is True and doc.get("evidence_verified") is True:
        return "VERIFIED", "TRUSTED_PRODUCER_PASSAGE_HASH"
    return "PRELIMINARY", "PASSAGE_HASH_OR_SOURCE_BYTES_NOT_AVAILABLE"


def _verified_filing_passage(doc: Dict[str, Any], meta: Dict[str, Any], excerpt: str) -> bool:
    """Return True only when a filing passage passes full provenance verification."""
    return _filing_passage_assessment(doc, meta, excerpt)[0] == "VERIFIED"


def _fr03_semantic_passages(query: str, doc: Dict[str, Any], rejected: Dict[str, str]) -> List[tuple[str, Dict[str, Any], str, str, str]]:
    """Use verified FR03 quotations without upgrading their evidentiary truth status."""
    did, source, locator = str(doc.get("doc_id") or ""), str(doc.get("source_id") or ""), str(doc.get("url") or doc.get("source_url") or "")
    parsed = urlsplit(locator)
    candidates = doc.get("semantic_relevant_claims") or []
    if not isinstance(candidates, (list, tuple)):
        rejected[did] = "FR03_CLAIM_STRUCTURE_INVALID"
        return []
    if not did or not source or parsed.scheme not in {"https", "http"} or not parsed.hostname:
        if candidates:
            rejected[did] = "MISSING_SOURCE_ID_OR_URL"
        return []

    results, seen = [], set()
    for item in candidates[:12]:
        if not isinstance(item, dict) or item.get("evidence_validated") is not True:
            rejected.setdefault(did, "FR03_QUOTATION_NOT_VERIFIED")
            continue
        excerpt = " ".join(str(item.get("evidence_excerpt") or "").split())
        excerpt = re.sub(
            r"^(?:SOURCE-MATCHED\s+ISSUER\s+CLAIMS\s*\([^)]*\)\s*:\s*)?(?:\[E\d+\s+[A-Z_]+(?:\s+offset=\d+)?\]\s*)+",
            "", excerpt, flags=re.I,
        ).strip()
        if len(excerpt) < 25 or excerpt.casefold() in seen:
            continue
        seen.add(excerpt.casefold())
        claimed_url = str(item.get("source_url") or "")
        if claimed_url and claimed_url.rstrip("/") != locator.rstrip("/"):
            rejected.setdefault(did, "FR03_SOURCE_URL_MISMATCH")
            continue
        if not _scope_matches(query, excerpt, doc, item):
            rejected.setdefault(did, "SCOPE_MISMATCH")
            continue
        if not _topic_matches(query, excerpt):
            rejected.setdefault(did, "NO_MATCHING_INFORMATION_REQUIREMENT")
            continue
        if source in _SOURCE_GROUPS["FIN"][0]:
            if not _issuer_matches_query(query, doc):
                rejected.setdefault(did, "ISSUER_IDENTITY_MISMATCH")
                continue
            if not any(excerpt.casefold() in " ".join(sq.split()).casefold() and _filing_passage_assessment(doc, md, sq)[0] in {"VERIFIED", "PRELIMINARY"} for md, sq in _iter_raw_passages(doc)):
                rejected.setdefault(did, "ISSUER_PASSAGE_VALIDATION_FAILED")
                continue
        results.append((
            excerpt,
            {
                "claim_id": str(item.get("claim_id") or ""), "claim_type": str(item.get("claim_type") or "OBSERVED"),
                "event_date": item.get("event_at") or doc.get("event_date"), "source_url": locator, "source_id": source,
                "issuer_name": str(doc.get("issuer_name") or doc.get("sec_company") or ""),
                "issuer_cik": str(doc.get("issuer_cik") or doc.get("sec_cik") or ""),
                "original_filing_url": str(doc.get("sec_filing_url") or locator),
                "source_content_sha256": str(doc.get("source_content_sha256") or ""),
                "passage_sha256": _sha256_text(excerpt),
                "section": str(item.get("section") or doc.get("section") or ""),
                "extraction_method": "FR03_SEMANTIC_QUOTATION", "evidence_validated": True,
            },
            "PRELIMINARY", "FR03_SOURCE_QUOTATION_VERIFIED", "QUOTE_VERIFIED_EVENT_UNCONFIRMED",
        ))
    if results:
        rejected.pop(did, None)
    return results


def _document_claims(
    query: str, docs: List[Dict[str, Any]], approved: Optional[set[str]],
    kiq_id: str = "", rejected: Optional[Dict[str, str]] = None, required_keys: Optional[set[str]] = None,
) -> List[Dict[str, Any]]:
    """Ground individually dated claims in FR03-eligible full text or SEC/ESEF excerpts."""
    claims = []
    rejected = rejected if rejected is not None else {}
    keys = {s["key"] for s in _required_evidence_specs(query)} | set(required_keys or ())
    substantive_keys = keys - {"PROGRAM_APPLICABILITY", "EVENT_EXISTENCE", "ISSUER_STATEMENT", "REGULATOR_DECISION", "SOURCE_PROVENANCE"}
    req_component = next((name for name, pat in _COMPONENT_PATTERNS.items() if re.search(pat, query, re.I)), "")
    cutoff = _as_of_date(query)

    for doc in docs:
        doc_id = doc.get("doc_id")
        if not doc_id or (approved is not None and doc_id not in approved) or not _available_as_of(doc, cutoff):
            continue
        status, source = str(doc.get("content_status") or "").upper(), doc.get("source_id")
        body_len = len(str(doc.get("text") or "").strip())
        restricted = status in (_NON_FULL_TEXT - {"METADATA_ONLY", "SUMMARY_ONLY", "TRUNCATED"})
        substantive = (
                not restricted
                and status in {"FULL_TEXT", "FULL_TEXT_RETRIEVED", "PARTIAL_TEXT"}
                and body_len >= 300
                and "[NEWSAPI_METADATA_ONLY:" not in str(doc.get("text") or "")
                and "[EXA_METADATA_ONLY]" not in str(doc.get("text") or "")
        )
        full = substantive or (status in {"FULL_TEXT", "FULL_TEXT_RETRIEVED"} and doc.get(
            "content_truncated") is not True and not _is_snippet_only(doc))
        is_official_web = bool(
            doc.get("verified_domain") is True and str(doc.get("origin_type") or "").startswith("PRIMARY"))
        primary = source in _PRIMARY_SOURCES or (source in {"SRC_005", "SRC_030", "SRC_EXA"} and is_official_web)
        authority = (
            "ISSUER_DISCLOSURE" if source in _SOURCE_GROUPS["FIN"][0]
            else "REGULATOR" if (
                        source in _SOURCE_GROUPS["REG"][0] or doc.get("evidence_authority") == "REGULATOR_OFFICIAL_WEB")
            else "ISSUER_RELEASE" if (source in {"SRC_005", "SRC_030", "SRC_EXA"} and is_official_web)
            else "SECONDARY"
        )
        published = _published_date(doc)
        issuer_ok = _issuer_matches_query(query, doc) if authority == "ISSUER_DISCLOSURE" else False

        passages = []
        if source in _SOURCE_GROUPS["FIN"][0] and not restricted:
            for meta, excerpt in _iter_raw_passages(doc):
                if meta.get("validated") is False or meta.get("is_validated") is False or str(meta.get("verification_status") or "").upper() in {"REJECTED", "INVALID", "UNSUPPORTED", "FAILED", "MISMATCH"}:
                    continue
                if len(excerpt.strip()) >= 25:
                    verdict, why = _filing_passage_assessment(doc, meta, excerpt)
                    passages.append((excerpt, meta, "VERIFIED" if approved is not None and verdict == "VERIFIED" else "PRELIMINARY", why, verdict))
        passages.extend(_fr03_semantic_passages(query, doc, rejected))
        if full and not restricted and len(str(doc.get("text") or "").strip()) >= 70 and not (source in _SOURCE_GROUPS["FIN"][0] and passages):
            body = str(doc["text"])
            verified = approved is not None and (_verified_filing_passage(doc, {}, body) if source in _SOURCE_GROUPS["FIN"][0] else primary)
            passages.append((body, {}, "VERIFIED" if verified else "PRELIMINARY", "FULL_SOURCE_VERIFIED" if verified else "SOURCE_VALIDATION_PENDING", "VERIFIED" if verified else "PRELIMINARY"))

        count, seen = 0, set()
        for body, meta, p_strength, v_reason, p_verdict in passages:
            for paragraph in re.split(r"\n\s*\n", body):
                sentences = re.split(r"(?<=[.!?])\s+|\n+", paragraph)
                for i, raw_s in enumerate(sentences):
                    sent = raw_s.strip()
                    if len(sent) < 25 or not _topic_matches(query, sent):
                        continue
                    prev = sentences[i - 1].strip() if i else ""
                    if len(prev) > 220:
                        prev = re.sub(r"^\S*\s+", "", prev[-220:]).strip()
                    passage = (prev + " " + sent[:700]).strip()
                    if not _scope_matches(query, passage, doc, meta):
                        continue
                    raw_forecast = _is_forecast(sent, query)
                    has_occurred_fact = bool(re.search(
                        r"\b(?:started|began|delivered|shipped|carried\s+out|conducted|completed|logged|"
                        r"confirmed|reported|issued|superseding|handed\s+over|fell\s+short|faces|slowed|"
                        r"invested|investing|is\s+upgrading|has\s+said)\b",
                        sent, re.I,
                    ))
                    forecast = raw_forecast and not has_occurred_fact
                    state = "STATUS_UNKNOWN" if forecast else _issue_state(sent, query)
                    fact = not forecast and (
                        any(_proof_matches(k, passage, query, req_component) for k in substantive_keys)
                        or ("ISSUER_STATEMENT" in keys and issuer_ok)
                        or (not substantive_keys and (_proof_matches("PROGRAM_APPLICABILITY", passage, query, req_component) or _topic_matches(query, sent)))
                    )
                    if state == "STATUS_UNKNOWN" and not fact and not forecast:
                        continue
                    event = _date_str(meta.get("event_date") or meta.get("occurrence_date") or doc.get("event_date"))
                    if (cutoff and event and event > cutoff) or (stamp := (sent.lower(), event or published)) in seen:
                        continue
                    seen.add(stamp)
                    pub_year = int(published[:4]) if len(published) >= 4 and published[:4].isdigit() else 0
                    past_years = [int(y) for y in
                                  re.findall(r"\b(?:in|since|from)\s+(?:[A-Za-z]+\s+)?(20\d{2})\b", sent, re.I)]
                    is_old_year_recap = bool(pub_year and past_years and max(past_years) <= pub_year - 2)
                    claims.append({
                        "doc_id": doc_id, "kiq_id": kiq_id, "state": state, "claim_state": state, "claim_authority": authority,
                        "claim_id": str(meta.get("claim_id") or ""), "text": passage, "quote": body if meta else sent[:500],
                        "issuer_name": str(meta.get("issuer_name") or doc.get("issuer_name") or ""),
                        "issuer_cik": str(meta.get("issuer_cik") or doc.get("issuer_cik") or ""),
                        "original_filing_url": str(meta.get("original_filing_url") or doc.get("sec_filing_url") or ""),
                        "extraction_method": str(meta.get("extraction_method") or ""),
                        "passage_validation_status": "PASSAGE_VERIFIED" if p_verdict == "VERIFIED" else p_verdict,
                        "kit_id": str(meta.get("kit_id") or ""), "date": event or published, "event_date": event,
                        "publication_date": published, "date_basis": "EVENT_DATE" if event else "PUBLICATION_DATE_ONLY",
                        "historical": bool(
                            is_old_year_recap
                            or (re.search(r"\b(?:previously|formerly|historically|earlier|prior\s+to|had\s+been|last\s+(?:year|quarter)|dříve|předtím)\b", sent, re.I) and state != "ISSUE_RESOLVED")
                        ),
                        "strength": p_strength, "source_id": source, "authority": authority,
                        "claim_type": "FORECAST" if forecast else str(meta.get("claim_type") or "OBSERVED"),
                        "issuer_matches_query": issuer_ok, "section": str(meta.get("section") or doc.get("section") or ""),
                        "source_url": str(meta.get("source_url") or doc.get("source_url") or doc.get("url") or ""),
                        "source_hash": str(meta.get("source_content_sha256") or ""),
                        "passage_hash": str(meta.get("passage_sha256") or _sha256_text(body)),
                        "verification_reason": v_reason,
                    })
                    count += 1
                    if count >= 12:
                        break
                if count >= 12:
                    break
            if count >= 12:
                break
    return claims


def _threat_claims(query: str, threats: List[ThreatAssessment], docs: Dict[str, Dict[str, Any]]) -> tuple[List[ThreatAssessment], List[Dict[str, Any]]]:
    """Project grounded ThreatAssessment objects into dated atomic claim records."""
    matched, claims = [], []
    for t in threats:
        text = " ".join(str(v or "") for v in (t.fact_check_quote, t.confirmed_facts, t.affected_program, t.company_affected))
        ids = {i for i in (t.evidence_ids or []) if i in docs}
        if not (ids and t.technical_grounding_status == "PASS" and t.validation_status in {ValidationStatus.SUPPORTED, ValidationStatus.PARTIALLY_SUPPORTED} and _scope_matches(query, text, {}) and _topic_matches(query, text)):
            continue
        matched.append(t)
        verified = t.validation_status == ValidationStatus.SUPPORTED and t.program_relevance == "DIRECT_KIT_MATCH" and t.claim_support_status == "STATED_IN_SOURCE"
        claim = str(t.confirmed_facts or t.fact_check_quote or "")
        fresh = getattr(getattr(t, "event_freshness", None), "value", getattr(t, "event_freshness", None)) == "HISTORICAL_CONTEXT"
        for did in sorted(ids):
            ev_d = _date_str(docs[did].get("event_date"))
            claims.append({
                "doc_id": did, "text": claim, "state": _issue_state(claim, query),
                "date": _date_str(docs[did].get("event_date") or docs[did].get("published_at") or getattr(t, "publication_time", "")),
                "event_date": ev_d, "publication_date": _published_date(docs[did]),
                "date_basis": "EVENT_DATE" if ev_d else "PUBLICATION_DATE_ONLY", "historical": fresh,
                "strength": "VERIFIED" if verified else "PRELIMINARY", "source_id": docs[did].get("source_id"),
                "authority": "ANALYST_ASSESSMENT", "source_url": str(docs[did].get("source_url") or docs[did].get("url") or ""),
                "verification_reason": "ANALYST_EVENT_VALIDATION" if verified else "EVENT_NOT_FULLY_VALIDATED",
            })
    return matched, claims


def _content_result(claims: List[Dict[str, Any]], searched: bool, query: str) -> str:
    """Summarize the latest non-historical claim status across contributing evidence."""
    cutoff = _as_of_date(query)
    dated = sorted((c for c in claims if c.get("state") != "STATUS_UNKNOWN" and c.get("date") and not c.get("historical")
                    and (not cutoff or (c.get("publication_date") and c["publication_date"] <= cutoff and c["date"] <= cutoff))),
                   key=lambda c: c["date"], reverse=True)
    if not dated:
        return "STATUS_UNKNOWN" if claims or not searched else "NO_RELEVANT_EVENT"
    latest = [c for c in dated if c["date"] == dated[0]["date"]]
    if len({c["state"] for c in latest}) != 1:
        return "STATUS_CONFLICTED"
    state = latest[0]["state"]
    if any(_claim_strength("CURRENT_STATUS", c, query) == "VERIFIED" for c in latest):
        return state
    return state.replace("ISSUE_", "ISSUE_REPORTED_", 1) if state.startswith("ISSUE_") else state


def _claim_fingerprint(claim: Dict[str, Any]) -> str:
    """Hash normalized claim text so repeated quotes count as one piece of evidence."""
    return _sha256_text(re.sub(r"\s+", " ", str(claim.get("text") or "")).strip().casefold())


def _dedupe_claims(claims: List[Dict[str, Any]]) -> tuple[List[Dict[str, Any]], set[str]]:
    """Deduplicate identical dated claims, prioritizing VERIFIED provenance."""
    seen, retained, dup_ids = {}, [], set()
    for claim in sorted(claims, key=lambda c: c.get("strength") == "VERIFIED", reverse=True):
        sig = (_claim_fingerprint(claim), claim.get("date"))
        if sig in seen:
            if claim["doc_id"] != seen[sig]:
                dup_ids.add(claim["doc_id"])
            continue
        seen[sig] = claim["doc_id"]
        retained.append(claim)
    return retained, dup_ids


def _document_dispositions(
    query: str, docs: List[Dict[str, Any]], approved: Optional[set[str]], cutoff: str,
    used_ids: set[str], claims: List[Dict[str, Any]], duplicates: set[str],
    rejected_claims: Optional[Dict[str, str]] = None,
) -> Dict[str, str]:
    """Record the reason each retrieved document did not support this particular KIQ."""
    candidates = {c["doc_id"] for c in claims}
    preliminary = {c["doc_id"] for c in claims if c.get("strength") != "VERIFIED"}
    reasons = {}
    for idx, doc in enumerate(docs):
        did = str(doc.get("doc_id") or f"MISSING_DOC_ID_{idx + 1}")
        if did in used_ids:
            continue
        reasons[did] = (
            "FR03_REJECTED_OR_NOT_APPROVED" if approved is not None and did not in approved
            else "OUTSIDE_AS_OF_DATE" if not _available_as_of(doc, cutoff)
            else str(rejected_claims[did]) if did in (rejected_claims or {}) and did not in candidates
            else "DUPLICATE_CLAIM" if did in duplicates
            else "CLAIM_NOT_VERIFIED" if did in preliminary
            else "NO_MATCHING_REQUIREMENT" if did in candidates
            else "CLAIM_NOT_VERIFIED" if str(doc.get("content_status") or "").upper() in (_NON_FULL_TEXT | {"PARTIAL_TEXT"})
            else "RELATED_CONTEXT_ONLY" if _topic_matches(query, f"{doc.get('title') or ''} {doc.get('text') or ''}")
            else "NO_MATCHING_REQUIREMENT"
        )
    return reasons


def _compose_kiq_answer_text(
    cutoff: str, content_result: str, answer_status: str, regulator_facts: List[Dict[str, Any]],
    contributing_claims: List[Dict[str, Any]], verified: List[Dict[str, Any]], missing: List[Dict[str, Any]],
    evidence_ids: List[str], evaluated_count: int,
) -> str:
    """Format a readable, source-cited natural-language answer for a runtime KIQ."""
    dangling_tail = re.compile(
        r"\b(?:in\s+the|of\s+the|for\s+the|to\s+the|on\s+the|with\s+the|by\s+the|from\s+the|"
        r"the|a|an|in|of|for|to|on|with|by|from|and|or|that|which)\s*$",
        re.I,
    )

    def _clean(raw: str, limit: int = 230) -> str:
        c = " ".join(str(raw or "").split()).strip().lstrip("#").strip()
        c = re.sub(r"^(?:SEC\s+EDGAR\s+OFFICIAL\s+FILING\..*?)?(?:Accession\s+number:\s*[\d-]+\.\s*)?", "", c, flags=re.I)
        c = re.sub(r"^(?:SOURCE-MATCHED\s+ISSUER\s+CLAIMS\s*\([^)]*\)\s*:\s*)?(?:\[E\d+\s+[A-Z_]+(?:\s+offset=\d+)?\]\s*)+", "", c, flags=re.I)
        c = re.sub(r"^(?:Definitions:|Reason:|Official Summary:)\s*", "", c, flags=re.I).strip()
        if len(c) <= limit:
            trimmed = c.rstrip(" ;,")
            while len(trimmed) > 35 and dangling_tail.search(trimmed):
                trimmed = trimmed.rsplit(" ", 1)[0].rstrip(" ,;:-")
            return trimmed
        cut = c[:limit].rsplit(" ", 1)[0].rstrip(" .,;:")
        while len(cut) > 35 and dangling_tail.search(cut):
            cut = cut.rsplit(" ", 1)[0].rstrip(" ,;:-")
        return (cut or c[:limit].strip()) + "…"

    def _tokens(text: str) -> set[str]:
        return {
            w for w in re.findall(r"[a-z0-9]{4,}", text.casefold())
            if w not in {"boeing", "ge9x", "777x", "777-9", "engine", "engines", "notes", "that", "with", "from", "this"}
        }

    parts: List[str] = [f"As of {cutoff}:"] if cutoff else []
    fallback_leads = {
        "ANSWERED": "Reviewed primary sources directly address this question.",
        "PARTIALLY_ANSWERED": "Reviewed sources address part of this question, while specific verification items remain open.",
        "NOT_SEARCHED": "This question was not covered by the sources selected for this run.",
    }
    parts.append(_STATUS_PHRASES.get(content_result, fallback_leads.get(answer_status, "No directly matching source passage was found for this question in the current dataset; this does not prove the absence of the issue.")))
    if regulator_facts:
        parts.append(str(regulator_facts[0].get("answer", "")).strip())

    timeline = sorted((c for c in contributing_claims if c.get("date") and c.get("state") != "STATUS_UNKNOWN"),
                      key=lambda c: (c["date"], c.get("publication_date", "")))
    seen_snips: List[str] = []
    seen_token_sets: List[set[str]] = []
    findings = []
    for claim in list(reversed(timeline)) + [c for c in contributing_claims if c not in timeline]:
        snip = _clean(claim.get("quote") or claim.get("text") or "", 220)
        low_snip = snip.casefold()
        toks = _tokens(snip)
        if len(snip) < 25 or any(low_snip[:60] in prev or prev[:60] in low_snip for prev in seen_snips):
            continue
        if toks and any(len(toks & prev_toks) / min(len(toks), len(prev_toks)) >= 0.7 for prev_toks in seen_token_sets):
            continue
        seen_snips.append(low_snip)
        if toks:
            seen_token_sets.append(toks)
        lbl = _AUTHORITY_LABELS.get(str(claim.get("authority") or "").upper(), "reviewed source")
        article = "An" if lbl[:1].lower() in "aeiou" else "A"
        dt = f" on {claim['date']}" if claim.get("date") else ""
        findings.append(f"{article} {lbl}{dt} notes that “{snip}” [{claim['doc_id']}].")
        if len(findings) >= 3:
            break
    if findings:
        parts.append(" ".join(findings))

    if forecasts := list(dict.fromkeys(f"“{_clean(c['text'], 170)}” [{c['doc_id']}]" for c in contributing_claims if c.get("claim_type") == "FORECAST"))[:2]:
        parts.append("Forward-looking expectations (not yet confirmed outcomes): " + "; ".join(forecasts) + ".")

    v_facts, m_facts = [r["required_fact"].lower() for r in verified], [r["required_fact"].lower() for r in missing]
    if v_facts and m_facts:
        parts.append(f"Evidence establishes {', '.join(v_facts[:3])}, whereas {', '.join(m_facts[:3])} still require direct confirmation.")
    elif v_facts:
        parts.append(f"All required points ({', '.join(v_facts[:4])}) are supported by the cited documents.")
    elif m_facts and answer_status != "NOT_SEARCHED":
        parts.append(f"Still needed for a complete answer: {', '.join(m_facts[:3])}.")
    if evidence_ids:
        parts.append(f"Based on {len(evidence_ids)} relevant document(s) ({', '.join(evidence_ids[:5])}) out of {evaluated_count} evaluated.")
    return " ".join(p.strip() for p in parts if p and p.strip())


def build_runtime_kiq_answers(
    report: EWSReport, kiq_plan: KIQPlan, collected_docs: List[Dict[str, Any]],
    selected_platforms: List[str] | None = None, accepted_document_ids: set[str] | None = None,
    user_query: str = "", searched_source_ids: set[str] | None = None,
    connector_telemetry: Optional[Dict[str, Any]] = None,
) -> List[KIQAnswer]:
    """Link every planned question to all eligible evidence, regardless of its platform."""
    connector_telemetry = getattr(report, "connector_status", None) or {} if connector_telemetry is None else connector_telemetry
    approved = accepted_document_ids
    eligible = [d for d in collected_docs if approved is None or d.get("doc_id") in approved]
    selected = {str(v).strip().lower() for v in (selected_platforms or [])}
    enabled_sources = (set().union(*(p[0] for p in _SOURCE_GROUPS.values())) if selected_platforms is None
                       else set().union(*(ids for ids, names in _SOURCE_GROUPS.values() if names & selected))) | {d["source_id"] for d in collected_docs if d.get("source_id")}
    threats = list(report.threats or []) + list(report.related_program_watchlist or [])

    catalog = [a for a in report.kiq_answers if not str(a.kiq_id).startswith("RKIQ_")]
    if approved is not None:
        for ans in catalog:
            ans.evidence_ids = [i for i in (ans.evidence_ids or []) if i in approved]
            if ans.answer_status in {"ANSWERED", "PARTIALLY_ANSWERED"} and not ans.evidence_ids:
                ans.related_event_ids, ans.answer_status, ans.evidence_coverage = [], "UNANSWERED", "NONE"
                ans.answer = "Previously cited evidence was not cleared by FR03."
                ans.verification_status = "FR03 evidence eligibility not established"

    runtime = []
    optional = getattr(KIQAnswer, "model_fields", {})
    for index, item in enumerate(_runtime_questions(user_query, kiq_plan), 1):
        query, required_keys, kiq_id = item["query"], item["keys"], f"RKIQ_{index:03d}"
        cutoff = _as_of_date(query)
        applicable = [d for d in eligible if _available_as_of(d, cutoff)]
        scoped_docs = {d["doc_id"]: d for d in applicable if d.get("doc_id")}
        matched, assessment_claims = _threat_claims(query, threats, scoped_docs)
        claim_rejections: Dict[str, str] = {}
        source_claims = _document_claims(query, applicable, approved, kiq_id, rejected=claim_rejections, required_keys=required_keys)

        official = _official_faa_certification_for_kiq(query, applicable)
        if official and official.get("doc_id") in scoped_docs:
            issued_on = _date_str(official.get("regulatory_decision_date")) if _date_mentioned(official.get("text", ""), official.get("regulatory_decision_date")) else ""
            source_claims.append({
                "doc_id": official["doc_id"], "text": official["verified_quote"], "state": "ISSUE_RESOLVED",
                "date": issued_on or _published_date(official), "event_date": issued_on,
                "publication_date": _published_date(official), "date_basis": "EVENT_DATE" if issued_on else "PUBLICATION_DATE_ONLY",
                "strength": "VERIFIED", "source_id": official.get("source_id"), "authority": "REGULATOR",
                "source_url": str(official.get("url") or ""), "verification_reason": "FAA_PRIMARY_FULL_TEXT",
            })
        else:
            official = None

        regulator_facts = []
        explicit_reg_ids = {m.group().upper() for pat in (_FAA_DOC_NUMBER_RE, _FAA_DOCKET_RE) for m in pat.finditer(query)}
        if ("REGULATORY" in _lifecycle_topics(query) or any(k.startswith(("REGULATORY", "COMPLIANCE", "INSPECTION")) for k in required_keys)
                or ("PROGRAM_APPLICABILITY" in required_keys and re.search(r"\b(?:FAA|airworthiness|directive|regulat\w*)\b", query, re.I))):
            cand_reg_docs = list(applicable)
            if explicit_reg_ids:
                for d in collected_docs:
                    if d.get("source_id") == "SRC_001" and _available_as_of(d, cutoff) and d not in cand_reg_docs:
                        if any(rid in f"{d.get('title') or ''} {d.get('text') or ''} {d.get('url') or ''}".upper() for rid in explicit_reg_ids):
                            cand_reg_docs.append(d)
            for d in cand_reg_docs:
                if d.get("source_id") == "SRC_001" and (fact := _scoped_faa_publication_fact(query, d, cutoff)):
                    regulator_facts.append(fact)
                    source_claims.extend(fact.get("verified_field_claims") or [])

        claims, dup_ids = _dedupe_claims(assessment_claims + source_claims)
        supported = [t for t in matched if t.validation_status == ValidationStatus.SUPPORTED and t.program_relevance == "DIRECT_KIT_MATCH" and t.claim_support_status == "STATED_IN_SOURCE"]
        preliminary = [t for t in matched if t not in supported]

        matched_ids = {c["doc_id"] for c in claims} | {f["document_id"] for f in regulator_facts if f.get("document_id")}
        relevant_raw = {
            str(d["doc_id"]) for d in collected_docs if d.get("doc_id")
            and (str(d["doc_id"]) in matched_ids or (_topic_matches(query, f"{d.get('title') or ''} {d.get('text') or ''}") and _scope_matches(query, str(d.get("text") or ""), d)))
        }
        source_status = _source_execution_status(query, bool(enabled_sources), enabled_sources, bool(relevant_raw), searched_source_ids, connector_telemetry, len(relevant_raw), len(relevant_raw & set(scoped_docs)))
        searched = source_status not in {"SOURCE_NOT_SELECTED", "QUERY_NOT_EXECUTED"}
        requirements = build_atomic_kiq_requirements(query, kiq_id, supported, preliminary, regulator_facts, official, set(scoped_docs), searched, claims, required_keys)

        verified = [r for r in requirements if r["verification_status"] == "VERIFIED"]
        tentative = [r for r in requirements if r["verification_status"] == "PRELIMINARY"]
        missing = [r for r in requirements if r["verification_status"] != "VERIFIED"]
        answer_status = ("NOT_SEARCHED" if not searched and not claims and not regulator_facts
                         else "ANSWERED" if requirements and len(verified) == len(requirements)
                         else "PARTIALLY_ANSWERED" if verified or tentative else "UNANSWERED")
        coverage = "SUPPORTED" if answer_status == "ANSWERED" else ("PARTIAL" if verified or tentative else "NONE")
        evidence_ids = sorted({did for r in requirements for did in r["doc_ids"]})
        contributing = [c for c in claims if c["doc_id"] in evidence_ids]
        content_res = _content_result(contributing, searched, query)
        if regulator_facts and content_res == "NO_RELEVANT_EVENT":
            content_res = "STATUS_UNKNOWN"
        latest = max((c["date"] for c in contributing if c.get("date")), default="")
        temporal = "HISTORICAL_ONLY" if cutoff and latest else ("CURRENT_OR_ONGOING" if latest and content_res not in {"STATUS_UNKNOWN", "STATUS_CONFLICTED"} else "UNKNOWN")
        verified_ids = {did for r in verified for did in r["verified_doc_ids"]}
        dispositions = _document_dispositions(query, collected_docs, approved, cutoff, set(evidence_ids), claims, dup_ids, claim_rejections)

        linked = [t for t in matched if set(t.evidence_ids or []) & set(evidence_ids)]
        for t in linked:
            if kiq_id not in t.kiq_ids:
                t.kiq_ids.append(kiq_id)

        answer = _compose_kiq_answer_text(cutoff, content_res, answer_status, regulator_facts, contributing, verified, missing, evidence_ids, len(scoped_docs))
        missing_text = "; ".join(f"{r['required_fact']}: {', '.join(r['missing_information'])}" for r in missing)
        details = {
            "evidence_requirements": requirements,
            "claim_requirement_links": [
                {"claim_id": s.get("claim_id", ""), "doc_id": s.get("doc_id", ""), "requirement_id": r["id"],
                 "requirement_key": r["key"], "rkiq_id": kiq_id, "strength": s.get("strength", "PRELIMINARY")}
                for r in requirements for s in r.get("supporting_claims") or []
            ],
            "claim_handoff_rejections": claim_rejections, "source_execution_status": source_status,
            "content_result": content_res, "issue_status": content_res, "unused_document_reasons": dispositions,
            "evidence_trace": list({
                (s.get("doc_id", ""), r["id"], s.get("passage_hash", ""), s.get("claim_type", "")): {
                    "kiq_id": kiq_id, "kit_id": s.get("kit_id", ""), "requirement_id": r["id"], "requirement_key": r["key"],
                    "doc_id": s.get("doc_id", ""), "source_id": s.get("source_id", ""), "issuer_name": s.get("issuer_name", ""),
                    "issuer_cik": s.get("issuer_cik", ""), "source_url": s.get("source_url", ""),
                    "original_filing_url": s.get("original_filing_url", ""), "quote": s.get("quote", ""),
                    "source_hash": s.get("source_hash", ""), "passage_hash": s.get("passage_hash", ""),
                    "extraction_method": s.get("extraction_method", ""),
                    "passage_validation_status": s.get("passage_validation_status", ""),
                    "claim_strength": s.get("strength", "PRELIMINARY"), "claim_state": s.get("claim_state", "STATUS_UNKNOWN"),
                    "claim_type": s.get("claim_type", "OBSERVED"), "verification_reason": s.get("verification_reason", ""),
                    "publication_date": s.get("publication_date", ""), "event_date": s.get("event_date", ""),
                    "authority": s.get("authority", ""), "document_number": s.get("document_number", ""),
                    "regulatory_stage": s.get("regulatory_stage", ""), "effective_date": s.get("effective_date", ""),
                    "effective_as_of_reference_date": s.get("effective_as_of_reference_date"),
                    "reference_date": s.get("reference_date", ""), "lifecycle_verified": s.get("lifecycle_verified"),
                    "supersession_status": s.get("supersession_status", ""),
                    "applicable_variants": s.get("applicable_variants", []),
                }
                for r in requirements for s in r.get("supporting_claims") or []
                if s.get("doc_id") in r["doc_ids"] and (s.get("quote") or s.get("claim_type") == "REGULATORY_DOCUMENT_IDENTITY")
            }.values()),
        }
        extra = {f: v for f, v in details.items() if f in optional}
        if missing_fields := {f: v for f, v in details.items() if f not in optional}:
            report.run_metadata = dict(getattr(report, "run_metadata", None) or {})
            audit = dict(report.run_metadata.get("kiq_runtime_audit") or {}) if isinstance(report.run_metadata.get("kiq_runtime_audit"), dict) else {}
            audit[kiq_id] = missing_fields
            report.run_metadata["kiq_runtime_audit"] = audit

        runtime.append(KIQAnswer(
            kiq_id=kiq_id, question=item["question"], answer_status=answer_status, evidence_coverage=coverage,
            temporal_relevance=temporal, answer=answer,
            related_event_ids=list(dict.fromkeys(t.event_id for t in linked)),
            evidence_ids=evidence_ids, retrieved_evidence_count=len(relevant_raw),
            validated_evidence_count=len(verified_ids), retrieved_document_ids=sorted(relevant_raw),
            verification_status=f"Verified {len(verified)}/{len(requirements)} atomic facts; {source_status}",
            uncertainty_level=ConfidenceLevel.LOW if answer_status == "ANSWERED" else (ConfidenceLevel.MEDIUM if verified else ConfidenceLevel.HIGH),
            recommended_next_step=("Monitor independently for new developments and downstream effects." if answer_status == "ANSWERED"
                                   else "Verify missing claims in dated, directly applicable primary records: " + ", ".join(r["required_fact"] for r in missing[:3])),
            missing_information=missing_text or None, **extra,
        ))
    return catalog + runtime


def runtime_kiq_status_counts(answers: List[KIQAnswer]) -> Dict[str, int]:
    """Count runtime KIQ answers by verification status."""
    statuses = [a.answer_status for a in answers if str(a.kiq_id).startswith("RKIQ_")]
    return {
        "runtime_kiq_answered": statuses.count("ANSWERED"),
        "runtime_kiq_partially_answered": statuses.count("PARTIALLY_ANSWERED"),
        "runtime_kiq_unanswered": statuses.count("UNANSWERED"),
        "runtime_kiq_not_searched": statuses.count("NOT_SEARCHED"),
    }