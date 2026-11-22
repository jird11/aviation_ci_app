# =============================================================================
# aviation_ci_app | Strategic KIT/KIQ mapping and runtime evidence coverage
#
# Responsibility: Map concrete intelligence findings to catalog questions and account for answered,
#   unresolved, or weakly evidenced KIQs.
# Design boundary: Issue-specific source evidence is required; generic aircraft or company overlap is
#   insufficient.
# =============================================================================

"""KIT/KIQ catalog mapping, evidence traceability, and question coverage."""

import hashlib
from datetime import date, datetime, timezone
from typing import Optional
from urllib.parse import urlsplit

from aero_ews.domain.evidence_text import _is_snippet_only, assess_source_passage, SUPPORTED_EXTRACTION_METHODS
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
from aero_ews.collection.queries import get_program_engine_domain
from tools import news_api_search_key

# Term extraction and conservative strategic-KIQ matching vocabulary.
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

# Evidence ontology: question intent and independently demonstrable claims.
# The rules describe fact types, not individual manufacturers or aircraft.
_REQUIREMENT_RULES = (
    ("SUPPLY_DISRUPTION", "A documented supply disruption", r"\b(?:suppl\w*|shortag\w*|bottleneck\w*|dodáv\w*|nedostat\w*|výpad\w*)\b", "SUPPLY_EVENT"),
    ("AFFECTED_COMPONENT", "Identity of the affected part or engine", r"\b(?:engine\w*|motor\w*|component\w*|part\w*|součást\w*|komponent\w*|turbine\w*|fan\s+blade\w*)\b", "COMPONENT_IDENTITY"),
    ("PRODUCTION_IMPACT", "Demonstrated impact on production or capacity", r"\b(?:production|manufactur\w*|assembly|capacity|output|výrob\w*|kapacit\w*)\b", "PRODUCTION_OUTCOME"),
    ("DELIVERY_IMPACT", "Demonstrated impact on customer deliveries", r"\b(?:deliver\w*|handover\w*|předáv\w*|dodání|předání)\b", "DELIVERY_OUTCOME"),
    ("REGULATORY_EXISTENCE", "Existence of the requested regulatory action", r"\b(?:airworthiness|directive\w*|regulation\w*|regulatory\s+action|AD|předpis\w*|nařízení|směrnic\w*)\b|\bFAA-\d{4}-\d+\b|\b20\d{2}-\d{5}\b", "OFFICIAL_REGULATION"),
    ("REGULATORY_PUBLICATION", "Official publication date", r"\b(?:publication\s+date|published\s+on|datum\s+zveřejnění|datum\s+publikace)\b", "PUBLICATION_DATE"),
    ("REGULATORY_EFFECTIVENESS", "Effective date and current regulatory stage", r"\b(?:effective\s+(?:date|on|from)|in\s+force|účinn\w*|platnost\w*)\b", "EFFECTIVE_DATE"),
    ("COMPLIANCE_DEADLINE", "Deadline for required compliance", r"\b(?:compliance\s+(?:date|deadline)|deadline|termín\s+(?:splnění|nápravy)|lhůt\w*)\b", "COMPLIANCE_DATE"),
    ("INSPECTION_REQUIREMENT", "Specific inspection or required corrective action", r"\b(?:inspect\w*|borescope|kontrol\w*|prohlídk\w*)\b", "INSPECTION_ACTION"),
    ("CERTIFICATION", "Completed certification or approval milestone", r"\b(?:certif\w*|type\s+approv\w*|certifik\w*|schválen\w*)\b", "CERTIFICATION_RECORD"),
    ("ORDER_CONTRACT", "Confirmed order or contractual commitment", r"\b(?:order\w*|purchas\w*|contract\w*|objednáv\w*|kontrakt\w*)\b", "COMMERCIAL_COMMITMENT"),
    ("ACCIDENT_INCIDENT", "Verified occurrence of the safety incident",
     r"\b(?:accident\w*|crash\w*|incident\w*|blowout|separation|nehod\w*)\b", "INCIDENT_RECORD"),
    ("INVESTIGATION_FINDING", "Documented investigation findings or probable cause",
     r"\b(?:investigat\w*|findings?|probable\s+cause|root\s+cause|lapses?|recommendations?|vyšetřov\w*|zjištění)\b",
     "INVESTIGATION_RECORD"),
    ("TECHNICAL_DEFECT", "Documented technical defect or quality finding",
     r"\b(?:defect\w*|fault\w*|failure\w*|quality\s+control|missing\s+bolts?|poruch\w*|závad\w*|vad\w*)\b",
     "TECHNICAL_FINDING"),
    ("EMISSIONS", "Documented emissions or environmental claim", r"\b(?:emission\w*|decarbon\w*|sustainab\w*|emis\w*|udržitel\w*)\b", "ENVIRONMENTAL_EVIDENCE"),
    ("FINANCIAL_CLAIM", "The stated financial disclosure", r"\b(?:financial|revenue|earnings|cash\s+flow|10-[kq]|20-f|6-k|(?:sec|edgar|esef|xbrl|corporate|quarterly|annual)\s+filing\w*|tržb\w*|výnos\w*|zisk\w*)\b", "FILING_PASSAGE"),
)
_IMPACT_PROOF = {
    "PRODUCTION_IMPACT": r"(?:production|manufactur\w*|assembly|capacity|output|výrob\w*|kapacit\w*).{0,60}(?:delay\w*|reduc\w*|cut|halt\w*|disrupt\w*|slow\w*|impact\w*|affect\w*|constraint\w*|zpožd\w*|omezen\w*|pokles\w*|ovliv\w*)|(?:delay\w*|reduc\w*|disrupt\w*|zpožd\w*|ovliv\w*).{0,60}(?:production|manufactur\w*|capacity|výrob\w*|kapacit\w*)",
    "DELIVERY_IMPACT": r"(?:deliver\w*|handover\w*|předáv\w*|dodání).{0,60}(?:delay\w*|postpon\w*|miss\w*|slip\w*|late|push\w*|reduc\w*|zpožd\w*|posun\w*|ovliv\w*)|(?:delay\w*|postpon\w*|zpožd\w*|posun\w*).{0,60}(?:deliver\w*|handover\w*|předáv\w*|dodání)",
}
_SUPPLY_PROOF = r"\b(?:shortag\w*|supply\s+(?:disrupt\w*|delay\w*|constraint\w*|issue\w*)|bottleneck\w*|nedostat\w*|výpad\w*|problém\w*\s+dodáv\w*|zpožd\w*\s+dodáv\w*)\b"
_CAUSE_PROOF = r"\b(?:because|due\s+to|caus\w*|result\w*\s+in|led\s+to|affect\w*|impact\w*|kvůli|způsob\w*|důsled\w*|ovliv\w*)\b"
_CAUSE_SOURCES = {
    "SUPPLY_DISRUPTION": _SUPPLY_PROOF,
    "CERTIFICATION_DELAY": r"\bcertif\w*|\bcertifik\w*",
    "HISTORICAL_DELAY": r"\b(?:certif\w*|shortag\w*|strik\w*|defect\w*|"
                        r"failure\w*|disrupt\w*|supply\w*|závad\w*|stávk\w*)\b",
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
    "REGULATORY": r"\b(?:regulat\w*|directive\w*|airworthiness|předpis\w*|nařízení)\b",
    "PRODUCTION": r"\b(?:production|manufactur\w*|assembly|výrob\w*)\b",
    "DELIVERY": r"\b(?:deliver\w*|handover\w*|dodáv\w*|předáv\w*)\b",
    "OPERATIONS": r"\b(?:operat\w*|service|grounding|provoz\w*)\b",
}
_ISSUE_WORDS = (
    r"delay\w*|pending|awaiting|postpon\w*|disrupt\w*|shortag\w*|halt\w*|"
    r"suspend\w*|fail\w*|defect\w*|strike\w*|zpožd\w*|odklad\w*|"
    r"nedostat\w*|výpad\w*|poruch\w*|závad\w*|stávk\w*|"
    r"issue\w*|problem\w*|problém\w*"
)
_CURRENT_WORDS = (
    r"\b(?:current\w*|latest|status|update\w*|still|ongoing|now|"
    r"recent\w*|resolved|completed|resum\w*|aktuáln\w*|současn\w*|"
    r"stav\w*|vyřešen\w*|obnoven\w*)\b"
)


def _lifecycle_topics(query: str) -> set[str]:
    return {name for name, pattern in _LIFECYCLE_TOPICS.items()
            if re.search(pattern, query, re.I)}


def _issue_state(text: str, query: str) -> str:
    """Identify a *stated* lifecycle change, never infer one from generic good news."""
    topics = _lifecycle_topics(query)
    if not topics:
        return "STATUS_UNKNOWN"
    # A projected milestone is not a completed event, even if the text also
    # names the responsible authority. Handle explicit withdrawal and negation
    # before the broader positive patterns.
    if _is_forecast(text, query):
        return "STATUS_UNKNOWN"
    if "CERTIFICATION" in topics:
        if re.search(
            r"\b(?:certif\w*|approval\w*|authorization|type\s+certificate)\b"
            r".{0,65}\b(?:withdrawn|revoked|rescinded|cancelled|canceled|retracted)\b|"
            r"\b(?:withdrawn|revoked|rescinded|cancelled|canceled|retracted)\b"
            r".{0,65}\b(?:certif\w*|approval\w*|authorization)\b",
            text, re.I,
        ):
            return "ISSUE_WORSENED"
        if re.search(
            r"\b(?:certif\w*|approval\w*)\b.{0,40}"
            r"\b(?:not|never)\s+(?:been\s+)?(?:granted|issued|received|obtained|approved|completed)\b|"
            r"\b(?:not|never)\s+(?:been\s+)?(?:certified|approved|granted)\b",
            text, re.I,
        ):
            return "ISSUE_ACTIVE"
    if "REGULATORY" in topics and re.search(
        r"\b(?:proposed|draft|proposal|NPRM|not\s+yet\s+effective)\b", text, re.I
    ):
        return "STATUS_UNKNOWN"
    patterns = {
        "CERTIFICATION": (
            r"\b(?:FAA|EASA|Federal\s+Aviation\s+Administration|"
            r"European\s+Union\s+Aviation\s+Safety\s+Agency|"
            r"European\s+Aviation\s+Safety\s+Agency|authority|regulator)\b"
            r".{0,100}\b(?:certif(?:ied|ies)|approv(?:ed|es)|grant(?:ed|s))\b|"
            r"\bcertif\w*.{0,65}\b(?:granted|issued|complet\w*|approved|finished|obtained)\b|"
            r"\b(?:achiev\w*|secured|attain\w*|issued|granted|received|obtained|completed)\b"
            r".{0,65}\b(?:type\s+certificat\w*|certification|approval)\b|"
            r"\b(?:has\s+been|was|were|is)\s+(?:certified|approved)\b|"
            r"\b(?:has|have)\s+(?:certified|approved)\b",
            r"\bcertif\w*.{0,55}\b(?:pending|delayed|awaiting|postponed|suspended)\b|"
            r"\b(?:pending|delayed|awaiting)\b.{0,45}\bcertif\w*",
        ),
        "LABOR": (
            r"\b(?:strike|walkout|stávk\w*)\b.{0,45}\b(?:end\w*|settled|resolved|over|ukončen\w*|skončil\w*)\b|"
            r"\b(?:end\w*|settled|ukončen\w*)\b.{0,45}\b(?:strike|walkout|stávk\w*)\b|"
            r"\b(?:workers?|union)\b.{0,50}\b(?:return\w*\s+to\s+work|agreement\s+reached)\b",
            r"\b(?:strike|walkout|stávk\w*)\b.{0,45}\b(?:ongoing|continues|began|started|trvá\w*)\b",
        ),
        "SUPPLY": (
            r"\b(?:shortage|supply\s+(?:constraint|disruption)|nedostat\w*)\b.{0,60}"
            r"\b(?:resolved|ended|eliminated|cleared|overcome|removed|vyřešen\w*)\b|"
            r"\b(?:supplier|dodavatel\w*)\b.{0,45}\b(?:output|capacity)\b.{0,35}\brestored\b",
            r"\b(?:shortage|supply\s+(?:constraint|disruption)|nedostat\w*)\b.{0,55}"
            r"\b(?:continues|persists|ongoing|worsened|remains)\b",
        ),
        "TECHNICAL": (
            r"\b(?:defect|fault|failure|závad\w*|poruch\w*)\b.{0,55}"
            r"\b(?:resolved|fixed|corrected|eliminated|repaired|vyřešen\w*)\b",
            r"\b(?:defect|fault|failure|závad\w*|poruch\w*)\b.{0,55}"
            r"\b(?:continues|persists|ongoing|worsened|detected|remains)\b",
        ),
        "REGULATORY": (
            r"\b(?:directive|regulation|rule|order|předpis\w*)\b.{0,55}"
            r"\b(?:withdr\w*|repeal\w*|rescind\w*|revok\w*|revoked|zrušen\w*)\b|"
            r"\b(?:withdr\w*|repeal\w*|rescind\w*|revok\w*|revoked|zrušen\w*)\b"
            r".{0,55}\b(?:directive|regulation|rule|order|předpis\w*)\b",
            r"\b(?:directive|regulation|rule|order)\b.{0,50}"
            r"\b(?:effective|in\s+force|issued|enforced)\b",
        ),
        "PRODUCTION": (
            r"\b(?:production|manufactur\w*|assembly|výrob\w*)\b.{0,50}"
            r"\b(?:resum\w*|restor\w*|restart\w*|normaliz\w*|obnoven\w*)\b|"
            r"\b(?:resum\w*|restor\w*|restart\w*|obnoven\w*)\b.{0,50}"
            r"\b(?:production|manufactur\w*|assembly|výrob\w*)\b",
            r"\b(?:production|manufactur\w*|assembly|výrob\w*)\b.{0,50}"
            r"\b(?:halted|stopped|delayed|disrupted|suspended)\b",
        ),
        "DELIVERY": (
            r"\b(?:deliver\w*|handover\w*|dodáv\w*)\b.{0,45}"
            r"\b(?:resum\w*|restor\w*|complet\w*|caught\s+up|obnoven\w*)\b|"
            r"\b(?:resum\w*|restor\w*|complet\w*|obnoven\w*)\b.{0,45}"
            r"\b(?:deliver\w*|handover\w*|dodáv\w*)\b",
            r"\b(?:deliver\w*|handover\w*|dodáv\w*)\b.{0,45}"
            r"\b(?:delayed|halted|disrupted|suspended)\b",
        ),
        "OPERATIONS": (
            r"\b(?:operations?|service|flights?|provoz\w*)\b.{0,50}"
            r"\b(?:resum\w*|restor\w*|restart\w*|obnoven\w*)\b|"
            r"\b(?:resum\w*|restor\w*|restart\w*|obnoven\w*)\b.{0,50}"
            r"\b(?:operations?|service|flights?|provoz\w*)\b",
            r"\b(?:operations?|service|flights?|provoz\w*)\b.{0,50}"
            r"\b(?:halted|suspended|disrupted|grounded)\b",
        ),
    }
    # When a KIQ tracks a shortage AND its delivery consequences, restoration
    # of deliveries alone cannot prove the shortage itself was eliminated.
    primary_topic = next(iter(
        t for t in ("CERTIFICATION", "LABOR", "SUPPLY", "TECHNICAL",
                    "REGULATORY", "PRODUCTION", "DELIVERY", "OPERATIONS")
        if t in topics
    ))
    issue = _LIFECYCLE_TOPICS[primary_topic]
    partial = (
        r"\b(?:partially|some|limited|částečn\w*)\b.{0,55}"
        r"\b(?:resum\w*|restor\w*|resolv\w*|obnoven\w*)\b|"
        r"\b(?:resum\w*|restor\w*|resolv\w*|obnoven\w*)\b.{0,45}"
        r"\b(?:partially|some|limited|částečn\w*)\b"
    )
    if re.search(issue, text, re.I) and re.search(partial, text, re.I):
        return "ISSUE_PARTIALLY_RESOLVED"
    deterioration = r"\b(?:worsen\w*|escalat\w*|intensif\w*|zhoršen\w*)\b"
    if (re.search(rf"{issue}.{{0,60}}{deterioration}", text, re.I)
            or re.search(rf"{deterioration}.{{0,60}}{issue}", text, re.I)):
        return "ISSUE_WORSENED"
    for topic in (primary_topic,):
        resolved, active = patterns[topic]
        if re.search(resolved, text, re.I) and not re.search(
            r"\b(?:not|never|without|pending|awaiting|expected|planned|proposed)\b"
            r".{0,40}\b(?:certif\w*|resolved|completed|approved|resumed)\b", text, re.I
        ):
            return "ISSUE_RESOLVED"
        if re.search(active, text, re.I):
            return "ISSUE_ACTIVE"
    return "STATUS_UNKNOWN"


def _required_evidence_specs(query: str) -> List[Dict[str, str]]:
    """Decompose a compound KIQ into independently verifiable fact types."""
    models = sorted(_detect_exact_variants(query) | _detect_engine_models(query))
    families = sorted(_detect_aircraft_families(query))
    named_entities = sorted(_named_subjects(query))
    component = next((name for name, pattern in _COMPONENT_PATTERNS.items()
                      if re.search(pattern, query, re.I)), "")
    requirements = [
        {"key": key, "required_fact": fact, "evidence_type": kind}
        for key, fact, trigger, kind in _REQUIREMENT_RULES if re.search(trigger, query, re.I)
        and (key != "AFFECTED_COMPONENT" or bool(
            _detect_engine_models(query) or component or re.search(
                r"\b(?:which|what|identify|affected|specific|jak\w*|kter\w*)\b"
                r".{0,45}\b(?:component|part|součást|komponent)\b", query, re.I
            )
        ))
    ]
    topics = _lifecycle_topics(query)
    issue_mentioned = bool(re.search(rf"\b(?:{_ISSUE_WORDS})\b", query, re.I))
    current_requested = bool(re.search(_CURRENT_WORDS, query, re.I))
    # A question about what an issuer *disclosed* is not a request to prove
    # that a regulator independently issued the referenced decision.
    issuer_question = bool(re.search(
        r"\b(?:what|which|how|co|jak|kdy)\b.{0,110}"
        r"\b(?:say|said|state|stated|states|stating|statement\w*|report\w*|disclos\w*|uved\w*|sděl\w*)\b|"
        r"\b(?:according\s+to|as\s+(?:disclosed|reported)\s+in)\b.{0,80}"
        r"\b(?:filing|sec|10-[kq])\b|"
        r"\b(?:sec|10-[kq]|20-f|filing)\b.{0,110}"
        r"\b(?:state|stated|states|stating|statement\w*|disclos\w*|report\w*|said|say)\b", query, re.I,
    ))
    explicit_regulator = bool(re.search(
        r"\b(?:did|has|have|when\s+did)\s+(?:the\s+)?"
        r"(?:FAA|EASA|regulat\w*)\b.{0,55}"
        r"\b(?:certif\w*|approv\w*|grant\w*|issu\w*)\b", query, re.I,
    ))
    issuer_only = issuer_question and not explicit_regulator
    if "CERTIFICATION" in topics and issue_mentioned:
        requirements = [r for r in requirements if r["key"] != "CERTIFICATION"]
    if "CERTIFICATION" in topics and issuer_only:
        financial_question = bool(re.search(
            r"\b(?:financial|revenue|earnings|cash\s+flow|profit|tržb\w*|výnos\w*|zisk\w*)\b",
            query, re.I,
        ))
        requirements = [r for r in requirements if r["key"] != "CERTIFICATION"
                        and (r["key"] != "FINANCIAL_CLAIM" or financial_question)]
        requirements.append(
            {"key": "ISSUER_STATEMENT", "required_fact": "Issuer's dated certification statement",
             "evidence_type": "ISSUER_DISCLOSURE"}
        )
        requirements.append({
            "key": "SOURCE_PROVENANCE", "required_fact": "Verifiable issuer-source reference",
            "evidence_type": "SOURCE_REFERENCE",
        })
    elif "CERTIFICATION" in topics and (current_requested or issue_mentioned or
                                          re.search(r"\b(?:complet\w*|certified|approv\w*)\b", query, re.I)):
        requirements.append(
            {"key": "REGULATOR_DECISION", "required_fact": "Direct certification decision by the responsible regulator",
             "evidence_type": "OFFICIAL_CERTIFICATION_RECORD"}
        )
        requirements.extend((
            {"key": "DECISION_DATE", "required_fact": "Date of the actual regulatory decision",
             "evidence_type": "DATED_REGULATOR_DECISION"},
            {"key": "SOURCE_PROVENANCE", "required_fact": "Verifiable primary-source reference",
             "evidence_type": "SOURCE_REFERENCE"},
        ))
    elif issuer_only:
        requirements.append({
            "key": "SOURCE_PROVENANCE", "required_fact": "Verifiable issuer-source reference",
            "evidence_type": "SOURCE_REFERENCE",
        })
    if topics and issue_mentioned:
        requirements.append({"key": "HISTORICAL_DELAY",
                             "required_fact": "Evidence of the historical issue or delay",
                             "evidence_type": "HISTORICAL_ISSUE"})
    if topics and (current_requested or issue_mentioned) and not issuer_only:
        requirements.append({"key": "CURRENT_STATUS",
                             "required_fact": "Latest dated, issue-specific status",
                             "evidence_type": "DATED_STATUS"})
    if topics and re.search(r"\b(?:change\w*|develop\w*|since|transition\w*|"
                            r"změn\w*|vývoj\w*|od\s+kdy)\b", query, re.I):
        requirements.append({"key": "STATUS_CHANGE",
                             "required_fact": "Dated transition between two evidenced states",
                             "evidence_type": "STATUS_TRANSITION"})
    if topics and not issuer_only and re.search(r"\b(?:resolv\w*|complet\w*|certified|fixed|reopen\w*|"
                                                r"resum\w*|vyřešen\w*|obnoven\w*)\b", query, re.I):
        requirements.append({"key": "RESOLUTION_EVIDENCE",
                             "required_fact": "Direct proof of an issue's resolution",
                             "evidence_type": "RESOLUTION_RECORD"})
    if topics and re.search(r"\b(?:remaining|residual|persist\w*|still|after\s+"
                            r"(?:resolution|recovery)|přetrváv\w*|zbývaj\w*)\b", query, re.I):
        requirements.append({"key": "REMAINING_IMPACT",
                             "required_fact": "Explicitly evidenced residual consequences",
                             "evidence_type": "RESIDUAL_IMPACT"})
    applicability_requested = bool(re.search(
        r"\b(?:applicabilit\w*|applicable\s+(?:model\w*|aircraft|type\w*)|"
        r"affected\s+(?:aircraft|model\w*|type\w*)|aircraft\s+covered|"
        r"which\s+(?:models?|aircraft|types?)|kter\w*\s+(?:model\w*|typ\w*|letadl\w*)|"
        r"na\s+jak\w*\s+(?:model\w*|typ\w*|letadl\w*)|vztahuje\s+se)\b",
        query, re.I,
    ))
    if models or applicability_requested:
        requirements.append({
            "key": "PROGRAM_APPLICABILITY", "required_fact": "Direct applicability to the named model or program",
            "evidence_type": "MODEL_APPLICABILITY",
        })
    if re.search(
        r"\b(?:already\s+effective|currently\s+effective|now\s+effective|"
        r"in\s+force|has\s+(?:taken\s+effect|entered\s+into\s+force)|"
        r"je\s+(?:již\s+)?účinn\w*|naby\w*\s+účinnost\w*)\b", query, re.I,
    ):
        requirements.append({
            "key": "EFFECTIVE_AS_OF_REFERENCE_DATE",
            "required_fact": "Whether the identified regulation is effective as of the reference date",
            "evidence_type": "DATED_REGULATORY_STATUS",
        })
    if (any(r["key"] in _CAUSE_SOURCES for r in requirements)
            and any(r["key"] in {"PRODUCTION_IMPACT", "DELIVERY_IMPACT"} for r in requirements)
            and re.search(r"\b(?:impact\w*|affect\w*|caus\w*|due\s+to|ovliv\w*|způsob\w*)\b", query, re.I)):
        requirements.append({
            "key": "CAUSAL_LINK", "required_fact": "Source-established causal link between supply and downstream impact",
            "evidence_type": "CAUSAL_EVIDENCE",
        })
    if not requirements:
        requirements.append({"key": "EVENT_EXISTENCE", "required_fact": "Verified occurrence of the requested event", "evidence_type": "SOURCE_EVENT"})
    requirements = list({r["key"]: r for r in requirements}.values())
    for req in requirements:
        req["required_entity_model"] = ", ".join(dict.fromkeys([*models, *families, *named_entities]))
        req["required_component"] = component
    return requirements


def _proof_matches(
    key: str, text: str, question: str, component: str,
    causal_patterns: Optional[List[str]] = None,
) -> bool:
    # Dates and legal effectiveness are lifecycle facts, not keyword matches.
    if key in {"REGULATORY_PUBLICATION", "REGULATORY_EFFECTIVENESS",
               "EFFECTIVE_AS_OF_REFERENCE_DATE", "COMPLIANCE_DEADLINE",
               "ISSUER_STATEMENT", "REGULATOR_DECISION", "DECISION_DATE", "SOURCE_PROVENANCE"}:
        return False
    if key in {"CURRENT_STATUS", "RESOLUTION_EVIDENCE"}:
        status = _issue_state(text, question)
        return status != "STATUS_UNKNOWN" and (
            key == "CURRENT_STATUS" or status == "ISSUE_RESOLVED"
        )
    if key == "STATUS_CHANGE":
        return False  # A single passage cannot establish the chronological transition.
    if key == "HISTORICAL_DELAY":
        if re.search(r"\b(?:no|without|zero|not|žádn\w*|bez)\b.{0,45}"
                     r"\b(?:issue\w*|problem\w*|delay\w*|shortag\w*|problém\w*)\b", text, re.I):
            return False
        return bool(re.search(rf"\b(?:{_ISSUE_WORDS})\b", text, re.I)
                    and any(re.search(p, text, re.I) for p in (
                        _LIFECYCLE_TOPICS[t] for t in _lifecycle_topics(question)
                    )))
    if key == "REMAINING_IMPACT":
        return bool(re.search(r"\b(?:remaining|residual|persist\w*|still|"
                              r"přetrváv\w*|zbývaj\w*)\b", text, re.I)
                    and any(re.search(p, text, re.I) for p in _IMPACT_PROOF.values()))
    if key == "PROGRAM_APPLICABILITY":
        if re.search(r"\b(?:not\s+applicable|does\s+not\s+apply|unaffected|excluded|nevztahuje\s+se)\b", text, re.I):
            return False
        variants = _detect_exact_variants(question)
        engines = _detect_engine_models(question)
        families = _detect_aircraft_families(question)
        if variants:
            # A family label alone never proves applicability to a named subtype.
            return bool(variants & _detect_exact_variants(text))
        if engines:
            return _engine_models_match(question, text)
        if families:
            return bool(families & _detect_aircraft_families(text))
        # Without an identified program, generic applicability language cannot
        # establish the subject of this question.
        return False
    if key == "AFFECTED_COMPONENT":
        if _detect_engine_models(question):
            return (_engine_models_match(question, text) and
                    (component in {"", "ENGINE"} or bool(re.search(
                        _COMPONENT_PATTERNS[component], text, re.I))))
        return bool(_detect_engine_models(text) or (component and component != "ENGINE"
                     and re.search(_COMPONENT_PATTERNS[component], text, re.I)))
    if key == "CAUSAL_LINK":
        sources = causal_patterns if causal_patterns is not None else [
            pattern for issue, pattern in _CAUSE_SOURCES.items()
            if any(req["key"] == issue for req in _required_evidence_specs(question))
        ]
        return bool(any(re.search(pattern, text, re.I) for pattern in sources)
                    and any(re.search(pattern, text, re.I) for pattern in _IMPACT_PROOF.values())
                    and re.search(_CAUSE_PROOF, text, re.I))
    if key == "SUPPLY_DISRUPTION":
        return bool(re.search(_SUPPLY_PROOF, text, re.I))
    if key in _IMPACT_PROOF:
        return bool(re.search(_IMPACT_PROOF[key], text, re.I))
    if key == "EVENT_EXISTENCE":
        return True
    if key == "INVESTIGATION_FINDING":
        return bool(re.search(
            r"\b(?:ntsb|investigat\w*|findings?|probable\s+cause|final\s+report|"
            r"preliminary\s+report|missing\s+(?:four\s+)?(?:key\s+)?bolts?|"
            r"maintenance\s+lapse|human\s+error|quality\s+control|audit|hearing|"
            r"recommendations?|safety\s+board)\b", text, re.I,
        ))
    if key == "CERTIFICATION":
        return _issue_state(text, question) == "ISSUE_RESOLVED" and not _is_forecast(text, question)
    if key == "CERTIFICATION_DELAY":
        return _proof_matches("HISTORICAL_DELAY", text, question, component)
    if key == "INSPECTION_REQUIREMENT" and re.search(r"\b(?:requirement\w*|mandatory|mandat\w*)\b", question, re.I):
        return bool(re.search(
            r"\b(?:must|shall|require\w*|mandat\w*)\b.{0,65}\binspect\w*\b|"
            r"\binspect\w*\b.{0,65}\b(?:required|mandated|mandatory)\b", text, re.I
        ))
    return bool(re.search(next(pattern for name, _, pattern, _ in _REQUIREMENT_RULES if name == key), text, re.I))


def _claim_strength(key: str, claim: Dict[str, Any], query: str) -> str:
    authority = claim.get("authority")
    if key == "REGULATOR_DECISION" and authority != "REGULATOR":
        return "PRELIMINARY"
    if ("CERTIFICATION" in _lifecycle_topics(query)
            and key in {"CURRENT_STATUS", "RESOLUTION_EVIDENCE", "CERTIFICATION"}
            and authority != "REGULATOR"):
        # Verified issuer disclosure ≠ independently verified legal decision.
        return "PRELIMINARY"
    return claim.get("strength", "PRELIMINARY")


_FAA_DOC_NUMBER_RE = re.compile(r"(?<![A-Z0-9-])20\d{2}-\d{4,6}(?!\d)", re.I)
_FAA_DOCKET_RE = re.compile(r"(?<![A-Z0-9])FAA-20\d{2}-\d{3,7}(?!\d)", re.I)
_FAA_MANUFACTURERS = ("BOEING", "AIRBUS", "EMBRAER", "BOMBARDIER", "ATR")
_FAA_STAGES = {"PROPOSED", "FINAL_ISSUED", "EFFECTIVE", "WITHDRAWN"}


def _faa_labeled_quote(text: str, field: str, expected: str = "") -> str:
    """Return the *actual* official field line, never a synthetic citation."""
    match = re.search(rf"(?im)^[ \t]*{re.escape(field)}:[ \t]*[^\r\n]*", text)
    if not match:
        return ""
    quote = match.group(0).strip()
    return quote if not expected or expected in quote else ""


def _faa_fact_claim(doc: Dict[str, Any], fact: Dict[str, Any],
                    key: str, quote: str, reference: str) -> Dict[str, Any]:
    """Provenance of one already-verified FAA field, separate from lifecycle review."""
    doc_id = str(fact["document_id"])
    published = str(fact.get("publication_date") or "")
    content = str(doc.get("text") or "")
    if quote and quote not in content:
        raise ValueError("FAA field citation is absent from the collected document")
    kinds = {
        "REGULATORY_EXISTENCE": "REGULATORY_DOCUMENT_IDENTITY",
        "REGULATORY_PUBLICATION": "REGULATORY_PUBLICATION_DATE",
        "REGULATORY_EFFECTIVENESS": "REGULATORY_EFFECTIVE_DATE",
        "EFFECTIVE_AS_OF_REFERENCE_DATE": "REGULATORY_EFFECTIVE_AS_OF_DATE",
        "COMPLIANCE_DEADLINE": "REGULATORY_COMPLIANCE_DATE",
        "PROGRAM_APPLICABILITY": "REGULATORY_PROGRAM_APPLICABILITY",
    }
    return {
        "claim_id": f"FAA_{doc_id}_{key}",
        "doc_id": doc_id, "source_id": "SRC_001",
        "source_url": str(fact["source_url"]),
        "authority": "REGULATOR", "strength": "VERIFIED",
        "claim_type": kinds.get(key, key), "regulatory_fact_key": key,
        "quote": quote, "text": quote or str(doc.get("title") or ""),
        "publication_date": published, "date": published,
        "event_date": "", "date_basis": "PUBLICATION_DATE_ONLY",
        "state": "STATUS_UNKNOWN", "historical": False,
        "passage_hash": hashlib.sha256(quote.encode("utf-8")).hexdigest() if quote else "",
        "source_hash": str(doc.get("source_content_sha256") or ""),
        "extraction_method": "OFFICIAL_LABELED_DOCUMENT_FIELD" if quote else "OFFICIAL_DOCUMENT_IDENTITY",
        "passage_validation_status": "PASSAGE_VERIFIED" if quote else "SOURCE_IDENTITY_VERIFIED",
        "verification_reason": ("OFFICIAL_DOCUMENT_FIELD_VERIFIED" if quote
                                else "OFFICIAL_DOCUMENT_IDENTITY_VERIFIED"),
        "document_number": str(fact.get("document_number") or ""),
        "regulatory_stage": str(fact.get("stage") or ""),
        "effective_date": str(fact.get("effective_date") or ""),
        "effective_as_of_reference_date": fact.get("effective_as_of_reference_date"),
        "reference_date": reference,
        "lifecycle_verified": bool(fact.get("lifecycle_verified")),
        "supersession_status": str(fact.get("supersession_status") or "UNKNOWN"),
        "applicable_variants": list(fact.get("applicable_variants") or []),
    }


def _scoped_faa_publication_fact(
    question: str, doc: Dict[str, Any], reference: str = "",
) -> Optional[Dict[str, Any]]:
    """Accept verified *publication fields* if a lifecycle-dependent assessment fails.

    Neither a valid Federal Register URL nor a dated AD establishes that the
    regulation is currently in force, has not been amended, or caused damage.
    """
    source = dict(doc)
    source["url"] = source.get("url") or source.get("source_url") or ""
    full_fact = assess_official_faa_fact(question, source)
    identity = inspect_official_faa_publication(source)
    if not identity or not identity.get("document_existence_verified") or not doc.get("doc_id"):
        return None

    positive_question = re.split(r"\b(?:exclude|excluding|except)\b", question,
                                 maxsplit=1, flags=re.I)[0]
    number = str(identity["document_number"])
    requested_numbers = {m.upper() for m in _FAA_DOC_NUMBER_RE.findall(positive_question)}
    requested_dockets = {m.upper() for m in _FAA_DOCKET_RE.findall(positive_question)}
    recorded_dockets = {str(value).upper() for value in identity.get("docket_ids") or []}
    if (requested_numbers and number not in requested_numbers) or (
        requested_dockets and not requested_dockets.intersection(recorded_dockets)
    ):
        return None
    if re.search(r"\bEASA\b", positive_question, re.I) and not re.search(
        r"\bFAA\b", positive_question, re.I
    ):
        return None

    text = str(source.get("text") or "")
    title = str(source.get("title") or "")
    source_status = str(source.get("content_status") or source.get("source_content_status") or "").upper()
    content_usable = (source_status not in _NON_FULL_TEXT
                      and source_status not in {"SOURCE_ACCESS_BLOCKED", "UNAVAILABLE"}
                      and source.get("content_truncated") is not True)
    # Metadata-only records can prove identity, but cannot silently become
    # verified citations about aircraft, obligations or future dates.
    summary = _faa_field(text, "Official Summary") if content_usable else ""
    body = title + "\n" + summary
    wanted_makers = {maker for maker in _FAA_MANUFACTURERS if re.search(
        rf"\b{maker}\b", positive_question, re.I
    )}
    wanted_variants = _detect_exact_variants(positive_question)
    wanted_families = _detect_aircraft_families(positive_question)
    wanted_engines = _detect_engine_models(positive_question)
    found_variants = _detect_exact_variants(summary)
    found_families = _detect_aircraft_families(summary)
    found_engines = _detect_engine_models(summary)
    engine_ad_match = bool(
        content_usable
        and re.search(r"\bengines?\b", title, re.I)
        and wanted_engines
        and _engine_models_match(positive_question, summary)
    )
    if wanted_makers and not engine_ad_match and not all(
            re.search(rf"\b{maker}\b", body, re.I) for maker in wanted_makers
    ):
        return None
    if content_usable and (
            (wanted_engines and not _engine_models_match(positive_question, summary))
            or (wanted_variants and not wanted_variants.intersection(found_variants)
                and (not engine_ad_match or bool(found_variants)))
            or (wanted_families and not wanted_families.intersection(found_families)
                and (not engine_ad_match or bool(found_families)))
    ):
        return None
    if not content_usable and not (requested_numbers or requested_dockets):
        # Metadata without a scoped summary can verify an exact document
        # identity, not the applicability of a general topic-based search.
        return None
    if re.search(r"\b(?:airworthiness\s+directives?|\bAD\b)\b", positive_question, re.I):
        if not re.search(r"\bairworthiness\s+directives?\b", body, re.I):
            return None
    if re.search(r"\b(?:minimum\s+equipment\s+list|\bMEL\b)\b", positive_question, re.I):
        if not re.search(r"\b(?:minimum\s+equipment\s+list|\bMEL\b)\b", body, re.I):
            return None
    if not requested_numbers and not requested_dockets and not any((
        wanted_variants, wanted_families, wanted_engines,
    )) and not _topic_matches(question, body):
        return None

    # First use the existing full lifecycle contract, then the verified
    # publication identity. This does not change assess_official_faa_fact().
    fact = dict(full_fact or {})
    fact.update({
        "document_id": str(doc["doc_id"]), "document_number": number,
        "docket_ids": sorted(recorded_dockets),
        "source_url": str(identity["source_url"]),
        "source_authority": "FAA_FEDERAL_REGISTER",
        "document_existence_verified": True,
        "requested_document_match": True, "requested_docket_match": True,
        "document_type_match": True,
        "publication_date": str(identity["publication_date"]),
        "lifecycle_verified": _faa_field(text, "Regulatory Lifecycle Check").upper() == "VERIFIED"
                              and full_fact is not None,
        "supersession_status": (str(full_fact.get("supersession_status") or "UNKNOWN")
                                if full_fact is not None else "UNKNOWN"),
        "program_unverified": bool(wanted_variants or wanted_families or wanted_engines)
                              and not bool(summary),
        "aircraft_or_engine_match": bool(
            (wanted_variants and wanted_variants.intersection(found_variants)) or
            (wanted_families and wanted_families.intersection(found_families)) or
            (wanted_engines and _engine_models_match(positive_question, summary))
        ),
    })
    if not full_fact:
        fact["missing_evidence"] = ["REGULATORY_LIFECYCLE_NOT_VERIFIED"]
        fact["content_evidence_status"] = "OFFICIAL_PUBLICATION_FIELDS_ONLY"

    stage = _faa_field(text, "Regulatory Stage").upper() if content_usable else ""
    if stage and doc.get("regulatory_stage") and str(doc["regulatory_stage"]).upper() != stage:
        return None
    if stage in _FAA_STAGES and (not doc.get("regulatory_stage") or
                                 str(doc["regulatory_stage"]).upper() == stage):
        fact["stage"] = stage
    elif not full_fact:
        fact["stage"] = "UNKNOWN"

    published = str(identity["publication_date"])
    effective, effective_conflict = _faa_consistent_date(
        _faa_field(text, "Effective Date") if content_usable else "",
        doc.get("regulatory_effective_date") if content_usable else "",
    )
    deadline, deadline_conflict = _faa_consistent_date(
        _faa_field(text, "Compliance Deadline") if content_usable else "",
        doc.get("regulatory_compliance_deadline") if content_usable else "",
    )
    # An official proposed date is not a legally established effective date.
    established = bool(effective and not effective_conflict and
                       content_usable and _faa_field(text, "Effective Date") and
                       fact.get("stage") in {"FINAL_ISSUED", "EFFECTIVE", "WITHDRAWN"})
    fact["effective_date"] = effective if established else None
    fact["effective_date_established"] = established
    fact["compliance_deadline"] = deadline if not deadline_conflict else None
    as_of = reference or _as_of_date(question) or datetime.now(timezone.utc).date().isoformat()
    as_of_day = date.fromisoformat(as_of)
    effective_as_of = bool(established and date.fromisoformat(effective) <= as_of_day and
                           fact.get("stage") in {"FINAL_ISSUED", "EFFECTIVE"})
    # A known future start date does not verify the document's future legal
    # status: an intervening amendment or withdrawal may still occur.
    as_of_observable = as_of_day <= datetime.now(timezone.utc).date()
    fact["effective_as_of_reference_date"] = (
        effective_as_of if established and as_of_observable else None
    )
    fact["reference_date"] = as_of
    if not full_fact:
        fact["regulatory_status"] = ("WITHDRAWN" if fact.get("stage") == "WITHDRAWN"
                                     else "EFFECTIVE" if effective_as_of and as_of_observable
                                     else str(fact.get("stage") or "UNKNOWN"))
    fact["applicable_variants"] = sorted(found_variants)
    requests_applicability = "PROGRAM_APPLICABILITY" in {
        requirement["key"] for requirement in _required_evidence_specs(question)
    }
    fact["program_applicability_verified"] = bool(
        summary and (
            (wanted_variants and wanted_variants.intersection(found_variants))
            or (wanted_families and wanted_families.intersection(found_families))
            or (wanted_engines and _engine_models_match(positive_question, summary))
            or (requests_applicability and not any((
                wanted_variants, wanted_families, wanted_engines,
            )) and any((found_variants, found_families, found_engines)))
        )
    )

    fields = {
        "REGULATORY_EXISTENCE": _faa_labeled_quote(text, "Federal Register Document", number),
        "REGULATORY_PUBLICATION": _faa_labeled_quote(text, "Publication Date", published),
    }
    if established:
        fields["REGULATORY_EFFECTIVENESS"] = _faa_labeled_quote(text, "Effective Date", effective)
        if as_of_observable:
            fields["EFFECTIVE_AS_OF_REFERENCE_DATE"] = fields["REGULATORY_EFFECTIVENESS"]
    if deadline and not deadline_conflict:
        fields["COMPLIANCE_DEADLINE"] = _faa_labeled_quote(text, "Compliance Deadline", deadline)
    if fact["program_applicability_verified"]:
        fields["PROGRAM_APPLICABILITY"] = _faa_labeled_quote(text, "Official Summary", summary)
    # Only the underlying identity may survive in the absence of source text.
    valid_keys = {"REGULATORY_EXISTENCE"}
    if fields["REGULATORY_PUBLICATION"]:
        valid_keys.add("REGULATORY_PUBLICATION")
    if established and fields.get("REGULATORY_EFFECTIVENESS"):
        valid_keys.add("REGULATORY_EFFECTIVENESS")
        if as_of_observable:
            valid_keys.add("EFFECTIVE_AS_OF_REFERENCE_DATE")
    if fields.get("COMPLIANCE_DEADLINE"):
        valid_keys.add("COMPLIANCE_DEADLINE")
    if fields.get("PROGRAM_APPLICABILITY"):
        valid_keys.add("PROGRAM_APPLICABILITY")
    fact["verified_fact_keys"] = sorted(valid_keys)
    fact["verified_field_claims"] = [
        _faa_fact_claim(source, fact, key, fields.get(key, ""), as_of)
        for key in sorted(valid_keys)
    ]
    if not fact.get("answer"):
        fact["answer"] = (
            f"FAA publication {number}, published {published}; stage "
            f"{fact.get('stage') or 'UNKNOWN'}; effective date "
            f"{effective if established else 'NOT_ESTABLISHED'}; "
            f"effective as of {as_of}: "
            f"{str(effective_as_of).upper() if established and as_of_observable else 'UNKNOWN'}. "
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
    """Return auditable atomic claims; contextual documents never verify downstream impacts."""
    facts = [f for f in regulatory_facts if f.get("requested_docket_match", True)
             and f.get("requested_document_match", True) and f.get("document_type_match", True)]
    allowed = eligible_document_ids
    records = []
    specs = [s for s in _required_evidence_specs(query)
             if required_keys is None or s["key"] in required_keys]
    causal_patterns = [_CAUSE_SOURCES[req["key"]] for req in specs if req["key"] in _CAUSE_SOURCES]
    cutoff = _as_of_date(query)
    claims = [c for c in (document_claims or [])
              if (allowed is None or c["doc_id"] in allowed)
              and (not cutoff or (c.get("publication_date") and c["publication_date"] <= cutoff
                                  and c.get("date", "") <= cutoff))]
    for index, spec in enumerate(specs, 1):
        key = spec["key"]
        verified_ids, preliminary_ids = set(), set()
        contributing = []
        for fact in facts:
            verified_fact_keys = set(fact.get("verified_fact_keys") or ())
            proof = {
                "REGULATORY_EXISTENCE": bool(fact.get("document_existence_verified")),
                "REGULATORY_PUBLICATION": bool(fact.get("publication_date")),
                # The date can be legally established *before* it arrives.
                "REGULATORY_EFFECTIVENESS": bool(fact.get("effective_date_established")),
                "EFFECTIVE_AS_OF_REFERENCE_DATE": (
                    fact.get("effective_as_of_reference_date") is not None
                ),
                "COMPLIANCE_DEADLINE": bool(fact.get("compliance_deadline")),
                "PROGRAM_APPLICABILITY": bool(fact.get("program_applicability_verified")),
                "INSPECTION_REQUIREMENT": _proof_matches(
                    "INSPECTION_REQUIREMENT", str(fact.get("answer") or ""), query,
                    spec["required_component"], causal_patterns,
                ),
                "CERTIFICATION": "CERTIFICATION" in str(fact.get("answer", "")).upper(),
            }.get(key, False)
            if verified_fact_keys:
                # The narrow fallback supplies *only* these independently
                # checked fields. It never verifies consequences or lifecycle.
                proof = proof and key in verified_fact_keys
            if proof and fact.get("document_id") and (
                allowed is None or fact["document_id"] in allowed
            ):
                verified_ids.add(fact["document_id"])
                contributing.extend(
                    claim for claim in fact.get("verified_field_claims") or []
                    if claim.get("regulatory_fact_key") == key
                    and claim.get("doc_id") == fact["document_id"]
                )
        if (official_confirmation and
                key in {"CERTIFICATION", "CURRENT_STATUS", "RESOLUTION_EVIDENCE",
                        "PROGRAM_APPLICABILITY", "REGULATOR_DECISION", "SOURCE_PROVENANCE",
                        "DECISION_DATE"}
                and (allowed is None or official_confirmation["doc_id"] in allowed)):
            if key != "DECISION_DATE" or _date_mentioned(
                official_confirmation.get("text", ""), official_confirmation.get("regulatory_decision_date")
            ):
                verified_ids.add(official_confirmation["doc_id"])

        for threat, target in [(t, verified_ids) for t in supported] + [
            (t, preliminary_ids) for t in partially_supported
        ]:
            evidence_ids = set(threat.evidence_ids or [])
            if allowed is not None:
                evidence_ids &= allowed
            if not evidence_ids:
                continue
            # Analyst-generated dates do not replace source-field verification.
            if key in {"REGULATORY_EFFECTIVENESS", "EFFECTIVE_AS_OF_REFERENCE_DATE",
                       "COMPLIANCE_DEADLINE", "REGULATORY_PUBLICATION"}:
                continue
            passages = [str(p) for p in (threat.fact_check_quote, threat.confirmed_facts) if p]
            if any(_proof_matches(key, passage, query, spec["required_component"], causal_patterns)
                   for passage in passages):
                verified_target = (preliminary_ids if target is verified_ids and
                                   threat.claim_support_status != "STATED_IN_SOURCE" else target)
                if key == "CAUSAL_LINK" and threat.causal_support_status != "EVIDENCED_IN_VERIFIED_SOURCE":
                    verified_target = preliminary_ids
                if ("CERTIFICATION" in _lifecycle_topics(query)
                        and key in {"CERTIFICATION", "CURRENT_STATUS", "RESOLUTION_EVIDENCE"}):
                    verified_target = preliminary_ids  # Analyst text is not the regulator's decision.
                verified_target.update(evidence_ids)

        for claim in claims:
            if claim.get("regulatory_fact_key"):
                # Official structured facts were already checked above. Do
                # not reclassify the same field by searching arbitrary words.
                continue
            if claim.get("claim_type") == "FORECAST" and key not in {
                "PROGRAM_APPLICABILITY", "ISSUER_STATEMENT"
            }:
                continue
            matches = (
                key == "ISSUER_STATEMENT" and claim.get("authority") == "ISSUER_DISCLOSURE"
                and claim.get("issuer_matches_query") is True
                and bool(claim.get("publication_date"))
                and _topic_matches(query, claim["text"])
            ) or (key == "SOURCE_PROVENANCE" and bool(urlsplit(str(claim.get("source_url") or "")).hostname)
                  and claim.get("strength") == "VERIFIED") or (
                key == "DECISION_DATE" and claim.get("authority") == "REGULATOR"
                and _date_mentioned(claim.get("text", ""), claim.get("event_date"))
                and claim.get("strength") == "VERIFIED"
            ) or (key not in {"ISSUER_STATEMENT", "REGULATOR_DECISION", "DECISION_DATE",
                              "SOURCE_PROVENANCE"} and _proof_matches(
                key, claim["text"] + " " + str(claim.get("section") or ""),
                query, spec["required_component"], causal_patterns,
            ))
            if matches:
                target = verified_ids if _claim_strength(key, claim, query) == "VERIFIED" else preliminary_ids
                if key == "CAUSAL_LINK" and claim.get("causal_link_verified") is not True:
                    target = preliminary_ids
                target.add(claim["doc_id"])
                contributing.append(claim)

        if key in {"CURRENT_STATUS", "STATUS_CHANGE"}:
            states = sorted(
                (c for c in claims if c.get("state") != "STATUS_UNKNOWN" and c.get("date")
                 and (key == "STATUS_CHANGE" or not c.get("historical"))),
                key=lambda c: c["date"], reverse=True,
            )
            if key == "CURRENT_STATUS":
                # Explicitly dated latest status; conflicting newest reports remain uncertain.
                latest = [c for c in states if c["date"] == states[0]["date"]] if states else []
                valid = bool(latest and len({c["state"] for c in latest}) == 1)
                confirmed_by_regulator = ({official_confirmation["doc_id"]}
                                        if official_confirmation else set())
                verified_ids = ({
                    c["doc_id"] for c in latest
                    if _claim_strength(key, c, query) == "VERIFIED"
                } if valid else set()) | (confirmed_by_regulator if valid or not latest else set())
                preliminary_ids = {
                    c["doc_id"] for c in latest
                    if _claim_strength(key, c, query) != "VERIFIED"
                }
                if not valid:
                    verified_ids.clear()
                    preliminary_ids.update(c["doc_id"] for c in latest)
                contributing = latest
            else:
                # Transition requires two *different* dated states in chronological order.
                pairs = [(old, new) for old in states for new in states
                         if old["date"] < new["date"] and old["state"] != new["state"]]
                verified_ids = set()
                if pairs:
                    old, new = pairs[0]
                    dest = verified_ids if all(
                        _claim_strength(key, c, query) == "VERIFIED" and c.get("event_date")
                        for c in (old, new)
                    ) else preliminary_ids
                    dest.update((old["doc_id"], new["doc_id"]))
                else:
                    preliminary_ids.clear()
                contributing = list(pairs[0]) if pairs else []

        state = ("NOT_SEARCHED" if not searched else "VERIFIED" if verified_ids
                 else "PRELIMINARY" if preliminary_ids else "MISSING")
        missing = [] if state == "VERIFIED" else [
            "No relevant source search was executed" if state == "NOT_SEARCHED" else
            ("Direct dated regulator certification decision" if key == "REGULATOR_DECISION" else
             "Validated issuer passage with filing URL, identity and content integrity" if key == "ISSUER_STATEMENT" else
             "Independent confirmation of the preliminary claim") if state == "PRELIMINARY" else
            f"Verified source passage for: {spec['required_fact']}"
        ]
        if state == "MISSING" and key == "REGULATOR_DECISION":
            missing = ["Direct dated certification record from the competent regulator"]
        supporting = [
            {"doc_id": c["doc_id"], "claim": c["text"][:420],
             "claim_id": c.get("claim_id", ""),
             "kiq_id": kiq_id, "kit_id": c.get("kit_id", ""),
             "source_id": c.get("source_id", ""), "quote": c.get("quote", ""),
             "issuer_name": c.get("issuer_name", ""),
             "issuer_cik": c.get("issuer_cik", ""),
             "original_filing_url": c.get("original_filing_url", ""),
             "extraction_method": c.get("extraction_method", ""),
             "passage_validation_status": c.get("passage_validation_status", ""),
             "publication_date": c.get("publication_date", ""),
             "event_date": c.get("event_date", ""),
             "date_basis": c.get("date_basis", "PUBLICATION_DATE_ONLY"),
             "authority": c.get("authority", "UNSPECIFIED"),
             "strength": _claim_strength(key, c, query),
             "source_url": c.get("source_url", ""),
             "source_hash": c.get("source_hash", ""),
             "passage_hash": c.get("passage_hash", ""),
             "verification_reason": c.get("verification_reason", "UNSPECIFIED"),
             "claim_type": c.get("claim_type", "OBSERVED"),
             "claim_state": c.get("state", "STATUS_UNKNOWN"),
             "document_number": c.get("document_number", ""),
             "regulatory_stage": c.get("regulatory_stage", ""),
             "effective_date": c.get("effective_date", ""),
             "effective_as_of_reference_date": c.get("effective_as_of_reference_date"),
             "reference_date": c.get("reference_date", ""),
             "lifecycle_verified": c.get("lifecycle_verified"),
             "supersession_status": c.get("supersession_status", ""),
             "applicable_variants": c.get("applicable_variants", [])}
            for c in contributing if c["doc_id"] in verified_ids | preliminary_ids
        ][:3]
        if (official_confirmation and official_confirmation["doc_id"] in verified_ids
                and key in {"REGULATOR_DECISION", "DECISION_DATE", "SOURCE_PROVENANCE",
                            "PROGRAM_APPLICABILITY", "CERTIFICATION", "RESOLUTION_EVIDENCE"}):
            official_quote = str(official_confirmation.get("verified_quote") or "")
            decision_date = (_date_str(official_confirmation.get("regulatory_decision_date"))
                             if _date_mentioned(official_confirmation.get("text", ""),
                                                official_confirmation.get("regulatory_decision_date")) else "")
            supporting = [{
                "doc_id": official_confirmation["doc_id"],
                "claim": official_quote[:420],
                "publication_date": _published_date(official_confirmation),
                "event_date": decision_date,
                "date_basis": "EVENT_DATE" if decision_date else "PUBLICATION_DATE_ONLY",
                "authority": "REGULATOR", "strength": "VERIFIED",
                "source_url": str(official_confirmation.get("url") or ""),
                "passage_hash": hashlib.sha256(official_quote.encode("utf-8")).hexdigest(),
                "verification_reason": "FAA_PRIMARY_FULL_TEXT",
            }]
        records.append({
            "id": f"{kiq_id}_REQ_{index:02d}", **spec,
            "verification_status": state,
            "doc_ids": sorted(verified_ids | preliminary_ids),
            "verified_doc_ids": sorted(verified_ids),
            "preliminary_doc_ids": sorted(preliminary_ids - verified_ids),
            "supporting_claims": supporting,
            "missing_information": missing,
        })
    return records


def _source_execution_status(
    query: str, enabled: bool, source_ids: set[str], retrieved: bool,
    searched_source_ids: Optional[set[str]], connector_telemetry: Optional[Dict[str, Any]],
    raw_document_count: Optional[int] = None,
    eligible_document_count: Optional[int] = None,
) -> str:
    """Distinguish nonexecution, connector failure, empty results and FR03 rejection."""
    if not enabled:
        return "SOURCE_NOT_SELECTED"
    relevant = [entry for entry in (connector_telemetry or {}).values()
                if isinstance(entry, dict) and entry.get("source_id") in source_ids]
    query_confirmed = False
    if relevant and any(entry.get("queries") for entry in relevant):
        wanted = {_norm_q(query), news_api_search_key(query)}
        matched = [entry for entry in relevant if any(
            _norm_q(q) in wanted or news_api_search_key(q) in wanted
            for q in entry.get("queries", [])
        )]
        # A Planner can rewrite KIQs into several retrieval expressions.
        # Current-run telemetry is evidence of execution even when the literal
        # question is different from those expressions.
        query_confirmed = bool(matched or (
            searched_source_ids is not None and source_ids & searched_source_ids
        ))
        relevant = matched or relevant

    def _is_hard_unavailable(entry: Dict[str, Any]) -> bool:
        errs = [str(e).strip() for e in (entry.get("errors") or []) if str(e).strip()]
        hard_errs = [e for e in errs if not e.upper().startswith("PARTIAL_COVERAGE")]
        status_up = str(entry.get("operational_status", "")).upper()
        if hard_errs:
            return True
        if status_up == "TEMPORARILY_UNAVAILABLE" and errs and int(entry.get("successful_responses") or 0) > 0:
            return False
        return status_up in {
            "RATE_LIMITED", "AUTHENTICATION_FAILED", "ACCESS_RESTRICTED",
            "TEMPORARILY_UNAVAILABLE", "FAILED", "ERROR", "TIMEOUT",
        }

    errors = any(_is_hard_unavailable(entry) for entry in relevant)
    any_raw = bool(retrieved or raw_document_count)
    if any_raw and eligible_document_count == 0:
        return "RESULTS_FILTERED_OUT"  # Retrieval succeeded; FR03 approved no evidence.
    if any_raw:
        return "PARTIAL_RESULT" if errors else "RESULTS_RETRIEVED"
    if errors:
        return "SOURCE_UNAVAILABLE"
    if searched_source_ids is not None and not (source_ids & searched_source_ids):
        return "QUERY_NOT_EXECUTED"
    completed = {
        "SUCCESS", "SUCCEEDED", "COMPLETED", "OK",
        "AVAILABLE", "PARTIAL_COVERAGE", "NO_MATCH", "NO_RESULTS", "EMPTY",
    }
    if query_confirmed and relevant and all(
        str(entry.get("operational_status") or "").upper() in completed for entry in relevant
    ):
        return "NO_MATCH"
    return "EXECUTION_UNVERIFIED"

# Compile strict word-boundary matching for strategic KIQ topic vocabulary.
def _compile_terms(*terms: str) -> re.Pattern:
    joined = "|".join(re.escape(t) for t in terms)
    return re.compile(rf"(?<![a-z0-9])(?:{joined})(?![a-z0-9])")

# Explicit KIQ issue patterns and required risk-domain combinations.
_KIQ_MATCH_RULES = [
    (
        "KIQ_1_1",
        {RiskType.SUPPLY_CHAIN, RiskType.TECHNICAL_QUALITY, RiskType.FINANCIAL},
        _compile_terms(
            "production delay", "production delays", "production disruption", "production disruptions",
            "delivery delay", "delivery delays", "delivery postponement", "delays to entry into service",
            "manufacturing disruption", "factory shutdown", "production halt", "production rate",
            "assembly disruption", "supplier production", "schedule slip",
        ),
    ),
    (
        "KIQ_1_2",
        {RiskType.SUPPLY_CHAIN, RiskType.TECHNICAL_QUALITY, RiskType.FINANCIAL},
        _compile_terms(
            "component shortage", "engine shortage", "parts shortage", "spare parts shortage",
            "material shortage", "raw material", "titanium shortage", "forging shortage",
            "supplier insolvency", "supplier strike", "industrial strike", "labor strike",
            "work stoppage", "supply shortage", "critical components", "engine removal",
            "engine removals", "powder metal", "powdered metal", "mro bottleneck", "shop visit",
        ),
    ),
    (
        "KIQ_2_1",
        {RiskType.COMPETITIVE, RiskType.ENVIRONMENTAL_TECHNOLOGICAL},
        _compile_terms(
            "strategic partnership", "strategic alliance", "product launch",
            "new aircraft", "new technology", "innovation partnership", "joint venture",
        ),
    ),
    (
        "KIQ_2_2",
        {RiskType.COMPETITIVE},
        _compile_terms(
            "aircraft order", "fleet order", "firm order", "order cancellation",
            "purchase agreement", "fleet contract", "aircraft contract", "orderbook",
            "orders totaling",
        ),
    ),
    (
        "KIQ_3_1",
        {RiskType.REGULATORY, RiskType.TECHNICAL_QUALITY, RiskType.ENVIRONMENTAL_TECHNOLOGICAL},
        _compile_terms(
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
        ),
    ),
]

# Normalize a KIT/KIQ question for conservative lexical comparison.
def _norm_q(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", " ", str(value or "").strip().lower()).strip()

# Select only catalog context that materially matches the current KIT.
def build_catalog_prompt_context(user_query: str) -> str:
    # Include catalog instructions only when they apply to the user’s explicit KIT.
    """Present catalog context only where it matches the user's actual KIT."""
    query_words = set(_WORD_RE.findall(user_query.lower())) - _QUERY_STOPWORDS
    lines = []
    for item in get_active_kiq_catalog():
        item_text = f"{item['question']} {' '.join(item['indicators'])}".lower()
        core_overlap = query_words & set(_WORD_RE.findall(item_text))
        if len(core_overlap) >= 2 or bool(core_overlap & _DISTINCTIVE_TERMS):
            lines.append(f"- [{item['kiq_id']}] {item['question']} | Indicators: {'; '.join(item['indicators'])}")

    return "\n".join(lines) if lines else (
        "No direct match in the strategic KIQ catalog. Preserve the user-defined "
        "ad-hoc KIT without assigning an unrelated catalog identifier."
    )

# Associate a validated event with specific strategic KIQ topic rules.
def match_kiqs_for_threat(threat: ThreatAssessment, catalog: List[Dict[str, Any]]) -> List[str]:
    """Conservative mapping to the thesis-aligned 5-KIQ strategic catalog."""
    evidence = f"{threat.threat_description or ''} {threat.confirmed_facts or ''} {threat.fact_check_quote or ''}".lower()
    allowed = {item["kiq_id"] for item in catalog}
    return [
        kiq_id
        for kiq_id, risk_types, pattern in _KIQ_MATCH_RULES
        if kiq_id in allowed and threat.risk_type in risk_types and pattern.search(evidence)
    ]

# Require evidence of the KIQ issue, not mere mention of the aircraft.
def _kiq_evidence_matches_topic(query: str, threat: ThreatAssessment) -> bool:
    """Require evidence of the specific issue, not generic aircraft overlap."""
    evidence = f"{threat.fact_check_quote or ''} {threat.confirmed_facts or ''}"

    if _detect_engine_models(query) and (not _engine_models_match(query, evidence)):
        return False

    wanted_regulatory_ids = {value.upper() for value in re.findall(
        r"\bFAA-\d{4}-\d+\b|\b20\d{2}-\d{5}\b", query, re.I
    )}
    if wanted_regulatory_ids and not wanted_regulatory_ids.issubset({value.upper() for value in re.findall(
        r"\bFAA-\d{4}-\d+\b|\b20\d{2}-\d{5}\b", evidence, re.I
    )}):
        return False

    ad_numbers = re.findall(r"\b20\d{2}-\d{4}(?:-[A-Z])?\b", query, re.I)
    if ad_numbers and not all(re.search(rf"\b{re.escape(num)}\b", evidence, re.I) for num in ad_numbers):
        return False

    requested = [pat for pat in _KIQ_ISSUE_GROUPS if re.search(pat, query, re.I)]
    return not requested or any(re.search(pat, evidence, re.I) for pat in requested)

# Check whether an official FAA source materially answers a regulatory KIQ.
def _is_matching_official_faa_doc(doc: Optional[Dict[str, Any]], specific_terms: set[str]) -> bool:
    if not doc or not specific_terms or doc.get("source_id") != "SRC_001":
        return False
    url = str(doc.get("url") or "")
    text = str(doc.get("text") or "")
    if (
        not url.startswith("https://www.federalregister.gov/documents/")
        or "Regulatory Lifecycle Check: VERIFIED" not in text
        or not re.search(r"(?m)^FAA Docket: FAA-\d{4}-\d+\s*$", text)
    ):
        return False
    combined_low = f"{doc.get('title') or ''} {text}".lower()
    return any(re.search(rf"\b{re.escape(tok)}\b", combined_low) for tok in specific_terms)

# Separate effective regulatory action from proposed or unresolved notices.
def _is_effective_faa_threat(t: ThreatAssessment) -> bool:
    summary = t.corroboration_summary or {}
    return (
        summary.get("FAA Lifecycle Verified") == "YES"
        and summary.get("Regulatory Stage") == "EFFECTIVE"
    )

def _faa_certification_models(text: str) -> set[str]:
    """Normalize exact aircraft variants, including 737-10 / 737 MAX 10 aliases."""
    from aero_ews.collection.queries import _model_tokens

    text = re.sub(r"\bFAA\s+(?=(?:B?737)[-\s])", "", text or "", flags=re.I)
    models = set()
    for token in _model_tokens(text):
        code = re.sub(r"[\s-]", "", token.upper())
        max_variant = re.fullmatch(r"B?737(?:MAX)?(\d{1,2})", code)
        models.add(f"737-{max_variant[1]}" if max_variant else code)
    return models


def _official_faa_certification_for_kiq(query: str, docs: List[Dict[str, Any]]):
    """Verify a dated FAA statement of issuance, without inferring certificate contents."""
    from datetime import date
    from urllib.parse import urlparse

    if not re.search(r"\b(?:certif\w*|type\s+approv\w*)\b", query, re.I):
        return None
    # An FAA statement cannot answer another regulator's decision or a docket-specific KIQ.
    if re.search(r"\b(?:EASA|TCCA|CAAC|CASA|ANAC|FAA[-\s]+20\d{2}[-\s]+\d+|20\d{2}-\d{5})\b", query, re.I):
        return None
    requested = _faa_certification_models(query)
    if not requested:
        return None

    issuance = re.compile(
        r"\b(?:issued|granted|approved)\b.{0,90}\b(?:amended\s+)?type\s+certificat\w*\b"
        r"|\b(?:amended\s+)?type\s+certificat\w*\b.{0,90}\b(?:issued|granted|approved)\b"
        r"|\b(?:FAA|Federal Aviation Administration)\b.{0,90}\bcertif(?:ied|ies)\b"
        r"|\b(?:certification|type\s+approval)\b.{0,70}\b(?:completed|granted|approved|issued)\b"
        r"|\b(?:completed|granted|approved|issued)\b.{0,70}\b(?:certification|type\s+approval)\b",
        re.I,
    )
    negated = re.compile(
        r"\b(?:not|never|without|pending|expected|planned|proposed|awaiting|denied|revoked|suspended)\b"
        r".{0,55}\b(?:issued|granted|approved|certif\w*|type\s+certificate)\b", re.I,
    )
    for doc in sorted(docs, key=lambda d: str(d.get("published_at") or ""), reverse=True):
        url = urlparse(str(doc.get("url") or ""))
        if (url.scheme != "https" or url.hostname not in {"faa.gov", "www.faa.gov"}
                or not re.fullmatch(r"/newsroom/[a-z0-9-]+/?", url.path, re.I)
                or doc.get("source_id") not in {"SRC_001", "SRC_004"}
                or (doc.get("source_id") == "SRC_004" and doc.get("verified_domain") is not True)
                or doc.get("content_status") not in {"FULL_TEXT", "FULL_TEXT_RETRIEVED"}
                or doc.get("content_truncated") is True
                or _is_snippet_only(doc)):
            continue
        published = str(doc.get("published_at") or "")
        try:
            date.fromisoformat(published)
            if not re.fullmatch(r"20\d{2}-\d{2}-\d{2}", published):
                continue
        except ValueError:
            continue

        title, body = str(doc.get("title") or ""), str(doc.get("text") or "")
        body_models = _faa_certification_models(body)
        if not requested.issubset(body_models):
            continue
        title_models = _faa_certification_models(title)
        for sentence in re.split(r"(?<=[.!?])\s+|\n+", body):
            if not issuance.search(sentence) or negated.search(sentence):
                continue
            stated_models = _faa_certification_models(sentence)
            if (requested.issubset(stated_models) or
                    (not stated_models and requested.issubset(title_models)
                     and issuance.search(title))):
                return {**doc, "matched_models": sorted(requested),
                        "verified_quote": sentence.strip()}
    return None

# Trace planned questions to documents and retained events with explicit unanswered states.
# No direct source support must remain visible as an intelligence gap.
# A related event alone does not establish that a planned KIQ has been answered.
# Evidence IDs provide traceability from each response to its source records.

_SOURCE_GROUPS = {
    "MEDIA": ({"SRC_004", "SRC_005"}, {"news", "newsapi", "news api", "pr",
                                       "official pr releases", "press releases"}),
    "REG": ({"SRC_001", "SRC_002", "SRC_003", "SRC_019", "SRC_020",
             "SRC_021", "SRC_022", "SRC_023", "SRC_026"},
            {"regulatory", "faa", "easa", "ntsb", "faa & easa regulations",
             "easa regulations", "ntsb investigations"}),
    "SOCIAL": ({"SRC_007", "SRC_008"},
               {"bluesky", "bluesky social network", "youtube", "youtube videos"}),
    "AIRSHOW": ({"SRC_006"}, {"airshow", "airshow websites"}),
    "FIN": ({"SRC_027", "SRC_031"},
            {"sec", "edgar", "esef", "xbrl", "financial", "oem & supplier pressroom"}),
}
_PRIMARY_SOURCES = set().union(_SOURCE_GROUPS["REG"][0], _SOURCE_GROUPS["FIN"][0])
_NON_FULL_TEXT = {
    "METADATA_ONLY", "SUMMARY_ONLY", "TRUNCATED", "SOURCE_POLICY_RESTRICTED",
    "CONTENT_UNAVAILABLE_OR_BLOCKED", "FILING_BLOCKED_OR_UNAVAILABLE",
    "ESEF_REPORT_UNAVAILABLE_OR_BLOCKED",
}


def _plan_queries(plan: KIQPlan) -> List[str]:
    queries = [
        *(plan.media_and_pr_queries or []),
        *(plan.regulatory_and_ntsb_queries or []),
        *(plan.social_and_video_queries or []),
        plan.airshow_query,
    ]
    return list(dict.fromkeys(q.strip() for q in queries if isinstance(q, str) and q.strip()))


def _runtime_questions(user_query: str, plan: KIQPlan) -> List[Dict[str, Any]]:
    """Derive information requirements from the KIT, independently of connectors."""
    planned = []
    required_models = _detect_exact_variants(user_query) | _detect_engine_models(user_query)
    allowed_models = set(required_models)
    if (re.search(r"\b(?:engine|engines|propulsion|turbine|gtf|leap)\b", user_query, re.I)
            and not _detect_engine_models(user_query)):
        domain = get_program_engine_domain(user_query)
        allowed_models |= _detect_engine_models(" ".join(domain["engine_models"]))
    for requirement in getattr(plan, "information_requirements", []) or []:
        question = str(getattr(requirement, "question", "") or "").strip()
        if not question:
            continue
        planned_models = _detect_exact_variants(question) | _detect_engine_models(question)
        if planned_models and (not allowed_models or not planned_models.issubset(allowed_models)):
            continue  # Planner cannot insert or substitute an unrequested exact program.
        req_identities = [
            str(value).strip() for value in getattr(requirement, "required_identity", []) or []
            if value and _norm_q(value) in _norm_q(user_query)
        ]
        plan_identities = [
            str(value).strip() for value in getattr(plan, "required_identity", []) or []
            if value and _norm_q(value) in _norm_q(user_query)
        ]
        identities = list(dict.fromkeys(req_identities)) or list(dict.fromkeys(plan_identities))
        question_models = _detect_exact_variants(question) | _detect_engine_models(question)
        filtered_identities = [
            value for value in identities
            if _norm_q(value) not in _norm_q(question)
               and (not question_models
                    or not (_detect_exact_variants(value) - question_models))
        ]
        query = " ".join([question, *filtered_identities]).strip()
        scoped_models = _detect_exact_variants(query) | _detect_engine_models(query)
        if scoped_models and (not allowed_models or not scoped_models.issubset(allowed_models)):
            continue
        if required_models and not (scoped_models & required_models):
            query = f"{query} {user_query}"
        keys = {s["key"] for s in _required_evidence_specs(query)}
        purposes = {getattr(p, "value", p) for p in getattr(requirement, "search_purposes", []) or []}
        keys |= {"CAUSAL_LINK"} if "CAUSE" in purposes else set()
        keys |= {"CURRENT_STATUS"} if "CURRENT_STATUS" in purposes else set()
        keys |= {"RESOLUTION_EVIDENCE"} if "RESOLUTION" in purposes else set()
        keys |= {"PRODUCTION_IMPACT", "DELIVERY_IMPACT"} & {
            s["key"] for s in _required_evidence_specs(user_query)
        } if "IMPACT" in purposes else set()
        planned.append({"query": query, "keys": keys, "question": question})
    if planned:
        original_keys = {spec["key"] for spec in _required_evidence_specs(user_query)}
        uncovered = original_keys - set().union(*(item["keys"] for item in planned))
        if uncovered:
            planned.append({"query": user_query, "keys": uncovered,
                            "question": f"Remaining explicitly requested facts: {user_query}"})
        return list({(_norm_q(item["question"]), tuple(sorted(item["keys"]))): item
                     for item in planned}.values())

    seeds = [user_query.strip()] if user_query and user_query.strip() else _plan_queries(plan)
    result = []
    for query in dict.fromkeys(seeds):
        keys = {s["key"] for s in _required_evidence_specs(query)}
        applicability = keys & {"PROGRAM_APPLICABILITY"}
        partitions = [
            ("Current status", {"CURRENT_STATUS", "RESOLUTION_EVIDENCE"}),
            ("Historical development", {"HISTORICAL_DELAY", "STATUS_CHANGE"}),
            ("Established cause", {"CAUSAL_LINK"}),
            ("Consequences", {"PRODUCTION_IMPACT", "DELIVERY_IMPACT", "REMAINING_IMPACT"}),
        ]
        assigned, groups = set(), []
        for label, wanted in partitions:
            included = keys & wanted
            if included:
                groups.append((label, included | applicability))
                assigned |= included
        remaining = keys - assigned - applicability
        if remaining:
            groups.append(("Documented facts", remaining | applicability))
        if not groups:
            groups.append(("Requested evidence", keys))
        for label, subset in groups:
            result.append({"query": query, "keys": subset,
                           "question": f"{label} for: {query}?"})
    return result


def _date_str(value: Any) -> str:
    try:
        parsed = date.fromisoformat(str(value or "")[:10])
        return parsed.isoformat() if parsed.year >= 1900 else ""
    except (ValueError, TypeError):
        return ""


def _as_of_date(query: str) -> str:
    """Read an explicit point-in-time question, not every date mentioned in a KIT."""
    marker = r"\b(?:as\s+of|as\s+at|status\s+(?:on|at)|ke\s+dni|k\s+datu|stav\s+k|k)\s+"
    match = re.search(marker + r"(20\d{2}-\d{2}-\d{2})\b", query, re.I)
    if match:
        return _date_str(match[1])
    months = {
        "january": 1, "february": 2, "march": 3, "april": 4, "may": 5,
        "june": 6, "july": 7, "august": 8, "september": 9, "october": 10,
        "november": 11, "december": 12, "ledna": 1, "února": 2,
        "března": 3, "dubna": 4, "května": 5, "června": 6,
        "července": 7, "srpna": 8, "září": 9, "října": 10,
        "listopadu": 11, "prosince": 12,
    }
    day_first = re.search(marker + r"(\d{1,2})\.?(?:\s+)([\wá-ž]+)\s+(20\d{2})", query, re.I)
    month_first = re.search(marker + r"([a-z]+)\s+(\d{1,2}),?\s+(20\d{2})", query, re.I)
    parts = ((day_first[1], day_first[2], day_first[3]) if day_first else
             (month_first[2], month_first[1], month_first[3]) if month_first else None)
    if parts and parts[1].lower() in months:
        return _date_str(f"{parts[2]}-{months[parts[1].lower()]:02d}-{int(parts[0]):02d}")
    return ""


def _published_date(doc: Dict[str, Any]) -> str:
    return _date_str(doc.get("published_at") or doc.get("publication_time")
                     or doc.get("publication_date"))


def _date_mentioned(text: str, value: Any) -> bool:
    stamp = _date_str(value)
    if not stamp:
        return False
    day = date.fromisoformat(stamp)
    formats = {stamp, f"{day.strftime('%B')} {day.day}, {day.year}",
               f"{day.day} {day.strftime('%B')} {day.year}"}
    return any(token.casefold() in str(text or "").casefold() for token in formats)


def _available_as_of(doc: Dict[str, Any], cutoff: str) -> bool:
    """A subsequent disclosure is not information available on an earlier date."""
    published = _published_date(doc)
    event = _date_str(doc.get("event_date"))
    return not cutoff or bool(published and published <= cutoff and (not event or event <= cutoff))


def _named_subjects(query: str) -> set[str]:
    positive = re.split(
        r"\b(?:exclude|excluding|except(?:\s+for)?|without|not\s+including|kromě|vyjma)\b",
        str(query or ""), maxsplit=1, flags=re.I,
    )[0]
    names = set(re.findall(r"\b[A-Z][a-z]{2,}(?:(?:\s*&\s*|-)[A-Z][a-z]{2,})?\b", positive))
    return names - {
        "Compressor", "Rotor", "Stator", "Clashing", "Blade", "Blades",
        "Are", "Was", "Were", "Can", "Could", "Should", "Would",
        "Anti", "Ice", "Anti-Ice", "Trent", "Remaining", "Specific",
        "Hurdles", "System", "Systems", "Proposed", "Mandated",
        "Interval", "Intervals", "Durability", "Compliance",
        "What", "Which", "When", "How", "Does", "Will", "Current", "Status",
        "Latest", "Historical", "Documented", "Established", "Consequences",
        "Certification", "Production", "Delivery", "Deliveries", "Component", "Supply",
        "January", "February", "March", "April", "May", "June", "July",
        "August", "September", "October", "November", "December", "Issuer",
        "Direct", "Official", "Regulator", "Reported", "Confirmed", "The",
        "Airworthiness", "Directive", "Directives", "Regulatory", "Safety",
        "Federal", "Register", "Minimum", "Equipment", "List", "Master",
        "Engine", "Engines", "Turbine", "Pressure", "High", "Applicability",
        "Effective", "Date", "Notice", "Notices", "Inspection", "Inspections",
        "Aero", "International", "Has", "Have", "Docket",
        "Aircraft", "Ground", "Aerospace", "Fleet", "Airline", "Airlines",
        "Variant", "Variants", "Family", "Model", "Models", "Operations", "Operational",
        "Availability", "Technical", "Defects", "Concerns",
        "Execution", "Factory", "Facilities", "Facility", "Manufacturing", "Renton",
        "Mid", "Mid-Exit", "Exit", "Door", "Plug", "Fuselage", "Flight", "Blowout",
        "Corporation", "Company", "Group", "Holdings", "Gear", "Landing", "Avionics",
        "Controls", "Control", "Export", "Western", "Fuel", "Manifold", "Airways",
        "Pacific", "Investigation", "Findings", "Probable", "Cause", "Quality",
        "Labor", "Labour", "Strike", "Dispute", "Supplier", "Suppliers", "Program",
        "Timeline", "Requirements", "Exemption", "Exemptions", "Commercial",
    }


def _issuer_matches_query(query: str, doc: Dict[str, Any]) -> bool:
    """A disclosure by supplier A cannot become a declaration by manufacturer B."""
    issuer = str(next((doc[k] for k in ("sec_company", "issuer_name", "issuer", "company")
                       if doc.get(k)), ""))
    core = set(_WORD_RE.findall(_norm_q(issuer))) - {
        "company", "corporation", "incorporated", "holding", "holdings", "group", "aerospace",
    }
    subjects = _named_subjects(query)
    return bool(issuer and (not subjects or any(
        _norm_q(subject) in core for subject in subjects
    )))


def _scope_matches(
    query: str, passage: str, doc: Dict[str, Any],
    passage_meta: Optional[Dict[str, Any]] = None,
) -> bool:
    """Ground issuer in source metadata, but aircraft/engine in the *local* passage."""
    meta = passage_meta or {}
    identity = " ".join(str(doc.get(k) or "") for k in (
        "sec_company", "sec_cik", "sec_ticker", "issuer", "issuer_name",
        "company", "company_name", "ticker", "cik", "evidence_authority",
    ))
    reference = " ".join(str(d.get(k) or "") for d, keys in (
        (doc, ("docket_id", "document_number", "url")),
        (meta, ("docket_id", "document_number", "url")),
    ) for k in keys)
    section = " ".join(str(d.get(k) or "") for d, keys in (
        (doc, ("section",)),
        (meta, ("section", "heading", "program", "affected_program", "component")),
    ) for k in keys)
    reference_ids = re.findall(
        r"\bFAA-\d{4}-\d+\b|\b20\d{2}-\d{5}\b|\b20\d{2}-\d{4}-[A-Z]\b",
        query, re.I,
    )
    if reference_ids and not all(re.search(re.escape(value), passage + " " + reference, re.I)
                                 for value in reference_ids):
        return False
    positive_q = re.split(
        r"\b(?:exclude|excluding|except(?:\s+for)?|without|not\s+including|kromě|vyjma)\b",
        str(query or ""), maxsplit=1, flags=re.I,
    )[0]
    requested = _detect_exact_variants(positive_q)
    local = _detect_exact_variants(passage)
    combined_variants = local | _detect_exact_variants(section)
    engines = _detect_engine_models(positive_q)
    local_engines = _detect_engine_models(passage)
    engine_hit = bool(engines and _engine_models_match(positive_q, passage + " " + section))
    variant_hit = bool(requested and (requested & combined_variants))

    if requested and local and not (requested & local):
        return False
    if engines and local_engines and not _engine_models_match(positive_q, passage):
        return False

    if requested and engines:
        if not (variant_hit or engine_hit):
            return False
    else:
        if requested and not variant_hit:
            return False
        if engines and not engine_hit:
            return False

    if any(re.search(pattern, positive_q, re.I) and not re.search(pattern, passage + " " + section, re.I)
           for name, pattern in _COMPONENT_PATTERNS.items() if name != "ENGINE"):
        return False
    named = _named_subjects(positive_q)
    if requested or engines:
        named = named - {"Airbus", "Boeing", "Embraer", "COMAC", "Pratt & Whitney", "Safran", "Rolls-Royce", "Alaska"}
    if named and not any(
            re.search(rf"\b{re.escape(name)}\b", passage + " " + section + " " + identity, re.I)
            for name in named
    ):
        return False
    return True


_ORDER_TOPIC_RE = re.compile(r"\b(?:order\w*|purchas\w*|contract\w*|backlog\w*|objednáv\w*|kontrakt\w*)\b", re.I)


def _topic_matches(query: str, passage: str) -> bool:
    topics = _lifecycle_topics(query)
    order_requested = bool(_ORDER_TOPIC_RE.search(query))
    if topics or order_requested:
        return any(re.search(_LIFECYCLE_TOPICS[t], passage, re.I) for t in topics) or (
            order_requested and bool(_ORDER_TOPIC_RE.search(passage))
        )
    words = set(_WORD_RE.findall(_norm_q(query))) - _QUERY_STOPWORDS
    return not words or bool(words & set(_WORD_RE.findall(_norm_q(passage))))


def _is_forecast(text: str, query: str) -> bool:
    """Future plans and expected approvals are not completed milestones."""
    topic = _LIFECYCLE_TOPICS.get("CERTIFICATION") if "CERTIFICATION" in _lifecycle_topics(query) else (
        r"\b(?:production|deliver\w*|suppl\w*|operations?)\b"
    )
    expectation = r"\b(?:expect\w*|anticipat\w*|forecast\w*|intend\w*|plan\w*|target\w*|project\w*|slat\w*|due)\b"
    future = r"\b(?:will\s+(?:be\s+)?(?:certif\w*|complet\w*|receiv\w*|obtain\w*|approv\w*)|may\s+be\s+certif\w*)\b"
    return bool(re.search(
        rf"{expectation}.{{0,90}}{topic}|{future}.{{0,65}}{topic}|"
        rf"{topic}.{{0,35}}(?:(?:is|was|are|were|remains)\s+)?"
        rf"{expectation}(?=\s+(?:to|by|for))|"
        rf"{topic}.{{0,55}}(?:{future}|\bwill\s+be\b)|"
        rf"{topic}.{{0,45}}\b(?:is|are|was)\s+expected\s+"
        rf"(?:next\b|in\b|by\b|during\b|later\b|soon\b)", text, re.I,
    ))


def _filing_passage_assessment(
    doc: Dict[str, Any], meta: Dict[str, Any], excerpt: str,
) -> tuple[str, str]:
    """Validate the actual SEC excerpt contract; missing proof remains preliminary."""
    if not excerpt.strip() or doc.get("source_id") not in {"SRC_027", "SRC_031"}:
        return "UNVERIFIED", "SOURCE_OR_PASSAGE_MISSING"
    if doc["source_id"] == "SRC_027":
        return assess_source_passage(doc, meta, excerpt=excerpt)
    if doc.get("evidence_verified") is False or meta.get("issuer_identity_verified") is False:
        return "UNVERIFIED", "PRODUCER_REJECTED_EVIDENCE"

    locator = str(doc.get("evidence_url") or doc.get("source_url") or doc.get("url") or "")
    passage_url = str(meta.get("source_url") or locator)
    original_url = str(doc.get("sec_filing_url") or meta.get("original_filing_url") or locator)
    a, b, original = urlsplit(locator), urlsplit(passage_url), urlsplit(original_url)
    if (a.scheme != "https" or not a.hostname or b._replace(fragment="") != a._replace(fragment="")
            or a.username or a.password or original.username or original.password):
        return "UNVERIFIED", "SOURCE_URL_MISMATCH"

    issuer = str(doc.get("issuer_name") or doc.get("sec_company") or doc.get("issuer") or "")
    passage_issuer = str(meta.get("issuer_name") or meta.get("issuer") or issuer)
    if not issuer or _norm_q(issuer) != _norm_q(passage_issuer):
        return "UNVERIFIED", "ISSUER_IDENTITY_MISMATCH"
    if doc["source_id"] == "SRC_027":
        cik = str(doc.get("issuer_cik") or doc.get("sec_cik") or doc.get("cik") or "").lstrip("0")
        passage_cik = str(meta.get("issuer_cik") or meta.get("sec_cik") or cik).lstrip("0")
        path_cik = re.search(r"/Archives/edgar/data/0*(\d+)/", original.path, re.I)
        if (not cik.isdigit() or passage_cik != cik or not path_cik
                or int(path_cik[1]) != int(cik) or original.hostname not in {"sec.gov", "www.sec.gov"}):
            return "UNVERIFIED", "SEC_FILING_IDENTITY_MISMATCH"
        if a.hostname not in {"sec.gov", "www.sec.gov"} and doc.get("evidence_origin") != "OFFICIAL_ISSUER_IR":
            return "UNVERIFIED", "UNAPPROVED_FILING_HOST"
    elif not (doc.get("verified_domain") is True and
              (doc.get("lei") or doc.get("issuer_lei") or doc.get("registration_id"))):
        return "UNVERIFIED", "ESEF_ISSUER_NOT_VERIFIED"

    # ESEF compatibility path; SEC is exclusively validated by the shared contract.
    method = str(meta.get("extraction_method") or meta.get("offset_basis") or
                 doc.get("extraction_method") or "").upper()
    start, end = meta.get("start"), meta.get("end")
    if (method not in SUPPORTED_EXTRACTION_METHODS | {
            "NORMALIZED_VISIBLE_TEXT", "FULL_TEXT", "HTML_VISIBLE_TEXT"}
            or not isinstance(start, int) or not isinstance(end, int)
            or start < 0 or end <= start or end - start < len(excerpt.strip())):
        return "UNVERIFIED", "EXTRACTION_PROVENANCE_MISSING"
    source_hash = str(doc.get("source_content_sha256") or "").lower()
    linked_hash = str(meta.get("source_content_sha256") or "").lower()
    if (not re.fullmatch(r"[0-9a-f]{64}", source_hash) or source_hash != linked_hash):
        return "UNVERIFIED", "SOURCE_HASH_MISMATCH_OR_MISSING"

    quoted_hash = str(meta.get("passage_sha256") or meta.get("excerpt_sha256") or "").lower()
    raw = doc.get("source_content_bytes") or doc.get("source_raw_bytes")
    raw_verified = isinstance(raw, bytes) and hashlib.sha256(raw).hexdigest() == source_hash
    if isinstance(raw, bytes) and not raw_verified:
        return "UNVERIFIED", "SOURCE_HASH_MISMATCH"
    if raw_verified:
        from bs4 import BeautifulSoup

        soup = BeautifulSoup(raw, "html.parser")
        for node in soup(["script", "style", "nav", "footer", "noscript"]):
            node.decompose()
        normalized = re.sub(r"\s+", " ", soup.get_text(" ", strip=True)).strip()
        if normalized[start:end].strip() != re.sub(r"\s+", " ", excerpt).strip():
            return "UNVERIFIED", "PASSAGE_NOT_IN_VERIFIED_SOURCE"
        return "VERIFIED", "FULL_SOURCE_AND_OFFSETS_VERIFIED"
    if quoted_hash and quoted_hash != hashlib.sha256(excerpt.encode("utf-8")).hexdigest():
        return "UNVERIFIED", "PASSAGE_HASH_MISMATCH"
    if (quoted_hash
            and meta.get("validated") is True and doc.get("evidence_verified") is True):
        return "VERIFIED", "TRUSTED_PRODUCER_PASSAGE_HASH"
    return "PRELIMINARY", "PASSAGE_HASH_OR_SOURCE_BYTES_NOT_AVAILABLE"


def _verified_filing_passage(doc: Dict[str, Any], meta: Dict[str, Any], excerpt: str) -> bool:
    return _filing_passage_assessment(doc, meta, excerpt)[0] == "VERIFIED"


def _fr03_semantic_passages(
    query: str, doc: Dict[str, Any], rejected: Dict[str, str],
) -> List[tuple[str, Dict[str, Any], str, str, str]]:
    """Use verified *quotations* from FR03 without upgrading their truth status.

    SEC issuer excerpts additionally retain the stricter issuer/URL/hash checks.
    FR03 catalog KIQ IDs are not runtime IDs and are deliberately ignored here.
    """
    did = str(doc.get("doc_id") or "")
    source = str(doc.get("source_id") or "")
    locator = str(doc.get("url") or doc.get("source_url") or "")
    parsed = urlsplit(locator)
    candidates = doc.get("semantic_relevant_claims") or []
    if not isinstance(candidates, (list, tuple)):
        rejected[did] = "FR03_CLAIM_STRUCTURE_INVALID"
        return []
    if not did or not source or parsed.scheme not in {"https", "http"} or not parsed.hostname:
        if candidates:
            rejected[did] = "MISSING_SOURCE_ID_OR_URL"
        return []

    results = []
    seen = set()
    for item in candidates[:12]:
        if not isinstance(item, dict) or item.get("evidence_validated") is not True:
            rejected.setdefault(did, "FR03_QUOTATION_NOT_VERIFIED")
            continue
        excerpt = " ".join(str(item.get("evidence_excerpt") or "").split())
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
            verified_in_filing = False
            original = doc.get("evidence_passages") or []
            if isinstance(original, dict):
                original = ([original] if any(k in original for k in
                            ("text", "passage", "quote", "excerpt")) else list(original.values()))
            if isinstance(original, (str, dict)):
                original = [original]
            for entry in original if isinstance(original, (list, tuple)) else []:
                metadata = entry if isinstance(entry, dict) else {}
                source_quote = str(next((metadata[k] for k in
                    ("text", "passage", "quote", "excerpt", "content") if metadata.get(k)), "")
                    if metadata else entry)
                if excerpt.casefold() not in " ".join(source_quote.split()).casefold():
                    continue
                verdict, _ = _filing_passage_assessment(doc, metadata, source_quote)
                if verdict in {"VERIFIED", "PRELIMINARY"}:
                    verified_in_filing = True
                    break
            if not verified_in_filing:
                rejected.setdefault(did, "ISSUER_PASSAGE_VALIDATION_FAILED")
                continue

        metadata = {
            "claim_id": str(item.get("claim_id") or ""),
            "claim_type": str(item.get("claim_type") or "OBSERVED"),
            "event_date": item.get("event_at") or doc.get("event_date"),
            "source_url": locator,
            "source_id": source,
            "issuer_name": str(doc.get("issuer_name") or doc.get("sec_company") or ""),
            "issuer_cik": str(doc.get("issuer_cik") or doc.get("sec_cik") or ""),
            "original_filing_url": str(doc.get("sec_filing_url") or locator),
            "source_content_sha256": str(doc.get("source_content_sha256") or ""),
            "passage_sha256": hashlib.sha256(excerpt.encode("utf-8")).hexdigest(),
            "section": str(item.get("section") or doc.get("section") or ""),
            "extraction_method": "FR03_SEMANTIC_QUOTATION",
            "evidence_validated": True,
        }
        results.append((excerpt, metadata, "PRELIMINARY",
                        "FR03_SOURCE_QUOTATION_VERIFIED", "QUOTE_VERIFIED_EVENT_UNCONFIRMED"))
    return results


def _document_claims(
    query: str, docs: List[Dict[str, Any]], approved: Optional[set[str]],
    kiq_id: str = "", rejected: Optional[Dict[str, str]] = None,
    required_keys: Optional[set[str]] = None,
) -> List[Dict[str, Any]]:
    """Ground individually dated claims in FR03-eligible full text or SEC excerpts."""
    claims = []
    rejected = rejected if rejected is not None else {}
    keys = {s["key"] for s in _required_evidence_specs(query)} | set(required_keys or ())
    cutoff = _as_of_date(query)
    for doc in docs:
        doc_id = doc.get("doc_id")
        if not doc_id or (approved is not None and doc_id not in approved) or not _available_as_of(doc, cutoff):
            continue
        status = str(doc.get("content_status") or "").upper()
        restricted_full_text = status in _NON_FULL_TEXT - {
            "METADATA_ONLY", "SUMMARY_ONLY", "TRUNCATED"
        }
        source = doc.get("source_id")
        full = (status in {"FULL_TEXT", "FULL_TEXT_RETRIEVED"}
                and doc.get("content_truncated") is not True and not _is_snippet_only(doc))
        primary = source in _PRIMARY_SOURCES or (
            source == "SRC_005" and doc.get("verified_domain") is True
        )
        strength = "VERIFIED" if approved is not None and full and primary else "PRELIMINARY"
        authority = ("ISSUER_DISCLOSURE" if source in _SOURCE_GROUPS["FIN"][0] else
                     "REGULATOR" if source in _SOURCE_GROUPS["REG"][0] else
                     "ISSUER_RELEASE" if source == "SRC_005" and doc.get("verified_domain") else
                     "SECONDARY")
        published = _published_date(doc)
        passages = []
        if source in _SOURCE_GROUPS["FIN"][0] and not restricted_full_text:
            raw = doc.get("evidence_passages") or []
            if isinstance(raw, dict):
                raw = [raw] if any(k in raw for k in ("text", "passage", "quote", "excerpt")) else list(raw.values())
            if isinstance(raw, (str, dict)):
                raw = [raw]
            for entry in raw if isinstance(raw, (list, tuple)) else []:
                meta = entry if isinstance(entry, dict) else {}
                if meta.get("validated") is False or meta.get("is_validated") is False or str(
                    meta.get("verification_status") or ""
                ).upper() in {"REJECTED", "INVALID", "UNSUPPORTED", "FAILED", "MISMATCH"}:
                    continue
                excerpt = str(next((meta[k] for k in ("text", "passage", "quote", "excerpt", "content")
                                    if meta.get(k)), "") if meta else entry)
                if len(excerpt.strip()) >= 25:
                    verdict, why = _filing_passage_assessment(doc, meta, excerpt)
                    passages.append((excerpt, meta, "VERIFIED" if approved is not None
                                     and verdict == "VERIFIED" else "PRELIMINARY", why, verdict))
        # Semantic excerpts are independent passage candidates. They remain
        # PRELIMINARY even when their quotation integrity passed FR03.
        passages.extend(_fr03_semantic_passages(query, doc, rejected))
        if full and not restricted_full_text and len(str(doc.get("text") or "").strip()) >= 70:
            body = str(doc["text"])
            verified = (approved is not None and _verified_filing_passage(doc, {}, body)
                        if source in _SOURCE_GROUPS["FIN"][0] else strength == "VERIFIED")
            passages.append((body, {}, "VERIFIED" if verified else "PRELIMINARY",
                             "FULL_SOURCE_VERIFIED" if verified else "SOURCE_VALIDATION_PENDING",
                             "VERIFIED" if verified else "PRELIMINARY"))
        count = 0
        seen = set()
        for body, meta, passage_strength, verification_reason, passage_verdict in passages:
            for paragraph in re.split(r"\n\s*\n", body):
                sentences = re.split(r"(?<=[.!?])\s+|\n+", paragraph)
                for i, sentence in enumerate(sentences):
                    sentence = sentence.strip()
                    if len(sentence) < 25 or not _topic_matches(query, sentence):
                        continue
                    previous = sentences[i - 1].strip() if i else ""
                    if len(previous) > 220:
                        previous = re.sub(r"^\S*\s+", "", previous[-220:]).strip()
                    passage = (previous + " " + sentence[:700]).strip()
                    if not _scope_matches(query, passage, doc, meta):
                        continue
                    forecast = _is_forecast(sentence, query)
                    state = "STATUS_UNKNOWN" if forecast else _issue_state(sentence, query)
                    req_component = next(
                        (name for name, pat in _COMPONENT_PATTERNS.items() if re.search(pat, query, re.I)),
                        "",
                    )
                    substantive_keys = {
                        key for key in keys
                        if key not in {"PROGRAM_APPLICABILITY", "EVENT_EXISTENCE",
                                       "ISSUER_STATEMENT", "REGULATOR_DECISION", "SOURCE_PROVENANCE"}
                    }
                    fact = not forecast and any(
                        _proof_matches(key, passage, query, req_component) for key in substantive_keys
                    )
                    if not fact and not forecast:
                        if "ISSUER_STATEMENT" in keys and authority == "ISSUER_DISCLOSURE" and _issuer_matches_query(
                                query, doc):
                            fact = True
                        elif not substantive_keys and (
                                _proof_matches("PROGRAM_APPLICABILITY", passage, query, req_component)
                                or _topic_matches(query, sentence)
                        ):
                            fact = True
                    if state == "STATUS_UNKNOWN" and not fact and not forecast:
                        continue
                    event = _date_str(meta.get("event_date") or meta.get("occurrence_date")
                                      or doc.get("event_date"))
                    if cutoff and event and event > cutoff:
                        continue
                    stamp = (sentence.lower(), event or published)
                    if stamp in seen:
                        continue
                    seen.add(stamp)
                    claims.append({
                        "doc_id": doc_id, "kiq_id": kiq_id, "state": state,
                        "claim_state": state, "claim_authority": authority,
                        "claim_id": str(meta.get("claim_id") or ""),
                        "text": passage, "quote": body if meta else sentence[:500],
                        "issuer_name": str(meta.get("issuer_name") or doc.get("issuer_name") or ""),
                        "issuer_cik": str(meta.get("issuer_cik") or doc.get("issuer_cik") or ""),
                        "original_filing_url": str(meta.get("original_filing_url") or
                                                   doc.get("sec_filing_url") or ""),
                        "extraction_method": str(meta.get("extraction_method") or ""),
                        "passage_validation_status": ("PASSAGE_VERIFIED" if
                                                      passage_verdict == "VERIFIED" else passage_verdict),
                        "kit_id": str(meta.get("kit_id") or ""),
                        "date": event or published, "event_date": event,
                        "publication_date": published,
                        "date_basis": "EVENT_DATE" if event else "PUBLICATION_DATE_ONLY",
                        "historical": bool(re.search(
                            r"\b(?:previously|formerly|historically|earlier|prior\s+to|"
                            r"had\s+been|last\s+(?:year|quarter)|dříve|předtím)\b",
                            sentence, re.I
                        ) and state != "ISSUE_RESOLVED"),
                        "strength": passage_strength, "source_id": source,
                        "authority": authority,
                        "claim_type": "FORECAST" if forecast else str(meta.get("claim_type") or "OBSERVED"),
                        "issuer_matches_query": _issuer_matches_query(query, doc)
                        if authority == "ISSUER_DISCLOSURE" else False,
                        "section": str(meta.get("section") or doc.get("section") or ""),
                        "source_url": str(meta.get("source_url") or doc.get("source_url") or doc.get("url") or ""),
                        "source_hash": str(meta.get("source_content_sha256") or ""),
                        "passage_hash": str(meta.get("passage_sha256") or
                                            hashlib.sha256(body.encode("utf-8")).hexdigest()),
                        "verification_reason": verification_reason,
                    })
                    count += 1
                    if count >= 12:
                        break
                if count >= 12:
                    break
            if count >= 12:
                break
    return claims


def _threat_claims(
    query: str, threats: List[ThreatAssessment], docs: Dict[str, Dict[str, Any]],
) -> tuple[List[ThreatAssessment], List[Dict[str, Any]]]:
    matched, claims = [], []
    for threat in threats:
        text = " ".join(str(value or "") for value in (
            threat.fact_check_quote, threat.confirmed_facts,
            threat.affected_program, threat.company_affected,
        ))
        ids = {i for i in (threat.evidence_ids or []) if i in docs}
        if not (ids and threat.technical_grounding_status == "PASS"
                and threat.validation_status in {
                    ValidationStatus.SUPPORTED, ValidationStatus.PARTIALLY_SUPPORTED
                } and _scope_matches(query, text, {}) and _topic_matches(query, text)):
            continue
        matched.append(threat)
        verified = (
            threat.validation_status == ValidationStatus.SUPPORTED
            and threat.program_relevance == "DIRECT_KIT_MATCH"
            and threat.claim_support_status == "STATED_IN_SOURCE"
        )
        for doc_id in sorted(ids):
            claim = str(threat.confirmed_facts or threat.fact_check_quote or "")
            claims.append({
                "doc_id": doc_id, "text": claim,
                "state": _issue_state(claim, query),
                "date": _date_str(docs[doc_id].get("event_date") or docs[doc_id].get("published_at")
                                  or getattr(threat, "publication_time", "")),
                "event_date": _date_str(docs[doc_id].get("event_date")),
                "publication_date": _published_date(docs[doc_id]),
                "date_basis": ("EVENT_DATE" if _date_str(docs[doc_id].get("event_date"))
                               else "PUBLICATION_DATE_ONLY"),
                "historical": getattr(
                    getattr(threat, "event_freshness", None), "value",
                    getattr(threat, "event_freshness", None)
                ) == "HISTORICAL_CONTEXT",
                "strength": "VERIFIED" if verified else "PRELIMINARY",
                "source_id": docs[doc_id].get("source_id"),
                "authority": "ANALYST_ASSESSMENT",
                "source_url": str(docs[doc_id].get("source_url") or docs[doc_id].get("url") or ""),
                "verification_reason": "ANALYST_EVENT_VALIDATION" if verified else "EVENT_NOT_FULLY_VALIDATED",
            })
    return matched, claims


def _content_result(claims: List[Dict[str, Any]], searched: bool, query: str) -> str:
    cutoff = _as_of_date(query)
    dated = sorted((c for c in claims if c.get("state") != "STATUS_UNKNOWN"
                    and c.get("date") and not c.get("historical")
                    and (not cutoff or (c.get("publication_date") and c["publication_date"] <= cutoff
                                        and c["date"] <= cutoff))),
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
    """A repeated quote is one piece of evidence, even under several DOC_IDs."""
    passage = re.sub(r"\s+", " ", str(claim.get("text") or "")).strip().casefold()
    return hashlib.sha256(passage.encode("utf-8")).hexdigest()


def _dedupe_claims(claims: List[Dict[str, Any]]) -> tuple[List[Dict[str, Any]], set[str]]:
    seen, retained, duplicate_ids = {}, [], set()
    for claim in sorted(claims, key=lambda c: c.get("strength") == "VERIFIED", reverse=True):
        signature = (_claim_fingerprint(claim), claim.get("date"))
        if signature in seen:
            if claim["doc_id"] != seen[signature]:
                duplicate_ids.add(claim["doc_id"])
            continue
        seen[signature] = claim["doc_id"]
        retained.append(claim)
    return retained, duplicate_ids


def _document_dispositions(
    query: str, docs: List[Dict[str, Any]], approved: Optional[set[str]],
    cutoff: str, used_ids: set[str], claims: List[Dict[str, Any]], duplicates: set[str],
    rejected_claims: Optional[Dict[str, str]] = None,
) -> Dict[str, str]:
    """Record the reason each retrieved document did not support this particular KIQ."""
    candidates = {claim["doc_id"] for claim in claims}
    preliminary = {claim["doc_id"] for claim in claims if claim.get("strength") != "VERIFIED"}
    reasons = {}
    for index, doc in enumerate(docs):
        doc_id = str(doc.get("doc_id") or f"MISSING_DOC_ID_{index + 1}")
        if doc_id in used_ids:
            continue
        if approved is not None and doc_id not in approved:
            reason = "FR03_REJECTED_OR_NOT_APPROVED"
        elif not _available_as_of(doc, cutoff):
            reason = "OUTSIDE_AS_OF_DATE"
        elif doc_id in (rejected_claims or {}) and doc_id not in candidates:
            reason = str(rejected_claims[doc_id])
        elif doc_id in duplicates:
            reason = "DUPLICATE_CLAIM"
        elif doc_id in preliminary:
            reason = "CLAIM_NOT_VERIFIED"
        elif doc_id in candidates:
            reason = "NO_MATCHING_REQUIREMENT"
        elif str(doc.get("content_status") or "").upper() in _NON_FULL_TEXT | {"PARTIAL_TEXT"}:
            reason = "CLAIM_NOT_VERIFIED"
        elif _topic_matches(query, str(doc.get("title") or "") + " " + str(doc.get("text") or "")):
            reason = "RELATED_CONTEXT_ONLY"
        else:
            reason = "NO_MATCHING_REQUIREMENT"
        reasons[doc_id] = reason
    return reasons


def build_runtime_kiq_answers(
    report: EWSReport,
    kiq_plan: KIQPlan,
    collected_docs: List[Dict[str, Any]],
    selected_platforms: List[str] | None = None,
    accepted_document_ids: set[str] | None = None,
    user_query: str = "",
    searched_source_ids: set[str] | None = None,
    connector_telemetry: Optional[Dict[str, Any]] = None,
) -> List[KIQAnswer]:
    """Link every question to all eligible evidence, regardless of its platform."""
    if connector_telemetry is None:
        connector_telemetry = getattr(report, "connector_status", None) or {}
    approved = accepted_document_ids
    eligible = [doc for doc in collected_docs
                if approved is None or doc.get("doc_id") in approved]
    raw_ids = {doc["doc_id"] for doc in collected_docs if doc.get("doc_id")}
    known_sources = set().union(*(pair[0] for pair in _SOURCE_GROUPS.values()))
    selected = {str(value).strip().lower() for value in (selected_platforms or [])}
    enabled_sources = (
        known_sources if selected_platforms is None else
        set().union(*(ids for ids, names in _SOURCE_GROUPS.values() if names & selected))
    )
    enabled_sources |= {doc["source_id"] for doc in collected_docs if doc.get("source_id")}
    threats = list(report.threats or []) + list(report.related_program_watchlist or [])

    catalog = [a for a in report.kiq_answers if not str(a.kiq_id).startswith("RKIQ_")]
    if approved is not None:
        for answer in catalog:
            answer.evidence_ids = [i for i in (answer.evidence_ids or []) if i in approved]
            if answer.answer_status in {"ANSWERED", "PARTIALLY_ANSWERED"} and not answer.evidence_ids:
                answer.related_event_ids = []
                answer.answer_status = "UNANSWERED"
                answer.evidence_coverage = "NONE"
                answer.answer = "Previously cited evidence was not cleared by FR03."
                answer.verification_status = "FR03 evidence eligibility not established"

    runtime = []
    for index, item in enumerate(_runtime_questions(user_query, kiq_plan), 1):
        query, required_keys = item["query"], item["keys"]
        kiq_id = f"RKIQ_{index:03d}"
        cutoff = _as_of_date(query)
        applicable = [doc for doc in eligible if _available_as_of(doc, cutoff)]
        scoped_documents = {doc["doc_id"]: doc for doc in applicable if doc.get("doc_id")}
        matched, assessment_claims = _threat_claims(query, threats, scoped_documents)
        claim_rejection_reasons: Dict[str, str] = {}
        source_claims = _document_claims(
            query, applicable, approved, kiq_id, rejected=claim_rejection_reasons,
            required_keys=required_keys,
        )
        official = _official_faa_certification_for_kiq(query, applicable)
        if official and official.get("doc_id") in scoped_documents:
            issued_on = (_date_str(official.get("regulatory_decision_date"))
                         if _date_mentioned(official.get("text", ""),
                                            official.get("regulatory_decision_date")) else "")
            source_claims.append({
                "doc_id": official["doc_id"],
                "text": official["verified_quote"],
                "state": "ISSUE_RESOLVED",
                "date": issued_on or _published_date(official),
                "event_date": issued_on,
                "publication_date": _published_date(official),
                "date_basis": "EVENT_DATE" if issued_on else "PUBLICATION_DATE_ONLY",
                "strength": "VERIFIED",
                "source_id": official.get("source_id"),
                "authority": "REGULATOR",
                "source_url": str(official.get("url") or ""),
                "verification_reason": "FAA_PRIMARY_FULL_TEXT",
            })
        else:
            official = None
        regulator_facts = []
        explicit_reg_ids = {m.group().upper() for m in _FAA_DOC_NUMBER_RE.finditer(query)} | {
            m.group().upper() for m in _FAA_DOCKET_RE.finditer(query)
        }
        if "REGULATORY" in _lifecycle_topics(query) or any(
                key.startswith(("REGULATORY", "COMPLIANCE", "INSPECTION"))
                for key in required_keys
        ) or "PROGRAM_APPLICABILITY" in required_keys and re.search(
            r"\b(?:FAA|airworthiness|directive|regulat\w*)\b", query, re.I
        ):
            candidate_reg_docs = list(applicable)
            if explicit_reg_ids:
                for doc in collected_docs:
                    if doc.get("source_id") == "SRC_001" and _available_as_of(doc, cutoff):
                        doc_txt = f"{doc.get('title') or ''} {doc.get('text') or ''} {doc.get('url') or ''}".upper()
                        if any(rid in doc_txt for rid in explicit_reg_ids) and doc not in candidate_reg_docs:
                            candidate_reg_docs.append(doc)
            for doc in candidate_reg_docs:
                if doc.get("source_id") == "SRC_001":
                    fact = _scoped_faa_publication_fact(query, doc, cutoff)
                    if fact:
                        regulator_facts.append(fact)
                        source_claims.extend(fact.get("verified_field_claims") or [])
        claims, duplicate_ids = _dedupe_claims(assessment_claims + source_claims)
        supported = [t for t in matched if (
            t.validation_status == ValidationStatus.SUPPORTED
            and t.program_relevance == "DIRECT_KIT_MATCH"
            and t.claim_support_status == "STATED_IN_SOURCE"
        )]
        preliminary = [t for t in matched if t not in supported]

        matched_ids = {c["doc_id"] for c in claims}
        matched_ids.update(f["document_id"] for f in regulator_facts if f.get("document_id"))
        relevant_raw = {str(doc.get("doc_id")) for doc in collected_docs if doc.get("doc_id")
                        and (str(doc.get("doc_id")) in matched_ids or
                             (_topic_matches(query, str(doc.get("title") or "") + " " +
                                             str(doc.get("text") or "")) and
                              _scope_matches(query, str(doc.get("text") or ""), doc)))}
        source_status = _source_execution_status(
            query, bool(enabled_sources), enabled_sources,
            bool(relevant_raw), searched_source_ids, connector_telemetry,
            raw_document_count=len(relevant_raw),
            eligible_document_count=len(relevant_raw & set(scoped_documents)),
        )
        # Failed or unverified execution is not evidence that no search was
        # attempted. NOT_SEARCHED is reserved for explicit nonexecution.
        searched = source_status not in {"SOURCE_NOT_SELECTED", "QUERY_NOT_EXECUTED"}
        requirements = build_atomic_kiq_requirements(
            query, kiq_id, supported, preliminary, regulator_facts, official,
            set(scoped_documents), searched, claims, required_keys,
        )
        verified = [r for r in requirements if r["verification_status"] == "VERIFIED"]
        tentative = [r for r in requirements if r["verification_status"] == "PRELIMINARY"]
        missing = [r for r in requirements if r["verification_status"] != "VERIFIED"]
        if not searched and not claims and not regulator_facts:
            answer_status = "NOT_SEARCHED"
        elif requirements and len(verified) == len(requirements):
            answer_status = "ANSWERED"
        elif verified or tentative:
            answer_status = "PARTIALLY_ANSWERED"
        else:
            answer_status = "UNANSWERED"

        coverage = (
            "SUPPORTED" if answer_status == "ANSWERED" else
            "PARTIAL" if verified or tentative else "NONE"
        )
        evidence_ids = sorted({doc_id for requirement in requirements
                               for doc_id in requirement["doc_ids"]})
        contributing_claims = [claim for claim in claims if claim["doc_id"] in evidence_ids]
        content_result = _content_result(contributing_claims, searched, query)
        if regulator_facts and content_result == "NO_RELEVANT_EVENT":
            content_result = "STATUS_UNKNOWN"
        latest = max((c["date"] for c in contributing_claims if c.get("date")), default="")
        temporal = ("HISTORICAL_ONLY" if cutoff and latest else
                    "CURRENT_OR_ONGOING" if latest and content_result not in {
                        "STATUS_UNKNOWN", "STATUS_CONFLICTED"
                    } else "UNKNOWN")
        verified_ids = {did for requirement in verified for did in requirement["verified_doc_ids"]}
        dispositions = _document_dispositions(
            query, collected_docs, approved, cutoff, set(evidence_ids), claims, duplicate_ids,
            claim_rejection_reasons,
        )
        distinct_sources = len({c.get("source_url") or c["doc_id"] for c in contributing_claims
                                if c["doc_id"] in verified_ids})
        linked = [threat for threat in matched if set(threat.evidence_ids or []) & set(evidence_ids)]
        events = list(dict.fromkeys(threat.event_id for threat in linked))
        for threat in linked:
            if kiq_id not in threat.kiq_ids:
                threat.kiq_ids.append(kiq_id)

        authority_labels = {
            "REGULATOR": "official regulatory record",
            "ISSUER_DISCLOSURE": "official issuer filing",
            "ISSUER_RELEASE": "official company press release",
            "ANALYST_ASSESSMENT": "validated source record",
            "SECONDARY": "secondary media report",
        }
        status_phrases = {
            "ISSUE_RESOLVED": "Confirmed regulatory evidence indicates that the tracked milestone or issue has been resolved.",
            "ISSUE_REPORTED_RESOLVED": "Available filings and media reports indicate that the tracked milestone has been achieved, though direct confirmation from the regulator itself is still pending.",
            "ISSUE_ACTIVE": "Current evidence confirms that the issue remains active.",
            "ISSUE_REPORTED_ACTIVE": "Available reporting suggests the issue remains active, pending primary confirmation.",
            "ISSUE_PARTIALLY_RESOLVED": "Evidence points to partial resolution, with residual items still open.",
            "ISSUE_WORSENED": "Recent evidence indicates the situation has deteriorated.",
            "STATUS_CONFLICTED": "Sources from the same period present conflicting accounts that require reconciliation.",
            "NO_RELEVANT_EVENT": "No relevant event matching this question was found within the searched sources.",
        }

        def _clean_snippet(raw_text: str, limit: int = 230) -> str:
            cleaned = " ".join(str(raw_text or "").split()).strip()
            cleaned = re.sub(r"^(?:Definitions:|Reason:|Official Summary:)\s*", "", cleaned, flags=re.I)
            if len(cleaned) <= limit:
                return cleaned.rstrip(" ;,")
            cut = cleaned[:limit].rsplit(" ", 1)[0].rstrip(" .,;:")
            return cut + "…"

        answer_parts: List[str] = []
        if cutoff:
            answer_parts.append(f"As of {cutoff}:")
        if content_result in status_phrases:
            answer_parts.append(status_phrases[content_result])
        elif answer_status == "ANSWERED":
            answer_parts.append("Reviewed primary sources directly address this question.")
        elif answer_status == "PARTIALLY_ANSWERED":
            answer_parts.append(
                "Reviewed sources address part of this question, while specific verification items remain open.")
        elif answer_status == "NOT_SEARCHED":
            answer_parts.append("This question was not covered by the sources selected for this run.")
        else:
            answer_parts.append(
                "No directly matching source passage was found for this question in the current dataset; this does not prove the absence of the issue.")

        if regulator_facts:
            answer_parts.append(str(regulator_facts[0].get("answer", "")).strip())

        timeline = sorted(
            (c for c in contributing_claims if c.get("date") and c.get("state") != "STATUS_UNKNOWN"),
            key=lambda c: (c["date"], c.get("publication_date", "")),
        )
        candidate_notes = list(reversed(timeline)) + [c for c in contributing_claims if c not in timeline]
        seen_snippets = set()
        finding_sentences: List[str] = []
        for claim in candidate_notes:
            snippet = _clean_snippet(claim.get("quote") or claim.get("text") or "", limit=220)
            norm_key = snippet[:90].casefold()
            if len(snippet) < 25 or norm_key in seen_snippets:
                continue
            seen_snippets.add(norm_key)
            src_label = authority_labels.get(str(claim.get("authority") or "").upper(), "reviewed source")
            dt_str = f" on {claim['date']}" if claim.get("date") else ""
            finding_sentences.append(f"A {src_label}{dt_str} notes that “{snippet}” [{claim['doc_id']}].")
            if len(finding_sentences) >= 3:
                break
        if finding_sentences:
            answer_parts.append(" ".join(finding_sentences))

        forecasts = list(dict.fromkeys(
            f"“{_clean_snippet(c['text'], 170)}” [{c['doc_id']}]"
            for c in contributing_claims if c.get("claim_type") == "FORECAST"
        ))[:2]
        if forecasts:
            answer_parts.append(
                "Forward-looking expectations (not yet confirmed outcomes): " + "; ".join(forecasts) + ".")

        verified_facts = [r["required_fact"].lower() for r in verified]
        missing_facts = [r["required_fact"].lower() for r in missing]
        if verified_facts and missing_facts:
            answer_parts.append(
                f"Evidence establishes {', '.join(verified_facts[:3])}, whereas {', '.join(missing_facts[:3])} still require direct confirmation."
            )
        elif verified_facts:
            answer_parts.append(
                f"All required points ({', '.join(verified_facts[:4])}) are supported by the cited documents.")
        elif missing_facts and answer_status != "NOT_SEARCHED":
            answer_parts.append(f"Still needed for a complete answer: {', '.join(missing_facts[:3])}.")

        if evidence_ids:
            answer_parts.append(
                f"Based on {len(evidence_ids)} relevant document(s) ({', '.join(evidence_ids[:5])}) out of {len(scoped_documents)} evaluated."
            )

        missing_text = "; ".join(
            f"{r['required_fact']}: {', '.join(r['missing_information'])}"
            for r in missing
        )
        answer = " ".join(part.strip() for part in answer_parts if part and part.strip())
        details = {
            "evidence_requirements": requirements,
            "claim_requirement_links": [
                {"claim_id": supporting.get("claim_id", ""),
                 "doc_id": supporting.get("doc_id", ""),
                 "requirement_id": requirement["id"],
                 "requirement_key": requirement["key"],
                 "rkiq_id": kiq_id,
                 "strength": supporting.get("strength", "PRELIMINARY")}
                for requirement in requirements
                for supporting in requirement.get("supporting_claims") or []
            ],
            "claim_handoff_rejections": claim_rejection_reasons,
            "source_execution_status": source_status,
            "content_result": content_result,
            "issue_status": content_result,
            "unused_document_reasons": dispositions,
            # Trace *the actual claim-to-requirement link*, not every sentence
            # from a document used by some other requirement. A verified FAA
            # field survives even when it carries no analytical event text.
            "evidence_trace": list({
                (support.get("doc_id", ""), requirement["id"],
                 support.get("passage_hash", ""), support.get("claim_type", "")): {
                    "kiq_id": kiq_id, "kit_id": support.get("kit_id", ""),
                    "requirement_id": requirement["id"],
                    "requirement_key": requirement["key"],
                    "doc_id": support.get("doc_id", ""),
                    "source_id": support.get("source_id", ""),
                    "issuer_name": support.get("issuer_name", ""),
                    "issuer_cik": support.get("issuer_cik", ""),
                    "source_url": support.get("source_url", ""),
                    "original_filing_url": support.get("original_filing_url", ""),
                    "quote": support.get("quote", ""),
                    "source_hash": support.get("source_hash", ""),
                    "passage_hash": support.get("passage_hash", ""),
                    "extraction_method": support.get("extraction_method", ""),
                    "passage_validation_status": support.get("passage_validation_status", ""),
                    "claim_strength": support.get("strength", "PRELIMINARY"),
                    "claim_state": support.get("claim_state", "STATUS_UNKNOWN"),
                    "claim_type": support.get("claim_type", "OBSERVED"),
                    "verification_reason": support.get("verification_reason", ""),
                    "publication_date": support.get("publication_date", ""),
                    "event_date": support.get("event_date", ""),
                    "authority": support.get("authority", ""),
                    "document_number": support.get("document_number", ""),
                    "regulatory_stage": support.get("regulatory_stage", ""),
                    "effective_date": support.get("effective_date", ""),
                    "effective_as_of_reference_date": support.get(
                        "effective_as_of_reference_date"
                    ),
                    "reference_date": support.get("reference_date", ""),
                    "lifecycle_verified": support.get("lifecycle_verified"),
                    "supersession_status": support.get("supersession_status", ""),
                    "applicable_variants": support.get("applicable_variants", []),
                }
                for requirement in requirements
                for support in requirement.get("supporting_claims") or []
                if support.get("doc_id") in requirement["doc_ids"]
                and (support.get("quote") or support.get("claim_type") ==
                     "REGULATORY_DOCUMENT_IDENTITY")
            }.values()),
        }
        optional = getattr(KIQAnswer, "model_fields", {})
        extra = {field: value for field, value in details.items() if field in optional}
        missing_contract_fields = {field: value for field, value in details.items() if field not in optional}
        if missing_contract_fields:
            report.run_metadata = dict(getattr(report, "run_metadata", None) or {})
            prior_audit = report.run_metadata.get("kiq_runtime_audit")
            audit = dict(prior_audit) if isinstance(prior_audit, dict) else {}
            audit[kiq_id] = missing_contract_fields
            report.run_metadata["kiq_runtime_audit"] = audit
        runtime.append(KIQAnswer(
            kiq_id=kiq_id,
            question=item["question"],
            answer_status=answer_status,
            evidence_coverage=coverage,
            temporal_relevance=temporal,
            answer=answer,
            related_event_ids=events,
            evidence_ids=evidence_ids,
            retrieved_evidence_count=len(relevant_raw),
            validated_evidence_count=len(verified_ids),
            retrieved_document_ids=sorted(relevant_raw),
            verification_status=(
                f"Verified {len(verified)}/{len(requirements)} atomic facts; {source_status}"
            ),
            uncertainty_level=(
                ConfidenceLevel.LOW if answer_status == "ANSWERED" else
                ConfidenceLevel.MEDIUM if verified else ConfidenceLevel.HIGH
            ),
            recommended_next_step=(
                "Monitor independently for new developments and downstream effects."
                if answer_status == "ANSWERED" else
                "Verify missing claims in dated, directly applicable primary records: "
                + ", ".join(r["required_fact"] for r in missing[:3])
            ),
            missing_information=missing_text or None,
            **extra,
        ))
    return catalog + runtime

# Aggregate the verification states of runtime KIQ answers.
# Status counts are used to report unanswered intelligence requirements transparently.
def runtime_kiq_status_counts(answers: List[KIQAnswer]) -> Dict[str, int]:
    """Count runtime KIQ answers by verification status."""
    statuses = [a.answer_status for a in answers if str(a.kiq_id).startswith("RKIQ_")]
    return {
        "runtime_kiq_answered": statuses.count("ANSWERED"),
        "runtime_kiq_partially_answered": statuses.count("PARTIALLY_ANSWERED"),
        "runtime_kiq_unanswered": statuses.count("UNANSWERED"),
        "runtime_kiq_not_searched": statuses.count("NOT_SEARCHED"),
    }
