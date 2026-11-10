"""General evidence contract for verified regulator documents.

A relevant technical source can be analyzed without proving every aircraft
applicability or downstream-impact claim. No aircraft-specific branching.
"""
from __future__ import annotations

import re
from datetime import date
from urllib.parse import urlparse
from typing import Any

# Issue ontology, NOT aircraft/model-specific exceptions. Extend as data.
ISSUES: dict[str, tuple[str, ...]] = {
    "AIRWORTHINESS_DIRECTIVE": (r"\bairworthiness\s+directives?\b", r"\b(?:faa|easa)\s+ad\b"),
    "MINIMUM_EQUIPMENT_LIST": (r"\bminimum\s+equipment\s+lists?\b", r"\bmel\b"),
    "CERTIFICATION": (r"\bcertif\w*\b", r"\btype\s+approval\b"),
    "INSPECTION": (r"\binspect\w*\b", r"\bborescope\b"),
    "SHORTAGE": (r"\bshortag\w*\b", r"\bsupply\s+constraints?\b", r"\bbottlenecks?\b"),
    "ORDER": (r"\b(?:firm\s+)?orders?\b", r"\b(?:aircraft\s+)?contracts?\b"),
}

COMPONENTS: dict[str, tuple[str, ...]] = {
    "HPT": (r"\bhpt\b", r"\bhigh[ -]pressure\s+turbine\b"),
    "HPC": (r"\bhpc\b", r"\bhigh[ -]pressure\s+compressor\b"),
    "FAN": (r"\bfan\s+(?:blade|rotor|case)\b",),
}


# Match a value against the configured issue or component patterns.
def _found(patterns: tuple[str, ...], value: str) -> bool:
    return any(re.search(p, value, flags=re.I) for p in patterns)


# Exclude explicitly negated targets from the requested evidence scope.
def _requested_positive_part(question: str) -> str:
    # Exclusions are constraints, not positive target entities.
    return re.split(r"\b(?:exclude|excluding|except)\b", question, maxsplit=1, flags=re.I)[0]


def assess_official_faa_fact(question: str, doc: dict[str, Any]) -> dict[str, Any] | None:
    """Validate the existence and scope of a dated FAA record (NOT its downstream impacts).

    Returns None for an unsupported topic. Otherwise the verified fact and
    whether the question is fully answerable from this source alone.
    """
    if doc.get("source_id") != "SRC_001":
        return None
    url = str(doc.get("url") or "")
    u = urlparse(url)
    if u.scheme != "https" or u.hostname not in ("federalregister.gov", "www.federalregister.gov"):
        return None
    if not u.path.startswith("/documents/"):
        return None

    text = str(doc.get("text") or "")
    title = str(doc.get("title") or "")
    facts = f"{title}\n{text}"
    if not re.search(r"(?im)^Regulatory Lifecycle Check:\s*VERIFIED\s*$", text):
        return None
    if not re.search(r"(?im)^FAA Docket:\s*FAA-\d{4}-\d+\s*$", text):
        return None
    stage_match = re.search(r"(?im)^Regulatory Stage:\s*(PROPOSED|FINAL_ISSUED|EFFECTIVE)\s*$", text)
    if not stage_match:
        return None
    summary_match = re.search(r"(?im)^Official Summary:\s*(.+)$", text)
    if not summary_match or len(summary_match.group(1).strip()) < 30:
        return None
    docno_match = re.search(r"(?im)^Federal Register Document:\s*(20\d{2}-\d{5})\s*$", text)
    docno = docno_match.group(1) if docno_match else None
    wanted_numbers = set(re.findall(r"(?<!\d)20\d{2}-\d{5}(?!\d)", question))
    if wanted_numbers and (docno not in wanted_numbers):
        return None

    from ews_validation import _detect_engine_models, _engine_models_match, _detect_exact_variants, _detect_aircraft_families

    positive_question = _requested_positive_part(question)
    if _detect_engine_models(positive_question) and not _engine_models_match(positive_question, facts):
        return None

    req_comp = {n for n, pats in COMPONENTS.items() if _found(pats, positive_question)}
    doc_comp = {n for n, pats in COMPONENTS.items() if _found(pats, facts)}
    if req_comp and not req_comp.issubset(doc_comp):
        return None

    wanted_issue = {n for n, pats in ISSUES.items() if _found(pats, positive_question)}
    # A source may verify a KIQ's AD status even if not its inspection impact.
    # The principal issue must be evidenced by the primary-source summary/title.
    principal = {x for x in wanted_issue if x in {"AIRWORTHINESS_DIRECTIVE", "MINIMUM_EQUIPMENT_LIST", "CERTIFICATION", "SHORTAGE", "ORDER"}}
    documented = {n for n, pats in ISSUES.items() if _found(pats, facts)}
    is_comparison = bool(re.search(r"\b(?:compare|versus|vs\.?)\b", positive_question, re.I))
    if principal and (not (principal & documented) if is_comparison else not principal.issubset(documented)):
        return None

    req_exact = _detect_exact_variants(positive_question)
    doc_exact = _detect_exact_variants(facts)
    req_families = _detect_aircraft_families(positive_question)
    doc_families = _detect_aircraft_families(facts)
    # Different explicitly named aircraft = not directly applicable.
    if req_families and doc_families and not (req_families & doc_families):
        return None
    if req_exact and doc_exact and not (req_exact & doc_exact):
        return None

    missing_program_proof = bool(
        (req_families and not doc_families) or (req_exact and not doc_exact)
    )
    stage = stage_match.group(1)
    eff_m = re.search(r"(?im)^Effective Date:\s*(\d{4}-\d{2}-\d{2})\s*$", text)
    eff_date = eff_m.group(1) if eff_m else None
    # A narrow factual status/number/date question can be answered without an event.
    # A broad operational or causal question cannot.
    q = question.lower()
    asks_impact = bool(re.search(r"\b(?:impact|production|deliver\w*|shortage|fleet|operation\w*|grounding|consequence|cause|risk|maintenance|spare\s+engine)\b", q))
    narrow_fact_question = bool(wanted_numbers or re.search(r"\b(?:effective\s+date|publication\s+date|issued\s+on)\b", q))
    wants_effective_date = bool(re.search(r"\beffective(?:\s+date|\s+on|\s+\w+\s+\d{1,2})\b", q))
    complete = bool(
        narrow_fact_question and not asks_impact and not missing_program_proof
        and not is_comparison and (not wants_effective_date or bool(eff_date))
    )

    status_note = f"FAA document {docno or 'UNKNOWN'} has verified regulatory stage {stage}"
    status_note += f"; publication {doc.get('published_at') or 'UNKNOWN'}"
    if eff_date:
        status_note += f"; effective date {eff_date}"
    else:
        status_note += "; effective date not established"
    status_note += f"; source {url}."
    if stage == "PROPOSED":
        status_note += " Proposal only; no effective obligation is established."
    elif stage == "FINAL_ISSUED":
        status_note += " Final issuance does not mean the effective date has passed."
    if missing_program_proof:
        status_note += " Applicability to the specific requested aircraft configuration is unverified."
    if asks_impact:
        status_note += " Operational or economic impact remains unverified."
    return {
        "document_id": str(doc.get("doc_id") or ""),
        "stage": stage,
        "effective_date": eff_date,
        "complete": complete,
        "program_unverified": missing_program_proof,
        "answer": status_note,
    }
