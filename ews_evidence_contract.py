"""Conservative evidence contract for FAA Federal Register documents.

Confirms the identified publication and its regulatory status, not aircraft
installation, compliance, causality or economic impacts without further proof.
"""
from __future__ import annotations

import os
import re
from datetime import date, datetime, timezone
from typing import Any
from urllib.parse import urlparse


# Generic issue and component ontology; no aircraft-specific exceptions.
ISSUES: dict[str, tuple[str, ...]] = {
    "AIRWORTHINESS_DIRECTIVE": (r"\bairworthiness\s+directives?\b", r"\b(?:faa|easa)\s+ad\b"),
    "MINIMUM_EQUIPMENT_LIST": (r"\bminimum\s+equipment\s+lists?\b", r"\bmel\b"),
    "CERTIFICATION": (r"\bcertif\w*\b", r"\b(?:type|regulatory)\s+approv\w*\b"),
    "INSPECTION": (r"\binspect\w*\b", r"\bborescope\b"),
    "SHORTAGE": (r"\bshortag\w*\b", r"\bsupply\s+constraints?\b", r"\bbottlenecks?\b"),
    "ORDER": (r"\b(?:firm\s+)?orders?\b", r"\b(?:aircraft\s+)?contracts?\b"),
    "DELAY": (r"\bdelay\w*\b", r"\bpostpon\w*\b", r"\breschedul\w*\b", r"\bpush(?:ed)?\s+back\b"),
}
COMPONENTS: dict[str, tuple[str, ...]] = {
    "HPT": (r"\bhpt\b", r"\bhigh[ -]pressure\s+turbine\b"),
    "HPC": (r"\bhpc\b", r"\bhigh[ -]pressure\s+compressor\b"),
    "FAN": (r"\bfan\s+(?:blade|rotor|case)\b",),
    "GEARBOX": (r"\bgear\s*box(?:es)?\b", r"\baccessory\s+gearbox\b"),
}
_DOCKET = re.compile(r"(?<![A-Z0-9])FAA-20\d{2}-\d{3,7}(?!\d)", re.I)
_DOCNO = re.compile(r"(?<![A-Z0-9-])20\d{2}-\d{4,6}(?!\d)", re.I)
_RELATIONS = {"SUPERSEDED_BY", "SUPERSEDES", "AMENDS", "WITHDRAWN", "REPLACES", "RELATED_DOCKET"}
_MANUFACTURERS = ("BOEING", "AIRBUS", "EMBRAER", "BOMBARDIER", "ATR")


def _found(patterns: tuple[str, ...], value: str) -> bool:
    return any(re.search(pattern, value, re.I) for pattern in patterns)


def _requested_positive_part(question: str) -> str:
    return re.split(r"\b(?:exclude|excluding|except)\b", question, maxsplit=1, flags=re.I)[0]


def _field(text: str, label: str) -> str:
    match = re.search(rf"(?im)^[ \t]*{re.escape(label)}:[ \t]*([^\r\n]*)", text)
    return match.group(1).strip() if match else ""


def _date_value(value: Any) -> str | None:
    try:
        raw = str(value or "")[:10]
        return date.fromisoformat(raw).isoformat()
    except ValueError:
        return None


def _consistent_date(*values: Any) -> tuple[str | None, bool]:
    supplied = [value for value in values if value and str(value).upper() not in {
        "NOT_ESTABLISHED", "DATE_UNKNOWN", "UNKNOWN",
    }]
    dates = {_date_value(value) for value in supplied} - {None}
    conflict = len(dates) > 1 or any(_date_value(value) is None for value in supplied)
    return (next(iter(dates)) if len(dates) == 1 and not conflict else None, conflict)


def _ids(value: Any, pattern: re.Pattern[str]) -> set[str]:
    parts = value if isinstance(value, (list, tuple, set)) else [value]
    return {match.group().upper() for item in parts
            for match in pattern.finditer(str(item or ""))}


def _relationships(doc: dict[str, Any], text: str, number: str) -> list[dict[str, str]]:
    """Keep explicit links and unverified metadata candidates distinct."""
    entries = []
    fields = {
        "SUPERSEDED_BY": ("superseded_by", "Superseded By"),
        "SUPERSEDES": ("supersedes", "Supersedes"),
        "AMENDS": ("amends", "Amends"),
        "REPLACES": ("replaces", "Replaces"),
        "RELATED_DOCKET": ("related_dockets", "Related Docket"),
        "WITHDRAWN": ("withdraws", "Withdraws"),
    }
    for kind, (key, label) in fields.items():
        pattern = _DOCKET if kind == "RELATED_DOCKET" else _DOCNO
        verified = _ids(_field(text, label), pattern)
        candidates = _ids(doc.get(key), pattern)
        entries.extend({"type": kind, "target": value, "verification_status": "VERIFIED",
                        "basis": "OFFICIAL_LABELED_FIELD"} for value in sorted(verified))
        entries.extend({"type": kind, "target": value, "verification_status": "UNVERIFIED",
                        "basis": "METADATA_ONLY"} for value in sorted(candidates - verified))

    structured = doc.get("regulatory_relationships") or []
    for item in structured if isinstance(structured, list) else []:
        if not isinstance(item, dict):
            continue
        kind = str(item.get("type") or "").upper()
        target_ids = _ids(item.get("target"), _DOCKET if kind == "RELATED_DOCKET" else _DOCNO)
        if kind in _RELATIONS:
            excerpt = str(item.get("evidence_excerpt") or "").strip()
            verb = {"SUPERSEDED_BY": r"supersed\w*\s+by", "SUPERSEDES": r"supersed\w*",
                    "AMENDS": r"amend\w*", "REPLACES": r"replac\w*",
                    "WITHDRAWN": r"withdraw\w*|rescinded?", "RELATED_DOCKET": r"docket"}[kind]
            for target in sorted(target_ids):
                grounded = (len(excerpt) >= 25 and excerpt in text and target.lower() in excerpt.lower()
                            and re.search(verb, excerpt, re.I))
                entries.append({"type": kind, "target": target,
                                "verification_status": "VERIFIED" if grounded else "UNVERIFIED",
                                "basis": "SOURCE_PASSAGE" if grounded else "STRUCTURED_CLAIM_UNVERIFIED"})

    merged: dict[tuple[str, str], dict[str, str]] = {}
    for entry in entries:
        if not entry["target"] or entry["target"] == number and entry["type"] != "WITHDRAWN":
            continue
        key = entry["type"], entry["target"]
        if key not in merged or entry["verification_status"] == "VERIFIED":
            merged[key] = entry
    return [merged[key] for key in sorted(merged)]


def _as_of_date() -> date:
    replay = _date_value(os.getenv("EWS_AS_OF_DATE"))
    return date.fromisoformat(replay) if replay else datetime.now(timezone.utc).date()


def inspect_official_faa_publication(doc: dict[str, Any]) -> dict[str, Any] | None:
    """Verify a Federal Register record's existence, without validating its technical claims."""
    if doc.get("source_id") != "SRC_001":
        return None
    try:
        parsed = urlparse(str(doc.get("url") or ""))
        host = parsed.hostname
        credentials = parsed.username or parsed.password
    except ValueError:
        return None
    if (parsed.scheme != "https" or host not in {
        "federalregister.gov", "www.federalregister.gov",
    } or credentials):
        return None
    path = re.fullmatch(
        r"/documents/(?:20\d{2}/\d{2}/\d{2}/)?(20\d{2}-\d{4,6})(?:/[^/?]*)?/?", parsed.path,
    )
    if not path:
        return None
    text = str(doc.get("text") or "")
    line_numbers = _ids(_field(text, "Federal Register Document"), _DOCNO)
    metadata_numbers = _ids(doc.get("faa_document_number"), _DOCNO)
    if ((line_numbers and metadata_numbers and line_numbers != metadata_numbers)
            or len(line_numbers | metadata_numbers) != 1
            or path.group(1) not in (line_numbers | metadata_numbers)):
        return None
    line_dockets = _ids(_field(text, "FAA Docket"), _DOCKET)
    metadata_dockets = (_ids(doc.get("faa_docket_id") or doc.get("docket_id"), _DOCKET)
                        | _ids(doc.get("docket_ids"), _DOCKET))
    if line_dockets and metadata_dockets and not line_dockets.issubset(metadata_dockets):
        return None
    publication, conflict = _consistent_date(
        _field(text, "Publication Date"), doc.get("regulatory_publication_date"), doc.get("published_at")
    )
    if not publication or conflict or date.fromisoformat(publication) > _as_of_date():
        return None
    return {
        "document_number": path.group(1), "docket_ids": sorted(line_dockets or metadata_dockets),
        "publication_date": publication, "document_existence_verified": True,
        "verification_basis": "OFFICIAL_URL_AND_CONSISTENT_DOCUMENT_METADATA",
        "content_evidence_status": "UNVERIFIED", "source_url": parsed.geturl(),
    }


def assess_official_faa_fact(question: str, doc: dict[str, Any]) -> dict[str, Any] | None:
    """Return a scoped FAA fact or None when its source/identity/event conflicts.

    ``complete`` means a narrow factual KIT can be answered from this source
    alone. Partial evidence carries named ``missing_evidence`` and must never
    be treated as confirmation of the missing aircraft/impact claim.
    """
    publication_record = inspect_official_faa_publication(doc)
    if not publication_record:
        return None
    if str(doc.get("content_status") or doc.get("source_content_status") or "").upper() in {
        "METADATA_ONLY", "SUMMARY_ONLY", "TRUNCATED", "SOURCE_ACCESS_BLOCKED", "UNAVAILABLE",
    }:
        return None
    url = str(doc.get("url") or "")

    text = str(doc.get("text") or "")
    title = str(doc.get("title") or "")
    if _field(text, "Regulatory Lifecycle Check").upper() != "VERIFIED":
        return None
    stage = _field(text, "Regulatory Stage").upper()
    if stage not in {"PROPOSED", "FINAL_ISSUED", "EFFECTIVE", "WITHDRAWN"}:
        return None
    if doc.get("regulatory_stage") and str(doc["regulatory_stage"]).upper() != stage:
        return None
    summary = _field(text, "Official Summary")
    if len(summary) < 30:
        return None

    # Keep primary document identity separate from later publications in its docket.
    number = publication_record["document_number"]

    line_dockets = _ids(_field(text, "FAA Docket"), _DOCKET)
    if not line_dockets:
        return None
    actual_dockets = line_dockets
    positive_question = _requested_positive_part(question)
    wanted_numbers = _ids(positive_question, _DOCNO)
    wanted_dockets = _ids(positive_question, _DOCKET)
    if (wanted_numbers and number not in wanted_numbers) or (
            wanted_dockets and not wanted_dockets.intersection(actual_dockets)):
        return None

    # Only title + official summary establish the event; registry authority alone is insufficient.
    from aero_ews.domain.identity import (
        _detect_aircraft_families, _detect_engine_models, _detect_exact_variants, _engine_models_match,
    )

    facts = f"{title}\n{summary}"
    requested_makers = {name for name in _MANUFACTURERS if re.search(rf"\b{name}\b", positive_question, re.I)}
    documented_makers = {name for name in _MANUFACTURERS if re.search(rf"\b{name}\b", facts, re.I)}
    if requested_makers and not requested_makers.issubset(documented_makers):
        return None
    requested_issues = {name for name, patterns in ISSUES.items() if _found(patterns, positive_question)}
    documented_issues = {name for name, patterns in ISSUES.items() if _found(patterns, facts)}
    is_comparison = bool(re.search(r"\b(?:compare|versus|vs\.?)\b", positive_question, re.I))
    # Secondary inspection details may be absent even when AD existence is verified.
    primary = requested_issues - {"INSPECTION"} or requested_issues
    if primary and (not primary.intersection(documented_issues) if is_comparison
                    else not primary.issubset(documented_issues)):
        return None

    requested_engines, documented_engines = _detect_engine_models(positive_question), _detect_engine_models(facts)
    if requested_engines and documented_engines and not _engine_models_match(positive_question, facts):
        return None
    wanted_families, found_families = _detect_aircraft_families(positive_question), _detect_aircraft_families(facts)
    wanted_variants, found_variants = _detect_exact_variants(positive_question), _detect_exact_variants(facts)
    if ((wanted_families and found_families and not wanted_families.intersection(found_families))
            or (wanted_variants and found_variants and not wanted_variants.intersection(found_variants))):
        return None
    # A model named in the title cannot lend its applicability to an unrelated
    # model explicitly identified in the substantive summary.
    summary_variants = _detect_exact_variants(summary)
    summary_families = _detect_aircraft_families(summary)
    if ((wanted_variants and summary_variants and not wanted_variants.intersection(summary_variants))
            or (wanted_families and summary_families and not wanted_families.intersection(summary_families))):
        return None

    missing: list[str] = []
    if (wanted_families and not found_families) or (wanted_variants and not found_variants) or (
            requested_engines and not documented_engines):
        return None
    required_components = {name for name, pats in COMPONENTS.items() if _found(pats, positive_question)}
    supported_components = {name for name, pats in COMPONENTS.items() if _found(pats, summary)}
    if required_components - supported_components:
        return None
    if re.search(r"\bEASA\b", positive_question, re.I):
        return None
    if requested_issues - documented_issues:
        missing.append("SECONDARY_ISSUE_NOT_EVIDENCED")
    if is_comparison:
        missing.append("COMPARISON_REQUIRES_ADDITIONAL_SOURCES")
    publication = publication_record["publication_date"]
    today = _as_of_date()
    effective, effective_conflict = _consistent_date(
        _field(text, "Effective Date"), doc.get("regulatory_effective_date")
    )
    deadline, deadline_conflict = _consistent_date(
        _field(text, "Compliance Deadline"), doc.get("regulatory_compliance_deadline")
    )
    referenced_dates = set(re.findall(r"(?<!\d)20\d{2}-\d{2}-\d{2}(?!\d)", positive_question))
    if referenced_dates and not referenced_dates.issubset(
            set(re.findall(r"(?<!\d)20\d{2}-\d{2}-\d{2}(?!\d)", facts))
            | {publication, effective, deadline}):
        return None
    if effective_conflict:
        missing.append("EFFECTIVE_DATE_CONFLICT")
    if deadline_conflict:
        missing.append("COMPLIANCE_DEADLINE_CONFLICT")
    relationships = _relationships(doc, text, number)
    superseded = any(item["type"] == "SUPERSEDED_BY" and item["verification_status"] == "VERIFIED"
                     for item in relationships)
    asked_relations = set()
    if re.search(r"\bsupersed\w*\b", positive_question, re.I):
        asked_relations.add("SUPERSEDES" if re.search(r"\bsupersedes?\b", positive_question, re.I)
                            else "SUPERSEDED_BY")
    if re.search(r"\bamend\w*\b", positive_question, re.I):
        asked_relations.add("AMENDS")
    if re.search(r"\breplac\w*\b", positive_question, re.I):
        asked_relations.add("REPLACES")
    if asked_relations and not any(item["type"] in asked_relations and
                                   item["verification_status"] == "VERIFIED" for item in relationships):
        missing.append("DOCUMENT_RELATIONSHIP_UNVERIFIED")
    if stage == "WITHDRAWN":
        temporal = "WITHDRAWN"
    elif superseded:
        temporal = "SUPERSEDED"
    elif stage == "PROPOSED":
        temporal = "PROPOSED"
    elif stage == "EFFECTIVE" and (not effective or date.fromisoformat(effective) > today):
        temporal = "STATUS_UNKNOWN"
    elif effective and date.fromisoformat(effective) <= today:
        temporal = "EFFECTIVE"
    else:
        temporal = "FINAL_ISSUED"

    requested_status = (
        "WITHDRAWN" if re.search(r"\b(?:withdrawn|withdrawal|rescinded?)\b", positive_question, re.I) else
        "PROPOSED" if re.search(r"\b(?:proposed\s+(?:rule|ad|directive)|nprm)\b", positive_question, re.I) else
        "EFFECTIVE" if re.search(r"\b(?:already\s+effective|in\s+force|currently\s+effective)\b", positive_question, re.I) else
        "FINAL_ISSUED" if re.search(r"\b(?:final\s+rule|final\s+directive|final\s+ad)\b", positive_question, re.I) else ""
    )
    if requested_status and requested_status != temporal and not (
            requested_status == "FINAL_ISSUED" and temporal == "EFFECTIVE"):
        return None
    if stage == "EFFECTIVE" and effective is None:
        missing.append("EFFECTIVE_DATE_NOT_ESTABLISHED")
    elif stage == "EFFECTIVE" and date.fromisoformat(effective) > today:
        missing.append("EFFECTIVE_STAGE_DATE_CONFLICT")

    asks_impact = bool(re.search(
        r"\b(?:impact|cause|why|production|deliver\w*|shortag\w*|fleet|operat\w*|ground\w*|"
        r"consequence|risk|maintenance|spare\s+engine)\b", question, re.I))
    wants_effective = bool(re.search(r"\beffective\s+(?:date|on)\b", question, re.I))
    if wants_effective and not effective:
        missing.append("EFFECTIVE_DATE_NOT_ESTABLISHED")
    if asks_impact:
        missing.append("DOWNSTREAM_IMPACT_UNVERIFIED")
    narrow_fact = bool((wanted_numbers or wanted_dockets or re.search(
        r"\b(?:effective\s+date|publication\s+date|issued\s+on)\b", question, re.I))
        and (not requested_issues or re.search(
            r"\b(?:status|effective|publication|issued|proposed|final|withdrawn|when|whether)\b", question, re.I)))
    complete = narrow_fact and not missing and not asks_impact

    note = (f"FAA document {number} in docket(s) {', '.join(sorted(actual_dockets))}: "
            f"regulatory stage {stage}; record-derived status {temporal}; publication {publication}; "
            f"effective date {effective or 'NOT_ESTABLISHED'}; compliance deadline {deadline or 'NOT_ESTABLISHED'}. "
            f"Official source: {url}.")
    if missing:
        note += " Not established: " + ", ".join(dict.fromkeys(missing)) + "."
    later_number = str(doc.get("faa_latest_docket_document_number") or "")
    return {
        "document_id": str(doc.get("doc_id") or ""), "document_number": number,
        "kit": question,
        "source_url": publication_record["source_url"], "source_authority": "FAA_FEDERAL_REGISTER",
        "document_existence_verified": True, "content_evidence_status": "OFFICIAL_SUMMARY_PRESENT",
        "evidence_excerpt": summary, "evidence_excerpt_in_collected_text": summary in text,
        "technical_conclusion_status": "UNVERIFIED",
        "docket_ids": sorted(actual_dockets), "requested_document_match": not wanted_numbers or number in wanted_numbers,
        "requested_docket_match": not wanted_dockets or bool(wanted_dockets.intersection(actual_dockets)),
        "document_type_match": not primary or bool(primary.intersection(documented_issues)),
        "temporal_status_match": not requested_status or requested_status == temporal or (
            requested_status == "FINAL_ISSUED" and temporal == "EFFECTIVE"),
        "aircraft_or_engine_match": not any(x in missing for x in (
            "PROGRAM_APPLICABILITY_UNVERIFIED", "COMPONENT_APPLICABILITY_UNVERIFIED")),
        "stage": stage, "regulatory_status": temporal, "publication_date": publication,
        "effective_date": effective, "compliance_deadline": deadline,
        "event_date": effective if temporal == "EFFECTIVE" else None,
        "compliance_deadline_passed": bool(deadline and date.fromisoformat(deadline) < today),
        "withdrawn": temporal == "WITHDRAWN", "superseded": superseded,
        "supersession_status": "VERIFIED" if superseded else "UNKNOWN",
        "relationships": relationships,
        "later_document_in_docket": later_number if later_number != number and _DOCNO.fullmatch(later_number) else None,
        "later_document_supersession_status": (
            "VERIFIED" if any(item["type"] == "SUPERSEDED_BY" and item["target"] == later_number
                              and item["verification_status"] == "VERIFIED" for item in relationships)
            else "UNVERIFIED" if later_number != number and _DOCNO.fullmatch(later_number)
            else "NOT_APPLICABLE"
        ),
        "complete": complete, "direct_kit_evidence": not missing and not asks_impact,
        "program_unverified": "PROGRAM_APPLICABILITY_UNVERIFIED" in missing,
        "missing_evidence": list(dict.fromkeys(missing)), "answer": note,
    }


