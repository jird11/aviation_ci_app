"""Conservative evidence contract for FAA Federal Register documents.

Confirms the identified publication and its regulatory status, not aircraft
installation, compliance, causality, or economic impacts without further proof.
"""
from __future__ import annotations

import os
import re
from datetime import date, datetime, timezone
from typing import Any
from urllib.parse import urlparse

# Generic issue and component ontology (preserved verbatim).
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

_REL_SPEC = {
    "SUPERSEDED_BY": ("superseded_by", "Superseded By", r"supersed\w*\s+by"),
    "SUPERSEDES": ("supersedes", "Supersedes", r"supersed\w*"),
    "AMENDS": ("amends", "Amends", r"amend\w*"),
    "REPLACES": ("replaces", "Replaces", r"replac\w*"),
    "RELATED_DOCKET": ("related_dockets", "Related Docket", r"docket"),
    "WITHDRAWN": ("withdraws", "Withdraws", r"withdraw\w*|rescinded?"),
}
_UNUSABLE_CONTENT = {"METADATA_ONLY", "SUMMARY_ONLY", "TRUNCATED", "SOURCE_ACCESS_BLOCKED", "UNAVAILABLE"}
_VALID_STAGES = {"PROPOSED", "FINAL_ISSUED", "EFFECTIVE", "WITHDRAWN"}
_ISO_DATE_RE = re.compile(r"(?<!\d)20\d{2}-\d{2}-\d{2}(?!\d)")
_FR_PATH_RE = re.compile(r"/documents/(?:20\d{2}/\d{2}/\d{2}/)?(20\d{2}-\d{4,6})(?:/[^/?]*)?/?")
_REQUESTED_STATUS_RULES = (
    ("WITHDRAWN", r"\b(?:withdrawn|withdrawal|rescinded?)\b"),
    ("PROPOSED", r"\b(?:proposed\s+(?:rule|ad|directive)|nprm)\b"),
    ("EFFECTIVE", r"\b(?:already\s+effective|in\s+force|currently\s+effective)\b"),
    ("FINAL_ISSUED", r"\b(?:final\s+rule|final\s+directive|final\s+ad)\b"),
)


def _found(patterns: tuple[str, ...], value: str) -> bool:
    """Return True if any regex pattern matches value case-insensitively."""
    return any(re.search(pat, value, re.I) for pat in patterns)


def _requested_positive_part(question: str) -> str:
    """Return the portion of the question preceding any exclusion clause."""
    return re.split(r"\b(?:exclude|excluding|except)\b", question, maxsplit=1, flags=re.I)[0]


def _field(text: str, label: str) -> str:
    """Extract the trimmed value of a labeled line from official record text."""
    m = re.search(rf"(?im)^[ \t]*{re.escape(label)}:[ \t]*([^\r\n]*)", text)
    return m.group(1).strip() if m else ""


def _date_value(value: Any) -> str | None:
    """Parse an ISO YYYY-MM-DD date prefix or return None."""
    try:
        return date.fromisoformat(str(value or "")[:10]).isoformat()
    except ValueError:
        return None


def _consistent_date(*values: Any) -> tuple[str | None, bool]:
    """Reconcile multiple date fields and flag conflicts or malformed non-empty values."""
    supplied = [v for v in values if v and str(v).upper() not in {"NOT_ESTABLISHED", "DATE_UNKNOWN", "UNKNOWN"}]
    parsed = [_date_value(v) for v in supplied]
    dates = {d for d in parsed if d is not None}
    conflict = len(dates) > 1 or any(d is None for d in parsed)
    return (next(iter(dates)) if len(dates) == 1 and not conflict else None, conflict)


def _ids(value: Any, pattern: re.Pattern[str]) -> set[str]:
    """Extract normalized uppercase identifier matches from a scalar or collection."""
    parts = value if isinstance(value, (list, tuple, set)) else [value]
    return {m.group().upper() for item in parts for m in pattern.finditer(str(item or ""))}


def _relationships(doc: dict[str, Any], text: str, number: str) -> list[dict[str, str]]:
    """Keep explicit verified regulatory links distinct from unverified metadata candidates."""
    entries: list[dict[str, str]] = []
    for kind, (key, label, _) in _REL_SPEC.items():
        pat = _DOCKET if kind == "RELATED_DOCKET" else _DOCNO
        verified, candidates = _ids(_field(text, label), pat), _ids(doc.get(key), pat)
        entries.extend({"type": kind, "target": v, "verification_status": "VERIFIED", "basis": "OFFICIAL_LABELED_FIELD"} for v in sorted(verified))
        entries.extend({"type": kind, "target": v, "verification_status": "UNVERIFIED", "basis": "METADATA_ONLY"} for v in sorted(candidates - verified))

    structured = doc.get("regulatory_relationships") or []
    for item in (structured if isinstance(structured, list) else ()):
        if not isinstance(item, dict) or (kind := str(item.get("type") or "").upper()) not in _RELATIONS:
            continue
        excerpt, verb = str(item.get("evidence_excerpt") or "").strip(), _REL_SPEC[kind][2]
        for target in sorted(_ids(item.get("target"), _DOCKET if kind == "RELATED_DOCKET" else _DOCNO)):
            grounded = bool(len(excerpt) >= 25 and excerpt in text and target.lower() in excerpt.lower() and re.search(verb, excerpt, re.I))
            entries.append({
                "type": kind, "target": target,
                "verification_status": "VERIFIED" if grounded else "UNVERIFIED",
                "basis": "SOURCE_PASSAGE" if grounded else "STRUCTURED_CLAIM_UNVERIFIED",
            })

    merged: dict[tuple[str, str], dict[str, str]] = {}
    for entry in entries:
        if not entry["target"] or (entry["target"] == number and entry["type"] != "WITHDRAWN"):
            continue
        k = entry["type"], entry["target"]
        if k not in merged or entry["verification_status"] == "VERIFIED":
            merged[k] = entry
    return [merged[k] for k in sorted(merged)]


def _as_of_date() -> date:
    """Return the configured replay cutoff date or today's UTC date."""
    replay = _date_value(os.getenv("EWS_AS_OF_DATE"))
    return date.fromisoformat(replay) if replay else datetime.now(timezone.utc).date()


def inspect_official_faa_publication(doc: dict[str, Any]) -> dict[str, Any] | None:
    """Verify a Federal Register record's existence without validating its technical claims."""
    if doc.get("source_id") != "SRC_001":
        return None
    try:
        parsed = urlparse(str(doc.get("url") or ""))
        host, creds = parsed.hostname, parsed.username or parsed.password
    except ValueError:
        return None
    if parsed.scheme != "https" or host not in {"federalregister.gov", "www.federalregister.gov"} or creds:
        return None
    if not (path := _FR_PATH_RE.fullmatch(parsed.path)):
        return None

    text = str(doc.get("text") or "")
    line_nums, meta_nums = _ids(_field(text, "Federal Register Document"), _DOCNO), _ids(doc.get("faa_document_number"), _DOCNO)
    all_nums = line_nums | meta_nums
    if (line_nums and meta_nums and line_nums != meta_nums) or len(all_nums) != 1 or path.group(1) not in all_nums:
        return None

    line_dockets = _ids(_field(text, "FAA Docket"), _DOCKET)
    meta_dockets = _ids(doc.get("faa_docket_id") or doc.get("docket_id"), _DOCKET) | _ids(doc.get("docket_ids"), _DOCKET)
    if line_dockets and meta_dockets and not line_dockets.issubset(meta_dockets):
        return None

    pub, conflict = _consistent_date(_field(text, "Publication Date"), doc.get("regulatory_publication_date"), doc.get("published_at"))
    if not pub or conflict or date.fromisoformat(pub) > _as_of_date():
        return None
    return {
        "document_number": path.group(1), "docket_ids": sorted(line_dockets or meta_dockets),
        "publication_date": pub, "document_existence_verified": True,
        "verification_basis": "OFFICIAL_URL_AND_CONSISTENT_DOCUMENT_METADATA",
        "content_evidence_status": "UNVERIFIED", "source_url": parsed.geturl(),
    }


def assess_official_faa_fact(question: str, doc: dict[str, Any]) -> dict[str, Any] | None:
    """Return a scoped FAA fact or None when source, identity, or event applicability conflicts."""
    if not (pub_rec := inspect_official_faa_publication(doc)):
        return None
    if str(doc.get("content_status") or doc.get("source_content_status") or "").upper() in _UNUSABLE_CONTENT:
        return None

    url, text, title = str(doc.get("url") or ""), str(doc.get("text") or ""), str(doc.get("title") or "")
    stage = _field(text, "Regulatory Stage").upper()
    summary = _field(text, "Official Summary")
    actual_dockets = _ids(_field(text, "FAA Docket"), _DOCKET)
    if (_field(text, "Regulatory Lifecycle Check").upper() != "VERIFIED"
            or stage not in _VALID_STAGES
            or (doc.get("regulatory_stage") and str(doc["regulatory_stage"]).upper() != stage)
            or len(summary) < 30 or not actual_dockets):
        return None

    number, pos_q = pub_rec["document_number"], _requested_positive_part(question)
    wanted_nums, wanted_dockets = _ids(pos_q, _DOCNO), _ids(pos_q, _DOCKET)
    if (wanted_nums and number not in wanted_nums) or (wanted_dockets and not (wanted_dockets & actual_dockets)):
        return None

    from aero_ews.domain.identity import (
        _detect_aircraft_families, _detect_engine_models, _detect_exact_variants, _engine_models_match,
    )

    facts = f"{title}\n{summary}"
    req_makers = {n for n in _MANUFACTURERS if re.search(rf"\b{n}\b", pos_q, re.I)}
    doc_makers = {n for n in _MANUFACTURERS if re.search(rf"\b{n}\b", facts, re.I)}
    if req_makers and not req_makers.issubset(doc_makers):
        return None

    req_issues = {n for n, p in ISSUES.items() if _found(p, pos_q)}
    doc_issues = {n for n, p in ISSUES.items() if _found(p, facts)}
    is_cmp = bool(re.search(r"\b(?:compare|versus|vs\.?)\b", pos_q, re.I))
    primary = (req_issues - {"INSPECTION"}) or req_issues
    if primary and (not (primary & doc_issues) if is_cmp else not primary.issubset(doc_issues)):
        return None

    req_engs, doc_engs = _detect_engine_models(pos_q), _detect_engine_models(facts)
    w_fams, f_fams = _detect_aircraft_families(pos_q), _detect_aircraft_families(facts)
    w_vars, f_vars = _detect_exact_variants(pos_q), _detect_exact_variants(facts)
    sum_vars, sum_fams = _detect_exact_variants(summary), _detect_aircraft_families(summary)
    req_comps = {n for n, p in COMPONENTS.items() if _found(p, pos_q)}
    sup_comps = {n for n, p in COMPONENTS.items() if _found(p, summary)}

    if ((req_engs and (not doc_engs or not _engine_models_match(pos_q, facts)))
            or (w_fams and (not f_fams or not (w_fams & f_fams) or (sum_fams and not (w_fams & sum_fams))))
            or (w_vars and (not f_vars or not (w_vars & f_vars) or (sum_vars and not (w_vars & sum_vars))))
            or (req_comps - sup_comps)
            or re.search(r"\bEASA\b", pos_q, re.I)):
        return None

    publication, today = pub_rec["publication_date"], _as_of_date()
    effective, eff_conflict = _consistent_date(_field(text, "Effective Date"), doc.get("regulatory_effective_date"))
    deadline, dl_conflict = _consistent_date(_field(text, "Compliance Deadline"), doc.get("regulatory_compliance_deadline"))
    if (ref_dates := set(_ISO_DATE_RE.findall(pos_q))) and not ref_dates.issubset(set(_ISO_DATE_RE.findall(facts)) | {publication, effective, deadline}):
        return None

    missing: list[str] = []
    if req_issues - doc_issues:
        missing.append("SECONDARY_ISSUE_NOT_EVIDENCED")
    if is_cmp:
        missing.append("COMPARISON_REQUIRES_ADDITIONAL_SOURCES")
    if eff_conflict:
        missing.append("EFFECTIVE_DATE_CONFLICT")
    if dl_conflict:
        missing.append("COMPLIANCE_DEADLINE_CONFLICT")

    relationships = _relationships(doc, text, number)
    superseded = any(i["type"] == "SUPERSEDED_BY" and i["verification_status"] == "VERIFIED" for i in relationships)
    asked_rels = set()
    if re.search(r"\bsupersed\w*\b", pos_q, re.I):
        asked_rels.add("SUPERSEDES" if re.search(r"\bsupersedes?\b", pos_q, re.I) else "SUPERSEDED_BY")
    if re.search(r"\bamend\w*\b", pos_q, re.I):
        asked_rels.add("AMENDS")
    if re.search(r"\breplac\w*\b", pos_q, re.I):
        asked_rels.add("REPLACES")
    if asked_rels and not any(i["type"] in asked_rels and i["verification_status"] == "VERIFIED" for i in relationships):
        missing.append("DOCUMENT_RELATIONSHIP_UNVERIFIED")

    eff_day = date.fromisoformat(effective) if effective else None
    temporal = (
        "WITHDRAWN" if stage == "WITHDRAWN"
        else "SUPERSEDED" if superseded
        else "PROPOSED" if stage == "PROPOSED"
        else "STATUS_UNKNOWN" if stage == "EFFECTIVE" and (eff_day is None or eff_day > today)
        else "EFFECTIVE" if eff_day is not None and eff_day <= today
        else "FINAL_ISSUED"
    )
    req_status = next((st for st, pat in _REQUESTED_STATUS_RULES if re.search(pat, pos_q, re.I)), "")
    if req_status and req_status != temporal and not (req_status == "FINAL_ISSUED" and temporal == "EFFECTIVE"):
        return None
    if stage == "EFFECTIVE" and eff_day is None:
        missing.append("EFFECTIVE_DATE_NOT_ESTABLISHED")
    elif stage == "EFFECTIVE" and eff_day > today:
        missing.append("EFFECTIVE_STAGE_DATE_CONFLICT")

    asks_impact = bool(re.search(r"\b(?:impact|cause|why|production|deliver\w*|shortag\w*|fleet|operat\w*|ground\w*|consequence|risk|maintenance|spare\s+engine)\b", question, re.I))
    if re.search(r"\beffective\s+(?:date|on)\b", question, re.I) and not effective:
        missing.append("EFFECTIVE_DATE_NOT_ESTABLISHED")
    if asks_impact:
        missing.append("DOWNSTREAM_IMPACT_UNVERIFIED")

    narrow_fact = bool(
        (wanted_nums or wanted_dockets or re.search(r"\b(?:effective\s+date|publication\s+date|issued\s+on)\b", question, re.I))
        and (not req_issues or re.search(r"\b(?:status|effective|publication|issued|proposed|final|withdrawn|when|whether)\b", question, re.I))
    )
    dedup_missing = list(dict.fromkeys(missing))
    note = (
        f"FAA document {number} in docket(s) {', '.join(sorted(actual_dockets))}: "
        f"regulatory stage {stage}; record-derived status {temporal}; publication {publication}; "
        f"effective date {effective or 'NOT_ESTABLISHED'}; compliance deadline {deadline or 'NOT_ESTABLISHED'}. "
        f"Official source: {url}." + (f" Not established: {', '.join(dedup_missing)}." if dedup_missing else "")
    )
    later_num = str(doc.get("faa_latest_docket_document_number") or "")
    has_later = bool(later_num != number and _DOCNO.fullmatch(later_num))
    return {
        "document_id": str(doc.get("doc_id") or ""), "document_number": number, "kit": question,
        "source_url": pub_rec["source_url"], "source_authority": "FAA_FEDERAL_REGISTER",
        "document_existence_verified": True, "content_evidence_status": "OFFICIAL_SUMMARY_PRESENT",
        "evidence_excerpt": summary, "evidence_excerpt_in_collected_text": summary in text,
        "technical_conclusion_status": "UNVERIFIED", "docket_ids": sorted(actual_dockets),
        "requested_document_match": not wanted_nums or number in wanted_nums,
        "requested_docket_match": not wanted_dockets or bool(wanted_dockets & actual_dockets),
        "document_type_match": not primary or bool(primary & doc_issues),
        "temporal_status_match": not req_status or req_status == temporal or (req_status == "FINAL_ISSUED" and temporal == "EFFECTIVE"),
        "aircraft_or_engine_match": not any(x in missing for x in ("PROGRAM_APPLICABILITY_UNVERIFIED", "COMPONENT_APPLICABILITY_UNVERIFIED")),
        "stage": stage, "regulatory_status": temporal, "publication_date": publication,
        "effective_date": effective, "compliance_deadline": deadline,
        "event_date": effective if temporal == "EFFECTIVE" else None,
        "compliance_deadline_passed": bool(deadline and date.fromisoformat(deadline) < today),
        "withdrawn": temporal == "WITHDRAWN", "superseded": superseded,
        "supersession_status": "VERIFIED" if superseded else "UNKNOWN",
        "relationships": relationships,
        "later_document_in_docket": later_num if has_later else None,
        "later_document_supersession_status": (
            "VERIFIED" if any(i["type"] == "SUPERSEDED_BY" and i["target"] == later_num and i["verification_status"] == "VERIFIED" for i in relationships)
            else ("UNVERIFIED" if has_later else "NOT_APPLICABLE")
        ),
        "complete": narrow_fact and not missing and not asks_impact,
        "direct_kit_evidence": not missing and not asks_impact,
        "program_unverified": "PROGRAM_APPLICABILITY_UNVERIFIED" in missing,
        "missing_evidence": dedup_missing, "answer": note,
    }