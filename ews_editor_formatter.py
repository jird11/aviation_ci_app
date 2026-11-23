"""Convert structured Editor text into validated, HITL-ready recommendations."""

import hashlib
import logging
import os
import re
from typing import List, Tuple

from tasks import ActionItem, EditorialOutput, ThreatAssessment, TripleAPillar, ValidationStatus

logger = logging.getLogger(__name__)

# Structural parsing patterns and fallback summary (preserved verbatim).
_HEADING_START = r"^[ \t]*(?:[-*][ \t]*)?(?:#{1,6}[ \t]*)?(?:\*\*|__)?"
_HEADING_END = r"(?:\*\*|__)?[ \t]*(?:(?::|[-–—])[ \t]*(?:\*\*|__)?[ \t]*(.*)|[ \t]*)$"
_BLOCK = re.compile(_HEADING_START + r"(SUMMARY|ANALYSIS|EVENT(?:[ _]ID)?)" + _HEADING_END, re.I | re.M)
_FIELD = re.compile(
    _HEADING_START + r"(ACTION|RATIONALE|PRO|CON|TRIPLE[ _-]A|RELATED[ _-]EVENTS|KPI)" + _HEADING_END,
    re.I | re.M,
)
_EVENT_ID = re.compile(r"\bEVT[_-][A-Z0-9_]+(?:-[A-Z0-9_]+)*\b", re.I)
_SAFE_VERBS = re.compile(
    r"(?i)^(?:verify|validate|check|review|assess|monitor|compare|"
    r"document|trace|investigate|audit|confirm|evaluate)\b"
)
_OPERATIONAL_VERBS = re.compile(
    r"(?i)\b(?:halt|suspend|cancel|terminate|replace|deploy|"
    r"implement|approve|order|freeze|switch|shut\s+down)\b"
)
_FALLBACK_SUMMARY = (
    "The Editor's management summary could not be reliably extracted. "
    "Retained intelligence signals require independent evidence verification "
    "and human review before operational conclusions are drawn."
)
_PRIORITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def _value(value) -> str:
    """Return the string representation of an Enum or scalar value."""
    return str(getattr(value, "value", value) or "")


def _clean(value: str, limit: int = 0) -> str:
    """Collapse internal whitespace and optionally truncate to a character limit."""
    res = re.sub(r"\s+", " ", str(value or "")).strip()
    return res[:limit].rstrip() if limit else res


def _sections(text: str):
    """Yield (block_kind, inline_header, full_content) tuples preserving internal blank lines."""
    matches = list(_BLOCK.finditer(text))
    for i, m in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        inline, rem = (m.group(2) or "").strip(), text[m.end():end].strip("\n")
        yield m.group(1).upper().replace(" ", "_"), inline, (inline + ("\n" if inline and rem else "") + rem).strip()


def parse_editor_blocks(raw_text: str) -> dict:
    """Shared parser for complete SUMMARY and ANALYSIS blocks (reusable by the pipeline)."""
    blocks = {}
    for kind, _, content in _sections(str(raw_text or "")):
        if kind in {"SUMMARY", "ANALYSIS"}:
            if kind not in blocks:
                blocks[kind] = content
            elif blocks[kind] != content:
                logger.warning("[EDITOR] Conflicting %s blocks; retaining the first", kind)
    return blocks


def _fields(content: str) -> dict:
    """Extract normalized ACTION/RATIONALE/PRO/CON/TRIPLE_A/RELATED_EVENTS/KPI fields from an event block."""
    matches, result = list(_FIELD.finditer(content)), {}
    for i, m in enumerate(matches):
        name = re.sub(r"[ -]", "_", m.group(1).upper())
        end = matches[i + 1].start() if i + 1 < len(matches) else len(content)
        val = _clean((m.group(2) or "") + " " + content[m.end():end])
        if name in result and result[name] != val:
            if name in {"ACTION", "RELATED_EVENTS"}:
                result["_AMBIGUOUS"] = name
            else:
                logger.warning("[EDITOR] Ignoring duplicate %s field", name)
        else:
            result[name] = val
    return result


def _model_max_length(model, field_name: str) -> int:
    """Read the integer max_length constraint from a Pydantic model field, or 0 if absent."""
    field = getattr(model, "model_fields", {}).get(field_name)
    return next((r.max_length for r in getattr(field, "metadata", ()) if isinstance(getattr(r, "max_length", None), int)), 0)


def _configured_limit(name: str) -> int:
    """Read a positive integer environment limit, logging and ignoring invalid values."""
    if not (raw := os.getenv(name, "").strip()):
        return 0
    try:
        if (val := int(raw)) > 0:
            return val
    except ValueError:
        pass
    logger.warning("Ignoring invalid positive integer configuration %s=%r", name, raw)
    return 0


def _summary(raw_text: str) -> Tuple[str, str]:
    """Extract and bound the SUMMARY section, falling back safely if missing, short, or conflicting."""
    if len({c for k, _, c in _sections(raw_text) if k == "SUMMARY" and c}) > 1:
        logger.warning("[EDITOR] Conflicting SUMMARY blocks; using safe fallback")
        return _FALLBACK_SUMMARY, "Conflicting SUMMARY blocks"
    summary = parse_editor_blocks(raw_text).get("SUMMARY", "").strip()
    if len(summary) < 20:
        reason = "SUMMARY block missing" if not summary else "SUMMARY block too short"
        logger.warning("[EDITOR] %s; using a safe summary fallback", reason)
        return _FALLBACK_SUMMARY, reason

    limits = [n for n in (_model_max_length(EditorialOutput, "executive_summary"), _configured_limit("EWS_EDITOR_SUMMARY_MAX_CHARS")) if n]
    if limits and len(summary) > (cap := min(limits)):
        if cap < 20:
            logger.warning("[EDITOR] Summary limit %d is below minimum; ignoring it", cap)
            return summary, ""
        summary = summary[:cap].rsplit(" ", 1)[0].rstrip() or summary[:cap]
        logger.warning("[EDITOR] SUMMARY trimmed to configured/model limit of %d characters", cap)
    return summary, ""


def _rank(threat: ThreatAssessment) -> tuple:
    """Compute a deterministic priority-ordering tuple for a ThreatAssessment."""
    return (
        _value(getattr(threat, "program_relevance", "")) == "DIRECT_KIT_MATCH",
        _value(getattr(threat, "event_freshness", "")) != "HISTORICAL_CONTEXT" and _value(getattr(threat, "event_status", "")) not in {"RESOLVED", "DISMISSED"},
        _value(threat.validation_status) == ValidationStatus.SUPPORTED.value,
        _value(getattr(threat, "technical_grounding_status", "")) == "PASS",
        bool(_clean(getattr(threat, "decision_question", ""))),
        _value(getattr(threat, "urgency", "")) == "HIGH",
        int(threat.threat_score),
    )


def _priority(threat: ThreatAssessment) -> str:
    """Derive action priority from relevance, lifecycle state, grounding, urgency, and score."""
    relevant, active, supported, grounded, _, urgent, score = _rank(threat)
    if not relevant or not active:
        return "LOW"
    if not (supported and grounded):
        return "MEDIUM" if (urgent or score >= 7) else "LOW"
    return "CRITICAL" if score >= 8 else ("HIGH" if (urgent or score >= 7) else ("MEDIUM" if score >= 5 else "LOW"))


def _deadline(threats: list) -> str:
    """Only structured, verified source deadlines can override HITL scheduling."""
    dates = set()
    for t in threats:
        verified = _value(t.validation_status) == ValidationStatus.SUPPORTED.value and _value(getattr(t, "technical_grounding_status", "")) == "PASS"
        found = {d for n in ("compliance_deadline", "regulatory_deadline", "evidenced_deadline") if (d := _clean(getattr(t, n, "")))}
        if not verified or len(found) != 1:
            return "Pending HITL scheduling"
        dates.update(found)
    return next(iter(dates)) if len(dates) == 1 else "Pending HITL scheduling"


def _proposals(text: str, threats: list) -> tuple[list, int]:
    """Parse Editor EVENT blocks and link each unambiguously to retained ThreatAssessment records."""
    by_id, duplicates = {}, set()
    for t in threats:
        if eid := _value(t.event_id).upper():
            duplicates.add(eid) if eid in by_id else by_id.__setitem__(eid, t)
    for eid in duplicates:
        by_id.pop(eid, None)

    def _norm_ids(raw: str) -> set[str]:
        hay = str(raw or "")
        found = {(ex if (ex := eid.upper()) in by_id else re.sub(r"^EVT-", "EVT_", ex)) for eid in _EVENT_ID.findall(hay)}
        found.update(kid for kid in by_id if re.search(rf"(?<![A-Za-z0-9_-]){re.escape(kid)}(?![A-Za-z0-9_-])", hay, re.I))
        return found

    proposals, rejected = [], 0
    for kind, header, body in _sections(text):
        if kind not in {"EVENT", "EVENT_ID"}:
            continue
        fields = _fields(body)
        # Skip empty headings without fields (e.g., a standalone 'EVENT' line preceding 'EVENT_ID:').
        if not fields and not _norm_ids(f"{header} {body}"):
            continue
        first_f = _FIELD.search(body)
        header_ids = _norm_ids(f"{header} {body[:first_f.start()] if first_f else body}")
        related_ids = _norm_ids(fields.get("RELATED_EVENTS", ""))
        ids = header_ids | related_ids

        # Recover an event ID mentioned inside ACTION/RATIONALE or match a single unambiguous candidate by company name.
        if not ids:
            in_body = _norm_ids(f"{fields.get('ACTION', '')} {fields.get('RATIONALE', '')}") & by_id.keys()
            if len(in_body) == 1:
                ids = in_body
            elif len(by_id) == 1 and len(_clean(fields.get("ACTION", ""))) >= 10:
                only_id = next(iter(by_id))
                company = _value(by_id[only_id].company_affected).casefold()
                if company and company in f"{header} {fields.get('ACTION', '')} {fields.get('RATIONALE', '')}".casefold():
                    ids = {only_id}

        if (fields.get("_AMBIGUOUS") or not ids or (ids - by_id.keys())
                or (len(header_ids) > 1 and not related_ids)
                or (header_ids and related_ids and not header_ids <= related_ids)
                or ("RELATED_EVENTS" in fields and not related_ids)):
            rejected += 1
            logger.warning("[EDITOR] Rejected ambiguous or unknown event linkage: ids=%s header=%r", sorted(ids), header[:120])
            continue
        proposals.append(([by_id[eid] for eid in sorted(ids)], fields))

    if proposals or not threats:
        return sorted(proposals, key=lambda item: max(_rank(t) for t in item[0]), reverse=True), rejected
    # When no valid event blocks were parsed, emit one backend-grounded verification task for the top event.
    eligible = [t for t in threats if _rank(t)[0] and _rank(t)[1]] or threats
    return [([max(eligible, key=_rank)], {})], rejected


def build_editorial_from_text(raw_text: str, threats: List[ThreatAssessment]) -> Tuple[EditorialOutput, int, int]:
    """Build typed HITL recommendations; return (EditorialOutput, recognized_count, fallback_count)."""
    text = str(raw_text or "")
    summary, reason = _summary(text)
    proposals, rejected = _proposals(text, threats)
    if limits := [n for n in (_configured_limit("EWS_EDITOR_MAX_ACTIONS"), _model_max_length(EditorialOutput, "action_plan")) if n]:
        proposals = proposals[:min(limits)]

    action_cap = _model_max_length(ActionItem, "action") or 600
    actions, recognized, fallbacks, seen = [], 0, 0, set()

    for related, fields in proposals:
        ids = sorted({_value(t.event_id) for t in related})
        proposal = _clean(fields.get("ACTION", ""), action_cap)
        has_proposal = len(proposal) >= 10
        recognized += has_proposal

        pre_harness = all(_value(getattr(t, "technical_grounding_status", "")) == "UNVERIFIED" for t in related)
        limited = False if pre_harness else any(
            _value(t.validation_status) != ValidationStatus.SUPPORTED.value
            or _value(getattr(t, "program_relevance", "")) != "DIRECT_KIT_MATCH"
            or _value(getattr(t, "technical_grounding_status", "")) != "PASS"
            for t in related
        )
        # Pre-Harness blocks only disruptive operational directives; full validation runs post-Harness in ews_reporting.py.
        safe_fallback = (
            not has_proposal
            or bool(_OPERATIONAL_VERBS.search(proposal) and (limited or pre_harness))
            or (limited and not _SAFE_VERBS.match(proposal))
        )
        action = f"Verify source evidence, KIT applicability and decision needs for {', '.join(ids)}." if safe_fallback else proposal
        fallbacks += safe_fallback

        action_id = "ACT_" + hashlib.sha256(f"EDITOR_TEXT_V2:{'|'.join(ids)}:{action}".encode("utf-8")).hexdigest()[:8].upper()
        if action_id in seen:
            recognized -= has_proposal
            fallbacks -= action != proposal
            continue
        seen.add(action_id)

        evidence = "; ".join(
            f"{t.event_id}: {_value(t.validation_status)}, KIT={t.program_relevance}, "
            f"Documents={','.join(getattr(t, 'evidence_ids', []) or []) or 'UNKNOWN'}"
            for t in related
        )
        ed_reason = _clean(fields.get("RATIONALE", ""), 350)
        rationale = f"Evidence status: {evidence}. " + (
            f"Editor analysis (not independent evidence): {ed_reason}" if (ed_reason and not limited and action == proposal)
            else "Further source verification or human review is required before implementation."
        )

        sf = {} if safe_fallback else fields
        p_name = sf.get("TRIPLE_A", "").lower()
        pillar = TripleAPillar.AGILITY if "agil" in p_name else (TripleAPillar.ALIGNMENT if "align" in p_name else TripleAPillar.ADAPTABILITY)
        risk = _value(max(related, key=_rank).risk_type)
        owner = "Regulatory Affairs Analyst" if risk == "REGULATORY" else ("Supply Chain Risk Analyst" if risk in {"SUPPLY_CHAIN", "TECHNICAL_QUALITY"} else "Competitive Intelligence Analyst")
        pro = _clean(sf.get("PRO", ""), 220) or "Supports documented verification and decision-making."
        con = _clean(sf.get("CON", ""), 220) or "Requires analyst effort and human approval."

        actions.append(ActionItem(
            action_id=action_id,
            related_event_ids=ids,
            related_threat_companies=sorted({_value(t.company_affected) for t in related}),
            action=action,
            rationale=rationale,
            pros_and_cons=f"PRO: {pro}; CON: {con}",
            triple_a_impact=pillar,
            uncertainty_assumptions="Editorial advice requires source verification and human approval.",
            owner=owner,
            deadline=_deadline(related),
            kpi=_clean(sf.get("KPI", ""), 250) or f"Evidence and management decision documented for {', '.join(ids)}.",
            priority=max((_priority(t) for t in related), key=_PRIORITY_ORDER.get),
            status="PROPOSED",
            decision="PENDING",
        ))

    audit = (
        "Editor text converted into typed recommendations; independent evidence QA remains authoritative."
        + (f" Summary fallback reason: {reason}." if reason else "")
        + (f" Rejected {rejected} action block(s) with ambiguous or unknown event links." if rejected else "")
    )
    return EditorialOutput(executive_summary=summary, qa_audit_summary=audit, action_plan=actions), recognized, fallbacks