"""Convert structured Editor text into validated, HITL-ready recommendations."""

import hashlib
import logging
import os
import re
from typing import List, Tuple

from tasks import ActionItem, EditorialOutput, ThreatAssessment, TripleAPillar, ValidationStatus

logger = logging.getLogger(__name__)

_HEADING_START = r"^[ \t]*(?:[-*][ \t]*)?(?:#{1,6}[ \t]*)?(?:\*\*|__)?"
_HEADING_END = r"(?:\*\*|__)?[ \t]*(?:(?::|[-–—])[ \t]*(?:\*\*|__)?[ \t]*(.*)|[ \t]*)$"
_BLOCK = re.compile(_HEADING_START + r"(SUMMARY|ANALYSIS|EVENT(?:[ _]ID)?)" + _HEADING_END, re.I | re.M)
_FIELD = re.compile(
    _HEADING_START + r"(ACTION|RATIONALE|PRO|CON|TRIPLE[ _-]A|RELATED[ _-]EVENTS|KPI)"
    + _HEADING_END, re.I | re.M,
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


def _value(value) -> str:
    return str(getattr(value, "value", value) or "")


def _clean(value: str, limit: int = 0) -> str:
    result = re.sub(r"\s+", " ", str(value or "")).strip()
    return result[:limit].rstrip() if limit else result


def _sections(text: str):
    """Yield structural blocks; blank lines inside a block are preserved."""
    matches = list(_BLOCK.finditer(text))
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        inline, remainder = (match.group(2) or "").strip(), text[match.end():end].strip("\n")
        content = (inline + ("\n" if inline and remainder else "") + remainder).strip()
        yield match.group(1).upper().replace(" ", "_"), inline, content


def parse_editor_blocks(raw_text: str) -> dict:
    """Shared parser for complete SUMMARY and ANALYSIS blocks (also reusable by pipeline)."""
    blocks = {}
    for kind, _, content in _sections(str(raw_text or "")):
        if kind in {"SUMMARY", "ANALYSIS"}:
            if kind not in blocks:
                blocks[kind] = content
            elif blocks[kind] != content:
                logger.warning("[EDITOR] Conflicting %s blocks; retaining the first", kind)
    return blocks


def _fields(content: str) -> dict:
    matches = list(_FIELD.finditer(content))
    result = {}
    for index, match in enumerate(matches):
        name = re.sub(r"[ -]", "_", match.group(1).upper())
        value = _clean((match.group(2) or "") + " " + content[match.end():
            matches[index + 1].start() if index + 1 < len(matches) else len(content)])
        if name in result and result[name] != value:
            if name in {"ACTION", "RELATED_EVENTS"}:
                result["_AMBIGUOUS"] = name
            else:
                logger.warning("[EDITOR] Ignoring duplicate %s field", name)
        else:
            result[name] = value
    return result


def _model_max_length(model, field_name: str) -> int:
    field = getattr(model, "model_fields", {}).get(field_name)
    return next((rule.max_length for rule in getattr(field, "metadata", ())
                 if isinstance(getattr(rule, "max_length", None), int)), 0)


def _configured_limit(name: str) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return 0
    try:
        value = int(raw)
        if value > 0:
            return value
    except ValueError:
        pass
    logger.warning("Ignoring invalid positive integer configuration %s=%r", name, raw)
    return 0


def _summary(raw_text: str) -> Tuple[str, str]:
    summaries = {content for kind, _, content in _sections(raw_text) if kind == "SUMMARY" and content}
    if len(summaries) > 1:
        logger.warning("[EDITOR] Conflicting SUMMARY blocks; using safe fallback")
        return _FALLBACK_SUMMARY, "Conflicting SUMMARY blocks"
    summary = parse_editor_blocks(raw_text).get("SUMMARY", "").strip()
    if len(summary) < 20:
        reason = "SUMMARY block missing" if not summary else "SUMMARY block too short"
        logger.warning("[EDITOR] %s; using a safe summary fallback", reason)
        return _FALLBACK_SUMMARY, reason

    limits = [n for n in (
        _model_max_length(EditorialOutput, "executive_summary"),
        _configured_limit("EWS_EDITOR_SUMMARY_MAX_CHARS"),
    ) if n]
    if limits and len(summary) > min(limits):
        cap = min(limits)
        if cap < 20:
            logger.warning("[EDITOR] Summary limit %d is below minimum; ignoring it", cap)
            return summary, ""
        summary = summary[:cap].rsplit(" ", 1)[0].rstrip() or summary[:cap]
        logger.warning("[EDITOR] SUMMARY trimmed to configured/model limit of %d characters", cap)
    return summary, ""


def _rank(threat: ThreatAssessment) -> tuple:
    relevance = _value(getattr(threat, "program_relevance", "")) == "DIRECT_KIT_MATCH"
    supported = _value(threat.validation_status) == ValidationStatus.SUPPORTED.value
    grounded = _value(getattr(threat, "technical_grounding_status", "")) == "PASS"
    freshness = _value(getattr(threat, "event_freshness", ""))
    status = _value(getattr(threat, "event_status", ""))
    active = freshness != "HISTORICAL_CONTEXT" and status not in {"RESOLVED", "DISMISSED"}
    urgent = _value(getattr(threat, "urgency", "")) == "HIGH"
    decision = bool(_clean(getattr(threat, "decision_question", "")))
    return relevance, active, supported, grounded, decision, urgent, int(threat.threat_score)


def _priority(threat: ThreatAssessment) -> str:
    relevant, active, supported, grounded, _, urgent, score = _rank(threat)
    if not relevant or not active:
        return "LOW"
    if not (supported and grounded):
        return "MEDIUM" if urgent or score >= 7 else "LOW"
    if score >= 8:
        return "CRITICAL"
    if urgent or score >= 7:
        return "HIGH"
    return "MEDIUM" if score >= 5 else "LOW"


def _deadline(threats: list) -> str:
    """Only structured, verified source deadlines can override HITL scheduling."""
    dates = set()
    for threat in threats:
        verified = (
            _value(threat.validation_status) == ValidationStatus.SUPPORTED.value
            and _value(getattr(threat, "technical_grounding_status", "")) == "PASS"
        )
        found = {
            _clean(getattr(threat, name, ""))
            for name in ("compliance_deadline", "regulatory_deadline", "evidenced_deadline")
            if _clean(getattr(threat, name, ""))
        }
        if not verified or len(found) != 1:
            return "Pending HITL scheduling"
        dates.update(found)
    return next(iter(dates)) if len(dates) == 1 else "Pending HITL scheduling"


def _proposals(text: str, threats: list) -> tuple[list, int]:
    by_id, duplicates = {}, set()
    for threat in threats:
        event_id = _value(threat.event_id).upper()
        if event_id in by_id:
            duplicates.add(event_id)
        elif event_id:
            by_id[event_id] = threat
    for event_id in duplicates:
        by_id.pop(event_id, None)

    def _norm_ids(raw: str) -> set[str]:
        found = set()
        for eid in _EVENT_ID.findall(raw or ""):
            exact = eid.upper()
            found.add(exact if exact in by_id else re.sub(r"^EVT-", "EVT_", exact))
        hay = str(raw or "")
        for known_id in by_id:
            if re.search(rf"(?<![A-Za-z0-9_-]){re.escape(known_id)}(?![A-Za-z0-9_-])", hay, re.I):
                found.add(known_id)
        return found

    proposals, rejected = [], 0
    for kind, header, body in _sections(text):
        if kind not in {"EVENT", "EVENT_ID"}:
            continue
        fields = _fields(body)
        # Přeskoč prázdné nadpisy bez polí (např. samostatný řádek 'EVENT' před 'EVENT_ID:').
        if not fields and not _norm_ids(header + " " + body):
            continue
        first_field = _FIELD.search(body)
        preamble = body[:first_field.start()] if first_field else body
        header_ids = _norm_ids(header + " " + preamble)
        related_ids = _norm_ids(fields.get("RELATED_EVENTS", ""))
        ids = header_ids | related_ids
        # Pokud Editor napsal ID až v textu ACTION/RATIONALE nebo existuje jediný jednoznačný kandidát:
        if not ids:
            in_body = _norm_ids(f"{fields.get('ACTION', '')} {fields.get('RATIONALE', '')}") & by_id.keys()
            if len(in_body) == 1:
                ids = in_body
            elif len(by_id) == 1 and len(_clean(fields.get("ACTION", ""))) >= 10:
                only_id = next(iter(by_id))
                only_threat = by_id[only_id]
                hay = f"{header} {fields.get('ACTION', '')} {fields.get('RATIONALE', '')}".casefold()
                company = _value(only_threat.company_affected).casefold()
                if company and company in hay:
                    ids = {only_id}
        ambiguous = (
            bool(fields.get("_AMBIGUOUS")) or not ids or bool(ids - by_id.keys())
            or (len(header_ids) > 1 and not related_ids)
            or (bool(header_ids and related_ids) and not header_ids <= related_ids)
            or ("RELATED_EVENTS" in fields and not related_ids)
        )
        if ambiguous:
            rejected += 1
            logger.warning(
                "[EDITOR] Rejected ambiguous or unknown event linkage: ids=%s header=%r",
                sorted(ids), header[:120],
            )
            continue
        proposals.append(([by_id[eid] for eid in sorted(ids)], fields))

    if proposals or not threats:
        return sorted(proposals, key=lambda item: max(_rank(t) for t in item[0]), reverse=True), rejected

    # A missing event structure produces only a backend-grounded verification task.
    eligible = [t for t in threats if _rank(t)[0] and _rank(t)[1]] or threats
    return [([max(eligible, key=_rank)], {})], rejected


def build_editorial_from_text(
    raw_text: str,
    threats: List[ThreatAssessment],
) -> Tuple[EditorialOutput, int, int]:
    """Build typed actions; return (editorial output, recognized, fallback counts)."""
    text = str(raw_text or "")
    summary, reason = _summary(text)
    proposals, rejected = _proposals(text, threats)
    max_actions = _configured_limit("EWS_EDITOR_MAX_ACTIONS")
    model_limit = _model_max_length(EditorialOutput, "action_plan")
    limits = [n for n in (max_actions, model_limit) if n]
    if limits:
        proposals = proposals[:min(limits)]

    actions, recognized, fallbacks, seen = [], 0, 0, set()
    for related, fields in proposals:
        ids = sorted({_value(t.event_id) for t in related})
        proposal = _clean(fields.get("ACTION", ""), _model_max_length(ActionItem, "action") or 600)
        recognized += len(proposal) >= 10
        pre_harness = all(
            _value(getattr(t, "technical_grounding_status", "")) == "UNVERIFIED"
            for t in related
        )
        limited = False if pre_harness else any(
            _value(t.validation_status) != ValidationStatus.SUPPORTED.value
            or _value(getattr(t, "program_relevance", "")) != "DIRECT_KIT_MATCH"
            or _value(getattr(t, "technical_grounding_status", "")) != "PASS"
            for t in related
        )
        # Pre-Harness blokuje pouze destruktivní/operativní zásahy; plnou validaci pak provede
        # _align_and_sanitize_action_plan() v ews_reporting.py až po Harnessu.
        safe_fallback = (
                len(proposal) < 10
                or bool(_OPERATIONAL_VERBS.search(proposal) and (limited or pre_harness))
                or (limited and not _SAFE_VERBS.match(proposal))
        )
        if safe_fallback:
            action = f"Verify source evidence, KIT applicability and decision needs for {', '.join(ids)}."
            fallbacks += 1
        else:
            action = proposal

        evidence = "; ".join(
            f"{t.event_id}: {_value(t.validation_status)}, KIT={t.program_relevance}, "
            f"Documents={','.join(getattr(t, 'evidence_ids', []) or []) or 'UNKNOWN'}"
            for t in related
        )
        rationale = f"Evidence status: {evidence}. "
        editor_reason = _clean(fields.get("RATIONALE", ""), 350)
        if editor_reason and not limited and action == proposal:
            rationale += f"Editor analysis (not independent evidence): {editor_reason}"
        else:
            rationale += "Further source verification or human review is required before implementation."

        safe_fields = {} if safe_fallback else fields
        pillar_name = safe_fields.get("TRIPLE_A", "").lower()
        pillar = (TripleAPillar.AGILITY if "agil" in pillar_name else
                  TripleAPillar.ALIGNMENT if "align" in pillar_name else
                  TripleAPillar.ADAPTABILITY)
        lead = max(related, key=_rank)
        risk = _value(lead.risk_type)
        owner = ("Regulatory Affairs Analyst" if risk == "REGULATORY" else
                 "Supply Chain Risk Analyst" if risk in {"SUPPLY_CHAIN", "TECHNICAL_QUALITY"} else
                 "Competitive Intelligence Analyst")
        pro = _clean(safe_fields.get("PRO", ""), 220) or "Supports documented verification and decision-making."
        con = _clean(safe_fields.get("CON", ""), 220) or "Requires analyst effort and human approval."
        key = "EDITOR_TEXT_V2:" + "|".join(ids) + ":" + action
        action_id = "ACT_" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:8].upper()
        if action_id in seen:
            recognized -= len(proposal) >= 10
            fallbacks -= action != proposal
            continue
        seen.add(action_id)
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
            kpi=_clean(safe_fields.get("KPI", ""), 250) or
                f"Evidence and management decision documented for {', '.join(ids)}.",
            priority=max((_priority(t) for t in related),
                         key={"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}.get),
            status="PROPOSED",
            decision="PENDING",
        ))

    audit = "Editor text converted into typed recommendations; independent evidence QA remains authoritative."
    if reason:
        audit += f" Summary fallback reason: {reason}."
    if rejected:
        audit += f" Rejected {rejected} action block(s) with ambiguous or unknown event links."
    return EditorialOutput(
        executive_summary=summary, qa_audit_summary=audit, action_plan=actions,
    ), recognized, fallbacks
