# =============================================================================
# aviation_ci_app | Agentic OSINT collection orchestration
#
# Responsibility: Execute adaptive multi-tool OSINT acquisition (Exa + governed
#   regulators, filings/PR, media/social, airshows) under a shared run budget.
# Design boundary: Collection produces evidence candidates; source relevance
#   and event validity are determined downstream by FR03 and Harness.
# =============================================================================

"""Adaptive OSINT collection driven by Agent 1 (Planning & Acquisition)."""

import json
import os
import re
from typing import List

from aero_ews.collection.queries import AGENCIES, _model_aliases, _model_tokens
from ews_state import KIQPlan, PIPELINE_STATE, logger, reset_collected_urls

_ENGINE_VARIANT_RE = re.compile(r"\b(?:[A-Z]{2,}[A-Z0-9]*-\d+[A-Z0-9-]*|[A-Z]{2,}\d+[A-Z0-9-]*)\b", re.I)


def _engine_variants(text: str) -> set[str]:
    """Preserve distinct named engine/model variants without assuming a fixed catalog."""
    return {
        m.group().upper()
        for m in _ENGINE_VARIANT_RE.finditer(str(text or ""))
        if not re.search(r"-(?:19|20)\d{2}(?:-|$)", m.group(), re.I)
    }


def _kit_precision(kit: str) -> str:
    """Classify KIT scope specificity as EXACT, PROGRAM, or BROAD."""
    if re.search(r"\bFAA-20\d{2}-\d{3,7}\b", kit, re.I):
        return "EXACT"
    models, variants = _model_tokens(kit), _engine_variants(kit)
    has_constraint = (
        any(re.search(rf"\b{re.escape(a)}\b", kit, re.I) for a in AGENCIES)
        or bool(re.search(r"\b(?:20\d{2}|\d{4}-\d{2}(?:-\d{2})?)\b", kit))
        or bool(re.search(
            r"\b(?:inspection\s+requirements?|compliance\s+deadlines?|mandatory\s+inspections?|"
            r"gearbox|specific\s+component|docket)\b",
            kit, re.I,
        ))
    )
    remainder = kit
    for m in models:
        for alias in _model_aliases(m[1:] if re.match(r"B\d{3}(?!\d)", m, re.I) else m):
            remainder = re.sub(re.escape(alias), " ", remainder, flags=re.I)
    details = re.findall(r"\b[a-z]{4,}\b", remainder, re.I)
    if (models or variants) and (has_constraint or len(details) >= 6 or len(variants) > 1):
        return "EXACT"
    return "PROGRAM" if (models or variants) else "BROAD"


def _parse_acquisition_reflection(raw_text: str) -> dict:
    """Safely parse the final JSON reflection returned by the Acquisition Agent."""
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", str(raw_text or "").strip(), flags=re.I).strip()
    if not text:
        return {}
    try:
        data = json.loads(text)
        return data if isinstance(data, dict) else {}
    except ValueError:
        match = re.search(r"\{.*\}", text, flags=re.S)
        if match:
            try:
                data = json.loads(match.group(0))
                return data if isinstance(data, dict) else {}
            except ValueError:
                pass
    return {"agent_rationale": text[:500]}


def _short_channel_query(user_query: str, max_words: int = 6) -> str:
    """Build a concise keyword query suitable for Bluesky, YouTube, NewsAPI, or Airshows."""
    words = [w for w in re.split(r"\s+", str(user_query or "").strip()) if w]
    return " ".join(words[:max_words]) or str(user_query or "").strip()


def _enforce_selected_platforms(
    user_query: str,
    kiq_plan: KIQPlan,
    budget,
) -> None:
    """Deterministically execute any user-selected platform skipped by the Acquisition Agent."""
    from aero_ews.collection.agent_tools import _new_docs_since, _scoped_limit
    from ews_sources_extra import collect_extra
    from ews_state import get_collected_documents, get_connector_telemetry
    from tools import (
        extract_youtube_transcript,
        scrape_airshow_website,
        scrape_manufacturer_pr_news,
        scrape_regulatory_agencies,
        search_aerospace_news,
        search_bluesky_aviation,
    )

    if PIPELINE_STATE.get("cancel_requested"):
        return

    telemetry = get_connector_telemetry()
    executed_sids = {
        str(info.get("source_id") or "")
        for info in telemetry.values()
        if isinstance(info, dict)
        and (info.get("queries") or info.get("http_requests") or info.get("accepted_count"))
    }

    social_q = (
        (kiq_plan.social_and_video_queries[0] if getattr(kiq_plan, "social_and_video_queries", None) else "")
        or _short_channel_query(user_query, 5)
    )
    media_q = (
        (kiq_plan.media_and_pr_queries[0] if getattr(kiq_plan, "media_and_pr_queries", None) else "")
        or _short_channel_query(user_query, 6)
    )
    reg_q = (
        (kiq_plan.regulatory_and_ntsb_queries[0] if getattr(kiq_plan, "regulatory_and_ntsb_queries", None) else "")
        or _short_channel_query(user_query, 6)
    )
    airshow_q = getattr(kiq_plan, "airshow_query", "") or _short_channel_query(user_query, 3)

    eff_limit = max(1, min(int(budget.per_call_limit), 5))

    # (enabled_check, already_ran_sids, tool_label, query, runner)
    mandatory_checks = [
        (
            budget.platform_enabled("bluesky", "soc"),
            {"SRC_007"},
            "search_media_and_social[bluesky]",
            social_q,
            lambda q: str(search_bluesky_aviation.run(q)),
        ),
        (
            budget.platform_enabled("youtube", "vide"),
            {"SRC_008"},
            "search_media_and_social[youtube]",
            social_q,
            lambda q: str(extract_youtube_transcript.run(q)),
        ),
        (
            budget.platform_enabled("news"),
            {"SRC_004"},
            "search_media_and_social[news]",
            media_q,
            lambda q: str(search_aerospace_news.run(q)),
        ),
        (
            budget.platform_enabled("airshow"),
            {"SRC_006"},
            "search_airshow_newsrooms",
            airshow_q,
            lambda q: str(scrape_airshow_website.run(q)),
        ),
        (
            budget.platform_enabled("regul", "faa", "easa"),
            {"SRC_001", "SRC_002"},
            "search_official_regulators",
            reg_q,
            lambda q: str(scrape_regulatory_agencies.run(q)),
        ),
        (
            budget.platform_enabled("pr", "sec", "filing"),
            {"SRC_005", "SRC_027", "SRC_030", "SRC_031"},
            "search_corporate_filings",
            media_q,
            lambda q: "\n".join([
                str(scrape_manufacturer_pr_news.run(q)),
                str(collect_extra(q, ["pr"], eff_limit)),
            ]),
        ),
    ]

    for enabled, sids, tool_label, q_text, runner in mandatory_checks:
        if PIPELINE_STATE.get("cancel_requested"):
            break
        if not enabled or (executed_sids & sids):
            continue
        before_ids = {d["doc_id"] for d in get_collected_documents()}
        logger.info("[PHASE 2 MANDATORY CHANNEL] Enforcing selected platform %s for query=%r", tool_label, q_text)
        try:
            with _scoped_limit(eff_limit):
                raw_out = runner(q_text)
            new_docs = _new_docs_since(before_ids)
            new_ids = [d["doc_id"] for d in new_docs]
            status = "RESULTS_RETRIEVED" if new_docs else "NO_MATCH"
            budget.record_step(
                tool_label,
                q_text,
                status,
                new_ids,
                raw_output=f"=== MANDATORY SELECTED PLATFORM: {tool_label} ({q_text}) ===\n{raw_out}\n",
                note="MANDATORY_SELECTED_PLATFORM_GUARANTEE",
            )
            executed_sids |= sids
        except Exception as exc:
            logger.warning("[PHASE 2 MANDATORY CHANNEL] %s failed: %s", tool_label, exc)
            budget.record_step(
                tool_label,
                q_text,
                "ERROR",
                [],
                note=f"MANDATORY_SELECTED_PLATFORM_ERROR: {type(exc).__name__}: {str(exc)[:180]}",
            )

def collect_osint_agentic(
    user_query: str,
    kiq_plan: KIQPlan,
    platforms: List[str],
    scope: str,
    limit: int,
    run_workspace: str,
) -> tuple[str, List[dict], dict, dict]:
    """Run Agent 1 adaptive OSINT acquisition with Exa + governed tools under a shared budget."""
    from agents import create_planning_and_acquisition_agent
    from aero_ews.collection.agent_tools import AcquisitionBudget, build_acquisition_tools
    from ews_agent_support import _kickoff_crew_with_smart_recovery
    from ews_state import Crew, Process, get_collected_documents, get_connector_telemetry, get_time_window_utc
    from tasks import AcquisitionTrace, create_acquisition_task

    reset_collected_urls()
    precision = _kit_precision(user_query)
    start_utc, end_utc = get_time_window_utc()
    window_start = start_utc.strftime("%Y-%m-%d") if start_utc else "UNRESTRICTED"
    window_end = end_utc.strftime("%Y-%m-%d")

    budget = AcquisitionBudget(
        max_total_calls=max(2, min(16, int(os.getenv("EWS_ACQUISITION_MAX_STEPS", "10")))),
        max_exa_calls=max(0, min(8, int(os.getenv("EWS_EXA_MAX_CALLS", "4")))),
        max_seconds=max(30, min(480, int(os.getenv("EWS_ACQUISITION_TIME_BUDGET_SEC", "180")))),
        per_call_limit=max(1, min(10, int(limit))),
        allowed_platforms=list(platforms),
    )
    tools = build_acquisition_tools(budget)
    agent = create_planning_and_acquisition_agent(
        tools=tools,
        max_iter=min(14, budget.max_total_calls + 4),
    )
    task = create_acquisition_task(
        agent,
        user_query,
        kiq_plan,
        scope=scope,
        precision=precision,
        platforms=platforms,
        budget_summary=budget.summary(),
        window_start=window_start,
        window_end=window_end,
    )

    tokens_in = tokens_out = 0
    reflection: dict = {}
    agent_error = ""

    logger.info(
        "[PHASE 2 AGENTIC] Starting Intelligence Planning & Acquisition loop for %r "
        "(budget: calls=%d, exa=%d, time=%ds, precision=%s)",
        user_query, budget.max_total_calls, budget.max_exa_calls, budget.max_seconds, precision,
    )
    try:
        crew = Crew(agents=[agent], tasks=[task], process=Process.sequential, verbose=False)
        res, tokens_in, tokens_out = _kickoff_crew_with_smart_recovery(crew, "PHASE_2_ACQUISITION")
        reflection = _parse_acquisition_reflection(getattr(res, "raw", "") or str(res or ""))
    except Exception as exc:
        agent_error = f"{type(exc).__name__}: {str(exc)[:240]}"
        logger.warning("[PHASE 2 AGENTIC] Acquisition agent failed (%s); calls_made=%d", agent_error, budget.calls_made)

    # Guarantee every explicitly user-selected platform executes at least once.
    _enforce_selected_platforms(user_query, kiq_plan, budget)

    header = (
        f"--- AGENTIC OSINT COLLECTION DATA FOR KIT '{user_query}' ---\n"
        f"Collection Mode: agentic_exa | Time Scope: {scope} ({window_start} -> {window_end}) | "
        f"Precision: {precision} | Platforms: {', '.join(platforms)}\n"
        f"Budget Used: {json.dumps(budget.summary(), ensure_ascii=False)}\n"
        f"Strategy Rationale: {getattr(kiq_plan, 'strategy_rationale', '')}\n"
        + ("=" * 70) + "\n\n"
    )
    raw_data = header + "\n".join(budget.raw_outputs)
    for out_path in ("raw_osint_data.txt", os.path.join(run_workspace, "raw_osint_data.txt")):
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(raw_data)

    docs = get_collected_documents()
    telemetry = get_connector_telemetry()

    primary_docs = sum(1 for d in docs if str(d.get("origin_type") or "").startswith("PRIMARY"))
    full_text_docs = sum(1 for d in docs if d.get("content_status") == "FULL_TEXT")
    metadata_docs = sum(1 for d in docs if d.get("content_status") == "METADATA_ONLY")
    sources_used = sorted({str(d.get("connector_name") or d.get("source_id") or "Unknown") for d in docs})

    raw_status = str(reflection.get("collection_status") or "").upper()
    if (agent_error or budget.calls_made == 0) and not docs:
        final_status = "FAILED" if (agent_error and not PIPELINE_STATE.get("cancel_requested")) else "NO_RESULTS"
    elif not docs:
        final_status = "NO_RESULTS"
    elif raw_status in {"COMPLETED", "PARTIAL_SUCCESS", "NO_RESULTS"}:
        final_status = raw_status
    elif agent_error or budget.summary()["remaining_total_calls"] == 0:
        final_status = "PARTIAL_SUCCESS"
    else:
        final_status = "COMPLETED"

    unresolved = reflection.get("unresolved_requirements")
    if not isinstance(unresolved, list):
        unresolved = [str(unresolved)] if unresolved else []
    unresolved = [str(x).strip() for x in unresolved if str(x).strip()][:8]

    rationale = str(reflection.get("agent_rationale") or "").strip()
    if agent_error:
        rationale = f"{rationale} [Agent error: {agent_error}]".strip()

    trace_obj = AcquisitionTrace(
        kit=user_query,
        collection_mode="agentic_exa",
        search_objective=str(reflection.get("search_objective") or getattr(kiq_plan, "strategy_rationale", "") or user_query)[:300],
        queries_executed=budget.calls_made,
        exa_calls_executed=budget.exa_calls_made,
        sources_used=sources_used,
        documents_found=len(docs),
        primary_documents=primary_docs,
        secondary_documents=len(docs) - primary_docs,
        full_text_documents=full_text_docs,
        metadata_only_documents=metadata_docs,
        unresolved_requirements=unresolved,
        collection_status=final_status,
        next_action=str(reflection.get("next_action") or "")[:240],
        agent_rationale=rationale[:600],
        steps=list(budget.trace),
        budget_summary=budget.summary(),
        fallback_used=False,
        llm_tokens_in=tokens_in,
        llm_tokens_out=tokens_out,
    )
    acquisition_trace = trace_obj.model_dump(mode="json")

    logger.info(
        "[PHASE 2 AGENTIC COMPLETE] status=%s docs=%d (primary=%d, secondary=%d) calls=%d exa=%d",
        final_status, len(docs), primary_docs, len(docs) - primary_docs,
        budget.calls_made, budget.exa_calls_made,
    )
    return raw_data, docs, telemetry, acquisition_trace