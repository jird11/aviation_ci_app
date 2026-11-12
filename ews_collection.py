# =============================================================================
# aviation_ci_app | OSINT collection orchestration and source allocation
#
# Responsibility: Distribute KIT/KIQ queries across governed source connectors and enforce per-source
#   retrieval budgets.
# Design boundary: Collection produces evidence candidates; source relevance and event validity are
#   determined downstream.
# =============================================================================

"""Source-specific OSINT collection and KIQ-driven query orchestration."""

import re
import urllib.parse

import feedparser
from bs4 import BeautifulSoup

from tools import (
    AEROSPACE_SUPPLIER_REGISTRY,
    get_dynamic_limit,
    get_scope_days,
    is_date_within_scope,
    news_api_search_key,
    record_connector_telemetry,
    register_collected_document,
    safe_http_get,
)

from ews_state import (
    Callable,
    KIQPlan,
    List,
    PIPELINE_STATE,
    extract_youtube_transcript,
    logger,
    math,
    os,
    reset_collected_urls,
    scrape_airshow_website,
    scrape_manufacturer_pr_news,
    scrape_ntsb_investigations,
    scrape_regulatory_agencies,
    search_aerospace_news,
    search_bluesky_aviation,
)
from ews_state import SOURCE_REGISTRY
from ews_sources_extra import collect_extra

OPTIONAL_SOURCE_CONNECTORS = {}


# Register an optional connector only when its source policy permits collection.
def register_optional_connector(
    name: str,
    platform_key: str,
    source_id: str,
    collector,
):
    """Register a governed optional evidence connector."""
    source = SOURCE_REGISTRY.get(source_id)

    if source is None:
        raise ValueError(f"Unknown source ID: {source_id}")

    if source.get("legal_status") not in {"ALLOWED", "RESTRICTED"}:
        raise ValueError(
            f"Source {source_id} is not enabled for collection"
        )

    if not callable(getattr(collector, "run", None)):
        raise TypeError("Collector must implement run(query)")

    OPTIONAL_SOURCE_CONNECTORS[name] = {
        "platform_key": platform_key.lower(),
        "source_id": source_id,
        "collector": collector,
    }


# Run unique KIQ queries within a shared, dynamically allocated retrieval quota.
# Do not exceed the remaining per-source retrieval budget across KIQ queries.
def run_kiq_batch(tool_obj: Callable, queries: List[str], total_limit: int, source_label: str) -> str:
    # Deduplicate planned queries while retaining their original order.
    # Retain order so repeated runs remain easier to compare.
    unique_queries = list(dict.fromkeys([q.strip() for q in queries if q and q.strip()]))
    if not unique_queries:
        return ""

    remaining = total_limit
    combined_output = f"=== SOURCE: {source_label} (KIQ queries: {', '.join(unique_queries)}) ===\n"
    total_found = 0

    for i, q in enumerate(unique_queries):
        if PIPELINE_STATE.get("cancel_requested"):
            break
        if remaining <= 0:
            break

        queries_left = len(unique_queries) - i
        # Distribute the remaining retrieval allowance across outstanding questions.
        current_quota = max(1, math.ceil(remaining / queries_left))
        os.environ["EWS_DYNAMIC_LIMIT"] = str(current_quota)

        logger.info(f"[KIQ COLLECTION -> {source_label}] Query '{q}' (quota: {current_quota}, remaining: {remaining})")
        res = tool_obj.run(q)
        if source_label == "News API" and "News API disabled for this process" in res:
            logger.warning("[NEWS API] Circuit open; skipping remaining planned queries.")
            break

        found_in_step = res.count("DATE:")
        if found_in_step > 0:
            combined_output += f"\n[Results for KIQ: '{q}']\n{res}\n"
            remaining -= found_in_step
            total_found += found_in_step
        else:
            logger.info(f"[KIQ COLLECTION -> {source_label}] Query '{q}' returned no new records, reallocating quota.")

    os.environ["EWS_DYNAMIC_LIMIT"] = str(total_limit)

    if total_found == 0:
        return f"=== SOURCE: {source_label} ===\nNo records found for any KIQ queries ({', '.join(unique_queries)}).\n"

    return combined_output

# Derive exploratory supplier-linked queries outside the primary aircraft program.
# Supplemental supplier searches may add context but do not establish KIT relevance.
def build_cross_program_queries(kit: str, max_queries: int = 2):
    """Derive exploratory related-program queries from known supplier links."""
    kit_lower = kit.lower()
    candidates = []

    for supplier in AEROSPACE_SUPPLIER_REGISTRY:
        if "OEM" in supplier.get("default_tier", ""):
            continue

        programs = supplier.get("programs", [])

        matched = [
            program for program in programs
            if re.search(
                rf"(?<!\w){re.escape(program)}(?!\w)",
                kit_lower,
                re.I,
            )
        ]

        if not matched:
            continue

        related = [p for p in programs if p not in matched]

        for program in related:
            candidates.append(
                {
                    "query": (
                        f"{supplier['official_name']} {program} "
                        "production delay shortage"
                    ),
                    "supplier": supplier["official_name"],
                    "related_program": program,
                    "original_programs": matched,
                    "relationship_status": "HYPOTHETICAL_SHARED_SUPPLIER",
                }
            )

    unique = {}
    for item in candidates:
        unique.setdefault(item["query"], item)

    return list(unique.values())[:max_queries]

class OfficialIndustryPRCollector:
    def run(self, query: str) -> str:
        return scrape_manufacturer_pr_news.run(query)

# Orchestrate the selected source connectors and aggregate their raw evidence output.
# Preserve evidence provenance and stable output contracts for downstream stages.
def collect_osint_data(
        user_query: str, kiq_plan: KIQPlan, platforms: List[str], scope: str, limit: int, run_workspace: str
) -> str:
    # Build selected connector workloads from the active KIT/KIQ plan.
    reset_collected_urls()
    platforms_str = " ".join(platforms).lower()
    financial_kit = bool(re.search(
        r"\b(?:sec|edgar|esef|xbrl|10-[kq]|20-f|6-k|filings?|annual\s+reports?|financial\s+statements?)\b",
        user_query, re.I,
    ))
    regulatory_kit = bool(re.search(
        r"\b(?:faa|easa|ntsb|airworthiness|directive|regulat\w*|"
        r"investigat\w*|accident|incident|crash|safety\s+notice|compliance)\b",
        user_query, re.I,
    ))

    raw_data = (
            f"--- RAW OSINT COLLECTION DATA FOR KIT '{user_query}' ---\n"
            f"Time Scope: {scope} | Per-Source Limit: {limit} | Platforms: {', '.join(platforms)}\n"
            f"Decomposition Strategy (KIQ Rationale): {kiq_plan.strategy_rationale}\n"
            f"  - Media & PR KIQs: {kiq_plan.media_and_pr_queries}\n"
            f"  - Regulatory & NTSB KIQs: {kiq_plan.regulatory_and_ntsb_queries}\n"
            f"  - Social & Video KIQs: {kiq_plan.social_and_video_queries}\n"
            f"  - Airshow KIQ: {kiq_plan.airshow_query}\n"
            + ("=" * 70)
            + "\n\n"
    )

    if "news" in platforms_str and not PIPELINE_STATE.get("cancel_requested"):

        unique_news_queries = []
        seen_news_keys = set()

        for q in kiq_plan.media_and_pr_queries:
            key = news_api_search_key(q)

            if key in seen_news_keys:
                logger.info(
                    "[NEWS API DEDUP] "
                    "Skipped equivalent query: %r -> %s",
                    q,
                    key,
                )
                continue

            seen_news_keys.add(key)
            unique_news_queries.append(q)

        raw_data += run_kiq_batch(
            search_aerospace_news,
            unique_news_queries,
            limit,
            "News API",
        ) + "\n"

    if ("regul" in platforms_str or "easa" in platforms_str or "faa" in platforms_str) and (not financial_kit or regulatory_kit) and not PIPELINE_STATE.get(
            "cancel_requested"):
        raw_data += (
                run_kiq_batch(
                    scrape_regulatory_agencies, kiq_plan.regulatory_and_ntsb_queries, limit, "FAA & EASA Regulations"
                )
                + "\n"
        )
    elif financial_kit and not regulatory_kit:
        raw_data += "[SOURCE ROUTING] FAA/EASA skipped: financial filing KIT without regulatory intent.\n"

    incident_kit = bool(re.search(
        r"\b(?:ntsb|accident\w*|incident\w*|crash\w*|investigat\w*|"
        r"mishap\w*|safety\s+event|runway\s+incursion|door\s+plug)\b",
        user_query, re.I,
    ))
    if "ntsb" in platforms_str and incident_kit and not PIPELINE_STATE.get("cancel_requested"):
        raw_data += (
                run_kiq_batch(
                    scrape_ntsb_investigations, kiq_plan.regulatory_and_ntsb_queries, limit, "NTSB Investigations"
                )
                + "\n"
        )
    elif "ntsb" in platforms_str and not incident_kit:
        raw_data += "[SOURCE ROUTING] NTSB not searched: no incident/investigation KIT.\n"

    if "pr" in platforms_str and not PIPELINE_STATE.get("cancel_requested"):
        raw_data += (
                run_kiq_batch(
                    OfficialIndustryPRCollector(),
                    kiq_plan.media_and_pr_queries,
                    limit,
                    "Official Industry PR",
                )
                + "\n"
        )

    if (
            os.getenv("EWS_CROSS_PROGRAM_SCAN", "0") == "1"
            and "pr" in platforms_str
            and not PIPELINE_STATE.get("cancel_requested")
    ):
        # Aggregate traceable source records and connector telemetry for downstream filtering.
        related_queries = build_cross_program_queries(
            user_query,
            max_queries=2,
        )

        if related_queries:
            raw_data += run_kiq_batch(
                OfficialIndustryPRCollector(),
                [item["query"] for item in related_queries],
                min(limit, 2),
                "Official Industry PR – Cross-Program",
            ) + "\n"

    if ("bluesky" in platforms_str or "soc" in platforms_str) and not PIPELINE_STATE.get("cancel_requested"):
        raw_data += (
                run_kiq_batch(search_bluesky_aviation, kiq_plan.social_and_video_queries, limit,
                              "Bluesky Social Network")
                + "\n"
        )

    if ("youtube" in platforms_str or "vide" in platforms_str) and not PIPELINE_STATE.get("cancel_requested"):
        yt_limit = min(limit, 5)
        raw_data += (
                run_kiq_batch(extract_youtube_transcript, kiq_plan.social_and_video_queries[:1], yt_limit,
                              "YouTube Videos")
                + "\n"
        )

    # The Planner always supplies an airshow query; that alone is not a business KIT.
    commercial_kit = bool(re.search(
        r"\b(?:air\s?shows?|exhibitions?|trade\s+fairs?|farnborough|"
        r"paris\s+air\s+show|dubai\s+air\s+show|singapore\s+air\s+show|"
        r"aircraft\s+orders?|orderbook|contracts?|sales|partnerships?|"
        r"alliances?|product\s+launch(?:es)?|unveil\w*|trade\s+deals?)\b",
        user_query, re.I,
    ))
    if "airshow" in platforms_str and not PIPELINE_STATE.get("cancel_requested"):
        if commercial_kit:
            airshow_cap = limit
            os.environ["EWS_DYNAMIC_LIMIT"] = str(airshow_cap)
            try:
                raw_data += scrape_airshow_website.run(kiq_plan.airshow_query or user_query) + "\n"
            finally:
                os.environ["EWS_DYNAMIC_LIMIT"] = str(limit)
        else:
            logger.info("[SOURCE ROUTING] Skipped airshow scraper: no exhibition/commercial KIT intent")
            raw_data += "[SOURCE ROUTING] Airshow not searched: no exhibition/commercial KIT intent.\n"

    if not PIPELINE_STATE.get("cancel_requested"):
        raw_data += collect_extra(
            user_query, platforms, limit
        ) + "\n"

    for name, config in OPTIONAL_SOURCE_CONNECTORS.items():
        if PIPELINE_STATE.get("cancel_requested"):
            break

        if config["platform_key"] not in platforms_str:
            continue

        raw_data += run_kiq_batch(
            config["collector"],
            kiq_plan.media_and_pr_queries[:1],
            limit,
            name,
        ) + "\n"
    with open("raw_osint_data.txt", "w", encoding="utf-8") as f:
        f.write(raw_data)
    with open(os.path.join(run_workspace, "raw_osint_data.txt"), "w", encoding="utf-8") as f:
        f.write(raw_data)

    return raw_data
