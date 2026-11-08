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

# Optional governed connector for supplier-specific press evidence.
class SupplierPressCollector:
    """Collect public supplier-news metadata relevant to the monitored KIT."""

    SUPPLIER_DOMAINS = {
        "Pratt & Whitney (RTX)": "rtx.com",
        "CFM International (GE / Safran)": "cfmaeroengines.com",
        "GE Aerospace": "geaerospace.com",
        "Safran S.A.": "safran-group.com",
    }

    # Execute the connector or helper using its configured collection policy.
    # Preserve evidence provenance and stable output contracts for downstream stages.
    def run(self, query: str) -> str:
        query_lower = query.lower()
        selected = []

        for supplier in AEROSPACE_SUPPLIER_REGISTRY:
            name = supplier["official_name"]

            if name not in self.SUPPLIER_DOMAINS:
                continue

            terms = [
                        alias
                        for alias in supplier.get("aliases", [])
                        if len(alias) >= 3
                    ] + supplier.get("programs", [])

            if any(
                    re.search(rf"(?<!\w){re.escape(term)}(?!\w)", query_lower, re.I)
                    for term in terms
            ):
                selected.append((name, self.SUPPLIER_DOMAINS[name]))

        if not selected:
            return "No matching supplier in the monitored registry."

        output = []
        found = accepted = 0
        limit = min(get_dynamic_limit(), 3)
        scope_days = get_scope_days()
        date_filter = f" when:{scope_days}d" if scope_days else ""

        for name, domain in selected[:2]:
            search = urllib.parse.quote(
                f"site:{domain} {query}{date_filter}"
            )

            rss_url = (
                "https://news.google.com/rss/search?q="
                f"{search}&hl=en-US&gl=US&ceid=US:en"
            )

            response = safe_http_get(
                rss_url,
                source_id="SRC_009",
                timeout=12,
            )

            if response is None or response.status_code != 200:
                continue

            feed = feedparser.parse(response.content)

            for entry in feed.entries[:limit]:
                found += 1

                published = entry.get("published", "DATE_UNKNOWN")

                if not is_date_within_scope(published):
                    continue

                title = entry.get("title", "")
                url = entry.get("link", "")

                if not title or not url:
                    continue

                summary = BeautifulSoup(
                    entry.get("description", ""),
                    "html.parser",
                ).get_text(" ", strip=True)[:400]

                document = register_collected_document(
                    source_id="SRC_009",
                    connector_name="Supplier PR",
                    url=url,
                    title=title,
                    raw_text=summary or title,
                    published_at=published,
                    query_used=query,
                )

                output.append(
                    f"DOC_ID: {document['doc_id']} | SOURCE_ID: SRC_009\n"
                    f"DATE: {document['published_at']}\n"
                    f"SUPPLIER: {name}\n"
                    f"TITLE: {document['title']}\n"
                    f"URL: {url}\n"
                    f"TEXT: {document['text']}\n---"
                )

                accepted += 1

        record_connector_telemetry(
            "Supplier PR",
            "SRC_009",
            query,
            found,
            accepted,
            max(0, found - accepted),
        )

        return (
            "\n".join(output)
            if output
            else "No matching supplier releases found."
        )


# Orchestrate the selected source connectors and aggregate their raw evidence output.
# Preserve evidence provenance and stable output contracts for downstream stages.
def collect_osint_data(
        user_query: str, kiq_plan: KIQPlan, platforms: List[str], scope: str, limit: int, run_workspace: str
) -> str:
    # Build selected connector workloads from the active KIT/KIQ plan.
    reset_collected_urls()
    platforms_str = " ".join(platforms).lower()

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

    if ("regul" in platforms_str or "easa" in platforms_str or "faa" in platforms_str) and not PIPELINE_STATE.get(
            "cancel_requested"):
        raw_data += (
                run_kiq_batch(
                    scrape_regulatory_agencies, kiq_plan.regulatory_and_ntsb_queries, limit, "FAA & EASA Regulations"
                )
                + "\n"
        )

    if "ntsb" in platforms_str and not PIPELINE_STATE.get("cancel_requested"):
        raw_data += (
                run_kiq_batch(
                    scrape_ntsb_investigations, kiq_plan.regulatory_and_ntsb_queries, limit, "NTSB Investigations"
                )
                + "\n"
        )

    if "pr" in platforms_str and not PIPELINE_STATE.get("cancel_requested"):
        raw_data += (
                run_kiq_batch(scrape_manufacturer_pr_news, kiq_plan.media_and_pr_queries, limit, "Manufacturer PR")
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
                SupplierPressCollector(),
                [item["query"] for item in related_queries],
                min(limit, 2),
                "Cross-Program Supplier Watch",
            ) + "\n"

    if "pr" in platforms_str and not PIPELINE_STATE.get("cancel_requested"):
        raw_data += (
                run_kiq_batch(
                    SupplierPressCollector(),
                    kiq_plan.media_and_pr_queries,
                    min(limit, 3),
                    "Supplier PR",
                )
                + "\n"
        )

    if ("bluesky" in platforms_str or "soc" in platforms_str) and not PIPELINE_STATE.get("cancel_requested"):
        raw_data += (
                run_kiq_batch(search_bluesky_aviation, kiq_plan.social_and_video_queries, limit,
                              "Bluesky Social Network")
                + "\n"
        )

    if ("youtube" in platforms_str or "vide" in platforms_str) and not PIPELINE_STATE.get("cancel_requested"):
        yt_limit = min(limit, 3)
        raw_data += (
                run_kiq_batch(extract_youtube_transcript, kiq_plan.social_and_video_queries[:1], yt_limit,
                              "YouTube Videos")
                + "\n"
        )

    if "airshow" in platforms_str and not PIPELINE_STATE.get("cancel_requested"):
        airshow_cap = 2 if scope in {"24h", "7d"} else min(limit, 5)
        os.environ["EWS_DYNAMIC_LIMIT"] = str(airshow_cap)
        airshow_q = kiq_plan.airshow_query or user_query
        raw_data += scrape_airshow_website.run(airshow_q) + "\n"
        os.environ["EWS_DYNAMIC_LIMIT"] = str(limit)


    for name, config in OPTIONAL_SOURCE_CONNECTORS.items():
        if PIPELINE_STATE.get("cancel_requested"):
            break

        if config["platform_key"] not in platforms_str:
            continue

        raw_data += run_kiq_batch(
            config["collector"],
            kiq_plan.media_and_pr_queries[:1],
            min(limit, 3),
            name,
        ) + "\n"
    with open("raw_osint_data.txt", "w", encoding="utf-8") as f:
        f.write(raw_data)
    with open(os.path.join(run_workspace, "raw_osint_data.txt"), "w", encoding="utf-8") as f:
        f.write(raw_data)

    return raw_data
