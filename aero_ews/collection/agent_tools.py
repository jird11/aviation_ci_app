# =============================================================================
# aviation_ci_app | Budget-governed CrewAI tools for Intelligence Acquisition Agent
#
# Responsibility: Wrap Exa semantic search, official regulators, corporate filings/PR,
#   media/social connectors, and coverage inspection into CrewAI BaseTool classes
#   enforcing a shared run-wide call and time budget.
# Design boundary: Tools collect and register raw DOC_xxx evidence candidates; they
#   never assert relevance or confirm threats (owned by FR03 and Harness).
# =============================================================================

"""CrewAI BaseTool wrappers and shared call/time budget for autonomous OSINT acquisition."""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, Optional, Type

from crewai.tools import BaseTool
from pydantic import BaseModel, ConfigDict, Field

from aero_ews.collection.exa_connector import search_exa_structured
from ews_sources_extra import collect_extra
from ews_state import PIPELINE_STATE
from tools import (
    extract_youtube_transcript,
    get_collected_documents,
    get_connector_telemetry,
    scrape_airshow_website,
    scrape_manufacturer_pr_news,
    scrape_ntsb_investigations,
    scrape_regulatory_agencies,
    search_aerospace_news,
    search_bluesky_aviation,
)

logger = logging.getLogger(__name__)


@contextmanager
def _scoped_limit(limit: int):
    prev = os.environ.get("EWS_DYNAMIC_LIMIT")
    os.environ["EWS_DYNAMIC_LIMIT"] = str(max(1, int(limit)))
    try:
        yield
    finally:
        if prev is None:
            os.environ.pop("EWS_DYNAMIC_LIMIT", None)
        else:
            os.environ["EWS_DYNAMIC_LIMIT"] = prev


def _new_docs_since(before_ids: set[str]) -> List[Dict[str, Any]]:
    return [d for d in get_collected_documents() if d.get("doc_id") not in before_ids]


def _compact_doc_briefs(docs: List[Dict[str, Any]], max_items: int = 8) -> List[Dict[str, Any]]:
    """Return compact metadata + short excerpt so the agent can evaluate coverage without context bloat."""
    return [
        {
            "doc_id": d.get("doc_id"),
            "source_id": d.get("source_id"),
            "connector": d.get("connector_name"),
            "origin_type": d.get("origin_type"),
            "published_at": d.get("published_at"),
            "content_status": d.get("content_status"),
            "domain": d.get("publisher_domain"),
            "title": str(d.get("title") or "")[:160],
            "excerpt": " ".join(str(d.get("text") or "").split())[:240],
        }
        for d in docs[:max_items]
    ]


@dataclass
class AcquisitionBudget:
    """Thread-safe shared call, Exa, and wall-clock budget for one acquisition run."""
    max_total_calls: int = field(
        default_factory=lambda: max(1, min(20, int(os.getenv("EWS_ACQUISITION_MAX_STEPS", "10"))))
    )
    max_exa_calls: int = field(
        default_factory=lambda: max(0, min(10, int(os.getenv("EWS_EXA_MAX_CALLS", "4"))))
    )
    max_seconds: int = field(
        default_factory=lambda: max(20, min(600, int(os.getenv("EWS_ACQUISITION_TIME_BUDGET_SEC", "180"))))
    )
    per_call_limit: int = 5
    allowed_platforms: Optional[List[str]] = None
    max_inspections: int = 12
    started_monotonic: float = field(default_factory=time.monotonic)
    calls_made: int = 0
    exa_calls_made: int = 0
    inspections_made: int = 0
    raw_outputs: List[str] = field(default_factory=list)
    trace: List[Dict[str, Any]] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def _platforms_str(self) -> str:
        return " ".join(p.lower() for p in (self.allowed_platforms or []))

    def platform_enabled(self, *keywords: str) -> bool:
        if not self.allowed_platforms:
            return True
        ps = self._platforms_str()
        return any(kw in ps for kw in keywords)

    def reserve_call(self, tool_name: str, *, is_exa: bool = False) -> tuple[bool, str]:
        """Atomically check and reserve one search call against shared limits."""
        with self._lock:
            if PIPELINE_STATE.get("cancel_requested"):
                return False, "CANCELLED_BY_USER"
            elapsed = time.monotonic() - self.started_monotonic
            if elapsed >= self.max_seconds:
                return False, f"TIME_BUDGET_EXCEEDED ({round(elapsed, 1)}s >= {self.max_seconds}s)"
            if self.calls_made >= self.max_total_calls:
                return False, f"TOTAL_CALL_LIMIT_REACHED ({self.calls_made}/{self.max_total_calls})"
            if is_exa and self.exa_calls_made >= self.max_exa_calls:
                return False, f"EXA_CALL_LIMIT_REACHED ({self.exa_calls_made}/{self.max_exa_calls})"
            self.calls_made += 1
            if is_exa:
                self.exa_calls_made += 1
            return True, "OK"

    def reserve_inspection(self) -> tuple[bool, str]:
        with self._lock:
            if self.inspections_made >= self.max_inspections:
                return False, f"INSPECTION_LIMIT_REACHED ({self.inspections_made}/{self.max_inspections})"
            self.inspections_made += 1
            return True, "OK"

    def record_step(
        self,
        tool_name: str,
        query: str,
        status: str,
        new_doc_ids: List[str],
        *,
        raw_output: str = "",
        note: str = "",
    ) -> None:
        with self._lock:
            if raw_output:
                self.raw_outputs.append(raw_output)
            self.trace.append({
                "step": len(self.trace) + 1,
                "tool": tool_name,
                "query": query,
                "status": status,
                "new_doc_count": len(new_doc_ids),
                "new_doc_ids": list(new_doc_ids),
                "elapsed_sec": round(time.monotonic() - self.started_monotonic, 2),
                "calls_used": self.calls_made,
                "exa_calls_used": self.exa_calls_made,
                "note": note,
            })

    def summary(self) -> Dict[str, Any]:
        with self._lock:
            elapsed = round(time.monotonic() - self.started_monotonic, 2)
            return {
                "calls_made": self.calls_made,
                "max_total_calls": self.max_total_calls,
                "remaining_total_calls": max(0, self.max_total_calls - self.calls_made),
                "exa_calls_made": self.exa_calls_made,
                "max_exa_calls": self.max_exa_calls,
                "remaining_exa_calls": max(0, self.max_exa_calls - self.exa_calls_made),
                "elapsed_sec": elapsed,
                "max_seconds": self.max_seconds,
                "remaining_seconds": round(max(0.0, self.max_seconds - elapsed), 1),
                "steps_recorded": len(self.trace),
            }


# ---------------------------------------------------------------------------
# Tool input schemas
# ---------------------------------------------------------------------------

class ExaSearchInput(BaseModel):
    query: str = Field(description="Natural-language or semantic English query describing the aviation evidence needed.")
    num_results: int = Field(default=5, ge=1, le=10, description="Maximum number of web documents to retrieve (1-10).")
    include_domains: Optional[List[str]] = Field(
        default=None,
        description="Optional domain allowlist (e.g. ['faa.gov', 'easa.europa.eu', 'reuters.com', 'flightglobal.com']).",
    )
    exclude_domains: Optional[List[str]] = Field(
        default=None,
        description="Optional domains to exclude from results.",
    )


class RegulatorSearchInput(BaseModel):
    query: str = Field(description="Short identifier-based regulatory query (e.g., 'PW1100G turbine disk', '737 MAX 10 certification', 'LEAP-1A').")
    include_ntsb: bool = Field(default=False, description="Set True ONLY for safety accidents, crashes, or NTSB investigations.")
    limit: int = Field(default=4, ge=1, le=10, description="Per-connector record limit.")


class CorporateFilingsInput(BaseModel):
    query: str = Field(description="Company/program/issue query for SEC EDGAR, ESEF filings, and official OEM press releases.")
    include_pr: bool = Field(default=True, description="Search official manufacturer PR feeds (Airbus, Boeing, etc.).")
    include_filings: bool = Field(default=True, description="Search SEC EDGAR and ESEF corporate filings.")
    limit: int = Field(default=4, ge=1, le=10, description="Per-connector record limit.")


class MediaSocialInput(BaseModel):
    query: str = Field(description="Concise 2-6 keyword query for News API, Bluesky, or YouTube.")
    channel: Literal["news", "bluesky", "youtube", "all"] = Field(
        default="news",
        description="Channel to search: 'news', 'bluesky', 'youtube', or 'all'.",
    )
    limit: int = Field(default=4, ge=1, le=10, description="Per-channel record limit.")


class AirshowSearchInput(BaseModel):
    query: str = Field(description="Short 2-3 word query with manufacturer and aircraft model (e.g., 'Airbus A321XLR', 'Boeing 777X', 'COMAC C919').")
    limit: int = Field(default=4, ge=1, le=10, description="Maximum number of airshow newsroom articles to collect.")


class CoverageInspectInput(BaseModel):
    focus_terms: Optional[List[str]] = Field(
        default=None,
        description="Optional list of key entities, models, or KIQ terms to check against currently collected documents.",
    )

# ---------------------------------------------------------------------------
# Governed CrewAI BaseTool implementations
# ---------------------------------------------------------------------------

class _BudgetedBaseTool(BaseTool):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    budget: AcquisitionBudget = Field(..., exclude=True)


class ExaSemanticSearchTool(_BudgetedBaseTool):
    name: str = "exa_semantic_search"
    description: str = (
        "Semantic web discovery via Exa Search API (POST /search). Use for broad discovery, "
        "alternative phrasing, industry trade press, or domain-targeted searches. "
        "Returns registered DOC_IDs and short excerpts; secondary results still require official corroboration."
    )
    args_schema: Type[BaseModel] = ExaSearchInput

    def _run(
        self,
        query: str,
        num_results: int = 5,
        include_domains: Optional[List[str]] = None,
        exclude_domains: Optional[List[str]] = None,
    ) -> str:
        allowed, reason = self.budget.reserve_call(self.name, is_exa=True)
        if not allowed:
            self.budget.record_step(self.name, query, "BUDGET_EXCEEDED", [], note=reason)
            return json.dumps({
                "status": "BUDGET_EXCEEDED", "reason": reason,
                "budget": self.budget.summary(), "new_documents": [],
            }, ensure_ascii=False)

        eff_limit = min(max(1, int(num_results)), max(1, self.budget.per_call_limit))
        res = search_exa_structured(
            query,
            num_results=eff_limit,
            include_domains=include_domains,
            exclude_domains=exclude_domains,
        )
        self.budget.record_step(
            self.name,
            query,
            res["status"],
            res["doc_ids"],
            raw_output=f"=== AGENT TOOL: EXA SEMANTIC SEARCH ({query}) ===\n{res['raw_text']}\n",
            note=res.get("error", ""),
        )
        return json.dumps({
            "status": res["status"],
            "error": res.get("error", ""),
            "query": res["query"],
            "accepted_count": res.get("accepted_count", 0),
            "new_doc_ids": res["doc_ids"],
            "new_documents": _compact_doc_briefs(res["documents"]),
            "budget": self.budget.summary(),
        }, ensure_ascii=False)


class OfficialRegulatorsSearchTool(_BudgetedBaseTool):
    name: str = "search_official_regulators"
    description: str = (
        "Query primary aviation regulators: FAA Federal Register, EASA Official AD Index, "
        "and optionally NTSB investigations. Use whenever regulatory confirmation, airworthiness directives, "
        "or certification status is required."
    )
    args_schema: Type[BaseModel] = RegulatorSearchInput

    def _run(self, query: str, include_ntsb: bool = False, limit: int = 4) -> str:
        if not self.budget.platform_enabled("regul", "faa", "easa", "ntsb"):
            return json.dumps({"status": "PLATFORM_DISABLED", "new_documents": []})
        allowed, reason = self.budget.reserve_call(self.name)
        if not allowed:
            self.budget.record_step(self.name, query, "BUDGET_EXCEEDED", [], note=reason)
            return json.dumps({"status": "BUDGET_EXCEEDED", "reason": reason, "budget": self.budget.summary()})

        before_ids = {d["doc_id"] for d in get_collected_documents()}
        eff_limit = min(max(1, int(limit)), max(1, self.budget.per_call_limit))
        raw_parts: List[str] = []
        with _scoped_limit(eff_limit):
            raw_parts.append(str(scrape_regulatory_agencies.run(query)))
            if include_ntsb and self.budget.platform_enabled("ntsb", "regul"):
                raw_parts.append(str(scrape_ntsb_investigations.run(query)))

        new_docs = _new_docs_since(before_ids)
        new_ids = [d["doc_id"] for d in new_docs]
        status = "RESULTS_RETRIEVED" if new_docs else "NO_MATCH"
        self.budget.record_step(
            self.name, query, status, new_ids,
            raw_output=f"=== AGENT TOOL: OFFICIAL REGULATORS ({query}) ===\n" + "\n".join(raw_parts) + "\n",
        )
        return json.dumps({
            "status": status,
            "query": query,
            "accepted_count": len(new_docs),
            "new_doc_ids": new_ids,
            "new_documents": _compact_doc_briefs(new_docs),
            "budget": self.budget.summary(),
        }, ensure_ascii=False)


class CorporateFilingsSearchTool(_BudgetedBaseTool):
    name: str = "search_corporate_filings"
    description: str = (
        "Query primary issuer disclosures: SEC EDGAR (10-K/10-Q/8-K), XBRL/ESEF filings, "
        "and official OEM press releases (Airbus, Boeing). Use to verify manufacturer/supplier statements, "
        "AOG guidance, production targets, and financial disclosures."
    )
    args_schema: Type[BaseModel] = CorporateFilingsInput

    def _run(
        self,
        query: str,
        include_pr: bool = True,
        include_filings: bool = True,
        limit: int = 4,
    ) -> str:
        if not self.budget.platform_enabled("pr", "sec", "filing"):
            return json.dumps({"status": "PLATFORM_DISABLED", "new_documents": []})
        allowed, reason = self.budget.reserve_call(self.name)
        if not allowed:
            self.budget.record_step(self.name, query, "BUDGET_EXCEEDED", [], note=reason)
            return json.dumps({"status": "BUDGET_EXCEEDED", "reason": reason, "budget": self.budget.summary()})

        before_ids = {d["doc_id"] for d in get_collected_documents()}
        eff_limit = min(max(1, int(limit)), max(1, self.budget.per_call_limit))
        raw_parts: List[str] = []
        with _scoped_limit(eff_limit):
            if include_pr:
                raw_parts.append(str(scrape_manufacturer_pr_news.run(query)))
            if include_filings:
                raw_parts.append(str(collect_extra(query, ["pr"], eff_limit)))

        new_docs = _new_docs_since(before_ids)
        new_ids = [d["doc_id"] for d in new_docs]
        status = "RESULTS_RETRIEVED" if new_docs else "NO_MATCH"
        self.budget.record_step(
            self.name, query, status, new_ids,
            raw_output=f"=== AGENT TOOL: CORPORATE FILINGS & PR ({query}) ===\n" + "\n".join(raw_parts) + "\n",
        )
        return json.dumps({
            "status": status,
            "query": query,
            "accepted_count": len(new_docs),
            "new_doc_ids": new_ids,
            "new_documents": _compact_doc_briefs(new_docs),
            "budget": self.budget.summary(),
        }, ensure_ascii=False)


class MediaAndSocialSearchTool(_BudgetedBaseTool):
    name: str = "search_media_and_social"
    description: str = (
        "Query secondary media and early-warning channels: News API ('news'), Bluesky ('bluesky'), "
        "or YouTube ('youtube'). Use short 2-5 keyword queries for context or early signals."
    )
    args_schema: Type[BaseModel] = MediaSocialInput

    def _run(
        self,
        query: str,
        channel: Literal["news", "bluesky", "youtube", "all"] = "news",
        limit: int = 4,
    ) -> str:
        allowed, reason = self.budget.reserve_call(self.name)
        if not allowed:
            self.budget.record_step(self.name, query, "BUDGET_EXCEEDED", [], note=reason)
            return json.dumps({"status": "BUDGET_EXCEEDED", "reason": reason, "budget": self.budget.summary()})

        before_ids = {d["doc_id"] for d in get_collected_documents()}
        eff_limit = min(max(1, int(limit)), max(1, self.budget.per_call_limit))
        raw_parts: List[str] = []
        with _scoped_limit(eff_limit):
            if channel in {"news", "all"} and self.budget.platform_enabled("news"):
                raw_parts.append(str(search_aerospace_news.run(query)))
            if channel in {"bluesky", "all"} and self.budget.platform_enabled("bluesky", "soc"):
                raw_parts.append(str(search_bluesky_aviation.run(query)))
            if channel in {"youtube", "all"} and self.budget.platform_enabled("youtube", "vide"):
                raw_parts.append(str(extract_youtube_transcript.run(query)))

        new_docs = _new_docs_since(before_ids)
        new_ids = [d["doc_id"] for d in new_docs]
        status = "RESULTS_RETRIEVED" if new_docs else ("PLATFORM_DISABLED" if not raw_parts else "NO_MATCH")
        self.budget.record_step(
            self.name, f"[{channel}] {query}", status, new_ids,
            raw_output=f"=== AGENT TOOL: MEDIA & SOCIAL ({channel}: {query}) ===\n" + "\n".join(raw_parts) + "\n",
        )
        return json.dumps({
            "status": status,
            "channel": channel,
            "query": query,
            "accepted_count": len(new_docs),
            "new_doc_ids": new_ids,
            "new_documents": _compact_doc_briefs(new_docs),
            "budget": self.budget.summary(),
        }, ensure_ascii=False)


class InspectCollectionCoverageTool(_BudgetedBaseTool):
    name: str = "inspect_collection_coverage"
    description: str = (
        "Deterministically inspect currently collected documents, primary vs secondary balance, "
        "content completeness (FULL_TEXT vs METADATA_ONLY), remaining call/Exa budget, and which "
        "focus terms are still missing. Does not consume a search call."
    )
    args_schema: Type[BaseModel] = CoverageInspectInput

    def _run(self, focus_terms: Optional[List[str]] = None) -> str:
        ok, reason = self.budget.reserve_inspection()
        if not ok:
            return json.dumps({"status": "INSPECTION_LIMIT_REACHED", "reason": reason, "budget": self.budget.summary()})

        docs = get_collected_documents()
        by_source: Dict[str, int] = {}
        by_content: Dict[str, int] = {}
        primary_count = 0
        for d in docs:
            cname = str(d.get("connector_name") or "Unknown")
            by_source[cname] = by_source.get(cname, 0) + 1
            cstat = str(d.get("content_status") or "UNKNOWN")
            by_content[cstat] = by_content.get(cstat, 0) + 1
            if str(d.get("origin_type") or "").startswith("PRIMARY"):
                primary_count += 1

        term_coverage: Dict[str, int] = {}
        for term in (focus_terms or [])[:12]:
            t_low = str(term).strip().lower()
            if not t_low:
                continue
            term_coverage[term] = sum(
                1 for d in docs
                if t_low in f"{d.get('title', '')} {d.get('text', '')}".lower()
            )

        telemetry = get_connector_telemetry()
        connector_errors = {
            name: info.get("errors", [])
            for name, info in telemetry.items()
            if isinstance(info, dict) and info.get("errors")
        }

        return json.dumps({
            "total_documents": len(docs),
            "primary_documents": primary_count,
            "secondary_documents": len(docs) - primary_count,
            "by_connector": by_source,
            "by_content_status": by_content,
            "focus_term_hits": term_coverage,
            "missing_focus_terms": [k for k, v in term_coverage.items() if v == 0],
            "connector_errors": connector_errors,
            "budget": self.budget.summary(),
            "recent_documents": _compact_doc_briefs(docs[-10:], max_items=10),
        }, ensure_ascii=False)


class AirshowNewsroomsSearchTool(_BudgetedBaseTool):
    name: str = "search_airshow_newsrooms"
    description: str = (
        "Crawl official international airshow newsrooms (Farnborough, Paris Air Show, Dubai, Singapore, ILA Berlin) "
        "via Playwright. Use for aircraft orders, contracts, product launches, partnerships, or exhibition announcements."
    )
    args_schema: Type[BaseModel] = AirshowSearchInput

    def _run(self, query: str, limit: int = 4) -> str:
        if not self.budget.platform_enabled("airshow"):
            return json.dumps({"status": "PLATFORM_DISABLED", "new_documents": []})
        allowed, reason = self.budget.reserve_call(self.name)
        if not allowed:
            self.budget.record_step(self.name, query, "BUDGET_EXCEEDED", [], note=reason)
            return json.dumps({"status": "BUDGET_EXCEEDED", "reason": reason, "budget": self.budget.summary()})

        before_ids = {d["doc_id"] for d in get_collected_documents()}
        eff_limit = min(max(1, int(limit)), max(1, self.budget.per_call_limit))
        with _scoped_limit(eff_limit):
            raw_out = str(scrape_airshow_website.run(query))

        new_docs = _new_docs_since(before_ids)
        new_ids = [d["doc_id"] for d in new_docs]
        status = "RESULTS_RETRIEVED" if new_docs else "NO_MATCH"
        self.budget.record_step(
            self.name, query, status, new_ids,
            raw_output=f"=== AGENT TOOL: AIRSHOW NEWSROOMS ({query}) ===\n{raw_out}\n",
        )
        return json.dumps({
            "status": status,
            "query": query,
            "accepted_count": len(new_docs),
            "new_doc_ids": new_ids,
            "new_documents": _compact_doc_briefs(new_docs),
            "budget": self.budget.summary(),
        }, ensure_ascii=False)


def build_acquisition_tools(budget: AcquisitionBudget) -> List[BaseTool]:
    """Build all 6 governed CrewAI acquisition tools bound to one shared run budget."""
    return [
        ExaSemanticSearchTool(budget=budget),
        OfficialRegulatorsSearchTool(budget=budget),
        CorporateFilingsSearchTool(budget=budget),
        MediaAndSocialSearchTool(budget=budget),
        AirshowNewsroomsSearchTool(budget=budget),
        InspectCollectionCoverageTool(budget=budget),
    ]