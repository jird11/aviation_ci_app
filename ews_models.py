# =============================================================================
# aviation_ci_app | Pydantic request contracts and API input validation
#
# Responsibility: Validate monitoring scope, enabled sources, optional replay
#   parameters, targeted scans, and analyst feedback.
# Design boundary: Schema validation does not grant permission or override
#   server-side human-review controls.
# =============================================================================

"""Pydantic request contracts for scans, human review, and analyst feedback."""

from datetime import date
from typing import Literal

from pydantic import field_validator, model_validator

from ews_state import BaseModel, Field, List, Optional

# UI platform-group expansions and allowed source platform labels (preserved verbatim).
_PLATFORM_GROUPS = {
    "news api & market intelligence": ["news"],
    "faa / easa / ntsb – regulatory & safety": ["regulatory", "ntsb"],
    "faa / easa / ntsb - regulatory & safety": ["regulatory", "ntsb"],
    "oem & supplier pressroom": ["pr"],
    "airshow & industry contracts": ["airshow"],
    "bluesky & youtube": ["bluesky", "youtube"],
}
_ALLOWED_PLATFORMS = {
    "news", "news api", "regulatory", "faa", "easa", "faa & easa regulations",
    "ntsb", "ntsb investigations", "pr", "official pr releases", "bluesky",
    "bluesky social network", "youtube", "youtube videos", "airshow", "airshow websites",
    "exa", "exa semantic search",
}


class EWSRequest(BaseModel):
    """Validated monitoring request including scope, platforms, and governance switches."""
    query: str = Field(min_length=1, max_length=600)
    scope: Literal["24h", "7d", "30d", "90d", "365d", "custom", "all"] = "7d"
    date_from: Optional[str] = None
    date_to: Optional[str] = None
    as_of_date: Optional[str] = None
    platforms: List[str] = Field(min_length=1)
    limit: int = Field(default=5, ge=1, le=100, strict=True)
    collection_mode: Literal["agentic_exa"] = "agentic_exa"
    auto_approve: bool = False
    replay_run_id: Optional[str] = None
    enable_qa_agent: Literal[True] = True
    enable_harness_validation: Literal[True] = True
    use_keyword_baseline: bool = False

    @field_validator("query")
    @classmethod
    def validate_query(cls, value: str) -> str:
        """Trim surrounding whitespace and reject blank KIT queries."""
        if not (cleaned := value.strip()):
            raise ValueError("KIT query must not be empty")
        return cleaned

    @field_validator("platforms")
    @classmethod
    def validate_platforms(cls, values: List[str]) -> List[str]:
        """Expand UI platform groups, validate labels, and deduplicate case-insensitively."""
        expanded = [
            item
            for v in values
            for item in (_PLATFORM_GROUPS.get(v.strip().lower(), [v]) if isinstance(v, str) else [v])
        ]
        names, seen = [], set()
        for item in expanded:
            if not isinstance(item, str) or (low := item.strip().lower()) not in _ALLOWED_PLATFORMS:
                raise ValueError(f"Unknown source platform: {item!r}")
            if low not in seen:
                seen.add(low)
                names.append(item.strip())
        return names

    @field_validator("date_from", "date_to", "as_of_date")
    @classmethod
    def validate_date(cls, value: str | None) -> str | None:
        """Convert empty date strings to None and validate ISO YYYY-MM-DD syntax."""
        if value is None or value == "":
            return None
        date.fromisoformat(value)
        return value

    @model_validator(mode="after")
    def validate_date_window(self):
        """Enforce required bounds for custom scope and chronological date ordering."""
        if self.scope == "custom" and (not self.date_from or not self.date_to):
            raise ValueError("Custom scope needs date_from and date_to")
        if self.date_from and self.date_to and self.date_from > self.date_to:
            raise ValueError("date_from must not be after date_to")
        return self


class TargetedScanRequest(BaseModel):
    """Follow-up verification request for an existing unresolved signal."""
    event_id: str
    company_affected: str
    what_is_missing: str
    affected_kiq_id: str = "KIQ_1_1"
    scope: str = "30d"


class AnalystFeedbackRequest(BaseModel):
    """Authorized analyst correction and reviewer-feedback payload."""
    event_id: str
    report_id: Optional[str] = None
    analyst_name: str = "Senior CI Analyst"
    feedback_type: str = "CONFIRM_RELEVANT"
    corrected_risk_type: Optional[str] = None
    corrected_score: Optional[int] = None
    flagged_source_url: Optional[str] = None
    added_missing_info: Optional[str] = None
    proposed_kiq: Optional[str] = None
    rationale: str = ""