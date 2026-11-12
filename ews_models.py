# =============================================================================
# aviation_ci_app | Pydantic request contracts and API input validation
#
# Responsibility: Validate monitoring scope, enabled sources, optional replay parameters, targeted scans,
#   and analyst feedback.
# Design boundary: Schema validation does not itself grant permission or override server-side human-review
#   controls.
# =============================================================================


"""Pydantic request contracts for scans, human review, and analyst feedback."""

from typing import Literal
from datetime import date
from pydantic import field_validator, model_validator

from ews_state import (
    BaseModel,
    Field,
    List,
    Optional,
)


# Validated monitoring request including scope, platform, and governance switches.
# API schema validation checks inputs; review authorization is enforced by route handlers.
class EWSRequest(BaseModel):

    query: str = Field(
        min_length=1,
        max_length=600,
    )

    scope: Literal[
        "24h",
        "7d",
        "30d",
        "90d",
        "365d",
        "custom",
        "all",
    ] = "7d"

    date_from: Optional[str] = None
    date_to: Optional[str] = None
    as_of_date: Optional[str] = None

    platforms: List[str] = Field(min_length=1)

    limit: int = Field(
        default=5,
        ge=1,
        le=100,
        strict=True,
    )

    auto_approve: bool = False

    replay_run_id: Optional[str] = None

    enable_qa_agent: Literal[True] = True
    enable_harness_validation: Literal[True] = True

    use_keyword_baseline: bool = False

    # Reject blank KIT questions and normalize leading/trailing whitespace.
    @field_validator("query")
    @classmethod
    def validate_query(cls, value: str) -> str:

        value = value.strip()

        if not value:
            raise ValueError(
                "KIT query must not be empty"
            )

        return value

    # Validate and deduplicate user-selected source platform labels.
    # Invalid input raises a schema error rather than being accepted or silently coerced.
    @field_validator("platforms")
    @classmethod
    def validate_platforms(
        cls,
        values: List[str],
    ) -> List[str]:

        groups = {
            "news api & market intelligence": ["news"],
            "faa / easa / ntsb – regulatory & safety": ["regulatory", "ntsb"],
            "faa / easa / ntsb - regulatory & safety": ["regulatory", "ntsb"],
            "oem & supplier pressroom": ["pr"],
            "airshow & industry contracts": ["airshow"],
            "bluesky & youtube": ["bluesky", "youtube"],
        }

        expanded = []
        for value in values:
            if isinstance(value, str):
                expanded.extend(
                    groups.get(value.strip().lower(), [value])
                )
            else:
                expanded.append(value)

        values = expanded

        allowed = {
            "news",
            "news api",

            "regulatory",
            "faa",
            "easa",
            "faa & easa regulations",

            "ntsb",
            "ntsb investigations",

            "pr",
            "official pr releases",

            "bluesky",
            "bluesky social network",

            "youtube",
            "youtube videos",

            "airshow",
            "airshow websites",
        }

        names = []

        for item in values:

            if (
                not isinstance(item, str)
                or item.strip().lower() not in allowed
            ):
                raise ValueError(
                    f"Unknown source platform: {item!r}"
                )

            canonical = item.strip()

            if canonical.lower() not in {
                name.lower() for name in names
            }:
                names.append(canonical)

        return names

    # Reject malformed monitoring date inputs before running collection.
    @field_validator(
        "date_from",
        "date_to",
        "as_of_date",
    )
    @classmethod
    def validate_date(
        cls,
        value: str | None,
    ) -> str | None:

        if value is None or value == "":
            return None

        date.fromisoformat(value)

        return value

    # Check custom date ranges and scope-specific request constraints.
    @model_validator(mode="after")
    def validate_date_window(self):

        if (
            self.scope == "custom"
            and (
                not self.date_from
                or not self.date_to
            )
        ):
            raise ValueError(
                "Custom scope needs date_from and date_to"
            )

        if (
            self.date_from
            and self.date_to
            and self.date_from > self.date_to
        ):
            raise ValueError(
                "date_from must not be after date_to"
            )

        return self


# Follow-up verification request for a specific existing signal.
# Callers must still apply endpoint-level authorization and governance controls.
class TargetedScanRequest(BaseModel):
    event_id: str
    company_affected: str
    what_is_missing: str
    affected_kiq_id: str = "KIQ_1_1"
    scope: str = "30d"


# Authorized correction and reviewer-feedback payload.
# Callers must still apply endpoint-level authorization and governance controls.
class AnalystFeedbackRequest(BaseModel):
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
