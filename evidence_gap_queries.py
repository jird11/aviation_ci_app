"""Bounded search leads for missing KIT facets, not verified factual conclusions.

The result may authorize an extra search within the already selected platforms;
it never changes an event's validation, score, KIQ status, or HITL decision.
"""

from __future__ import annotations

import re
from typing import Any

from query_constraints import has_verified_subject_link, kit_components, kit_entities, kit_models

# Facet definitions: (facet_id, query_trigger_re, evidence_presence_re, search_terms) — preserved verbatim.
_FACETS = (
    ("COMPONENT", r"\b(?:casting\w*|forging\w*|turbine\s+blades?|fan\s+blades?)\b", r"\b(?:casting\w*|forging\w*|turbine\s+blades?|fan\s+blades?)\b", "component manufacturing supplier"),
    ("SUPPLY_CONSTRAINT", r"\b(?:shortag\w*|supply\s+constraint\w*|bottleneck\w*|scarcity)\b", r"\b(?:shortag\w*|supply\s+(?:constraint\w*|disruption\w*)|bottleneck\w*|scarcity|capacity\s+constraint\w*)\b", "shortage supply constraint bottleneck"),
    ("DELIVERY_IMPACT", r"\b(?:deliver\w*|production\s+impact|schedule\s+impact|disrupt\w*)\b", r"\b(?:deliver\w*\s+(?:delay\w*|disrupt\w*|impact\w*)|(?:delay\w*|disrupt\w*)\s+(?:deliver\w*|production)|production\s+(?:halt\w*|slowdown|impact\w*))\b", "delivery disruption production delay impact"),
    ("REGULATORY_RELATIONSHIP", r"\b(?:supersed\w*|replac\w*|withdraw\w*|rescind\w*)\b", r"\b(?:supersed\w*|replac\w*|withdraw\w*|rescind\w*)\b", "supersedes replacement withdrawn airworthiness directive"),
)
_EXACT_REG_RE = re.compile(r"\bFAA-20\d{2}-\d+\b|(?<!\d)20\d{2}-\d{5}(?!\d)", re.I)
_YEAR_RE = re.compile(r"(?:19|20)\d{2}")
_EXCLUDED_STATUSES = {"METADATA_ONLY", "UNAVAILABLE"}


def missing_kiq_facets(
    query: str,
    documents: list[dict[str, Any]],
    *,
    max_queries: int = 2,
) -> list[dict[str, str]]:
    """Propose narrow searches for KIT facets absent from collected candidate source text.

    Keyword presence is only a retrieval heuristic and never constitutes claim proof.
    """
    query = " ".join(str(query or "").split())
    if not query or max_queries <= 0:
        return []

    # Build mandatory subject/model/component anchors; skip open-ended unanchored queries.
    entities = kit_entities(query)
    models = [m for m in kit_models(query) if not _YEAR_RE.fullmatch(m)]
    anchors = [*_EXACT_REG_RE.findall(query)[:1], *entities[:1], *models[:1], *kit_components(query)[:1]]
    if not anchors:
        return []

    # Collect substantive, subject-linked candidate texts before checking facet coverage.
    entity_re = re.compile(rf"(?<!\w)(?:{'|'.join(map(re.escape, entities))})(?!\w)", re.I) if entities else None
    relevant_text = "\n".join(
        content for doc in documents
        if str(doc.get("content_status") or "").upper() not in _EXCLUDED_STATUSES
        and len(content := f"{doc.get('title') or ''} {doc.get('text') or ''}") >= 80
        and (not entity_re or (entity_re.search(content) and has_verified_subject_link(query, content)))
    )

    # Emit up to max_queries bounded follow-up leads for requested but unobserved facets.
    return [
        {
            "facet": facet,
            "query": " ".join(dict.fromkeys([*anchors, *search_terms.split()]))[:155],
            "reason": f"No matching {facet.lower()} passage in collected candidate source text; verification remains open.",
        }
        for facet, requested, observed, search_terms in _FACETS
        if re.search(requested, query, re.I) and not re.search(observed, relevant_text, re.I)
    ][:max_queries]