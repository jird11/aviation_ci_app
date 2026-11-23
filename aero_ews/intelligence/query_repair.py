"""Pure additive repair helpers for planner queries missing explicit KIT constraints."""

from __future__ import annotations

import re
from typing import Callable, Iterable

# Guard violations repairable by appending missing KIT terms (preserved verbatim).
ADDITIVE_REASONS = frozenset({
    "MISSING_MODEL", "MISSING_AUTHORITY", "MISSING_COMPONENT",
    "MISSING_ENTITY", "ISSUE_SCOPE_MISMATCH",
})
_TOKEN = re.compile(r"[\w][\w./+-]*")


def surface_terms(subject: str, wanted: Iterable[str],
                  detector: Callable[[str], Iterable[str]], max_ngram: int = 3) -> list[str]:
    """Return shortest n-gram spans from subject whose detector outputs cover wanted keys."""
    remaining, tokens, found = set(wanted), _TOKEN.findall(subject or ""), []
    # Scan increasing n-gram lengths so shorter exact surface forms are preferred.
    for size in range(1, max_ngram + 1):
        for start in range(max(len(tokens) - size + 1, 0)):
            if not remaining:
                return found
            span = " ".join(tokens[start:start + size])
            if hit := set(detector(span)) & remaining:
                found.append(span)
                remaining -= hit
    return found


def append_missing(proposed: str, terms: Iterable[str]) -> str:
    """Append terms absent from the query (case-insensitive word-boundary match)."""
    base, extra = proposed or "", []
    for raw in terms:
        if not (term := (raw or "").strip()):
            continue
        # Check both original query and already-queued additions to prevent duplicates.
        pat = rf"(?<!\w){re.escape(term)}(?!\w)"
        if not re.search(pat, base, re.I) and not re.search(pat, " ".join(extra), re.I):
            extra.append(term)
    return " ".join([base.strip(), *extra]).strip()