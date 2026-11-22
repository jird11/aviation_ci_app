"""Additive repair of planner queries that merely lack a KIT constraint.

The planner guard used to replace every non-compliant query with one generic
``<KIT> + <intent>`` sentence, so a dozen distinct, purposeful queries collapsed
into one per channel. A query that only *lacks* a KIT model, authority,
component, entity or intent is repaired here by appending the missing KIT terms,
which keeps its distinctive wording (site: filters, quoted phrases, source hints).

Pure functions only: detectors are injected so the module has no heavy imports.
"""

from __future__ import annotations

import re
from typing import Callable, Iterable

# Violations that can be fixed by adding words. Anything else (unrequested
# model/authority/topic, excluded entity, time-scope drift) still needs replacement.
ADDITIVE_REASONS = frozenset({
    "MISSING_MODEL", "MISSING_AUTHORITY", "MISSING_COMPONENT",
    "MISSING_ENTITY", "ISSUE_SCOPE_MISMATCH",
})

_TOKEN = re.compile(r"[\w][\w./+-]*")


def surface_terms(subject: str, wanted: Iterable[str],
                  detector: Callable[[str], Iterable[str]], max_ngram: int = 3) -> list[str]:
    """Shortest spans of ``subject`` whose detected keys cover ``wanted``."""
    remaining = set(wanted)
    tokens = _TOKEN.findall(subject or "")
    found: list[str] = []
    for size in range(1, max_ngram + 1):
        for start in range(0, max(len(tokens) - size + 1, 0)):
            if not remaining:
                return found
            span = " ".join(tokens[start:start + size])
            hit = set(detector(span)) & remaining
            if hit:
                found.append(span)
                remaining -= hit
    return found


def append_missing(proposed: str, terms: Iterable[str]) -> str:
    """Append terms that are not already in the query (case-insensitive)."""
    base = proposed or ""
    extra: list[str] = []

    def present(term: str, text: str) -> bool:
        return re.search(rf"(?<![\w]){re.escape(term)}(?![\w])", text, re.I) is not None

    for term in terms:
        term = (term or "").strip()
        if term and not present(term, base) and not present(term, " ".join(extra)):
            extra.append(term)
    return " ".join([(proposed or "").strip(), *extra]).strip()
