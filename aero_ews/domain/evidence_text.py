"""Source-bound passage verification, distinct from event or KIQ confirmation."""

import hashlib
import hmac
import json
import re
import unicodedata
from typing import Any, Dict, List
from urllib.parse import urlsplit


SEC_VISIBLE_TEXT_METHOD = "HTML_VISIBLE_TEXT_WHITESPACE_V1"
SUPPORTED_EXTRACTION_METHODS = frozenset({SEC_VISIBLE_TEXT_METHOD})
_METADATA_ONLY = {"METADATA_ONLY", "SUMMARY_ONLY", "STRUCTURED_DATA"}
_PASSAGE_KEYS = ("verified_passages", "source_passages", "evidence_passages", "passages")
_HASH_KEYS = ("quote_sha256", "passage_sha256", "quote_hash", "passage_hash", "sha256")
_VERIFIED_STATES = {"SOURCE_PASSAGE_VERIFIED", "PASSAGE_VERIFIED", "QUOTE_VERIFIED", "VERIFIED"}
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def normalize_text(text: str) -> str:
    if not text:
        return ""
    text = re.sub(r"[\u2010-\u2015]", "-", str(text))
    text = re.sub(r"[\u2018-\u201B\u00B4\u0060]", "'", text)
    text = re.sub(r"[\u201C-\u201F]", '"', text)
    return re.sub(r"\s+", " ", text).strip()


def _normalize_for_quote_match(text: str) -> str:
    clean = re.sub(r"\n[ \t]*\d{1,4}[ \t]*\n[ \t]*Table of Contents[ \t]*\n",
                   " ", str(text or ""), flags=re.I)
    return re.sub(r"\s+", " ", re.sub(r"[^\w\s]", " ", normalize_text(clean).lower())).strip()


def _first(data: Dict[str, Any], *keys: str) -> str:
    return next((str(value).strip() for key in keys
                 if (value := data.get(key)) not in (None, "")), "")


def _metadata_layers(doc: Dict[str, Any]):
    """Inspect bounded metadata layers, including serialized replay metadata."""
    queue, seen = [doc], set()
    for layer in queue:
        if isinstance(layer, str):
            try:
                layer = json.loads(layer)
            except (ValueError, TypeError):
                continue
        if not isinstance(layer, dict) or id(layer) in seen:
            continue
        seen.add(id(layer))
        yield layer
        for key in ("source_metadata", "metadata", "evidence_metadata", "sec_metadata",
                    "extraction_metadata", "sec"):
            nested = layer.get(key)
            if isinstance(nested, (dict, str)) and len(queue) < 12:
                queue.append(nested)


def _same_url(first: str, second: str) -> bool:
    try:
        a, b = urlsplit(first), urlsplit(second)
        return bool(a.scheme == b.scheme == "https" and a.hostname and b.hostname
                    and not (a.username or a.password or b.username or b.password)
                    and a._replace(fragment="") == b._replace(fragment=""))
    except ValueError:
        return False


def _issuer_key(name: str) -> str:
    normalized = unicodedata.normalize("NFKD", str(name or "").casefold())
    return re.sub(r"\W+", " ", "".join(
        char for char in normalized if not unicodedata.combining(char)
    )).strip()


def _sec_identity_error(doc: Dict[str, Any], passage: Dict[str, Any]) -> str:
    if doc.get("source_id") and doc["source_id"] != "SRC_027":
        return "SOURCE_TYPE_MISMATCH"
    if doc.get("doc_id") and _first(passage, "document_id", "doc_id") != str(doc["doc_id"]):
        return "SOURCE_DOCUMENT_ID_MISMATCH"
    locator = _first(doc, "evidence_url", "source_url", "url")
    if not _same_url(locator, _first(passage, "source_url")):
        return "SOURCE_URL_MISMATCH"
    filing_url = _first(doc, "sec_filing_url")
    original = _first(passage, "original_filing_url")
    if filing_url and not _same_url(filing_url, original):
        return "FILING_URL_MISMATCH"
    issuer = _first(doc, "issuer_name", "sec_company", "issuer")
    if not issuer or _issuer_key(issuer) != _issuer_key(_first(passage, "issuer_name", "issuer")):
        return "ISSUER_IDENTITY_MISMATCH"
    cik = _first(doc, "issuer_cik", "sec_cik", "cik").lstrip("0") or "0"
    other_cik = _first(passage, "issuer_cik").lstrip("0") or "0"
    try:
        original_parts, locator_parts = urlsplit(original), urlsplit(locator)
        path = re.search(r"/Archives/edgar/data/0*(\d+)/", original_parts.path, re.I)
    except ValueError:
        return "SEC_FILING_IDENTITY_MISMATCH"
    if not (cik.isdigit() and cik != "0" and cik == other_cik and path
            and int(path.group(1)) == int(cik)
            and original_parts.hostname in {"sec.gov", "www.sec.gov"}):
        return "SEC_FILING_IDENTITY_MISMATCH"
    if _first(passage, "evidence_authority") == "SEC_EDGAR":
        if locator_parts.hostname not in {"sec.gov", "www.sec.gov"}:
            return "UNAPPROVED_FILING_HOST"
    elif _first(passage, "evidence_authority") != "OFFICIAL_ISSUER_IR":
        return "SOURCE_AUTHORITY_UNVERIFIED"
    if (doc.get("evidence_origin") and doc["evidence_origin"] != passage.get("evidence_authority")):
        return "SOURCE_AUTHORITY_MISMATCH"
    return ""


def _source_identity_matches(doc: Dict[str, Any], passage: Dict[str, Any]) -> bool:
    """Backward-compatible identity check; a provider ID alone is not enough."""
    if not isinstance(doc, dict) or not isinstance(passage, dict):
        return False
    if doc.get("source_id") == "SRC_027" or passage.get("extraction_method"):
        return not _sec_identity_error(doc, passage)
    source = passage.get("source")
    layers = (passage, source) if isinstance(source, dict) else (passage,)
    pairs = ((("doc_id", "document_id"), ("doc_id", "document_id", "source_doc_id")),
             (("url", "source_url", "document_url"), ("url", "source_url", "document_url")),
             (("accession_number", "accession_no"), ("accession_number", "accession_no")))
    matched = False
    for doc_keys, passage_keys in pairs:
        provided = [_first(layer, key) for layer in layers for key in passage_keys if layer.get(key)]
        if provided:
            actual = _first(doc, *doc_keys)
            if "url" in doc_keys:
                actual = actual.split("#", 1)[0].rstrip("/")
                provided = [value.split("#", 1)[0].rstrip("/") for value in provided]
            if not actual or any(value != actual for value in provided):
                return False
            matched = True
    for key, doc_keys in (("source_id", ("source_id",)),
                          ("issuer_cik", ("issuer_cik", "cik"))):
        if any(_first(layer, key) not in ("", _first(doc, *doc_keys)) for layer in layers):
            return False
    return matched


def assess_source_passage(
    doc: Dict[str, Any], passage: Dict[str, Any], *,
    source_bytes: bytes | None = None, excerpt: str | None = None,
) -> tuple[str, str]:
    """Verify an SEC passage's stored contract, optionally rechecking source bytes.

    VERIFIED means source passage integrity, *not* semantic entailment, issuer truth,
    regulator confirmation, or proof that a current downstream impact persists.
    Without raw bytes, a valid producer attestation is trusted but not re-fetched.
    """
    if not isinstance(doc, dict) or not isinstance(passage, dict):
        return "UNVERIFIED", "PASSAGE_INVALID_METADATA"
    method = _first(passage, "extraction_method", "offset_basis")
    if method not in SUPPORTED_EXTRACTION_METHODS:
        return "UNVERIFIED", "UNSUPPORTED_EXTRACTION_METHOD"
    if passage.get("offset_basis") != "NORMALIZED_VISIBLE_TEXT":
        return "UNVERIFIED", "OFFSET_BASIS_MISMATCH"
    if any(not _first(passage, key) for key in (
            "excerpt_id", "original_source_url", "filing_date", "publication_date",
            "original_filing_url", "evidence_authority")):
        return "UNVERIFIED", "PROVENANCE_INCOMPLETE"
    identity_error = _sec_identity_error(doc, passage)
    if identity_error:
        return "UNVERIFIED", identity_error
    quote = _first(passage, "text", "quote", "passage_text", "passage", "excerpt")
    if (excerpt is not None and excerpt != quote) or len(quote) < 16 or len(quote.split()) < 3:
        return "UNVERIFIED", "PASSAGE_TEXT_MISMATCH_OR_INCOMPLETE"
    start, end, claim_start = (passage.get(key) for key in ("start", "end", "claim_start"))
    if (any(type(value) is not int for value in (start, end, claim_start))
            or not 0 <= start <= claim_start < end
            or end - start < len(quote)
            or not quote.endswith(_first(passage, "claim_sentence"))
            or not _first(passage, "claim_sentence")):
        return "UNVERIFIED", "PASSAGE_OFFSETS_INVALID"
    source_hash = _first(doc, "source_content_sha256").lower()
    passage_source_hash = _first(passage, "source_content_sha256").lower()
    digest = _first(passage, "passage_sha256").lower()
    if not (all(_SHA256.fullmatch(value) for value in (source_hash, passage_source_hash, digest))
            and hmac.compare_digest(source_hash, passage_source_hash)):
        return "UNVERIFIED", "SOURCE_HASH_MISMATCH_OR_MISSING"
    if not hmac.compare_digest(digest, hashlib.sha256(quote.encode("utf-8")).hexdigest()):
        return "UNVERIFIED", "PASSAGE_HASH_MISMATCH"
    if source_bytes is None:
        source_bytes = doc.get("source_content_bytes") or doc.get("source_raw_bytes")
    if source_bytes is not None:
        if not isinstance(source_bytes, bytes):
            return "UNVERIFIED", "SOURCE_BYTES_INVALID"
        if not hmac.compare_digest(source_hash, hashlib.sha256(source_bytes).hexdigest()):
            return "UNVERIFIED", "SOURCE_HASH_MISMATCH"
        from bs4 import BeautifulSoup

        soup = BeautifulSoup(source_bytes, "html.parser")
        for node in soup(["script", "style", "nav", "footer", "noscript"]):
            node.decompose()
        text = re.sub(r"\s+", " ", soup.get_text(" ", strip=True)).strip()
        if (end > len(text) or text[start:end].strip() != quote
                or text[claim_start:end].strip() != passage["claim_sentence"]):
            return "UNVERIFIED", "PASSAGE_NOT_IN_VERIFIED_SOURCE"
    if (passage.get("validated") is not True
            or passage.get("validation_status") != "SOURCE_PASSAGE_VERIFIED"
            or passage.get("verification_basis") != "EXACT_NORMALIZED_SOURCE_SPAN"
            or doc.get("evidence_verified") is not True):
        return "PRELIMINARY", "PRODUCER_VERIFICATION_UNCONFIRMED"
    if (passage.get("issuer_identity_verified") is not True
            or passage.get("issuer_identity_status") != "SEC_CIK_VERIFIED"
            or doc.get("issuer_identity_verified") is not True):
        return "PRELIMINARY", "ISSUER_IDENTITY_NOT_INDEPENDENTLY_VERIFIED"
    return ("VERIFIED", "SOURCE_BYTES_AND_OFFSETS_VERIFIED" if source_bytes is not None
            else "TRUSTED_PRODUCER_PASSAGE_HASH_REMOTE_UNCHECKED")


def _passage_status(doc: Dict[str, Any], passage: Any, source_text: str) -> str:
    if not isinstance(passage, dict):
        return "PASSAGE_INVALID_METADATA"
    if doc.get("source_id") == "SRC_027" or passage.get("extraction_method"):
        verdict, reason = assess_source_passage(doc, passage)
        return "PASSAGE_VERIFIED" if verdict == "VERIFIED" else reason
    # Legacy non-SEC passages still require an anchored quote, hash, and explicit status.
    if not _source_identity_matches(doc, passage):
        return "SOURCE_IDENTITY_UNVERIFIED"
    quote = _first(passage, "quote", "text", "passage_text", "passage", "excerpt")
    if len(quote) < 16 or len(quote.split()) < 3:
        return "PASSAGE_INVALID_METADATA"
    if normalize_text(quote) not in source_text:
        return "PASSAGE_NOT_FOUND"
    digests = [_first(passage, key).lower().removeprefix("sha256:")
               for key in _HASH_KEYS if passage.get(key)]
    if not digests:
        return "PASSAGE_HASH_MISSING"
    expected = {hashlib.sha256(value.encode("utf-8")).hexdigest()
                for value in (quote, normalize_text(quote))}
    if any(not _SHA256.fullmatch(item) or not any(
            hmac.compare_digest(item, value) for value in expected) for item in digests):
        return "PASSAGE_HASH_MISMATCH"
    flags = ("quote_verified", "passage_verified", "verified")
    if any(key in passage and passage[key] is not True for key in flags):
        return "PASSAGE_VERIFICATION_UNCONFIRMED"
    status = _first(passage, "verification_status", "status", "validation_status").upper()
    if (status and status not in _VERIFIED_STATES) or not (
        any(passage.get(key) is True for key in flags) or status in _VERIFIED_STATES
    ):
        return "PASSAGE_VERIFICATION_UNCONFIRMED"
    return "PASSAGE_VERIFIED"


def audit_source_passages(doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Record an explicit decision for every source passage, including failures."""
    text = str(doc.get("text") or "")
    status = str(doc.get("content_status") or "").upper()
    if "BLOCKED" in status:
        return [{"status": "SOURCE_ACCESS_BLOCKED"}]
    if status == "UNAVAILABLE" or not text.strip():
        return [{"status": "SOURCE_TEXT_UNAVAILABLE"}]
    if (status in _METADATA_ONLY
            or str(doc.get("origin_type") or "").endswith("RSS_METADATA_ONLY")
            or "[OFFICIAL_RSS_METADATA_ONLY:" in text
            or "[NEWSAPI_METADATA_ONLY:" in text
            or doc.get("source_id") == "SRC_009"
            or (doc.get("title") and _normalize_for_quote_match(text) ==
                _normalize_for_quote_match(str(doc["title"])))):
        return [{"status": "SOURCE_METADATA_ONLY"}]
    records, seen = [], set()
    for layer in _metadata_layers(doc):
        for key in _PASSAGE_KEYS:
            passages = layer.get(key)
            if passages is None:
                continue
            if isinstance(passages, str):
                try:
                    passages = json.loads(passages)
                except (ValueError, TypeError):
                    pass
            for passage in (passages if isinstance(passages, list) else [passages]):
                marker = id(passage)
                if marker not in seen:
                    records.append(passage)
                    seen.add(marker)
    if not records:
        return [{"status": "PASSAGES_NOT_PROVIDED"}]
    source_text = normalize_text(text)
    return [{"index": index, "status": _passage_status(doc, passage, source_text),
             "passage": passage} for index, passage in enumerate(records)]


def get_verified_source_passages(doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Preserve original document provenance; never treat a quote as an event verdict."""
    provenance = {key: doc[key] for key in ("doc_id", "source_id", "published_at", "url")
                  if doc.get(key) not in (None, "")}
    result = []
    for item in audit_source_passages(doc):
        if item["status"] == "PASSAGE_VERIFIED":
            passage = item["passage"]
            result.append({**passage, **provenance,
                           "quote": _first(passage, "text", "quote", "passage_text", "passage", "excerpt"),
                           "producer_validation_status": passage.get("validation_status", ""),
                           "validation_status": "PASSAGE_VERIFIED", "verified_scope": "PASSAGE_ONLY"})
    return result


def _has_eligible_verified_passage(doc: Dict[str, Any]) -> bool:
    return bool(get_verified_source_passages(doc))


def _is_snippet_only(doc: Dict[str, Any]) -> bool:
    text, title = str(doc.get("text") or "").strip(), str(doc.get("title") or "").strip()
    if _has_eligible_verified_passage(doc):
        return False  # Only individual quotes are verified, not the complete document.
    return (str(doc.get("content_status") or "").upper() in _METADATA_ONLY | {"PARTIAL_TEXT", "UNAVAILABLE"}
            or len(text) < 220
            or str(doc.get("origin_type") or "").endswith("RSS_METADATA_ONLY")
            or "[OFFICIAL_RSS_METADATA_ONLY:" in text
            or "[NEWSAPI_METADATA_ONLY:" in text
            or _normalize_for_quote_match(text) == _normalize_for_quote_match(title)
            or doc.get("source_id") == "SRC_009")
