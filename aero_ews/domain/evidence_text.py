"""Source-bound passage verification, distinct from event or KIQ confirmation."""

import hashlib, hmac, json, re, unicodedata
from typing import Any, Dict, List
from urllib.parse import urlsplit

# Supported extraction methods, status vocabularies, and metadata keys (preserved verbatim).
SEC_VISIBLE_TEXT_METHOD = "HTML_VISIBLE_TEXT_WHITESPACE_V1"
SUPPORTED_EXTRACTION_METHODS = frozenset({SEC_VISIBLE_TEXT_METHOD})
_METADATA_ONLY = {"METADATA_ONLY", "SUMMARY_ONLY", "STRUCTURED_DATA"}
_PASSAGE_KEYS = ("verified_passages", "source_passages", "evidence_passages", "passages")
_HASH_KEYS = ("quote_sha256", "passage_sha256", "quote_hash", "passage_hash", "sha256")
_VERIFIED_STATES = {"SOURCE_PASSAGE_VERIFIED", "PASSAGE_VERIFIED", "QUOTE_VERIFIED", "VERIFIED"}
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_SEC_HOSTS = {"sec.gov", "www.sec.gov"}
_META_LAYER_KEYS = ("source_metadata", "metadata", "evidence_metadata", "sec_metadata", "extraction_metadata", "sec")
_QUOTE_KEYS = ("text", "quote", "passage_text", "passage", "excerpt")
_REQUIRED_SEC_FIELDS = ("excerpt_id", "original_source_url", "filing_date", "publication_date", "original_filing_url", "evidence_authority")


# Text normalization, field extraction, URL comparison, and metadata-marker helpers.
def _first(data: Dict[str, Any], *keys: str) -> str: return next((str(v).strip() for k in keys if (v := data.get(k)) not in (None, "")), "")
def _has_eligible_verified_passage(doc: Dict[str, Any]) -> bool: return bool(get_verified_source_passages(doc))
def _is_metadata_only_marker(doc: Dict[str, Any], text: str) -> bool:
    return str(doc.get("origin_type") or "").endswith("RSS_METADATA_ONLY") or "[OFFICIAL_RSS_METADATA_ONLY:" in text or "[NEWSAPI_METADATA_ONLY:" in text or doc.get("source_id") == "SRC_009"


def normalize_text(text: str) -> str:
    """Normalize typographic dashes/quotes and collapse whitespace."""
    if not text:
        return ""
    s = re.sub(r"[\u2018-\u201B\u00B4\u0060]", "'", re.sub(r"[\u2010-\u2015]", "-", str(text)))
    return re.sub(r"\s+", " ", re.sub(r"[\u201C-\u201F]", '"', s)).strip()


def _normalize_for_quote_match(text: str) -> str:
    """Strip SEC page-break TOC headers, punctuation, and case for quote comparison."""
    clean = re.sub(r"\n[ \t]*\d{1,4}[ \t]*\n[ \t]*Table of Contents[ \t]*\n", " ", str(text or ""), flags=re.I)
    return re.sub(r"\s+", " ", re.sub(r"[^\w\s]", " ", normalize_text(clean).lower())).strip()


def _metadata_layers(doc: Dict[str, Any]):
    """Inspect up to 12 bounded metadata layers, including JSON-serialized replay blobs."""
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
        for k in _META_LAYER_KEYS:
            if isinstance(nested := layer.get(k), (dict, str)) and len(queue) < 12:
                queue.append(nested)


def _same_url(first: str, second: str) -> bool:
    """Compare two credential-free HTTPS URLs ignoring URL fragments."""
    try:
        a, b = urlsplit(first), urlsplit(second)
        return bool(a.scheme == b.scheme == "https" and a.hostname and b.hostname and not (a.username or a.password or b.username or b.password) and a._replace(fragment="") == b._replace(fragment=""))
    except ValueError:
        return False


def _issuer_key(name: str) -> str:
    """Normalize an issuer name by folding case, diacritics, and non-word separators."""
    norm = unicodedata.normalize("NFKD", str(name or "").casefold())
    return re.sub(r"\W+", " ", "".join(ch for ch in norm if not unicodedata.combining(ch))).strip()


def _sec_identity_error(doc: Dict[str, Any], passage: Dict[str, Any]) -> str:
    """Validate SEC document, URL, issuer, CIK, and authority consistency; return error code or ''."""
    if doc.get("source_id") and doc["source_id"] != "SRC_027": return "SOURCE_TYPE_MISMATCH"
    if doc.get("doc_id") and _first(passage, "document_id", "doc_id") != str(doc["doc_id"]): return "SOURCE_DOCUMENT_ID_MISMATCH"
    locator = _first(doc, "evidence_url", "source_url", "url")
    if not _same_url(locator, _first(passage, "source_url")): return "SOURCE_URL_MISMATCH"
    filing_url, original = _first(doc, "sec_filing_url"), _first(passage, "original_filing_url")
    if filing_url and not _same_url(filing_url, original): return "FILING_URL_MISMATCH"
    issuer = _first(doc, "issuer_name", "sec_company", "issuer")
    if not issuer or _issuer_key(issuer) != _issuer_key(_first(passage, "issuer_name", "issuer")): return "ISSUER_IDENTITY_MISMATCH"

    cik, other_cik = _first(doc, "issuer_cik", "sec_cik", "cik").lstrip("0") or "0", _first(passage, "issuer_cik").lstrip("0") or "0"
    try:
        orig_parts, loc_parts = urlsplit(original), urlsplit(locator)
        path = re.search(r"/Archives/edgar/data/0*(\d+)/", orig_parts.path, re.I)
    except ValueError:
        return "SEC_FILING_IDENTITY_MISMATCH"
    if not (cik.isdigit() and cik != "0" and cik == other_cik and path and int(path.group(1)) == int(cik) and orig_parts.hostname in _SEC_HOSTS):
        return "SEC_FILING_IDENTITY_MISMATCH"
    authority = _first(passage, "evidence_authority")
    if authority == "SEC_EDGAR" and loc_parts.hostname not in _SEC_HOSTS: return "UNAPPROVED_FILING_HOST"
    if authority not in {"SEC_EDGAR", "OFFICIAL_ISSUER_IR"}: return "SOURCE_AUTHORITY_UNVERIFIED"
    if doc.get("evidence_origin") and doc["evidence_origin"] != passage.get("evidence_authority"): return "SOURCE_AUTHORITY_MISMATCH"
    return ""


def _source_identity_matches(doc: Dict[str, Any], passage: Dict[str, Any]) -> bool:
    """Backward-compatible identity check; a provider ID alone is not sufficient."""
    if not isinstance(doc, dict) or not isinstance(passage, dict):
        return False
    if doc.get("source_id") == "SRC_027" or passage.get("extraction_method"):
        return not _sec_identity_error(doc, passage)

    layers = (passage, src) if isinstance(src := passage.get("source"), dict) else (passage,)
    matched = False
    for d_keys, p_keys in ((("doc_id", "document_id"), ("doc_id", "document_id", "source_doc_id")), (("url", "source_url", "document_url"), ("url", "source_url", "document_url")), (("accession_number", "accession_no"), ("accession_number", "accession_no"))):
        if provided := [_first(layer, k) for layer in layers for k in p_keys if layer.get(k)]:
            actual = _first(doc, *d_keys)
            if "url" in d_keys:
                actual, provided = actual.split("#", 1)[0].rstrip("/"), [v.split("#", 1)[0].rstrip("/") for v in provided]
            if not actual or any(v != actual for v in provided):
                return False
            matched = True
    return matched and not any(_first(layer, k) not in ("", _first(doc, *dk)) for k, dk in (("source_id", ("source_id",)), ("issuer_cik", ("issuer_cik", "cik"))) for layer in layers)


def assess_source_passage(
    doc: Dict[str, Any], passage: Dict[str, Any], *,
    source_bytes: bytes | None = None, excerpt: str | None = None,
) -> tuple[str, str]:
    """Verify an SEC passage's stored contract and optionally recheck raw source bytes.

    VERIFIED confirms source passage integrity only, never semantic entailment or downstream impact.
    """
    if not isinstance(doc, dict) or not isinstance(passage, dict): return "UNVERIFIED", "PASSAGE_INVALID_METADATA"
    if _first(passage, "extraction_method", "offset_basis") not in SUPPORTED_EXTRACTION_METHODS: return "UNVERIFIED", "UNSUPPORTED_EXTRACTION_METHOD"
    if passage.get("offset_basis") != "NORMALIZED_VISIBLE_TEXT": return "UNVERIFIED", "OFFSET_BASIS_MISMATCH"
    if any(not _first(passage, k) for k in _REQUIRED_SEC_FIELDS): return "UNVERIFIED", "PROVENANCE_INCOMPLETE"
    if err := _sec_identity_error(doc, passage): return "UNVERIFIED", err

    quote = _first(passage, *_QUOTE_KEYS)
    if (excerpt is not None and excerpt != quote) or len(quote) < 16 or len(quote.split()) < 3:
        return "UNVERIFIED", "PASSAGE_TEXT_MISMATCH_OR_INCOMPLETE"
    start, end, claim_start = (passage.get(k) for k in ("start", "end", "claim_start"))
    claim_sent = _first(passage, "claim_sentence")
    if any(type(v) is not int for v in (start, end, claim_start)) or not 0 <= start <= claim_start < end or end - start < len(quote) or not claim_sent or not quote.endswith(claim_sent):
        return "UNVERIFIED", "PASSAGE_OFFSETS_INVALID"

    src_hash, p_src_hash, digest = _first(doc, "source_content_sha256").lower(), _first(passage, "source_content_sha256").lower(), _first(passage, "passage_sha256").lower()
    if not (all(_SHA256.fullmatch(v) for v in (src_hash, p_src_hash, digest)) and hmac.compare_digest(src_hash, p_src_hash)):
        return "UNVERIFIED", "SOURCE_HASH_MISMATCH_OR_MISSING"
    if not hmac.compare_digest(digest, hashlib.sha256(quote.encode("utf-8")).hexdigest()):
        return "UNVERIFIED", "PASSAGE_HASH_MISMATCH"

    source_bytes = (doc.get("source_content_bytes") or doc.get("source_raw_bytes")) if source_bytes is None else source_bytes
    if source_bytes is not None:
        if not isinstance(source_bytes, bytes): return "UNVERIFIED", "SOURCE_BYTES_INVALID"
        if not hmac.compare_digest(src_hash, hashlib.sha256(source_bytes).hexdigest()): return "UNVERIFIED", "SOURCE_HASH_MISMATCH"
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(source_bytes, "html.parser")
        for node in soup(["script", "style", "nav", "footer", "noscript"]):
            node.decompose()
        text = re.sub(r"\s+", " ", soup.get_text(" ", strip=True)).strip()
        if end > len(text) or text[start:end].strip() != quote or text[claim_start:end].strip() != passage["claim_sentence"]:
            return "UNVERIFIED", "PASSAGE_NOT_IN_VERIFIED_SOURCE"

    if passage.get("validated") is not True or passage.get("validation_status") != "SOURCE_PASSAGE_VERIFIED" or passage.get("verification_basis") != "EXACT_NORMALIZED_SOURCE_SPAN" or doc.get("evidence_verified") is not True:
        return "PRELIMINARY", "PRODUCER_VERIFICATION_UNCONFIRMED"
    if passage.get("issuer_identity_verified") is not True or passage.get("issuer_identity_status") != "SEC_CIK_VERIFIED" or doc.get("issuer_identity_verified") is not True:
        return "PRELIMINARY", "ISSUER_IDENTITY_NOT_INDEPENDENTLY_VERIFIED"
    return "VERIFIED", ("SOURCE_BYTES_AND_OFFSETS_VERIFIED" if source_bytes is not None else "TRUSTED_PRODUCER_PASSAGE_HASH_REMOTE_UNCHECKED")


def _passage_status(doc: Dict[str, Any], passage: Any, source_text: str) -> str:
    """Evaluate a single SEC or legacy non-SEC passage against its source text and hashes."""
    if not isinstance(passage, dict): return "PASSAGE_INVALID_METADATA"
    if doc.get("source_id") == "SRC_027" or passage.get("extraction_method"):
        verdict, reason = assess_source_passage(doc, passage)
        return "PASSAGE_VERIFIED" if verdict == "VERIFIED" else reason

    # Legacy non-SEC passages require identity match, anchored quote, SHA-256 hash, and explicit verified status.
    if not _source_identity_matches(doc, passage): return "SOURCE_IDENTITY_UNVERIFIED"
    quote = _first(passage, "quote", "text", "passage_text", "passage", "excerpt")
    if len(quote) < 16 or len(quote.split()) < 3: return "PASSAGE_INVALID_METADATA"
    if normalize_text(quote) not in source_text: return "PASSAGE_NOT_FOUND"
    if not (digests := [_first(passage, k).lower().removeprefix("sha256:") for k in _HASH_KEYS if passage.get(k)]): return "PASSAGE_HASH_MISSING"
    expected = {hashlib.sha256(v.encode("utf-8")).hexdigest() for v in (quote, normalize_text(quote))}
    if any(not _SHA256.fullmatch(d) or not any(hmac.compare_digest(d, e) for e in expected) for d in digests): return "PASSAGE_HASH_MISMATCH"
    flags = ("quote_verified", "passage_verified", "verified")
    status = _first(passage, "verification_status", "status", "validation_status").upper()
    if any(k in passage and passage[k] is not True for k in flags) or (status and status not in _VERIFIED_STATES) or not (any(passage.get(k) is True for k in flags) or status in _VERIFIED_STATES):
        return "PASSAGE_VERIFICATION_UNCONFIRMED"
    return "PASSAGE_VERIFIED"


def audit_source_passages(doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Record an explicit verification decision for every source passage, including failures."""
    text, status = str(doc.get("text") or ""), str(doc.get("content_status") or "").upper()
    if "BLOCKED" in status: return [{"status": "SOURCE_ACCESS_BLOCKED"}]
    if status == "UNAVAILABLE" or not text.strip(): return [{"status": "SOURCE_TEXT_UNAVAILABLE"}]
    if status in _METADATA_ONLY or _is_metadata_only_marker(doc, text) or (doc.get("title") and _normalize_for_quote_match(text) == _normalize_for_quote_match(str(doc["title"]))):
        return [{"status": "SOURCE_METADATA_ONLY"}]

    records, seen = [], set()
    for layer in _metadata_layers(doc):
        for k in _PASSAGE_KEYS:
            if (passages := layer.get(k)) is None:
                continue
            if isinstance(passages, str):
                try:
                    passages = json.loads(passages)
                except (ValueError, TypeError):
                    pass
            for p in (passages if isinstance(passages, list) else [passages]):
                if id(p) not in seen:
                    seen.add(id(p))
                    records.append(p)
    if not records:
        return [{"status": "PASSAGES_NOT_PROVIDED"}]
    source_text = normalize_text(text)
    return [{"index": i, "status": _passage_status(doc, p, source_text), "passage": p} for i, p in enumerate(records)]


def get_verified_source_passages(doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return verified passages with document provenance attached; never treat a quote as an event verdict."""
    prov = {k: doc[k] for k in ("doc_id", "source_id", "published_at", "url") if doc.get(k) not in (None, "")}
    return [
        {**p, **prov, "quote": _first(p, *_QUOTE_KEYS), "producer_validation_status": p.get("validation_status", ""),
         "validation_status": "PASSAGE_VERIFIED", "verified_scope": "PASSAGE_ONLY"}
        for item in audit_source_passages(doc)
        if item["status"] == "PASSAGE_VERIFIED" and (p := item["passage"]) is not None
    ]


def _is_snippet_only(doc: Dict[str, Any]) -> bool:
    """Return True when a document lacks verified passages and appears truncated or metadata-only."""
    text, title = str(doc.get("text") or "").strip(), str(doc.get("title") or "").strip()
    if _has_eligible_verified_passage(doc):
        return False
    return (
        str(doc.get("content_status") or "").upper() in (_METADATA_ONLY | {"PARTIAL_TEXT", "UNAVAILABLE"})
        or len(text) < 220 or _is_metadata_only_marker(doc, text)
        or _normalize_for_quote_match(text) == _normalize_for_quote_match(title)
    )