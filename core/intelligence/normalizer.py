"""
core/intelligence/normalizer.py
=================================
Response normalization engine for ReconMind Phase 3 by wamiqsec.

WHY NORMALIZATION EXISTS:
─────────────────────────
Raw HTTP responses cannot be directly compared for vulnerability detection.
They contain content that changes between requests for reasons completely
unrelated to security:
    - CSRF tokens regenerate every request
    - Timestamps advance every second
    - Ad slots render different ads
    - Session-specific nonces change
    - CDN edge nodes add different headers

If we compare raw responses, every page with a CSRF token will look
"different" between requests — generating false positives.

Normalization strips all this noise BEFORE comparison so we're only
comparing the stable, meaningful content of the response.

WHAT NORMALIZATION PRODUCES:
    NormalizedResponse — a cleaned, stable representation of a response
    that can be reliably compared against another NormalizedResponse
    to measure meaningful differences.

CRITICAL DESIGN PRINCIPLE:
    Normalization must be DETERMINISTIC.
    The same response must ALWAYS produce the same NormalizedResponse.
    We cannot afford non-deterministic normalization or we create
    false positives/negatives from normalization itself.
"""

import re
import hashlib
import html
from dataclasses import dataclass, field
from typing import List, Set, Dict, Optional, Tuple

from bs4 import BeautifulSoup

from core.intelligence.baseline_calibrator import BaselineProfile, DYNAMIC_CONTENT_PATTERNS
from core.utils.logger import get_logger

log = get_logger(__name__)


@dataclass
class NormalizedResponse:
    """
    A cleaned, stable representation of an HTTP response body.

    All dynamic content has been removed or replaced with placeholders.
    This object is designed for reliable comparison.

    Attributes:
        raw_length:       Original response body length in bytes.
        normalized_body:  Body with all dynamic content stripped.
        normalized_length: Length of normalized body.
        content_tokens:   Set of meaningful words (for similarity).
        dom_fingerprint:  Hash of DOM structure (stable).
        dom_node_count:   Number of DOM nodes.
        numeric_map:      Map of positions to numeric values found.
        semantic_field:   Classified content type (user_data, public_content, etc.)
        pii_found:        List of PII patterns detected.
        structure_hash:   Hash of the normalized body for equality checks.
        encoding_forms:   Any alternative encoding forms detected.
        stripped_sections: List of what was stripped (for debugging).
    """

    raw_length: int = 0
    normalized_body: str = ""
    normalized_length: int = 0
    content_tokens: Set[str] = field(default_factory=set)
    dom_fingerprint: str = ""
    dom_node_count: int = 0
    numeric_map: Dict[int, str] = field(default_factory=dict)
    semantic_field: str = "unknown"
    pii_found: List[str] = field(default_factory=list)
    structure_hash: str = ""
    encoding_forms: List[str] = field(default_factory=list)
    stripped_sections: List[str] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# Normalization step implementations
# ─────────────────────────────────────────────────────────────────────────────

# CSRF / security token patterns
TOKEN_PATTERNS = [
    (re.compile(r'(value=["\'])([A-Za-z0-9+/=_-]{20,})(["\'])', re.I), r'\1__TOKEN__\3'),
    (re.compile(r'(csrf[_-]?token["\s]*[:=]["\s]*)([A-Za-z0-9+/=_-]{16,})', re.I), r'\1__CSRF__'),
    (re.compile(r'(nonce["\s]*[:=]["\s]*)([A-Za-z0-9+/=_-]{16,})', re.I), r'\1__NONCE__'),
    (re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'), '__JWT__'),
]

# Timestamp normalization patterns
TIMESTAMP_PATTERNS = [
    # ISO 8601
    re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?'),
    # Date + time
    re.compile(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}'),
    # Unix timestamp (10 digits, 2020+)
    re.compile(r'\b1[6-9]\d{8}\b'),
    # US date formats
    re.compile(r'\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2},?\s+\d{4}\b'),
    # Relative times
    re.compile(r'\b(?:\d+\s+(?:second|minute|hour|day|week|month|year)s?\s+ago|just now)\b', re.I),
]

# Encoding normalization
ENCODING_MAP = {
    "&lt;":   "<",
    "&gt;":   ">",
    "&amp;":  "&",
    "&quot;": '"',
    "&#x27;": "'",
    "&#39;":  "'",
    "&#x2F;": "/",
    "&#47;":  "/",
}

# PII detection patterns for semantic analysis
PII_DETECTION_PATTERNS = {
    "email":        re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
    "phone":        re.compile(r'\b(?:\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'),
    "ssn":          re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
    "credit_card":  re.compile(r'\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13})\b'),
    "ip_private":   re.compile(r'\b(?:10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)\b'),
    "api_key":      re.compile(r'(?:api[_-]?key|api[_-]?secret|access[_-]?key)["\s]*[:=]["\s]*([A-Za-z0-9_-]{20,})', re.I),
    "password":     re.compile(r'"password"\s*:', re.I),
    "private_key":  re.compile(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----'),
    "aws_key":      re.compile(r'(?:AKIA|ASIA)[A-Z0-9]{16}'),
}

# Semantic field classification keywords
SEMANTIC_KEYWORDS = {
    "user_data": {
        "name", "username", "email", "phone", "address", "profile",
        "account", "user", "member", "subscriber", "customer", "client",
        "password", "credential", "token", "session", "birthday", "dob",
    },
    "public_content": {
        "article", "post", "blog", "news", "comment", "category", "tag",
        "published", "author", "content", "text", "description", "title",
        "product", "price", "review", "rating", "item", "listing",
    },
    "system_data": {
        "error", "exception", "stack", "trace", "warning", "debug",
        "server", "database", "query", "version", "path", "file",
        "memory", "cpu", "process", "thread", "config", "setting",
    },
    "auth_data": {
        "login", "logout", "register", "signup", "signin", "authenticate",
        "authorization", "permission", "role", "access", "token", "jwt",
        "oauth", "sso", "saml", "openid", "csrf", "cookie",
    },
    "error_data": {
        "error", "404", "403", "500", "not found", "forbidden",
        "unauthorized", "invalid", "failed", "exception", "denied",
    },
}


def _strip_tokens(body: str) -> Tuple[str, List[str]]:
    """
    Strip CSRF tokens, nonces, and other security tokens.

    Returns:
        (stripped_body: str, list_of_stripped_descriptions: List[str])
    """
    stripped = []
    result = body

    for pattern, replacement in TOKEN_PATTERNS:
        if isinstance(replacement, str):
            new_result, count = pattern.subn(replacement, result)
        else:
            new_result = result
            count = 0

        if count > 0:
            result = new_result
            stripped.append(f"Stripped {count} token pattern(s)")

    return result, stripped


def _strip_timestamps(body: str) -> Tuple[str, List[str]]:
    """Replace all timestamp patterns with a stable placeholder."""
    stripped = []
    result = body

    for pattern in TIMESTAMP_PATTERNS:
        new_result, count = pattern.subn("__TIMESTAMP__", result)
        if count > 0:
            result = new_result
            stripped.append(f"Stripped {count} timestamp(s)")

    return result, stripped


def _normalize_whitespace(body: str) -> str:
    """
    Collapse all whitespace sequences to single spaces.
    Strip leading/trailing whitespace.
    """
    return re.sub(r'\s+', ' ', body).strip()


def _normalize_encoding(body: str) -> Tuple[str, List[str]]:
    """
    Decode HTML entities and URL encoding to normalized form.
    This ensures that <script> and &lt;script&gt; compare as equal.
    """
    encoding_forms = []
    result = body

    # Check for HTML entities before decoding
    if re.search(r'&(?:lt|gt|amp|quot|#\d+|#x[0-9a-fA-F]+);', result):
        encoding_forms.append("html_entities")
        for encoded, decoded in ENCODING_MAP.items():
            result = result.replace(encoded, decoded)

    # Check for URL encoding
    if re.search(r'%[0-9a-fA-F]{2}', result):
        encoding_forms.append("url_encoding")
        try:
            from urllib.parse import unquote
            result = unquote(result, errors='ignore')
        except Exception:
            pass

    return result, encoding_forms


def _apply_baseline_patterns(body: str, profile: BaselineProfile) -> Tuple[str, List[str]]:
    """
    Apply the dynamic patterns discovered during baseline calibration.

    This strips patterns that were identified as changing between
    calibration requests for this specific URL.

    Args:
        body:    Response body to strip.
        profile: BaselineProfile with dynamic_sections identified.

    Returns:
        (stripped_body, list of what was stripped)
    """
    stripped = []
    result = body

    for section in profile.dynamic_sections:
        try:
            pattern = re.compile(section.pattern, re.I | re.S)
            new_result, count = pattern.subn("__DYNAMIC__", result)
            if count > 0:
                result = new_result
                stripped.append(f"Stripped baseline dynamic: {section.description}")
        except re.error:
            pass  # Invalid regex from calibration — skip

    return result, stripped


def _extract_numeric_map(body: str) -> Dict[int, str]:
    """
    Build a map of {character_position: numeric_value} for all numbers in body.

    This is used by IDOR analysis to track WHICH numbers change between
    responses — not just WHETHER numbers change.

    Returns:
        Dict mapping string positions to numeric strings found.
    """
    numeric_map = {}
    for match in re.finditer(r'\b\d+\b', body):
        numeric_map[match.start()] = match.group(0)
    return numeric_map


def _detect_pii(body: str) -> List[str]:
    """
    Detect PII patterns in the response body.

    Returns list of PII type names found (e.g. ["email", "phone"]).
    Does NOT return actual PII values to avoid storing sensitive data.
    """
    found = []
    for pii_type, pattern in PII_DETECTION_PATTERNS.items():
        if pattern.search(body):
            found.append(pii_type)
    return found


def _classify_semantic_field(tokens: Set[str]) -> str:
    """
    Classify the response content into a semantic field.

    Uses keyword overlap between content tokens and known semantic categories.
    The category with highest overlap wins.

    Args:
        tokens: Set of words from the normalized response.

    Returns:
        Semantic field name: "user_data", "public_content", "system_data",
        "auth_data", "error_data", or "unknown".
    """
    scores = {}
    for field_name, keywords in SEMANTIC_KEYWORDS.items():
        overlap = len(tokens.intersection(keywords))
        scores[field_name] = overlap

    if not scores or max(scores.values()) == 0:
        return "unknown"

    return max(scores, key=scores.get)


def _extract_content_tokens(body: str) -> Set[str]:
    """Extract meaningful words from the body for similarity analysis."""
    try:
        soup = BeautifulSoup(body, "html.parser")
        text = soup.get_text(separator=" ")
    except Exception:
        text = body

    # Extract 3+ letter words, lowercase
    words = re.findall(r'\b[a-zA-Z]{3,}\b', text)
    return set(w.lower() for w in words)


def _build_dom_fingerprint(html_body: str) -> Tuple[str, int]:
    """Build a structural hash of the DOM (tag names + classes, not content)."""
    try:
        soup = BeautifulSoup(html_body, "html.parser")
        tags = []
        for tag in soup.find_all(True):
            classes = " ".join(sorted(tag.get("class", [])))
            tags.append(f"{tag.name}:{classes}")
        tag_str = "|".join(sorted(tags))
        return hashlib.md5(tag_str.encode()).hexdigest(), len(tags)
    except Exception:
        return "", 0


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def normalize_response(
    body: str,
    profile: Optional[BaselineProfile] = None,
) -> NormalizedResponse:
    """
    Normalize a response body for comparison.

    Applies all normalization steps in order:
        1. Strip security tokens (CSRF, nonces, JWTs)
        2. Strip timestamps
        3. Apply baseline-specific dynamic patterns (if profile given)
        4. Normalize whitespace
        5. Normalize encoding (HTML entities, URL encoding)
        6. Extract content tokens
        7. Build DOM fingerprint
        8. Map numeric positions
        9. Detect PII
        10. Classify semantic field

    Args:
        body:    Raw HTTP response body string.
        profile: BaselineProfile for this URL (if available).
                 Enables baseline-specific stripping.

    Returns:
        NormalizedResponse ready for comparison.
    """
    nr = NormalizedResponse()
    nr.raw_length = len(body)

    all_stripped = []
    working = body

    # Step 1: Strip security tokens
    working, stripped = _strip_tokens(working)
    all_stripped.extend(stripped)

    # Step 2: Strip timestamps
    working, stripped = _strip_timestamps(working)
    all_stripped.extend(stripped)

    # Step 3: Apply baseline-specific patterns
    if profile and profile.dynamic_sections:
        working, stripped = _apply_baseline_patterns(working, profile)
        all_stripped.extend(stripped)

    # Step 4: Normalize encoding BEFORE whitespace
    # (encoding normalization might introduce extra spaces)
    working, enc_forms = _normalize_encoding(working)
    nr.encoding_forms = enc_forms

    # Step 5: Normalize whitespace
    working = _normalize_whitespace(working)

    nr.normalized_body = working
    nr.normalized_length = len(working)
    nr.stripped_sections = all_stripped

    # Step 6: Extract content tokens
    nr.content_tokens = _extract_content_tokens(working)

    # Step 7: DOM fingerprint
    if "<html" in body.lower() or "<div" in body.lower():
        nr.dom_fingerprint, nr.dom_node_count = _build_dom_fingerprint(body)

    # Step 8: Map numeric positions
    nr.numeric_map = _extract_numeric_map(working)

    # Step 9: Detect PII
    nr.pii_found = _detect_pii(working)

    # Step 10: Semantic field classification
    nr.semantic_field = _classify_semantic_field(nr.content_tokens)

    # Step 11: Structure hash for equality checks
    nr.structure_hash = hashlib.md5(working.encode()).hexdigest()

    log.debug(
        "Normalized: raw=%d → normalized=%d tokens=%d field=%s pii=%s",
        nr.raw_length, nr.normalized_length,
        len(nr.content_tokens), nr.semantic_field, nr.pii_found,
    )

    return nr
