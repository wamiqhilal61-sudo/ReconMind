"""
core/engines/xss/encoding_detector.py
========================================
Encoding Analysis Engine for wamiqsec/ReconMind Phase 5.

Determines the exact encoding state of a marker reflection:
raw, partially encoded, fully encoded, or filtered.
This is the engine that distinguishes a harmless encoded reflection
from a raw reflection of dangerous characters.
"""

import re
from typing import List, Tuple, Dict

from models.response_profile import ResponseProfile, ReflectionInfo, ReflectionType
from core.utils.logger import get_logger

log = get_logger(__name__)


XSS_CHARS = ["<", ">", "'", '"', "`", "\\", ";", "{", "}", "/", "(", ")"]

CHAR_ENCODINGS: Dict[str, List[str]] = {
    "<": ["&lt;", "&#60;", "&#x3c;", "&#x3C;", "&#X3c;", "\\u003c", "\\u003C",
          "\\x3c", "\\x3C", "%3c", "%3C", "%253c", "%253C", "\\74", "\u003c",
          "&LT;", "&#0060;"],
    ">": ["&gt;", "&#62;", "&#x3e;", "&#x3E;", "\\u003e", "\\u003E", "\\x3e",
          "\\x3E", "%3e", "%3E", "%253e", "%253E", "\\76", "\u003e", "&GT;"],
    '"': ["&quot;", "&#34;", "&#x22;", "\\u0022", "\\x22", "%22", "%2522",
          "\u0022", "&QUOT;", "&#0034;"],
    "'": ["&#x27;", "&#39;", "&apos;", "\\u0027", "\\x27", "%27", "%2527",
          "\u0027", "&#0039;"],
    "`": ["&#x60;", "&#96;", "\\u0060", "\\x60", "%60"],
    "\\": ["&#x5c;", "&#92;", "\\\\", "\\u005c", "%5c", "%5C"],
    ";": ["&#x3b;", "&#59;", "\\u003b", "%3b", "%3B"],
    "(": ["&#x28;", "&#40;", "\\u0028", "%28"],
    ")": ["&#x29;", "&#41;", "\\u0029", "%29"],
    "/": ["&#x2f;", "&#47;", "\\u002f", "%2f", "%2F"],
}


def _check_char_adjacent_to_marker(
    body: str, char: str, marker: str, adjacency: int = 3,
) -> Tuple[bool, bool, List[str]]:
    """
    Check if a character appears RAW or ENCODED immediately adjacent to the
    marker — not just "somewhere nearby" on the page.

    WHY ADJACENCY MATTERS:
        A naive "is this char within N chars of the marker" check produces
        false positives constantly, because ordinary HTML structure
        (</p>, </body>, <div>, etc.) contains '<' and '>' within a few dozen
        characters of almost any reflected string on any real page.

        We only care whether OUR injected character (which we appended
        directly after the marker, e.g. marker + "<") survived. That means
        the character must appear in the tiny window immediately touching
        the marker boundary — not generally "nearby".

    Args:
        body:      Full response body.
        char:      Character we're checking.
        marker:    The marker string we injected (char was appended after it).
        adjacency: How many characters immediately after the marker to check.

    Returns:
        (raw: bool, encoded: bool, encoding_forms: List[str])
    """
    idx = body.find(marker)
    if idx == -1:
        return False, False, []

    tail_start = idx + len(marker)
    tail = body[tail_start: tail_start + adjacency]

    raw = char in tail

    encoding_forms = []
    encoded = False
    max_enc_len = max((len(e) for e in CHAR_ENCODINGS.get(char, [""])), default=adjacency)
    enc_tail = body[tail_start: tail_start + max_enc_len + 2]
    for enc_form in CHAR_ENCODINGS.get(char, []):
        if enc_tail.startswith(enc_form) or enc_tail.lower().startswith(enc_form.lower()):
            encoding_forms.append(enc_form)
            encoded = True

    return raw, encoded, encoding_forms


def _check_char_in_response(body: str, char: str, context_window: str = "") -> Tuple[bool, bool, List[str]]:
    """
    Legacy whole-window character check.

    Retained for callers that pass an explicit context_window, but no
    longer used by analyze_encoding() for marker-adjacent char testing —
    see _check_char_adjacent_to_marker() for the precision-correct version.
    """
    search_in = context_window if context_window else body
    raw = char in search_in
    encoding_forms = []
    encoded = False
    for enc_form in CHAR_ENCODINGS.get(char, []):
        if enc_form in search_in or enc_form.lower() in search_in.lower():
            encoding_forms.append(enc_form)
            encoded = True
    return raw, encoded, encoding_forms


def _extract_context_window(body: str, marker: str, radius: int = 200) -> str:
    idx = body.find(marker)
    if idx == -1:
        return ""
    start = max(0, idx - radius)
    end = min(len(body), idx + len(marker) + radius)
    return body[start:end]


def _classify_reflection_type(
    raw: bool, chars_raw: List[str], chars_encoded: List[str],
    chars_blocked: List[str], marker_present: bool,
    matched_encoding_forms: List[str] = None,
) -> ReflectionType:
    if not marker_present:
        return ReflectionType.NOT_REFLECTED

    if not chars_raw and not chars_encoded and not chars_blocked:
        return ReflectionType.RAW if raw else ReflectionType.HTML_ENCODED

    dangerous_present = set(chars_raw + chars_encoded + chars_blocked)
    if not dangerous_present:
        return ReflectionType.RAW

    if chars_raw and not chars_encoded and not chars_blocked:
        return ReflectionType.RAW

    if chars_encoded and not chars_raw and not chars_blocked:
        # Classify by the actual matched forms (not a re-derived guess) —
        # priority: which encoding scheme was ACTUALLY observed in the response.
        forms = matched_encoding_forms or []
        if any(f.startswith("&") for f in forms):
            return ReflectionType.HTML_ENCODED
        if any(f.startswith("\\u") or f.startswith("\\x") for f in forms):
            return ReflectionType.JS_ENCODED
        if any(f.startswith("%") for f in forms):
            return ReflectionType.URL_ENCODED
        return ReflectionType.HTML_ENCODED

    if chars_raw and chars_encoded:
        return ReflectionType.PARTIAL

    if chars_blocked and not chars_raw and not chars_encoded:
        return ReflectionType.FILTERED

    if chars_raw and chars_blocked:
        return ReflectionType.PARTIAL

    return ReflectionType.PARTIAL


def _find_all_marker_positions(body: str, marker: str) -> List[int]:
    positions, start = [], 0
    while True:
        idx = body.find(marker, start)
        if idx == -1:
            break
        positions.append(idx)
        start = idx + 1
    return positions


def _extract_snippets(body: str, marker: str, radius: int = 80) -> List[str]:
    snippets = []
    for pos in _find_all_marker_positions(body, marker):
        s, e = max(0, pos - radius), min(len(body), pos + len(marker) + radius)
        snippets.append(body[s:e].replace("\n", "|").replace("\r", ""))
    return snippets


def analyze_encoding(profile: ResponseProfile, marker: str, test_chars: List[str] = None) -> ResponseProfile:
    """
    Analyze the encoding state of a marker reflection.

    Pipeline stage: enriches profile.reflection_info with full
    char-level encoding analysis.
    """
    if test_chars is None:
        test_chars = XSS_CHARS

    body = profile.raw_body
    ri = ReflectionInfo()

    positions = _find_all_marker_positions(body, marker)
    if not positions:
        ri.reflection_type = ReflectionType.NOT_REFLECTED
        profile.reflection_info = ri
        log.debug("Marker not found in response body: %s", profile.url)
        return profile

    ri.positions = positions
    ri.count = len(positions)
    ri.snippets = _extract_snippets(body, marker)

    context_window = _extract_context_window(body, marker, radius=150)

    for char in test_chars:
        raw, encoded, enc_forms = _check_char_adjacent_to_marker(body, char, marker)
        if raw:
            ri.chars_raw.append(char)
        elif encoded:
            ri.chars_encoded.append(char)
            ri.encoding_forms.extend(enc_forms)

    ri.is_raw = bool(positions)
    ri.reflection_type = _classify_reflection_type(
        raw=ri.is_raw, chars_raw=ri.chars_raw, chars_encoded=ri.chars_encoded,
        chars_blocked=ri.chars_blocked, marker_present=True,
        matched_encoding_forms=ri.encoding_forms,
    )
    ri.encoding_forms = list(set(ri.encoding_forms))

    for header_name, header_val in profile.response_headers.items():
        if marker in header_val:
            ri.in_header = True
            ri.header_name = header_name
            break

    profile.reflection_info = ri

    log.info(
        "Encoding analysis: param=%r reflection=%s raw_chars=%s encoded_chars=%s",
        profile.param_name, ri.reflection_type.value, ri.chars_raw, ri.chars_encoded,
    )
    return profile
