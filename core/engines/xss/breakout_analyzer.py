"""
core/engines/xss/breakout_analyzer.py
=========================================
Breakout Analysis Engine for wamiqsec/ReconMind Phase 5.

Tests whether the dangerous characters required by a detected context
actually survive unencoded when injected — answering "can the user
escape this context?" rather than just "what context is this?"
"""

import time
from typing import Optional

from models.response_profile import ResponseProfile, BreakoutInfo
from core.extractor.param_extractor import Parameter, ParamType
from core.recon.url_handler import URLTarget
from core.utils.http_client import safe_get, safe_post
from core.engines.xss.context_engine import get_required_breakout_chars, context_is_executable
from core.engines.xss.encoding_detector import CHAR_ENCODINGS
from config.settings import CONFIG
from core.utils.logger import get_logger

from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

log = get_logger(__name__)


def _build_probe_url(target: URLTarget, param: Parameter, value: str) -> str:
    parsed = urlparse(target.normalized)
    qp = parse_qs(parsed.query, keep_blank_values=True)
    qp[param.name] = [value]
    return urlunparse(parsed._replace(query=urlencode({k: v[0] for k, v in qp.items()})))


def _fetch_probe(target: URLTarget, param: Parameter, value: str) -> Optional[str]:
    if param.param_type == ParamType.GET:
        url = _build_probe_url(target, param, value)
        resp = safe_get(url, allow_redirects=False)
    else:
        post_url = param.form_action or target.base_url()
        resp = safe_post(post_url, data={param.name: value}, allow_redirects=False)
    return resp.text if resp is not None else None


def _char_survived_raw(body: str, char: str, marker: str, adjacency: int = 3) -> bool:
    """
    Check if the char we appended directly after the marker survived raw.

    We inject probe_value = marker + char, so the char we're testing for
    must appear immediately after the marker's position — not generally
    "nearby" (which would false-positive on ordinary HTML tags like </p>).
    """
    idx = body.find(marker)
    if idx == -1:
        return False
    tail_start = idx + len(marker)
    tail = body[tail_start: tail_start + adjacency]
    return char in tail


def _char_survived_encoded(body: str, char: str, marker: str, adjacency: int = 3) -> tuple:
    """Check if the char we appended after the marker survived in encoded form."""
    idx = body.find(marker)
    if idx == -1:
        return False, []
    tail_start = idx + len(marker)
    max_enc_len = max((len(e) for e in CHAR_ENCODINGS.get(char, [""])), default=adjacency)
    enc_tail = body[tail_start: tail_start + max_enc_len + 2]
    forms_found = [
        enc for enc in CHAR_ENCODINGS.get(char, [])
        if enc_tail.startswith(enc) or enc_tail.lower().startswith(enc.lower())
    ]
    return bool(forms_found), forms_found


def analyze_breakout(
    profile: ResponseProfile,
    target: URLTarget,
    param: Parameter,
    marker: str,
    context_type: str,
) -> ResponseProfile:
    """
    Test whether dangerous characters can escape the detected context.

    Pipeline stage: enriches profile.breakout_info.
    Only runs for executable contexts; non-executable contexts get
    feasible=False immediately without making probe requests.
    """
    bi = BreakoutInfo(was_tested=False)

    if not context_is_executable(context_type):
        bi.feasible = False
        bi.reason = f"Context {context_type} is not executable — no breakout needed"
        profile.breakout_info = bi
        return profile

    required = get_required_breakout_chars(context_type)
    bi.required_chars = set(required)
    bi.chars_tested = list(required)
    bi.was_tested = True

    for char in required:
        probe_value = marker + char
        body = _fetch_probe(target, param, probe_value)
        time.sleep(0.15)

        if body is None:
            bi.chars_blocked.append(char)
            continue

        if _char_survived_raw(body, char, marker):
            bi.chars_raw.append(char)
            log.debug("  Breakout char=%r survived RAW", char)
            continue

        encoded, enc_forms = _char_survived_encoded(body, char, marker)
        if encoded:
            bi.chars_encoded.append(char)
            log.debug("  Breakout char=%r ENCODED as %s", char, enc_forms)
            continue

        bi.chars_blocked.append(char)
        log.debug("  Breakout char=%r BLOCKED", char)

    bi.feasible = bool(bi.required_chars and bi.required_chars.issubset(set(bi.chars_raw)))

    if bi.feasible:
        bi.confidence = 1.0
        bi.reason = f"All required chars {list(bi.required_chars)} survived raw"
    elif bi.chars_raw:
        survived = set(bi.chars_raw)
        missing = bi.required_chars - survived
        bi.confidence = len(survived & bi.required_chars) / max(1, len(bi.required_chars))
        bi.reason = f"Partial breakout: {list(survived)} raw, missing {list(missing)}"
    elif bi.chars_encoded:
        bi.confidence = 0.1
        bi.reason = f"Required chars encoded: {bi.chars_encoded}"
    else:
        bi.confidence = 0.0
        bi.reason = f"All required chars blocked: {bi.chars_blocked}"

    log.info(
        "Breakout analysis: context=%s required=%s raw=%s encoded=%s blocked=%s feasible=%s conf=%.0f%%",
        context_type, list(bi.required_chars), bi.chars_raw, bi.chars_encoded,
        bi.chars_blocked, bi.feasible, bi.confidence * 100,
    )

    profile.breakout_info = bi
    return profile
