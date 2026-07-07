"""
core/payloads/xss/payload_selector.py
========================================
Dynamic payload selector for wamiqsec/ReconMind Phase 5.

Selects context-appropriate payloads using detected context and
breakout analysis, instead of spraying every payload at every parameter.
"""

from typing import List, Dict, Any

from core.engines.xss.context_engine import XSSContext
from models.response_profile import ResponseProfile
from core.utils.logger import get_logger

from core.payloads.xss.html_body import TIER1 as HTML_T1, TIER2 as HTML_T2, TIER3 as HTML_T3
from core.payloads.xss.attributes import (
    ATTR_DOUBLE_QUOTE, ATTR_SINGLE_QUOTE, ATTR_EVENT_HANDLER, ATTR_UNQUOTED,
    JS_STRING_SINGLE, JS_STRING_DOUBLE, JS_STRING_TEMPLATE, JS_SCRIPT_BLOCK,
    SVG_PAYLOADS, JSON_PAYLOADS, URL_ATTR_PAYLOADS,
)

log = get_logger(__name__)
Payload = Dict[str, Any]

_PAYLOAD_MAP: Dict[str, tuple] = {
    XSSContext.HTML_BODY:          (HTML_T1, HTML_T2, HTML_T3),
    XSSContext.HTML_ATTR_DOUBLE:   (ATTR_DOUBLE_QUOTE, ATTR_DOUBLE_QUOTE, []),
    XSSContext.HTML_ATTR_SINGLE:   (ATTR_SINGLE_QUOTE, ATTR_SINGLE_QUOTE, []),
    XSSContext.HTML_ATTR_UNQUOTED: (ATTR_UNQUOTED, ATTR_UNQUOTED, []),
    XSSContext.HTML_ATTR_EVENT:    (ATTR_EVENT_HANDLER, ATTR_EVENT_HANDLER, []),
    XSSContext.SCRIPT_BLOCK:       (JS_SCRIPT_BLOCK, JS_SCRIPT_BLOCK, []),
    XSSContext.JS_STRING_SINGLE:   (JS_STRING_SINGLE, JS_STRING_SINGLE, []),
    XSSContext.JS_STRING_DOUBLE:   (JS_STRING_DOUBLE, JS_STRING_DOUBLE, []),
    XSSContext.JS_STRING_TEMPLATE: (JS_STRING_TEMPLATE, JS_STRING_TEMPLATE, []),
    XSSContext.JSON_VALUE:         (JSON_PAYLOADS, JSON_PAYLOADS, []),
    XSSContext.SVG_CONTEXT:        (SVG_PAYLOADS, SVG_PAYLOADS, []),
    XSSContext.TEXTAREA_CONTEXT:   (HTML_T1, HTML_T2, []),
    XSSContext.URL_ATTR:           (URL_ATTR_PAYLOADS, URL_ATTR_PAYLOADS, []),
}

_NON_EXECUTABLE = {XSSContext.HTML_TITLE, XSSContext.HTML_NOSCRIPT, XSSContext.UNKNOWN}


def select_payloads(
    profile: ResponseProfile,
    max_payloads: int = 10,
    include_waf_bypass: bool = False,
) -> List[Payload]:
    """Select context-appropriate XSS payloads based on ResponseProfile state."""
    ctx = profile.context_info
    bi = profile.breakout_info

    if ctx is None:
        return []

    context_type = ctx.context_type
    if context_type in _NON_EXECUTABLE:
        log.debug("Context %s is non-executable — no payloads", context_type)
        return []

    tier1, tier2, tier3 = _PAYLOAD_MAP.get(context_type, (HTML_T1, HTML_T2, HTML_T3))
    selected: List[Payload] = list(tier1)

    breakout_ok = bi is not None and bi.feasible
    if breakout_ok:
        for p in tier2:
            if p not in selected:
                selected.append(p)

    if include_waf_bypass and tier3:
        for p in tier3:
            if p not in selected:
                selected.append(p)

    blocked = set(bi.chars_blocked) if bi else set()
    if blocked:
        selected = [p for p in selected if not set(p.get("requires", [])).intersection(blocked)]

    log.info("Payload selection: context=%s breakout=%s -> %d payload(s)",
              context_type, breakout_ok, min(len(selected), max_payloads))

    return selected[:max_payloads]
