"""
core/engines/xss/context_engine.py
=====================================
Context Detection Engine for wamiqsec/ReconMind Phase 5.

Determines exactly WHERE in a response document the injected marker
landed, using script-block scanning, comment scanning, JSON detection,
and full DOM parsing — in that priority order.
"""

import re
from typing import Tuple, Optional
from bs4 import BeautifulSoup

from models.response_profile import ResponseProfile, ContextInfo
from core.utils.logger import get_logger

log = get_logger(__name__)


class XSSContext:
    HTML_BODY           = "HTML_BODY"
    HTML_ATTR_DOUBLE     = "HTML_ATTR_DOUBLE"
    HTML_ATTR_SINGLE     = "HTML_ATTR_SINGLE"
    HTML_ATTR_UNQUOTED   = "HTML_ATTR_UNQUOTED"
    HTML_ATTR_EVENT       = "HTML_ATTR_EVENT"
    HTML_COMMENT         = "HTML_COMMENT"
    SCRIPT_BLOCK         = "SCRIPT_BLOCK"
    JS_STRING_DOUBLE     = "JS_STRING_DOUBLE"
    JS_STRING_SINGLE     = "JS_STRING_SINGLE"
    JS_STRING_TEMPLATE   = "JS_STRING_TEMPLATE"
    JSON_VALUE           = "JSON_VALUE"
    SVG_CONTEXT          = "SVG_CONTEXT"
    TEXTAREA_CONTEXT     = "TEXTAREA_CONTEXT"
    URL_ATTR             = "URL_ATTR"
    HTML_TITLE           = "HTML_TITLE"
    HTML_NOSCRIPT        = "HTML_NOSCRIPT"
    UNKNOWN              = "UNKNOWN"


EXECUTABLE_CONTEXTS = {
    XSSContext.HTML_BODY, XSSContext.HTML_ATTR_DOUBLE, XSSContext.HTML_ATTR_SINGLE,
    XSSContext.HTML_ATTR_UNQUOTED, XSSContext.HTML_ATTR_EVENT, XSSContext.HTML_COMMENT,
    XSSContext.SCRIPT_BLOCK, XSSContext.JS_STRING_DOUBLE, XSSContext.JS_STRING_SINGLE,
    XSSContext.JS_STRING_TEMPLATE, XSSContext.JSON_VALUE, XSSContext.SVG_CONTEXT,
    XSSContext.TEXTAREA_CONTEXT, XSSContext.URL_ATTR,
}

BREAKOUT_CHARS_REQUIRED = {
    XSSContext.HTML_BODY:          ["<"],
    XSSContext.HTML_ATTR_DOUBLE:   ['"'],
    XSSContext.HTML_ATTR_SINGLE:   ["'"],
    XSSContext.HTML_ATTR_UNQUOTED: [" "],
    XSSContext.HTML_ATTR_EVENT:    ['"', "'"],
    XSSContext.HTML_COMMENT:       ["-", ">"],
    XSSContext.SCRIPT_BLOCK:       ["<"],
    XSSContext.JS_STRING_DOUBLE:   ['"'],
    XSSContext.JS_STRING_SINGLE:   ["'"],
    XSSContext.JS_STRING_TEMPLATE: ["`"],
    XSSContext.JSON_VALUE:         ['"'],
    XSSContext.SVG_CONTEXT:        ["<"],
    XSSContext.TEXTAREA_CONTEXT:   ["<"],
    XSSContext.URL_ATTR:           ["j"],
}

EVENT_HANDLER_ATTRS = {
    "onclick", "ondblclick", "onmousedown", "onmouseup", "onmouseover",
    "onmousemove", "onmouseout", "onmouseenter", "onmouseleave",
    "onkeydown", "onkeypress", "onkeyup", "onload", "onunload",
    "onbeforeunload", "onsubmit", "onreset", "onfocus", "onblur",
    "onchange", "oninput", "oninvalid", "onselect", "onerror",
    "onabort", "onresize", "onscroll", "ontoggle", "onpointerdown",
    "onpointerup", "onpointerover", "onpointermove", "onpointerout",
    "onsearch", "oncontextmenu", "onwheel", "ondrag", "ondrop",
    "ondragstart", "ondragend", "onanimationstart", "onanimationend",
    "ontransitionend", "oncanplay", "onplay", "onpause",
}

URL_ATTRS = {
    "href", "src", "action", "formaction", "data", "poster",
    "background", "xlink:href", "xml:base", "srcdoc",
}


def _check_script_context(html: str, marker: str) -> Optional[Tuple[str, float, str]]:
    """Check if marker is inside a <script> block; determine string-literal nesting."""
    script_re = re.compile(r'<script[^>]*>(.*?)</script>', re.S | re.I)

    for match in script_re.finditer(html):
        js_block = match.group(1)
        if marker not in js_block:
            continue

        idx = js_block.find(marker)
        before = js_block[:idx]
        s = max(0, idx - 80)
        e = min(len(js_block), idx + len(marker) + 80)
        snippet = js_block[s:e].replace("\n", "|")

        clean_before = re.sub(r"\\['\"`]", "  ", before)
        single_open = clean_before.count("'") % 2 == 1
        double_open = clean_before.count('"') % 2 == 1
        template_open = clean_before.count('`') % 2 == 1

        if single_open:
            return XSSContext.JS_STRING_SINGLE, 0.92, snippet
        elif double_open:
            return XSSContext.JS_STRING_DOUBLE, 0.92, snippet
        elif template_open:
            return XSSContext.JS_STRING_TEMPLATE, 0.92, snippet
        else:
            return XSSContext.SCRIPT_BLOCK, 0.88, snippet

    return None


def _check_comment_context(html: str, marker: str) -> Optional[Tuple[str, float, str]]:
    idx = html.find(marker)
    if idx == -1:
        return None
    before = html[:idx]

    last_open, last_close = before.rfind("<!--"), before.rfind("-->")
    if last_open > last_close:
        s, e = max(0, idx - 60), min(len(html), idx + len(marker) + 60)
        return XSSContext.HTML_COMMENT, 0.90, html[s:e].replace("\n", "|")

    last_js_open, last_js_close = before.rfind("/*"), before.rfind("*/")
    if last_js_open > last_js_close:
        s, e = max(0, idx - 60), min(len(html), idx + len(marker) + 60)
        return XSSContext.HTML_COMMENT, 0.85, html[s:e].replace("\n", "|")

    return None


def _check_json_context(html: str, marker: str, content_type: str) -> Optional[Tuple[str, float, str]]:
    is_json_ct = "application/json" in content_type.lower()
    looks_json = html.strip().startswith(('{', '['))
    if not (is_json_ct or looks_json) or marker not in html:
        return None
    idx = html.find(marker)
    s, e = max(0, idx - 60), min(len(html), idx + len(marker) + 60)
    return XSSContext.JSON_VALUE, 0.85, html[s:e].replace("\n", "|")


def _check_dom_context(html: str, marker: str) -> Tuple[str, float, str]:
    """Walk the parsed DOM to find exactly where the marker landed."""
    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception as e:
        log.debug("BeautifulSoup parse error: %s", e)
        return XSSContext.UNKNOWN, 0.0, ""

    for tag in soup.find_all(True):
        tag_name = tag.name.lower() if tag.name else ""

        direct_string = tag.string
        if direct_string and marker in str(direct_string):
            snippet = f"<{tag_name}>{str(direct_string)[:80]}</{tag_name}>"
            if tag_name == "title":
                return XSSContext.HTML_TITLE, 0.95, snippet
            if tag_name in ("meta", "link"):
                return XSSContext.HTML_NOSCRIPT, 0.95, snippet
            if tag_name == "noscript":
                return XSSContext.HTML_NOSCRIPT, 0.90, snippet
            if tag_name == "textarea":
                return XSSContext.TEXTAREA_CONTEXT, 0.90, snippet
            if tag_name == "svg":
                return XSSContext.SVG_CONTEXT, 0.88, snippet
            if tag_name not in ("script", "style"):
                return XSSContext.HTML_BODY, 0.88, snippet

        for attr_name, attr_value in tag.attrs.items():
            attr_str = " ".join(attr_value) if isinstance(attr_value, list) else str(attr_value or "")
            if marker not in attr_str:
                continue

            attr_lower = attr_name.lower()
            snippet = f'<{tag_name} {attr_name}="{attr_str[:60]}">'

            if attr_lower in EVENT_HANDLER_ATTRS:
                return XSSContext.HTML_ATTR_EVENT, 0.95, snippet
            if attr_lower in URL_ATTRS:
                return XSSContext.URL_ATTR, 0.90, snippet

            raw_attr_re = re.compile(re.escape(attr_name) + r'\s*=\s*(["\'])', re.I)
            quote_match = raw_attr_re.search(html)
            if quote_match:
                q = quote_match.group(1)
                return (XSSContext.HTML_ATTR_DOUBLE if q == '"' else XSSContext.HTML_ATTR_SINGLE), 0.90, snippet

            return XSSContext.HTML_ATTR_UNQUOTED, 0.80, snippet

    idx = html.find(marker)
    if idx != -1:
        s, e = max(0, idx - 100), min(len(html), idx + len(marker) + 100)
        ctx_chunk = html[s:e]
        if re.search(r'<[a-zA-Z][^>]*' + re.escape(marker), ctx_chunk, re.S):
            return XSSContext.HTML_ATTR_DOUBLE, 0.65, ctx_chunk.replace("\n", "|")
        return XSSContext.HTML_BODY, 0.70, ctx_chunk.replace("\n", "|")

    return XSSContext.UNKNOWN, 0.0, ""


def detect_context(profile: ResponseProfile, marker: str) -> ResponseProfile:
    """
    Detect exactly where in the response document the marker landed.

    Priority: script block -> comment -> JSON -> DOM parsing.
    """
    html = profile.raw_body
    ci = ContextInfo()

    if not html or marker not in html:
        ci.context_type = XSSContext.UNKNOWN
        ci.confidence = 0.0
        ci.detection_method = "not_found"
        profile.context_info = ci
        return profile

    result = _check_script_context(html, marker)
    if result:
        ctx, conf, snippet = result
        ci.context_type, ci.confidence, ci.snippet = ctx, conf, snippet
        ci.is_in_script_block = True
        ci.is_executable = ctx in EXECUTABLE_CONTEXTS
        ci.detection_method = "script_block_scan"
        ci.is_in_template = (ctx == XSSContext.JS_STRING_TEMPLATE)
        profile.context_info = ci
        log.info("Context detected (script): %s (%.0f%%)", ctx, conf * 100)
        return profile

    result = _check_comment_context(html, marker)
    if result:
        ctx, conf, snippet = result
        ci.context_type, ci.confidence, ci.snippet = ctx, conf, snippet
        ci.is_executable = ctx in EXECUTABLE_CONTEXTS
        ci.detection_method = "comment_scan"
        profile.context_info = ci
        log.info("Context detected (comment): %s (%.0f%%)", ctx, conf * 100)
        return profile

    result = _check_json_context(html, marker, profile.content_type)
    if result:
        ctx, conf, snippet = result
        ci.context_type, ci.confidence, ci.snippet = ctx, conf, snippet
        ci.is_executable = ctx in EXECUTABLE_CONTEXTS
        ci.detection_method = "json_detection"
        profile.context_info = ci
        log.info("Context detected (json): %s (%.0f%%)", ctx, conf * 100)
        return profile

    ctx, conf, snippet = _check_dom_context(html, marker)
    ci.context_type, ci.confidence, ci.snippet = ctx, conf, snippet
    ci.is_executable = ctx in EXECUTABLE_CONTEXTS
    ci.detection_method = "dom_parser"
    if ctx == XSSContext.HTML_ATTR_EVENT:
        ci.is_event_handler = True
    if ctx == XSSContext.URL_ATTR:
        ci.is_url_attr = True

    profile.context_info = ci
    log.info("Context detected (dom): %s (%.0f%%) executable=%s", ctx, conf * 100, ci.is_executable)
    return profile


def get_required_breakout_chars(context_type: str) -> list:
    return BREAKOUT_CHARS_REQUIRED.get(context_type, ["<"])


def context_is_executable(context_type: str) -> bool:
    return context_type in EXECUTABLE_CONTEXTS
