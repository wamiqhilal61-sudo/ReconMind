"""
core/analyzer/context_analyzer.py
===================================
Context analyzer for ReconMind.

Why this file exists:
    Knowing THAT a value was reflected is only half the story. The other
    half — and what determines exploitability — is WHERE in the response
    it landed. Reflected input inside a JavaScript block is almost always
    exploitable. Input inside an HTML comment is interesting. Input HTML-
    encoded inside a paragraph is much lower risk.

    This module classifies each reflection snippet into one of these
    contexts:

        CONTEXT_JS          →  Inside a <script> block or JS event handler
        CONTEXT_HTML_ATTR   →  Inside an HTML attribute value
        CONTEXT_HTML_BODY   →  Inside visible HTML body text
        CONTEXT_JSON        →  Inside a JSON response value
        CONTEXT_COMMENT     →  Inside an HTML/JS comment
        CONTEXT_UNKNOWN     →  Could not determine context

    The context determines the XSS exploitation vector:
        JS context          → `</script><script>alert(1)</script>`
        Attribute context   → `" onmouseover="alert(1)`
        HTML body context   → `<script>alert(1)</script>`

    This classification feeds directly into the risk scoring engine.

How context detection works:
    We scan backwards from the marker's position in the response to
    identify what HTML/JS structure we're inside. This is not a full
    parser — we use targeted regex patterns that are fast and accurate
    enough for the reconnaissance phase.
"""

from dataclasses import dataclass, field
from typing import List, Optional
import re

from modules.reflection.reflection_engine import ReflectionResult
from core.utils.logger import get_logger

log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Context constants
# ---------------------------------------------------------------------------

class ReflectionContext:
    """Enumeration of detectable reflection context types."""

    JS          = "JS"           # Inside a JavaScript block
    HTML_ATTR   = "HTML_ATTR"    # Inside an HTML attribute value
    HTML_BODY   = "HTML_BODY"    # Inside visible HTML text
    JSON        = "JSON"         # Inside a JSON structure
    COMMENT     = "COMMENT"      # Inside an HTML or JS comment
    UNKNOWN     = "UNKNOWN"      # Context could not be determined


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class ContextAnalysis:
    """
    The result of context analysis on a single ReflectionResult.

    Attributes:
        reflection:       The ReflectionResult being analyzed.
        context:          One of ReflectionContext.* constants.
        context_snippet:  The relevant snippet showing the context.
        dangerous_sinks:  List of dangerous JS sinks found near the reflection.
        in_event_handler: True if the reflection is in an HTML event attribute.
        notes:            Additional analyst notes.
    """

    reflection: ReflectionResult
    context: str = ReflectionContext.UNKNOWN
    context_snippet: str = ""
    dangerous_sinks: List[str] = field(default_factory=list)
    in_event_handler: bool = False
    notes: List[str] = field(default_factory=list)

    def __repr__(self) -> str:
        return (
            f"ContextAnalysis({self.reflection.parameter.name!r} "
            f"→ {self.context})"
        )


# ---------------------------------------------------------------------------
# Dangerous JS sink patterns
# These are the functions/properties that, when our input reaches them,
# lead to direct JavaScript execution or DOM manipulation.
# ---------------------------------------------------------------------------

DANGEROUS_SINK_PATTERNS = [
    r'eval\s*\(',
    r'document\.write\s*\(',
    r'innerHTML\s*=',
    r'outerHTML\s*=',
    r'insertAdjacentHTML\s*\(',
    r'location\s*=',
    r'location\.href\s*=',
    r'location\.replace\s*\(',
    r'setTimeout\s*\(',
    r'setInterval\s*\(',
    r'\.src\s*=',
    r'\.action\s*=',
    r'document\.domain\s*=',
    r'window\.name\s*=',
]

# HTML event handler attribute prefixes
EVENT_HANDLER_PATTERN = re.compile(
    r'\bon\w+\s*=\s*["\']?[^"\']*',
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Context detection logic
# ---------------------------------------------------------------------------

def _detect_js_context(snippet: str, full_response: str, marker: str) -> bool:
    """
    Return True if the marker appears to be inside a JavaScript context.

    Detection strategy:
        1. Check if the snippet contains JS-like syntax around the marker.
        2. Scan backwards in the full response from the marker position
           to find an opening <script> tag without a closing </script>.
        3. Check for inline event handlers: onerror=, onclick=, etc.

    Args:
        snippet:       Context snippet around the reflection.
        full_response: Complete response body for deep scan.
        marker:        The marker string.

    Returns:
        True if likely in JS context.
    """
    # Quick check: is the marker followed by JS-like tokens?
    js_proximity_pattern = re.compile(
        r'(var |let |const |function |=>|;|\{|\}|\(|\)|==|===|!=|&&|\|\||'
        r'return |typeof |undefined|null|true|false)',
        re.IGNORECASE,
    )
    if js_proximity_pattern.search(snippet):
        log.debug("    JS context detected via proximity pattern")
        return True

    # Deep check: find marker position and look backwards for unclosed <script>
    marker_pos = full_response.find(marker)
    if marker_pos == -1:
        return False

    text_before = full_response[:marker_pos]

    # Find the last <script> and last </script> before the marker
    last_script_open = text_before.rfind("<script")
    last_script_close = text_before.rfind("</script>")

    if last_script_open > last_script_close:
        log.debug("    JS context detected via <script> block scan")
        return True

    return False


def _detect_html_attribute_context(snippet: str, full_response: str, marker: str) -> tuple:
    """
    Return (in_attribute: bool, in_event_handler: bool).

    Detection strategy:
        Look for the pattern:  attribute="...marker..."
        or:                    attribute='...marker...'
        An unquoted attribute value is detected by proximity to '='.

    Args:
        snippet:       Context snippet.
        full_response: Full response body.
        marker:        The injected marker.

    Returns:
        Tuple of (in_attribute: bool, in_event_handler: bool).
    """
    # Check if marker is wrapped in an attribute context
    attr_pattern = re.compile(
        r'[\w-]+\s*=\s*["\']?[^"\'<>]*' + re.escape(marker),
        re.IGNORECASE,
    )
    if attr_pattern.search(snippet):
        # Is it an event handler?
        event_handler = bool(EVENT_HANDLER_PATTERN.search(snippet))
        log.debug(
            "    HTML attribute context detected (event_handler=%s)", event_handler
        )
        return True, event_handler

    return False, False


def _detect_json_context(snippet: str) -> bool:
    """
    Return True if the reflection appears to be inside a JSON structure.

    JSON context indicators:
        - Marker surrounded by quotes in a key-value pattern
        - Nearby JSON punctuation: {, }, [, ], :, ,
    """
    json_pattern = re.compile(
        r'["\']?\s*' + re.escape(snippet[:20]) + r'.*?[{}\[\],:]',
        re.DOTALL,
    )
    # Simpler heuristic: count JSON structural chars in snippet
    structural_chars = sum(snippet.count(c) for c in '{}[]":,')
    if structural_chars >= 3:
        log.debug("    JSON context detected via structural char density")
        return True
    return False


def _detect_comment_context(snippet: str, full_response: str, marker: str) -> bool:
    """
    Return True if the reflection is inside an HTML or JS comment.

    HTML comment:  <!-- ... -->
    JS comment:    // ...  or  /* ... */
    """
    marker_pos = full_response.find(marker)
    if marker_pos == -1:
        return False

    text_before = full_response[:marker_pos]

    # HTML comment check
    last_comment_open = text_before.rfind("<!--")
    last_comment_close = text_before.rfind("-->")
    if last_comment_open > last_comment_close:
        log.debug("    HTML comment context detected")
        return True

    # JS block comment check
    last_js_comment_open = text_before.rfind("/*")
    last_js_comment_close = text_before.rfind("*/")
    if last_js_comment_open > last_js_comment_close:
        log.debug("    JS block comment context detected")
        return True

    # JS line comment: check if the line containing the marker starts with //
    line_start = text_before.rfind("\n")
    line_text = text_before[line_start:] if line_start != -1 else text_before
    if re.search(r'//[^\n]*$', line_text):
        log.debug("    JS line comment context detected")
        return True

    return False


def _find_dangerous_sinks(full_response: str, marker: str, radius: int = 200) -> List[str]:
    """
    Check whether any dangerous JavaScript sinks appear near the reflection.

    'Near' means within `radius` characters of the marker position.

    Args:
        full_response: Complete response body.
        marker:        The injected marker.
        radius:        Character window to search around the marker.

    Returns:
        List of dangerous sink names found nearby.
    """
    marker_pos = full_response.find(marker)
    if marker_pos == -1:
        return []

    window_start = max(0, marker_pos - radius)
    window_end = min(len(full_response), marker_pos + len(marker) + radius)
    window = full_response[window_start:window_end]

    found_sinks: List[str] = []
    for pattern in DANGEROUS_SINK_PATTERNS:
        match = re.search(pattern, window, re.IGNORECASE)
        if match:
            found_sinks.append(match.group(0).strip())

    if found_sinks:
        log.debug("    Dangerous sinks near reflection: %s", found_sinks)

    return found_sinks


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_reflection_context(
    reflection: ReflectionResult,
    full_response: str,
) -> ContextAnalysis:
    """
    Classify the context of a single reflection.

    This function is called for each reflected parameter. It uses the
    snippets from the ReflectionResult and the full response body to
    determine where the reflection landed.

    Args:
        reflection:    A ReflectionResult where .reflected is True.
        full_response: The complete HTTP response body as text.

    Returns:
        ContextAnalysis with context classification and sink findings.
    """
    marker = reflection.marker
    analysis = ContextAnalysis(reflection=reflection)

    if not reflection.reflected:
        analysis.context = ReflectionContext.UNKNOWN
        return analysis

    # Use the first snippet as the primary analysis surface
    primary_snippet = reflection.snippets[0] if reflection.snippets else ""

    log.debug(
        "Analyzing context for param %r | snippet: %r",
        reflection.parameter.name, primary_snippet[:60],
    )

    # --- Priority order matters: JS > attribute > comment > JSON > HTML body ---

    # 1. Check for JavaScript context first (highest risk)
    if _detect_js_context(primary_snippet, full_response, marker):
        analysis.context = ReflectionContext.JS
        analysis.notes.append("Reflection lands inside JavaScript execution context")

    # 2. Check for HTML attribute context
    elif True:
        in_attr, in_event = _detect_html_attribute_context(
            primary_snippet, full_response, marker
        )
        if in_attr:
            analysis.context = ReflectionContext.HTML_ATTR
            analysis.in_event_handler = in_event
            if in_event:
                analysis.notes.append("Reflection is inside an HTML event handler attribute")
            else:
                analysis.notes.append("Reflection is inside an HTML attribute value")

        # 3. Check for comment context
        elif _detect_comment_context(primary_snippet, full_response, marker):
            analysis.context = ReflectionContext.COMMENT
            analysis.notes.append("Reflection is inside an HTML or JavaScript comment")

        # 4. Check for JSON context
        elif _detect_json_context(primary_snippet):
            analysis.context = ReflectionContext.JSON
            analysis.notes.append("Reflection is inside a JSON response body")

        # 5. Default: HTML body
        else:
            analysis.context = ReflectionContext.HTML_BODY
            analysis.notes.append("Reflection is inside visible HTML body text")

    # Always check for dangerous sinks regardless of context
    analysis.dangerous_sinks = _find_dangerous_sinks(full_response, marker)

    if analysis.dangerous_sinks:
        analysis.notes.append(
            f"Dangerous JS sinks found near reflection: {', '.join(analysis.dangerous_sinks)}"
        )

    analysis.context_snippet = primary_snippet
    return analysis


def analyze_all_reflections(
    reflection_results: List[ReflectionResult],
    full_response: str,
) -> List[ContextAnalysis]:
    """
    Run context analysis on all reflection results for a URLTarget.

    Called by the pipeline orchestrator after reflection probing.

    Args:
        reflection_results: List of ReflectionResult objects from the
                            reflection engine.
        full_response:      The baseline HTTP response body.

    Returns:
        List of ContextAnalysis objects, one per reflected parameter.
        Non-reflected parameters are skipped.
    """
    analyses: List[ContextAnalysis] = []

    for result in reflection_results:
        if not result.reflected:
            continue

        analysis = analyze_reflection_context(result, full_response)
        analyses.append(analysis)

        log.info(
            "  Context for %r: %s%s",
            result.parameter.name,
            analysis.context,
            " [event-handler]" if analysis.in_event_handler else "",
        )

    log.info(
        "Context analysis complete: %d reflected params analyzed",
        len(analyses),
    )
    return analyses
