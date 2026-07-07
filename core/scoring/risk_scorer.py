"""
core/scoring/risk_scorer.py
============================
Risk scoring engine for ReconMind.

Why this file exists:
    After reflection detection and context analysis, we have a pile of data.
    But a human analyst needs prioritization — "which of these 47 parameters
    should I look at first?" The scoring engine answers that question with
    a consistent, tunable point system.

    Points are additive. Each confirmed signal adds to the score:
        +20  parameter was reflected
        +30  reflection was NOT HTML-encoded
        +50  reflection is inside JavaScript
        +40  a dangerous sink (eval, innerHTML) is nearby
        +25  reflection is inside an HTML attribute
        +10  reflection is inside a comment
        +15  reflection is in JSON
        (bonuses for event handlers, multiple reflections, etc.)

    The total maps to a severity label:
        ≥70  → HIGH    (investigate immediately)
        ≥40  → MEDIUM  (investigate this session)
        ≥10  → LOW     (low priority, document)
        <10  → INFO    (not worth acting on alone)

Tuning:
    All weights come from CONFIG.scoring — a security engineer can raise
    or lower thresholds without touching this code.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional

from core.analyzer.context_analyzer import ContextAnalysis, ReflectionContext
from modules.reflection.reflection_engine import ReflectionResult
from config.settings import CONFIG
from core.utils.logger import get_logger

log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Severity labels
# ---------------------------------------------------------------------------

class Severity:
    HIGH   = "HIGH"
    MEDIUM = "MEDIUM"
    LOW    = "LOW"
    INFO   = "INFO"


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class ScoredFinding:
    """
    A fully scored and labeled vulnerability finding.

    Attributes:
        url:           The URL where the finding was discovered.
        parameter:     Parameter name that triggered the finding.
        param_type:    Type of parameter (GET, POST, etc.).
        score:         Total calculated risk score.
        severity:      Human label: HIGH / MEDIUM / LOW / INFO.
        reasons:       Bullet list of conditions that contributed to the score.
        context:       Reflection context classification.
        context_snippet: The code snippet showing the reflection.
        dangerous_sinks: Any dangerous JS sinks found nearby.
        recommendations: Actionable next steps for the analyst.
    """

    url: str
    parameter: str
    param_type: str
    score: int = 0
    severity: str = Severity.INFO
    reasons: List[str] = field(default_factory=list)
    context: str = ReflectionContext.UNKNOWN
    context_snippet: str = ""
    dangerous_sinks: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)

    def __repr__(self) -> str:
        return (
            f"ScoredFinding([{self.severity}] {self.parameter!r} "
            f"score={self.score} context={self.context})"
        )


# ---------------------------------------------------------------------------
# Scoring logic
# ---------------------------------------------------------------------------

def _calculate_score(analysis: ContextAnalysis) -> tuple:
    """
    Calculate the risk score and build the reasons list for one finding.

    Args:
        analysis: ContextAnalysis from the context analyzer.

    Returns:
        Tuple of (score: int, reasons: List[str])
    """
    cfg = CONFIG.scoring
    score = 0
    reasons: List[str] = []

    reflection = analysis.reflection

    # --- Base: was input reflected at all? ---
    if reflection.reflected:
        score += cfg.reflected_input
        reasons.append(f"Input was reflected in response (+{cfg.reflected_input})")

    # --- Encoding check: raw reflection is the dangerous case ---
    if reflection.raw_reflected:
        score += cfg.unencoded_reflection
        reasons.append(
            f"Reflection was NOT HTML-encoded — raw input in page (+{cfg.unencoded_reflection})"
        )
    elif reflection.reflected:
        reasons.append("Reflection was HTML-encoded (lower risk, but encoding can be bypassed)")

    # --- Context scoring ---
    if analysis.context == ReflectionContext.JS:
        score += cfg.js_context
        reasons.append(
            f"Reflection lands inside a JavaScript execution context (+{cfg.js_context})"
        )

    elif analysis.context == ReflectionContext.HTML_ATTR:
        score += cfg.html_attribute_context
        reasons.append(
            f"Reflection lands inside an HTML attribute (+{cfg.html_attribute_context})"
        )
        # Event handler is even more dangerous — give a bonus
        if analysis.in_event_handler:
            bonus = 20
            score += bonus
            reasons.append(
                f"Attribute is an event handler (e.g. onclick, onerror) — direct execution context (+{bonus})"
            )

    elif analysis.context == ReflectionContext.JSON:
        score += cfg.json_context
        reasons.append(f"Reflection is inside a JSON body (+{cfg.json_context})")

    elif analysis.context == ReflectionContext.COMMENT:
        score += cfg.html_comment_context
        reasons.append(f"Reflection is inside an HTML/JS comment (+{cfg.html_comment_context})")

    elif analysis.context == ReflectionContext.HTML_BODY:
        # HTML body without encoding is still exploitable
        if reflection.raw_reflected:
            bonus = 15
            score += bonus
            reasons.append(
                f"Unencoded reflection in HTML body — direct HTML injection (+{bonus})"
            )

    # --- Dangerous sinks nearby ---
    if analysis.dangerous_sinks:
        score += cfg.dangerous_sink
        sink_list = ", ".join(analysis.dangerous_sinks[:3])
        reasons.append(
            f"Dangerous JS sink(s) near reflection: {sink_list} (+{cfg.dangerous_sink})"
        )

    # --- Reflection frequency bonus ---
    if reflection.reflection_count > 1:
        bonus = min(reflection.reflection_count * 5, 20)  # cap at +20
        score += bonus
        reasons.append(
            f"Marker reflected {reflection.reflection_count}× (multiple injection points) (+{bonus})"
        )

    # --- Header reflection ---
    if reflection.reflected_in_header:
        bonus = 15
        score += bonus
        reasons.append(f"Marker reflected in HTTP response header (+{bonus})")

    return score, reasons


def _score_to_severity(score: int) -> str:
    """
    Map a numeric score to a severity label.

    Args:
        score: Calculated integer score.

    Returns:
        One of Severity.* constants.
    """
    cfg = CONFIG.reporting
    if score >= cfg.high_threshold:
        return Severity.HIGH
    elif score >= cfg.medium_threshold:
        return Severity.MEDIUM
    elif score >= cfg.low_threshold:
        return Severity.LOW
    else:
        return Severity.INFO


def _build_recommendations(analysis: ContextAnalysis, severity: str) -> List[str]:
    """
    Generate actionable recommendations based on context and severity.

    Args:
        analysis:  ContextAnalysis for the finding.
        severity:  Calculated severity label.

    Returns:
        List of recommendation strings.
    """
    recs: List[str] = []

    ctx = analysis.context

    if ctx == ReflectionContext.JS:
        recs.append("Test closing the JS string/context: `';alert(1)//`")
        recs.append("Test template literal breakout: `` `${alert(1)}` ``")
        recs.append("Check if Content-Security-Policy blocks inline scripts")

    elif ctx == ReflectionContext.HTML_ATTR:
        if analysis.in_event_handler:
            recs.append("Inject JS directly: `alert(1)` (already in event context)")
        else:
            recs.append("Break out of attribute with: `\" onmouseover=\"alert(1)`")
            recs.append("Test: `' onmouseover='alert(1)`")

    elif ctx == ReflectionContext.HTML_BODY:
        recs.append("Inject raw HTML: `<script>alert(1)</script>`")
        recs.append("Try SVG vector: `<svg onload=alert(1)>`")
        recs.append("Test img tag: `<img src=x onerror=alert(1)>`")

    elif ctx == ReflectionContext.JSON:
        recs.append("Test JSON string breakout: `\", \"xss\": \"<script>alert(1)</script>`")
        recs.append("Check how the JSON is consumed by the page JS")

    elif ctx == ReflectionContext.COMMENT:
        recs.append("Test comment breakout: `-->\\n<script>alert(1)</script><!--`")

    if analysis.dangerous_sinks:
        recs.append(
            f"Trace data flow from reflected param to sink: {analysis.dangerous_sinks[0]}"
        )

    if severity == Severity.HIGH:
        recs.append("PRIORITY: Test with Burp Suite Repeater — likely exploitable")

    return recs


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def score_finding(analysis: ContextAnalysis, url: str) -> ScoredFinding:
    """
    Convert a ContextAnalysis into a ScoredFinding with severity label.

    Args:
        analysis: ContextAnalysis from the context analyzer.
        url:      The URL being analyzed (for the report).

    Returns:
        ScoredFinding with score, severity, reasons, and recommendations.
    """
    score, reasons = _calculate_score(analysis)
    severity = _score_to_severity(score)
    recommendations = _build_recommendations(analysis, severity)

    finding = ScoredFinding(
        url=url,
        parameter=analysis.reflection.parameter.name,
        param_type=analysis.reflection.parameter.param_type,
        score=score,
        severity=severity,
        reasons=reasons,
        context=analysis.context,
        context_snippet=analysis.context_snippet,
        dangerous_sinks=analysis.dangerous_sinks,
        recommendations=recommendations,
    )

    log.info(
        "Scored finding: [%s] %r score=%d context=%s",
        severity, finding.parameter, score, analysis.context,
    )

    return finding


def score_all_findings(
    analyses: List[ContextAnalysis],
    url: str,
) -> List[ScoredFinding]:
    """
    Score all ContextAnalysis results for a URLTarget.

    Called by the pipeline orchestrator after context analysis.

    Args:
        analyses: List of ContextAnalysis objects.
        url:      Target URL string.

    Returns:
        List of ScoredFinding objects sorted by score (highest first).
    """
    findings: List[ScoredFinding] = []

    for analysis in analyses:
        finding = score_finding(analysis, url)

        # Only keep findings above minimum display threshold
        if finding.score >= CONFIG.reporting.min_display_score:
            findings.append(finding)

    # Sort by score descending — highest risk first
    findings.sort(key=lambda f: f.score, reverse=True)

    log.info(
        "Scoring complete: %d findings (HIGH: %d, MEDIUM: %d, LOW: %d)",
        len(findings),
        sum(1 for f in findings if f.severity == Severity.HIGH),
        sum(1 for f in findings if f.severity == Severity.MEDIUM),
        sum(1 for f in findings if f.severity == Severity.LOW),
    )

    return findings
