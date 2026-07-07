"""
core/modes/passive_mode.py
============================
Passive Recon Mode orchestrator for ReconMind Phase 4 by wamiqsec.

WHAT PASSIVE MODE IS:
────────────────────────────────────────────────────────────────
Passive mode is the safe reconnaissance layer. It maps the attack
surface without ever sending a payload. This is appropriate for:

    - Initial target assessment before asking for permission to scan
    - Bug bounty programs that restrict automated testing
    - Continuous monitoring pipelines
    - Building intelligence before active testing
    - Situations where WAF triggering is unacceptable

WHAT PASSIVE MODE DOES:
    For each URL in scope:
        1. Fetch the page (single request per URL)
        2. Classify the response type (API, auth, admin, search, etc.)
        3. Extract parameters (GET, POST, hidden, JSON)
        4. Analyze security headers (CSP, CORS, cookies, HSTS)
        5. Extract JavaScript endpoints and secrets
        6. Detect dangerous DOM sinks
        7. Map application routes
        8. Calculate interest scores for prioritization

WHAT PASSIVE MODE NEVER DOES:
    - Send XSS/SQLi/LFI/SSRF payloads
    - Perform brute-force or enumeration attacks
    - Send more than one request per URL
    - Modify any application state
    - Trigger authentication changes
    - Generate WAF alerts

OUTPUT:
    PassiveScanReport — a complete surface map that feeds into:
        - Active mode (prioritized target list)
        - Manual-assist mode (hunting guide)
        - Database (persistent intelligence)

RATE LIMITING:
    All requests go through configurable delay and budget controls.
    If request_budget is exhausted, the scan stops gracefully.
"""

import time
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set
from urllib.parse import urlparse, urljoin

from core.recon.url_handler import URLTarget, load_single_url, load_urls_from_file
from core.extractor.param_extractor import extract_parameters, Parameter
from core.engines.response.response_classifier import classify_response, ResponseClassification, PageType
from core.engines.javascript.js_intelligence import analyze_js_from_url, JSIntelligenceReport
from core.engines.passive.passive_analyzer import analyze_response_passively, PassiveAnalysisReport
from core.utils.http_client import safe_get
from config.settings import CONFIG
from core.utils.logger import get_logger

log = get_logger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Data models
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class PassiveTargetResult:
    """
    Complete passive analysis result for a single URL.

    This is the atomic unit produced by passive mode.
    """
    url: str
    status_code: int = 0
    content_type: str = ""

    # Analysis results
    classification: Optional[ResponseClassification] = None
    passive_analysis: Optional[PassiveAnalysisReport] = None
    js_intelligence: Optional[JSIntelligenceReport] = None

    # Extracted parameters
    parameters: List[Parameter] = field(default_factory=list)

    # Interest and prioritization
    interest_score: int = 0
    priority_label: str = "LOW"  # HIGH / MEDIUM / LOW
    priority_reasons: List[str] = field(default_factory=list)

    # Request tracking
    requests_used: int = 0
    analysis_errors: List[str] = field(default_factory=list)


@dataclass
class PassiveScanReport:
    """
    Complete passive scan report for an entire target scope.

    This is what passive mode produces as its final output.
    Consumed by active mode, manual-assist mode, and the reporting layer.
    """
    seed_urls: List[str] = field(default_factory=list)
    target_results: List[PassiveTargetResult] = field(default_factory=list)

    # Aggregate intelligence
    all_endpoints_found: List[str] = field(default_factory=list)
    all_secrets_found: List[Dict] = field(default_factory=list)
    all_dom_sinks: List[Dict] = field(default_factory=list)
    all_routes: List[str] = field(default_factory=list)
    graphql_endpoints: List[str] = field(default_factory=list)
    websocket_endpoints: List[str] = field(default_factory=list)

    # Technology intelligence
    tech_stack: Set[str] = field(default_factory=set)
    detected_frameworks: List[str] = field(default_factory=list)

    # Priority targets for active testing
    high_priority_targets: List[PassiveTargetResult] = field(default_factory=list)
    medium_priority_targets: List[PassiveTargetResult] = field(default_factory=list)

    # Stats
    total_urls_analyzed: int = 0
    total_requests_made: int = 0
    total_params_found: int = 0
    total_js_secrets: int = 0
    total_dom_sinks: int = 0
    scan_duration: float = 0.0

    # Security posture summary
    missing_security_headers: Dict[str, int] = field(default_factory=dict)
    cors_misconfigs: int = 0
    cookie_issues: int = 0
    csp_bypass_urls: List[str] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# Interest scoring
# ─────────────────────────────────────────────────────────────────────────────

def _calculate_target_interest(
    classification: ResponseClassification,
    passive_report: PassiveAnalysisReport,
    js_report: Optional[JSIntelligenceReport],
    params: List[Parameter],
) -> tuple:
    """
    Calculate overall interest score and priority label for a target.

    Returns:
        (score: int, label: str, reasons: List[str])
    """
    score = 0
    reasons = []

    # Page type contribution
    type_scores = {
        PageType.ADMIN:     50,
        PageType.API:       35,
        PageType.UPLOAD:    40,
        PageType.PROFILE:   30,
        PageType.DASHBOARD: 25,
        PageType.AUTH:      20,
        PageType.GRAPHQL:   35,
        PageType.SEARCH:    15,
        PageType.REDIRECT:  20,
        PageType.PUBLIC:    5,
        PageType.ERROR:     2,
    }
    type_score = type_scores.get(classification.page_type, 5)
    score += type_score
    if type_score >= 30:
        reasons.append(f"High-value page type: {classification.page_type}")

    # Parameter count
    if len(params) >= 5:
        score += 15
        reasons.append(f"Rich parameter set: {len(params)} params")
    elif len(params) >= 2:
        score += 8

    # Security header issues from passive analysis
    score += passive_report.interest_score
    if passive_report.high_count > 0:
        reasons.append(f"{passive_report.high_count} HIGH security header findings")
    if passive_report.cors and passive_report.cors.severity == "HIGH":
        score += 20
        reasons.append("CORS misconfiguration detected")

    # CSP absence or bypass
    if passive_report.csp and not passive_report.csp.is_present:
        score += 10
        reasons.append("No CSP — XSS not mitigated")
    elif passive_report.csp and passive_report.csp.bypass_vectors:
        score += 15
        reasons.append(f"CSP bypass vectors: {len(passive_report.csp.bypass_vectors)}")

    # JS intelligence
    if js_report:
        if js_report.secrets:
            score += 30
            reasons.append(f"JS secrets detected: {len(js_report.secrets)}")
        if js_report.high_priority_sinks:
            score += 25
            reasons.append(f"DOM-XSS sinks with user input: {len(js_report.high_priority_sinks)}")
        if js_report.graphql_ops:
            score += 20
            reasons.append("GraphQL operations found in JS")
        if js_report.routes:
            admin_routes = [r for r in js_report.routes if r.is_admin_route]
            if admin_routes:
                score += 20
                reasons.append(f"Admin routes in JS: {[r.path for r in admin_routes[:3]]}")

    # Numeric parameters (IDOR candidates)
    numeric_params = [p for p in params if p.value.isdigit()]
    if numeric_params:
        score += 10 * len(numeric_params)
        reasons.append(f"Numeric params (IDOR candidates): {[p.name for p in numeric_params]}")

    # File/path parameters (LFI candidates)
    file_params = [
        p for p in params
        if any(hint in p.name.lower() for hint in ["file", "path", "page", "template", "include"])
    ]
    if file_params:
        score += 20
        reasons.append(f"File path params (LFI candidates): {[p.name for p in file_params]}")

    # URL params (redirect/SSRF candidates)
    url_params = [
        p for p in params
        if any(hint in p.name.lower() for hint in ["url", "redirect", "next", "src", "callback"])
    ]
    if url_params:
        score += 20
        reasons.append(f"URL params (redirect/SSRF candidates): {[p.name for p in url_params]}")

    # Priority label
    if score >= 60:
        label = "HIGH"
    elif score >= 30:
        label = "MEDIUM"
    else:
        label = "LOW"

    return score, label, reasons


# ─────────────────────────────────────────────────────────────────────────────
# Core passive analysis per URL
# ─────────────────────────────────────────────────────────────────────────────

class RequestBudget:
    """Tracks and enforces the total request budget for a passive scan."""

    def __init__(self, budget: int):
        self.budget = budget
        self.used = 0

    def consume(self, n: int = 1) -> bool:
        """Consume n requests from budget. Returns False if budget exhausted."""
        if self.used + n > self.budget:
            return False
        self.used += n
        return True

    @property
    def remaining(self) -> int:
        return max(0, self.budget - self.used)

    @property
    def exhausted(self) -> bool:
        return self.used >= self.budget


def _analyze_target_passively(
    target: URLTarget,
    budget: RequestBudget,
) -> PassiveTargetResult:
    """
    Run complete passive analysis on a single URLTarget.

    Makes exactly ONE HTTP request per URL (the page fetch).
    All analysis derives from that single response.

    Args:
        target: URLTarget to analyze.
        budget: Shared request budget tracker.

    Returns:
        PassiveTargetResult with all analysis.
    """
    cfg = CONFIG.passive
    result = PassiveTargetResult(url=target.normalized)

    # ── Budget check ──────────────────────────────────────────────────────
    if not budget.consume(1):
        result.analysis_errors.append("Request budget exhausted")
        log.warning("Request budget exhausted — skipping %s", target.normalized)
        return result

    # ── Fetch page ────────────────────────────────────────────────────────
    log.info("Passive analysis: %s", target.normalized)
    response = safe_get(target.normalized)
    result.requests_used = 1

    if response is None:
        result.analysis_errors.append("Failed to fetch URL")
        return result

    result.status_code = response.status_code
    result.content_type = response.headers.get("Content-Type", "")
    html_body = response.text
    resp_headers = dict(response.headers)

    # ── Stage 1: Response classification ──────────────────────────────────
    if cfg.classify_responses:
        result.classification = classify_response(
            url=target.normalized,
            html=html_body,
            status_code=response.status_code,
            content_type=result.content_type,
            response_headers=resp_headers,
        )

    # ── Stage 2: Passive security header analysis ──────────────────────────
    if cfg.analyze_security_headers:
        result.passive_analysis = analyze_response_passively(
            url=target.normalized,
            status_code=response.status_code,
            headers=resp_headers,
            body=html_body,
        )

    # ── Stage 3: Parameter extraction (passive — no probing) ───────────────
    # We set the baseline response on target so extract_parameters doesn't re-fetch
    setattr(target, "baseline_response", response)
    setattr(target, "http_status", response.status_code)

    # Extract params from what we already have (no new requests)
    from core.extractor.param_extractor import (
        _extract_get_params, _extract_form_params, _extract_json_params,
        _attach_parameters,
    )
    all_params = []
    all_params.extend(_extract_get_params(target))
    all_params.extend(_extract_form_params(html_body, target.base_url()))
    all_params.extend(_extract_json_params(html_body, result.content_type))
    _attach_parameters(target, all_params)
    result.parameters = all_params

    # ── Stage 4: JavaScript intelligence ──────────────────────────────────
    if cfg.analyze_js_files or cfg.extract_js_endpoints:
        if not budget.consume(0):  # JS files will consume budget when fetched
            log.debug("Budget low — skipping JS analysis for %s", target.normalized)
        else:
            result.js_intelligence = analyze_js_from_url(target, html_body)
            if result.js_intelligence:
                result.requests_used += len(result.js_intelligence.js_files_analyzed)

    # ── Stage 5: Interest scoring ──────────────────────────────────────────
    classification = result.classification or classify_response(
        url=target.normalized,
        html=html_body,
        status_code=response.status_code,
        content_type=result.content_type,
    )
    passive_report = result.passive_analysis or analyze_response_passively(
        url=target.normalized,
        status_code=response.status_code,
        headers=resp_headers,
    )

    result.interest_score, result.priority_label, result.priority_reasons = (
        _calculate_target_interest(
            classification=classification,
            passive_report=passive_report,
            js_report=result.js_intelligence,
            params=result.parameters,
        )
    )

    log.info(
        "  Result: type=%s params=%d interest=%d priority=%s",
        getattr(classification, "page_type", "?"),
        len(result.parameters),
        result.interest_score,
        result.priority_label,
    )

    # Rate limiting
    time.sleep(cfg.request_delay)

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Report aggregation
# ─────────────────────────────────────────────────────────────────────────────

def _aggregate_report(
    results: List[PassiveTargetResult],
    seed_urls: List[str],
    duration: float,
    budget: RequestBudget,
) -> PassiveScanReport:
    """Aggregate all PassiveTargetResult objects into a PassiveScanReport."""
    report = PassiveScanReport(seed_urls=seed_urls)
    report.scan_duration = duration
    report.total_requests_made = budget.used

    for result in results:
        report.total_urls_analyzed += 1
        report.total_params_found += len(result.parameters)

        # Collect intelligence
        if result.js_intelligence:
            for ep in result.js_intelligence.endpoints:
                if ep.url not in report.all_endpoints_found:
                    report.all_endpoints_found.append(ep.url)
            for secret in result.js_intelligence.secrets:
                report.all_secrets_found.append({
                    "type": secret.secret_type,
                    "source": secret.source_file,
                    "url": result.url,
                })
            for sink in result.js_intelligence.sinks:
                if sink.is_dom_xss_vector:
                    report.all_dom_sinks.append({
                        "sink": sink.sink_name,
                        "source_file": sink.source_file,
                        "url": result.url,
                    })
            for route in result.js_intelligence.routes:
                report.all_routes.append(route.path)
            for op in result.js_intelligence.graphql_ops:
                if result.url not in report.graphql_endpoints:
                    report.graphql_endpoints.append(result.url)
            report.websocket_endpoints.extend(result.js_intelligence.websocket_urls)
            report.total_js_secrets += len(result.js_intelligence.secrets)
            report.total_dom_sinks += len([s for s in result.js_intelligence.sinks if s.is_dom_xss_vector])

        # Tech stack
        if result.passive_analysis:
            for tech in result.passive_analysis.tech_stack:
                report.tech_stack.add(tech)
            if result.passive_analysis.cors and result.passive_analysis.cors.severity in ("HIGH", "MEDIUM"):
                report.cors_misconfigs += 1
            report.cookie_issues += len(result.passive_analysis.cookie_findings)
            for h in result.passive_analysis.missing_headers:
                report.missing_security_headers[h] = report.missing_security_headers.get(h, 0) + 1
            if result.passive_analysis.csp and result.passive_analysis.csp.bypass_vectors:
                report.csp_bypass_urls.append(result.url)

        # Priority lists
        if result.priority_label == "HIGH":
            report.high_priority_targets.append(result)
        elif result.priority_label == "MEDIUM":
            report.medium_priority_targets.append(result)

    # Sort by interest score
    report.high_priority_targets.sort(key=lambda r: r.interest_score, reverse=True)
    report.medium_priority_targets.sort(key=lambda r: r.interest_score, reverse=True)
    report.all_routes = list(set(report.all_routes))

    return report


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def run_passive_mode(
    targets: List[URLTarget],
) -> PassiveScanReport:
    """
    Run Passive Recon Mode on a list of URLTargets.

    This is the main entry point called by main.py when --mode passive is set.

    Pipeline per target:
        1. Budget check
        2. Single page fetch
        3. Response classification
        4. Security header analysis
        5. Parameter extraction (no probing)
        6. JavaScript intelligence
        7. Interest scoring

    Args:
        targets: List of URLTarget objects to analyze passively.

    Returns:
        PassiveScanReport with complete surface map and prioritized targets.
    """
    cfg = CONFIG.passive
    budget = RequestBudget(cfg.request_budget)

    log.info(
        "=== PASSIVE RECON MODE === %d targets | budget=%d | delay=%.1fs",
        len(targets), cfg.request_budget, cfg.request_delay,
    )

    start_time = time.time()
    results: List[PassiveTargetResult] = []
    seen_urls: Set[str] = set()

    for i, target in enumerate(targets, 1):
        if budget.exhausted:
            log.warning("Request budget exhausted after %d targets", i - 1)
            break

        if target.normalized in seen_urls:
            continue
        seen_urls.add(target.normalized)

        log.info("[%d/%d] %s (budget remaining: %d)", i, len(targets), target.normalized, budget.remaining)

        try:
            result = _analyze_target_passively(target, budget)
            results.append(result)
        except KeyboardInterrupt:
            log.warning("Passive scan interrupted by user")
            break
        except Exception as exc:
            log.error("Error analyzing %s: %s", target.normalized, exc)
            results.append(PassiveTargetResult(
                url=target.normalized,
                analysis_errors=[str(exc)],
            ))

    duration = time.time() - start_time
    report = _aggregate_report(results, [t.normalized for t in targets], duration, budget)
    report.target_results = results

    log.info(
        "=== PASSIVE SCAN COMPLETE === %d URLs | %d requests | %.1fs | "
        "HIGH:%d MEDIUM:%d endpoints:%d secrets:%d sinks:%d",
        report.total_urls_analyzed,
        report.total_requests_made,
        duration,
        len(report.high_priority_targets),
        len(report.medium_priority_targets),
        len(report.all_endpoints_found),
        report.total_js_secrets,
        report.total_dom_sinks,
    )

    return report
