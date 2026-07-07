"""
core/modes/active_mode.py
===========================
Active Validation Mode orchestrator for ReconMind Phase 4 by wamiqsec.

WHAT ACTIVE MODE IS:
────────────────────────────────────────────────────────────────
Active mode is the intelligent testing layer. Unlike passive mode
which only observes, active mode injects payloads — but with
significantly more intelligence than Phase 2:

    1. Uses response classification to skip modules on wrong page types
    2. Uses baseline calibration before any injection
    3. Uses the new context engine for XSS (not the old regex approach)
    4. Uses statistical timing for SSRF (not single-sample)
    5. Uses semantic similarity for IDOR (not size diff)
    6. Uses multi-stage validation before promoting findings
    7. Uses confidence thresholds to suppress low-signal results
    8. Includes CSRF testing
    9. Includes SQLi with three-technique validation

PROGRESSIVE VALIDATION:
    Each finding goes through validation stages:
    Stage 1: Detection (passive signal)
    Stage 2: Confirmation (active probe)
    Stage 3: Exploitation test (controlled)

    A finding only promotes to "REPORTABLE" after passing
    the configured number of stages (CONFIG.active.validation_stages).

MODULE SELECTION BY PAGE TYPE:
    The response classifier tells us what each page does.
    We only run modules appropriate for that page type.

    ADMIN page    → all modules, high aggressiveness
    AUTH page     → XSS, SQLi, CSRF
    API endpoint  → IDOR, SQLi, SSRF
    SEARCH page   → XSS (with search-aware suppressor), SQLi
    UPLOAD page   → LFI, SSRF
    PUBLIC page   → XSS only (light)
    REDIRECT page → Redirect, SSRF

NOISE REDUCTION SUMMARY:
    - Classification-based module skipping
    - Confidence threshold suppression
    - Baseline calibration before all diff-based tests
    - Statistical timing (3 samples) for SSRF
    - Semantic similarity (not size diff) for IDOR
    - Parser-aware context detection for XSS
    - Breakout analysis before XSS payload firing
"""

import time
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any

from core.recon.url_handler import URLTarget
from core.extractor.param_extractor import extract_parameters
from core.engines.response.response_classifier import (
    classify_response, ResponseClassification, PageType,
)
from core.engines.xss.xss_context_engine import analyze_xss_context
from modules.reflection.reflection_engine import run_reflection_probes, ReflectionResult
from modules.idor.idor_validator import run_idor_validation, IDORResult
from modules.ssrf.ssrf_validator import run_ssrf_validation, SSRFResult
from modules.sqli.sqli_validator import run_sqli_validation, SQLiResult
from modules.lfi.lfi_tester import run_lfi_tests, LFIFinding
from modules.redirects.redirect_tester import run_redirect_tests, RedirectFinding
from modules.csrf.csrf_validator import run_csrf_validation, CSRFResult
from modules.xss.xss_tester import run_xss_tests, XSSFinding
from config.settings import CONFIG
from core.utils.logger import get_logger

log = get_logger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Data model
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ActiveScanResult:
    """
    Complete active scan result for a single URLTarget.

    Aggregates findings from all modules with classification context.
    """
    url: str
    classification: Optional[ResponseClassification] = None

    # Phase 3 module results (high confidence, intelligence-backed)
    idor_results: List[IDORResult] = field(default_factory=list)
    ssrf_results: List[SSRFResult] = field(default_factory=list)
    sqli_results: List[SQLiResult] = field(default_factory=list)
    csrf_results: List[CSRFResult] = field(default_factory=list)

    # Phase 2 module results (kept for compatibility)
    xss_findings: List[XSSFinding] = field(default_factory=list)
    lfi_findings: List[LFIFinding] = field(default_factory=list)
    redirect_findings: List[RedirectFinding] = field(default_factory=list)

    # Summary
    total_reportable: int = 0
    total_suppressed: int = 0
    modules_run: List[str] = field(default_factory=list)
    modules_skipped: List[str] = field(default_factory=list)
    scan_duration: float = 0.0

    @property
    def all_reportable(self) -> List[Any]:
        """Return all non-suppressed findings across all modules."""
        findings = []
        findings.extend([r for r in self.idor_results if not r.suppressed])
        findings.extend([r for r in self.ssrf_results if not r.suppressed])
        findings.extend([r for r in self.sqli_results if not r.suppressed])
        findings.extend([r for r in self.csrf_results if not r.suppressed])
        findings.extend(self.xss_findings)
        findings.extend(self.lfi_findings)
        findings.extend(self.redirect_findings)
        return findings


# ─────────────────────────────────────────────────────────────────────────────
# Module gating based on classification
# ─────────────────────────────────────────────────────────────────────────────

def _should_run_module(
    module_name: str,
    classification: ResponseClassification,
    args_skip: Dict[str, bool],
) -> tuple:
    """
    Determine whether a module should run on this target.

    Args:
        module_name:     Module identifier (e.g. "IDOR", "XSS").
        classification:  Response classification result.
        args_skip:       Dict of user-supplied --skip-* flags.

    Returns:
        (should_run: bool, reason: str)
    """
    # User explicitly skipped this module
    skip_flag = f"skip_{module_name.lower()}"
    if args_skip.get(skip_flag, False):
        return False, f"--skip-{module_name.lower()} flag set"

    # Classification says this module is suppressed for this page type
    if module_name in classification.suppressed_modules:
        return False, f"Module suppressed for {classification.page_type} page type"

    # If classification has recommended modules, only run those
    # (unless recommended_modules is empty = run all)
    if (
        classification.recommended_modules
        and module_name not in classification.recommended_modules
    ):
        # Don't hard-suppress, just deprioritize with a warning
        # (some modules are relevant across page types)
        return True, f"Running despite not being priority for {classification.page_type}"

    return True, "Module applicable for this target"


# ─────────────────────────────────────────────────────────────────────────────
# Core active pipeline per target
# ─────────────────────────────────────────────────────────────────────────────

def _run_active_on_target(
    target: URLTarget,
    args_skip: Dict[str, bool],
    phase1_only: bool = False,
) -> ActiveScanResult:
    """
    Run full active validation pipeline on a single URLTarget.

    Pipeline:
        1. Fetch page + classify response type
        2. Extract parameters (if not already done)
        3. Gate modules based on classification
        4. Run applicable modules with Phase 3 validators
        5. Aggregate results

    Args:
        target:      URLTarget to scan.
        args_skip:   Dict of skip flags from CLI args.
        phase1_only: If True, stop after reflection analysis.

    Returns:
        ActiveScanResult with all findings.
    """
    start = time.time()
    result = ActiveScanResult(url=target.normalized)

    # ── Step 1: Fetch and classify ────────────────────────────────────────
    baseline_response = getattr(target, "baseline_response", None)
    if baseline_response is None:
        from core.utils.http_client import safe_get
        baseline_response = safe_get(target.normalized)
        if baseline_response:
            setattr(target, "baseline_response", baseline_response)
            setattr(target, "http_status", baseline_response.status_code)

    if baseline_response is None:
        log.warning("Could not fetch %s — skipping active scan", target.normalized)
        return result

    html_body = baseline_response.text
    resp_headers = dict(baseline_response.headers)
    content_type = baseline_response.headers.get("Content-Type", "")

    classification = classify_response(
        url=target.normalized,
        html=html_body,
        status_code=baseline_response.status_code,
        content_type=content_type,
        response_headers=resp_headers,
    )
    result.classification = classification

    log.info(
        "Active scan: %s [%s] aggressiveness=%.1f",
        target.normalized, classification.page_type, classification.aggressiveness,
    )

    # ── Step 2: Parameter extraction ──────────────────────────────────────
    params = getattr(target, "parameters", None)
    if params is None:
        target = extract_parameters(target)
        params = getattr(target, "parameters", [])

    if not params:
        log.info("No parameters — skipping active scan for %s", target.normalized)
        return result

    log.info("  Parameters: %d found", len(params))

    # ── Step 3: Phase 1 reflection (always runs) ──────────────────────────
    reflection_results = run_reflection_probes(target)
    reflected = [r for r in reflection_results if r.reflected]
    setattr(target, "reflection_results", reflection_results)

    # ── Step 4: Context analysis for XSS (Phase 4 engine) ─────────────────
    xss_context_analyses = []
    if reflected:
        log.info("  Reflection: %d/%d params reflect", len(reflected), len(params))
        from core.analyzer.context_analyzer import analyze_all_reflections
        ctx_analyses = analyze_all_reflections(reflection_results, html_body)
        setattr(target, "context_analyses", ctx_analyses)

        # Run new parser-aware context engine for each reflected param
        for reflection in reflected:
            ctx_result = analyze_xss_context(
                target=target,
                param=reflection.parameter,
                reflection_response=html_body,
                marker=reflection.marker,
            )
            xss_context_analyses.append(ctx_result)
    else:
        log.info("  No reflections detected")

    if phase1_only:
        result.scan_duration = time.time() - start
        return result

    # ── Step 5: Module execution (gated by classification) ────────────────

    # XSS — only if reflections found AND context is exploitable
    exploitable_xss = [ctx for ctx in xss_context_analyses if ctx.is_exploitable]
    run_xss, reason = _should_run_module("XSS", classification, args_skip)
    if run_xss and exploitable_xss:
        log.info("  Running XSS tests (%d exploitable contexts)", len(exploitable_xss))
        result.xss_findings = run_xss_tests(target)
        result.modules_run.append("XSS")
    elif not run_xss:
        result.modules_skipped.append(f"XSS ({reason})")
    else:
        result.modules_skipped.append("XSS (no exploitable reflection contexts)")

    # IDOR — Phase 3 validator (semantic similarity + auth detection)
    run_idor, reason = _should_run_module("IDOR", classification, args_skip)
    numeric_params = [p for p in params if p.value.isdigit()]
    if run_idor and numeric_params:
        log.info("  Running IDOR validation (%d numeric params)", len(numeric_params))
        result.idor_results = run_idor_validation(target)
        result.modules_run.append("IDOR")
    elif not run_idor:
        result.modules_skipped.append(f"IDOR ({reason})")
    else:
        result.modules_skipped.append("IDOR (no numeric parameters)")

    # SSRF — Phase 3 validator (statistical timing)
    run_ssrf, reason = _should_run_module("SSRF", classification, args_skip)
    if run_ssrf:
        log.info("  Running SSRF validation")
        result.ssrf_results = run_ssrf_validation(target)
        result.modules_run.append("SSRF")
    else:
        result.modules_skipped.append(f"SSRF ({reason})")

    # SQLi — Phase 3 three-technique validator
    run_sqli, reason = _should_run_module("SQLI", classification, args_skip)
    if run_sqli:
        log.info("  Running SQLi validation")
        result.sqli_results = run_sqli_validation(target)
        result.modules_run.append("SQLi")
    else:
        result.modules_skipped.append(f"SQLi ({reason})")

    # LFI
    run_lfi, reason = _should_run_module("LFI", classification, args_skip)
    if run_lfi:
        log.info("  Running LFI tests")
        result.lfi_findings = run_lfi_tests(target)
        result.modules_run.append("LFI")
    else:
        result.modules_skipped.append(f"LFI ({reason})")

    # Redirects
    run_redir, reason = _should_run_module("REDIRECT", classification, args_skip)
    if run_redir:
        log.info("  Running redirect tests")
        result.redirect_findings = run_redirect_tests(target)
        result.modules_run.append("REDIRECT")
    else:
        result.modules_skipped.append(f"REDIRECT ({reason})")

    # CSRF — runs on forms, AUTH and FORM page types
    run_csrf, reason = _should_run_module("CSRF", classification, args_skip)
    if run_csrf and classification.page_type in (PageType.AUTH, PageType.FORM, PageType.DASHBOARD, PageType.ADMIN, PageType.PROFILE):
        log.info("  Running CSRF validation")
        result.csrf_results = run_csrf_validation(target)
        result.modules_run.append("CSRF")
    elif run_csrf:
        result.modules_skipped.append("CSRF (page type doesn't have state-changing forms)")
    else:
        result.modules_skipped.append(f"CSRF ({reason})")

    # ── Summarize ──────────────────────────────────────────────────────────
    all_findings = result.all_reportable
    result.total_reportable = len(all_findings)

    # Count suppressions
    result.total_suppressed = (
        len([r for r in result.idor_results if r.suppressed]) +
        len([r for r in result.ssrf_results if r.suppressed]) +
        len([r for r in result.sqli_results if r.suppressed]) +
        len([r for r in result.csrf_results if r.suppressed])
    )

    result.scan_duration = time.time() - start

    log.info(
        "Active scan complete: %s — %d reportable | %d suppressed | modules: %s",
        target.normalized,
        result.total_reportable,
        result.total_suppressed,
        ", ".join(result.modules_run),
    )

    if result.modules_skipped:
        log.debug("  Skipped: %s", "; ".join(result.modules_skipped))

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def run_active_mode(
    targets: List[URLTarget],
    args_skip: Optional[Dict[str, bool]] = None,
    phase1_only: bool = False,
) -> List[ActiveScanResult]:
    """
    Run Active Validation Mode on a list of URLTargets.

    This is the main entry point called by main.py when
    --mode active is set (or no mode is specified, defaulting to active).

    Args:
        targets:     List of URLTarget objects to actively test.
        args_skip:   Dict of skip flags: {"skip_xss": True, ...}.
        phase1_only: If True, only run reflection analysis.

    Returns:
        List of ActiveScanResult objects, one per target.
    """
    args_skip = args_skip or {}

    log.info(
        "=== ACTIVE VALIDATION MODE === %d targets | phase1_only=%s",
        len(targets), phase1_only,
    )

    all_results: List[ActiveScanResult] = []

    for i, target in enumerate(targets, 1):
        log.info("[%d/%d] Active scan: %s", i, len(targets), target.normalized)

        try:
            result = _run_active_on_target(target, args_skip, phase1_only)
            all_results.append(result)
        except KeyboardInterrupt:
            log.warning("Active scan interrupted after %d targets", i - 1)
            break
        except Exception as exc:
            log.error("Error on %s: %s", target.normalized, exc, exc_info=True)
            all_results.append(ActiveScanResult(url=target.normalized))

    total_reportable = sum(r.total_reportable for r in all_results)
    total_suppressed = sum(r.total_suppressed for r in all_results)

    log.info(
        "=== ACTIVE MODE COMPLETE === %d targets | %d reportable | %d suppressed",
        len(all_results), total_reportable, total_suppressed,
    )

    if total_suppressed > 0:
        reduction_pct = total_suppressed / max(1, total_suppressed + total_reportable) * 100
        log.info(
            "False positive reduction: %.0f%% of findings suppressed by intelligence pipeline",
            reduction_pct,
        )

    return all_results
