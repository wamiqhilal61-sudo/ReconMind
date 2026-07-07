"""
modules/idor/idor_validator.py
================================
Professional IDOR detection engine for ReconMind Phase 3 by wamiqsec.

THIS REPLACES idor_tester.py

THE OLD APPROACH (WHAT WAS WRONG):
────────────────────────────────────────────────────────────────
    for each numeric param:
        fetch id=N (baseline)
        fetch id=N+1 (probe)
        if size_diff > 50:
            report_idor()

This flagged /post?id=1 vs /post?id=2 on every blog on the internet.
Every CMS, every news site, every e-commerce listing was a false positive.

THE NEW APPROACH (WHAT WE BUILT):
────────────────────────────────────────────────────────────────
    for each numeric param:

        STEP 1: Baseline Calibration
            Make 3 requests with the SAME id to learn natural variance.
            Know what "normal" looks like before comparing anything.

        STEP 2: Auth Context Detection
            Is this session authenticated?
            What is our own user ID?
            Does this endpoint require auth?

        STEP 3: Oracle Probing
            What does id=0 return? id=-1? id=999999999?
            This tells us if the server validates IDs at all.

        STEP 4: Intelligent Probing
            Fetch adjacent IDs.
            Normalize both responses (strip CSRF, timestamps, etc.)
            Compute semantic similarity (not just size diff).
            Detect PII patterns in the probe response.
            Classify semantic field of probe response.

        STEP 5: Confidence Scoring
            Each observation triggers an evidence signal.
            Public endpoint? → Apply suppressor (reduce confidence).
            High natural variance? → Apply suppressor.
            PII found? → Strong positive signal.
            Semantic field changed? → Moderate positive signal.

        STEP 6: Decision
            confidence >= 0.65: Report with manual verify note.
            confidence >= 0.85: Report as HIGH.
            confidence < 0.45: Suppress entirely.

RESULT: /post?id=1 vs /post?id=2:
    - No auth detected → suppressor applied
    - Semantic field: both "public_content" → suppressor applied
    - No PII found → no positive signal
    - Confidence: 0.12 → SUPPRESSED ✓ (correct — not a bug)

RESULT: /api/user?id=1234 vs /api/user?id=1235:
    - Auth detected (session cookie present)
    - Endpoint requires auth (oracle: id=0 → 403)
    - Semantic field: both "user_data" (suspicious)
    - Email pattern found in probe (strong positive signal)
    - Confidence: 0.78 → MEDIUM (needs manual verify) ✓ (correct)
"""

import time
from dataclasses import dataclass, field
from typing import List, Optional, Dict
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

from core.recon.url_handler import URLTarget
from core.extractor.param_extractor import Parameter, ParamType
from core.utils.http_client import safe_get, safe_post
from core.intelligence.baseline_calibrator import calibrate_baseline, BaselineProfile
from core.intelligence.normalizer import normalize_response, NormalizedResponse
from core.intelligence.similarity_engine import compute_similarity, SimilarityReport
from core.intelligence.confidence_engine import (
    create_bundle, mark_signal, calculate_confidence, EvidenceBundle,
)
from core.auth.auth_detector import (
    detect_auth_from_response, probe_endpoint_access,
    AuthContext, EndpointAccessProfile,
)
from config.settings import CONFIG
from core.utils.logger import get_logger

log = get_logger(__name__)


@dataclass
class IDORResult:
    """
    Professional IDOR finding with full evidence chain.

    Replaces the old IDORFinding dataclass.
    Contains everything needed for accurate triage and reporting.
    """
    url: str
    parameter: str
    param_type: str
    original_id: str
    tested_id: str

    # Evidence
    bundle: Optional[EvidenceBundle] = None
    similarity_report: Optional[SimilarityReport] = None
    auth_context: Optional[AuthContext] = None
    endpoint_profile: Optional[EndpointAccessProfile] = None

    # Final assessment
    confidence: float = 0.0
    severity: str = "INFO"
    suppressed: bool = True
    false_positive_risk: str = "HIGH"
    requires_manual_verification: bool = True

    # For reporting compatibility
    notes: List[str] = field(default_factory=list)
    evidence: str = ""

    def to_report_dict(self) -> Dict:
        """Convert to dict for JSON/Markdown reporting."""
        return {
            "module": "IDOR",
            "url": self.url,
            "parameter": self.parameter,
            "original_id": self.original_id,
            "tested_id": self.tested_id,
            "confidence": f"{self.confidence:.0%}",
            "severity": self.severity,
            "suppressed": self.suppressed,
            "false_positive_risk": self.false_positive_risk,
            "requires_manual_verification": self.requires_manual_verification,
            "evidence_chain": self.bundle.full_evidence if self.bundle else [],
            "notes": self.notes,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Core testing logic
# ─────────────────────────────────────────────────────────────────────────────

def _build_probe_url(target: URLTarget, param: Parameter, value: str) -> str:
    """Build a URL with the parameter value replaced."""
    parsed = urlparse(target.normalized)
    qp = parse_qs(parsed.query, keep_blank_values=True)
    qp[param.name] = [value]
    new_query = urlencode({k: v[0] for k, v in qp.items()})
    return urlunparse(parsed._replace(query=new_query))


def _fetch_with_param(
    target: URLTarget,
    param: Parameter,
    value: str,
):
    """Fetch a URL with the specified parameter value. Returns response or None."""
    if param.param_type == ParamType.GET:
        url = _build_probe_url(target, param, value)
        return safe_get(url, allow_redirects=False), url
    else:
        post_url = param.form_action or target.base_url()
        form_data = {param.name: value}
        return safe_post(post_url, data=form_data, allow_redirects=False), post_url


def _is_public_content(similarity: SimilarityReport, baseline_nr: NormalizedResponse) -> bool:
    """
    Heuristic: determine if content differences are explained by
    public paginated content (articles, blog posts, products).

    Args:
        similarity:   Similarity report between baseline and probe.
        baseline_nr:  Normalized baseline response.

    Returns:
        True if differences are likely explained by public content variation.
    """
    # If baseline is public content and probe has no PII, it's probably
    # just different public content
    if (baseline_nr.semantic_field == "public_content"
            and not similarity.pii_introduced
            and not similarity.semantic_field_changed):
        return True

    # If structural similarity is high (same template) but Jaccard is low
    # (different text): typical paginated public content
    if (similarity.structural_similarity >= 0.80
            and similarity.jaccard_similarity < 0.40
            and not similarity.pii_introduced):
        return True

    return False


def _test_single_adjacent_id(
    target: URLTarget,
    param: Parameter,
    test_id: str,
    baseline_nr: NormalizedResponse,
    baseline_profile: BaselineProfile,
    auth_ctx: AuthContext,
    endpoint_profile: EndpointAccessProfile,
) -> Optional[IDORResult]:
    """
    Test a single adjacent ID and produce an IDORResult with full evidence.

    This is the core analysis function called for each ID being tested.

    Args:
        target:           URLTarget.
        param:            Numeric parameter being tested.
        test_id:          Adjacent ID string to test.
        baseline_nr:      Normalized baseline response.
        baseline_profile: Calibrated baseline statistics.
        auth_ctx:         Authentication context.
        endpoint_profile: Endpoint access control profile.

    Returns:
        IDORResult if worth reporting (any confidence), None if clearly not IDOR.
    """
    response, probe_url = _fetch_with_param(target, param, test_id)
    time.sleep(0.15)

    if response is None:
        return None

    probe_status = response.status_code

    # Skip clear error responses
    if probe_status in (500, 502, 503):
        log.debug("  id=%s → HTTP %d (server error) — skipping", test_id, probe_status)
        return None

    # ── Create evidence bundle ─────────────────────────────────────────────
    bundle = create_bundle(
        module="IDOR",
        url=probe_url,
        parameter=param.name,
        param_type=param.param_type,
        summary=f"IDOR test: {param.name}={param.value} → {test_id}",
    )

    # ── Signal: HTTP 200 for adjacent ID ──────────────────────────────────
    if probe_status == 200:
        mark_signal(bundle, "status_200_for_adjacent_id",
                    f"HTTP 200 received for {param.name}={test_id}")
    else:
        # 403/404 for adjacent ID = access control is working
        log.debug("  id=%s → HTTP %d (access control signal)", test_id, probe_status)
        # Still worth creating the result for reporting, but very low confidence
        result = IDORResult(
            url=probe_url,
            parameter=param.name,
            param_type=param.param_type,
            original_id=param.value,
            tested_id=test_id,
            confidence=0.05,
            severity="INFO",
            suppressed=True,
            notes=[f"HTTP {probe_status} for id={test_id} — access control appears functional"],
        )
        return result

    # ── Normalize probe response ───────────────────────────────────────────
    probe_nr = normalize_response(response.text, baseline_profile)

    # ── Compute semantic similarity ────────────────────────────────────────
    similarity = compute_similarity(
        baseline=baseline_nr,
        probe=probe_nr,
        context="IDOR",
        length_tolerance=baseline_profile.length_tolerance,
    )

    # ── Signal: Semantic similarity low ───────────────────────────────────
    if similarity.composite_similarity < 0.50:
        mark_signal(bundle, "semantic_similarity_low",
                    f"Composite similarity: {similarity.composite_similarity:.0%} "
                    f"(Jaccard: {similarity.jaccard_similarity:.0%})")

    # ── Signal: Semantic field changed ────────────────────────────────────
    if similarity.semantic_field_changed:
        mark_signal(bundle, "semantic_field_changed",
                    f"Field: {baseline_nr.semantic_field} → {probe_nr.semantic_field}")

    # ── Signal: PII detected ───────────────────────────────────────────────
    if similarity.pii_introduced:
        mark_signal(bundle, "pii_pattern_detected",
                    f"PII types found in probe: {', '.join(similarity.pii_introduced)}")

    # ── Signal: Nonexistent ID oracle ─────────────────────────────────────
    if endpoint_profile.oracle_confident:
        if endpoint_profile.nonexistent_behavior == 404:
            mark_signal(bundle, "nonexistent_id_returns_404",
                        f"id=0 → HTTP 404 (server validates ID existence)")
        elif endpoint_profile.nonexistent_behavior in (401, 403):
            mark_signal(bundle, "endpoint_requires_auth",
                        f"Unauthenticated probe → HTTP {endpoint_profile.nonexistent_behavior}")

    # ── Signal: Endpoint requires auth ────────────────────────────────────
    if auth_ctx.is_authenticated and endpoint_profile.requires_auth:
        mark_signal(bundle, "endpoint_requires_auth",
                    "Session cookies present + endpoint returns 401/403 without them")

    # ── Apply suppressors ─────────────────────────────────────────────────

    # Suppressor 1: Unauthenticated session on what looks like public content
    if not auth_ctx.is_authenticated:
        mark_signal(bundle, "endpoint_is_public",
                    "No authentication detected in current session")

    # Suppressor 2: High natural variance in baseline
    if baseline_profile.length_variance > 500:
        mark_signal(bundle, "high_natural_variance",
                    f"Baseline length variance: {baseline_profile.length_variance} bytes")

    # Suppressor 3: Public content pattern detected
    if _is_public_content(similarity, baseline_nr):
        mark_signal(bundle, "content_matches_public_pattern",
                    f"Response matches public content pattern "
                    f"(semantic field: {baseline_nr.semantic_field}, no PII)")

    # ── Calculate final confidence ─────────────────────────────────────────
    bundle = calculate_confidence(bundle)

    # ── Build result ───────────────────────────────────────────────────────
    result = IDORResult(
        url=probe_url,
        parameter=param.name,
        param_type=param.param_type,
        original_id=param.value,
        tested_id=test_id,
        bundle=bundle,
        similarity_report=similarity,
        auth_context=auth_ctx,
        endpoint_profile=endpoint_profile,
        confidence=bundle.combined_confidence,
        severity=bundle.severity,
        suppressed=bundle.suppressed,
        false_positive_risk=bundle.false_positive_risk,
        requires_manual_verification=bundle.requires_manual,
        evidence=similarity.interpretation,
    )

    # Build human-readable notes
    if bundle.combined_confidence >= 0.65:
        result.notes.append(
            f"Confidence {bundle.combined_confidence:.0%} — manual verification required"
        )
        result.notes.append(
            "Create two accounts, access Account B's resource with Account A's session"
        )
    if similarity.pii_introduced:
        result.notes.append(
            f"PII types introduced: {', '.join(similarity.pii_introduced)} — escalate priority"
        )

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def run_idor_validation(target: URLTarget) -> List[IDORResult]:
    """
    Run intelligent IDOR validation on all numeric parameters.

    This is the Phase 3 replacement for run_idor_tests().
    Uses the full intelligence pipeline instead of simple size diff.

    Args:
        target: URLTarget with .parameters populated by Phase 1.

    Returns:
        List of IDORResult objects for all tested parameters.
        Suppressed results (low confidence) are still returned but
        marked with suppressed=True so the reporter can filter them.
    """
    cfg = CONFIG.idor
    parameters: List[Parameter] = getattr(target, "parameters", [])

    if not parameters:
        return []

    # Filter to numeric parameters only
    numeric_params = [
        p for p in parameters
        if p.value.isdigit() and int(p.value) > 0
    ]

    if not numeric_params:
        log.info("No numeric parameters on %s — skipping IDOR validation", target.normalized)
        return []

    log.info(
        "Starting IDOR validation on %s — %d numeric param(s)",
        target.normalized, len(numeric_params),
    )

    # ── Detect auth context from baseline response ────────────────────────
    baseline_response = getattr(target, "baseline_response", None)
    auth_ctx = AuthContext()
    if baseline_response is not None:
        auth_ctx = detect_auth_from_response(baseline_response)

    all_results: List[IDORResult] = []

    for param in numeric_params:
        log.info("  IDOR validation: param=%r value=%r", param.name, param.value)

        # ── Step 1: Baseline calibration ──────────────────────────────────
        baseline_profile = calibrate_baseline(target, param, n_samples=3)

        if not baseline_profile.calibration_ok:
            log.warning("  Calibration failed for %r — skipping", param.name)
            continue

        # ── Step 2: Endpoint access profile (oracle test) ─────────────────
        endpoint_profile = probe_endpoint_access(target, param, auth_ctx)

        # ── Step 3: Normalize baseline response ───────────────────────────
        # Use the LAST calibration response as our normalized baseline
        # (or fetch a fresh one if calibration didn't store it)
        fresh_response, _ = _fetch_with_param(target, param, param.value)
        if fresh_response is None:
            log.warning("  Could not fetch baseline for normalization — skipping")
            continue

        baseline_nr = normalize_response(fresh_response.text, baseline_profile)
        time.sleep(0.2)

        # ── Step 4: Test adjacent IDs ─────────────────────────────────────
        original_id = int(param.value)
        adjacent_ids = []
        for i in range(1, cfg.adjacent_id_range + 1):
            if original_id - i > 0:
                adjacent_ids.append(str(original_id - i))
            adjacent_ids.append(str(original_id + i))

        for test_id in adjacent_ids:
            result = _test_single_adjacent_id(
                target=target,
                param=param,
                test_id=test_id,
                baseline_nr=baseline_nr,
                baseline_profile=baseline_profile,
                auth_ctx=auth_ctx,
                endpoint_profile=endpoint_profile,
            )

            if result is None:
                continue

            all_results.append(result)

            # Log based on suppression
            if not result.suppressed:
                log.info(
                    "  [IDOR CANDIDATE] param=%r id=%s→%s confidence=%.0f%% risk=%s",
                    param.name, param.value, test_id,
                    result.confidence * 100, result.false_positive_risk,
                )
            else:
                log.debug(
                    "  [SUPPRESSED] param=%r id=%s→%s confidence=%.0f%%",
                    param.name, param.value, test_id, result.confidence * 100,
                )

    # Summary
    reportable = [r for r in all_results if not r.suppressed]
    suppressed = [r for r in all_results if r.suppressed]

    log.info(
        "IDOR validation complete: %d reportable / %d suppressed (false positive reduction: %.0f%%)",
        len(reportable),
        len(suppressed),
        (len(suppressed) / len(all_results) * 100) if all_results else 0,
    )

    setattr(target, "idor_results", all_results)
    return all_results
