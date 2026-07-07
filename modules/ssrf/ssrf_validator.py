"""
modules/ssrf/ssrf_validator.py
================================
Professional SSRF detection engine for ReconMind Phase 3 by wamiqsec.

THIS REPLACES ssrf_tester.py for the timing-based detection.
Direct signature detection (metadata in response body) is kept — it was already reliable.

THE OLD TIMING PROBLEM:
────────────────────────────────────────────────────────────────
    baseline_time = measure_once()
    probe_time    = measure_once()
    if probe_time - baseline_time > 2.0:
        report_ssrf()

Problems:
    1. Network jitter makes single measurements unreliable
    2. Server load spikes affect timing randomly
    3. A 2s absolute threshold doesn't account for slow baselines
    4. No statistical validation

Example false positive:
    baseline: 0.8s (server is fast)
    probe:    3.2s (network had a hiccup)
    delta:    2.4s → reports SSRF
    Reality:  Network jitter. No SSRF.

THE NEW APPROACH:
────────────────────────────────────────────────────────────────
    baseline_times = [measure() for _ in range(3)]  # 3 samples
    probe_times    = [measure() for _ in range(3)]  # 3 samples

    baseline_median = median(baseline_times)
    probe_median    = median(probe_times)
    delta           = probe_median - baseline_median

    # Statistical threshold: probe must be consistently slow,
    # not just randomly slow once
    baseline_stddev = stdev(baseline_times)
    threshold = baseline_median + max(2.0, 3 * baseline_stddev)

    if probe_median > threshold AND stddev(probe_times) < 1.5:
        # Probe is consistently slow AND baseline is stable
        # Calculate confidence based on delta magnitude
        confidence = ...
    else:
        suppress()

Additionally: we test timing against an INVALID IP (not just a valid internal IP).
If the delay only appears with valid internal IPs and NOT with invalid ones,
that's much stronger evidence of SSRF than a delay alone.
"""

import time
import statistics
from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Dict
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

from core.recon.url_handler import URLTarget
from core.extractor.param_extractor import Parameter, ParamType
from core.utils.http_client import safe_get, safe_post
from core.intelligence.baseline_calibrator import BaselineProfile
from core.intelligence.confidence_engine import (
    create_bundle, mark_signal, calculate_confidence, EvidenceBundle,
)
from core.payloads.ssrf_payloads import (
    get_all_metadata_targets, get_all_signatures,
    LOCALHOST_BYPASSES,
)
from config.settings import CONFIG
from core.utils.logger import get_logger

log = get_logger(__name__)

# Number of timing samples for statistical reliability
TIMING_SAMPLES = 3

# RFC 5737 TEST-NET — never routes anywhere. Used as negative control for timing.
INVALID_IP_CONTROL = "http://192.0.2.1:80"

# Timing threshold multiplier: probe must exceed baseline by this factor
TIMING_FACTOR_THRESHOLD = 2.5

# Maximum acceptable stddev in probe timings (if too variable, results are unreliable)
MAX_PROBE_TIMING_STDDEV = 2.0


@dataclass
class TimingProfile:
    """Statistical timing measurements for a single probe."""
    samples: List[float] = field(default_factory=list)
    median: float = 0.0
    mean: float = 0.0
    stddev: float = 0.0
    min_time: float = 0.0
    max_time: float = 0.0
    is_consistent: bool = False  # True if stddev is low relative to median

    def compute(self) -> None:
        """Calculate all statistics from samples."""
        if not self.samples:
            return
        self.median = statistics.median(self.samples)
        self.mean = statistics.mean(self.samples)
        self.stddev = statistics.stdev(self.samples) if len(self.samples) > 1 else 0.0
        self.min_time = min(self.samples)
        self.max_time = max(self.samples)
        # Consistent = stddev is less than 40% of median
        self.is_consistent = (
            self.median > 0
            and (self.stddev / self.median) < 0.40
        ) if self.median > 0 else True


@dataclass
class SSRFResult:
    """
    Professional SSRF finding with full evidence chain.

    Replaces old SSRFFinding for Phase 3.
    """
    url: str
    parameter: str
    param_type: str
    injected_target: str
    detection_method: str  # "direct", "time-based", "time-based-control-confirmed"

    bundle: Optional[EvidenceBundle] = None
    baseline_timing: Optional[TimingProfile] = None
    probe_timing: Optional[TimingProfile] = None
    control_timing: Optional[TimingProfile] = None

    confidence: float = 0.0
    severity: str = "INFO"
    suppressed: bool = True
    evidence: str = ""
    notes: List[str] = field(default_factory=list)

    # For reporting compatibility
    response_code: int = 0
    response_size: int = 0


# ─────────────────────────────────────────────────────────────────────────────
# Helper functions
# ─────────────────────────────────────────────────────────────────────────────

def _build_probe_url(target: URLTarget, param: Parameter, payload: str) -> str:
    """Build GET probe URL with SSRF payload injected."""
    parsed = urlparse(target.normalized)
    qp = parse_qs(parsed.query, keep_blank_values=True)
    qp[param.name] = [payload]
    new_query = urlencode({k: v[0] for k, v in qp.items()})
    return urlunparse(parsed._replace(query=new_query))


def _timed_request(
    target: URLTarget,
    param: Parameter,
    payload: str,
) -> Tuple[float, Optional[object]]:
    """Execute a single timed request. Returns (elapsed_seconds, response)."""
    start = time.perf_counter()  # Higher precision than time.time()

    if param.param_type == ParamType.GET:
        url = _build_probe_url(target, param, payload)
        response = safe_get(url, allow_redirects=False)
    else:
        post_url = param.form_action or target.base_url()
        response = safe_post(
            post_url,
            data={param.name: payload},
            allow_redirects=False,
        )

    elapsed = time.perf_counter() - start
    return elapsed, response


def _collect_timing_samples(
    target: URLTarget,
    param: Parameter,
    payload: str,
    n: int = TIMING_SAMPLES,
) -> TimingProfile:
    """
    Collect N timing samples for a given payload.

    Args:
        target:  URLTarget.
        param:   Parameter to inject into.
        payload: Value to inject.
        n:       Number of samples.

    Returns:
        TimingProfile with all measurements.
    """
    profile = TimingProfile()
    for i in range(n):
        elapsed, _ = _timed_request(target, param, payload)
        profile.samples.append(elapsed)
        if i < n - 1:
            time.sleep(0.5)  # Cooldown between timing samples

    profile.compute()
    return profile


def _detect_direct_ssrf(response, target_url: str) -> Tuple[bool, str]:
    """
    Check if the response contains signatures of a fetched internal resource.

    Args:
        response:   HTTP response object.
        target_url: The internal URL we injected.

    Returns:
        (confirmed: bool, evidence_snippet: str)
    """
    if response is None:
        return False, ""

    all_signatures = get_all_signatures()
    response_text = response.text

    # Check target-specific signatures first
    target_sigs = all_signatures.get(target_url, [])
    for sig in target_sigs:
        if sig in response_text:
            idx = response_text.find(sig)
            start = max(0, idx - 30)
            end = min(len(response_text), idx + len(sig) + 100)
            snippet = response_text[start:end].replace("\n", "↵")
            return True, f"Signature '{sig}' found: {snippet}"

    # Generic cloud metadata signals
    generic_signals = [
        "ami-id", "instance-id", "computeMetadata", "subscriptionId",
        "access_token", "token_type", "serviceAccounts",
        "YOU KNOW, FOR SEARCH",  # Elasticsearch
        "redis_version",          # Redis
        "Containers",             # Docker
        "apiVersion",             # Kubernetes
    ]
    for sig in generic_signals:
        if sig in response_text:
            idx = response_text.find(sig)
            start = max(0, idx - 20)
            end = min(len(response_text), idx + len(sig) + 80)
            snippet = response_text[start:end].replace("\n", "↵")
            return True, f"Cloud/service signature '{sig}' found: {snippet}"

    return False, ""


def _timing_is_anomalous(
    baseline: TimingProfile,
    probe: TimingProfile,
) -> Tuple[bool, str, float]:
    """
    Statistically determine if probe timing is anomalously high.

    Args:
        baseline: Timing profile for normal requests.
        probe:    Timing profile for SSRF payload requests.

    Returns:
        (is_anomalous: bool, explanation: str, confidence: float)
    """
    if not baseline.samples or not probe.samples:
        return False, "Insufficient timing data", 0.0

    delta = probe.median - baseline.median

    # Threshold: baseline median + 3x stddev (or 2.0s minimum)
    threshold = baseline.median + max(2.0, 3 * baseline.stddev)

    if probe.median < threshold:
        return (
            False,
            f"Probe median ({probe.median:.2f}s) below threshold ({threshold:.2f}s)",
            0.0,
        )

    if not probe.is_consistent:
        return (
            False,
            f"Probe timing inconsistent (stddev={probe.stddev:.2f}s) — likely network jitter",
            0.0,
        )

    # Calculate confidence based on how far probe exceeds threshold
    ratio = probe.median / baseline.median if baseline.median > 0 else float('inf')

    if ratio >= 5.0:
        confidence = 0.65
    elif ratio >= TIMING_FACTOR_THRESHOLD:
        confidence = 0.50
    else:
        confidence = 0.30

    explanation = (
        f"Probe median {probe.median:.2f}s vs baseline {baseline.median:.2f}s "
        f"(factor: {ratio:.1f}x, delta: {delta:.2f}s)"
    )

    return True, explanation, confidence


# ─────────────────────────────────────────────────────────────────────────────
# SSRF candidate detection
# ─────────────────────────────────────────────────────────────────────────────

SSRF_PARAM_NAME_HINTS = {
    "url", "uri", "src", "source", "href", "link", "path",
    "file", "fetch", "load", "proxy", "request", "host",
    "endpoint", "service", "api", "target", "domain", "ip",
    "callback", "ping", "webhook", "notify", "from", "to",
    "dest", "redirect", "image", "img", "resource",
}


def _is_ssrf_candidate(param: Parameter) -> bool:
    """Return True if this parameter might accept URLs (SSRF candidate)."""
    name_lower = param.name.lower()

    if name_lower in SSRF_PARAM_NAME_HINTS:
        return True

    for hint in ["url", "uri", "src", "host", "domain", "server",
                 "proxy", "request", "fetch", "load", "api", "endpoint"]:
        if hint in name_lower:
            return True

    val = param.value.lower()
    if val.startswith(("http://", "https://", "//", "ftp://")):
        return True

    import re
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', param.value):
        return True

    return False


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def run_ssrf_validation(target: URLTarget) -> List[SSRFResult]:
    """
    Run professional SSRF validation with statistical timing analysis.

    Phase 3 improvements over Phase 2:
        - Statistical timing (3 samples, median comparison)
        - Control probe (invalid IP timing as negative control)
        - Confidence scoring via EvidenceBundle
        - Suppression of noisy network false positives

    Args:
        target: URLTarget with .parameters populated by Phase 1.

    Returns:
        List of SSRFResult objects (includes suppressed for transparency).
    """
    parameters: List[Parameter] = getattr(target, "parameters", [])
    candidates = [p for p in parameters if _is_ssrf_candidate(p)]

    if not candidates:
        log.info("No SSRF candidates on %s", target.normalized)
        return []

    log.info(
        "SSRF validation: %s — %d candidate(s): %s",
        target.normalized, len(candidates), [p.name for p in candidates],
    )

    all_results: List[SSRFResult] = []
    metadata_targets = get_all_metadata_targets()

    for param in candidates:
        log.info("  SSRF testing: param=%r", param.name)

        # ── Step 1: Direct detection (metadata/service signatures) ─────────
        for meta_target in metadata_targets:
            internal_url = meta_target["url"]

            if param.param_type == ParamType.GET:
                probe_url = _build_probe_url(target, param, internal_url)
                response = safe_get(probe_url, allow_redirects=False)
            else:
                post_url = param.form_action or target.base_url()
                response = safe_post(
                    post_url,
                    data={param.name: internal_url},
                    allow_redirects=False,
                )
                probe_url = post_url

            time.sleep(0.25)

            if response is None:
                continue

            direct_confirmed, evidence = _detect_direct_ssrf(response, internal_url)

            if direct_confirmed:
                bundle = create_bundle(
                    module="SSRF",
                    url=probe_url,
                    parameter=param.name,
                    param_type=param.param_type,
                )
                mark_signal(bundle, "metadata_signature_direct",
                            f"{meta_target['provider']} signature confirmed: {evidence}")
                bundle = calculate_confidence(bundle)

                result = SSRFResult(
                    url=probe_url,
                    parameter=param.name,
                    param_type=param.param_type,
                    injected_target=internal_url,
                    detection_method="direct",
                    bundle=bundle,
                    confidence=bundle.combined_confidence,
                    severity=bundle.severity,
                    suppressed=bundle.suppressed,
                    evidence=evidence,
                    response_code=response.status_code,
                    response_size=len(response.content),
                )
                result.notes.append(
                    f"{meta_target['provider']} metadata accessible — "
                    "extract IAM credentials via /iam/security-credentials/"
                )
                result.notes.append(
                    "DO NOT extract actual credentials — document and report"
                )
                all_results.append(result)

                log.info(
                    "  [SSRF DIRECT CONFIRMED] param=%r target=%r confidence=%.0f%%",
                    param.name, internal_url, bundle.combined_confidence * 100,
                )
                break  # Found direct SSRF — no need to test more targets

        # ── Step 2: Statistical timing detection ───────────────────────────
        # Only run timing if direct detection didn't find anything
        if not any(r.parameter == param.name and r.detection_method == "direct"
                   for r in all_results):

            log.debug("  Running statistical timing SSRF for param=%r", param.name)

            # Baseline timing (3 samples with original value)
            baseline_timing = _collect_timing_samples(
                target, param, param.value, n=TIMING_SAMPLES
            )
            time.sleep(0.5)

            # Probe timing (3 samples with internal IP)
            probe_payload = "http://169.254.169.254/latest/meta-data/"
            probe_timing = _collect_timing_samples(
                target, param, probe_payload, n=TIMING_SAMPLES
            )
            time.sleep(0.5)

            # Control timing (3 samples with INVALID IP — negative control)
            control_timing = _collect_timing_samples(
                target, param, INVALID_IP_CONTROL, n=TIMING_SAMPLES
            )

            # Statistical analysis
            timing_anomalous, timing_explanation, timing_confidence = _timing_is_anomalous(
                baseline_timing, probe_timing
            )

            if timing_anomalous:
                bundle = create_bundle(
                    module="SSRF",
                    url=_build_probe_url(target, param, probe_payload),
                    parameter=param.name,
                    param_type=param.param_type,
                )

                mark_signal(bundle, "timing_delay_consistent",
                            timing_explanation)

                # Bonus: if control timing is FAST but probe is SLOW,
                # the delay is IP-specific (stronger SSRF signal)
                control_anomalous, _, _ = _timing_is_anomalous(
                    baseline_timing, control_timing
                )
                if not control_anomalous:
                    mark_signal(bundle, "timing_delay_ip_specific",
                                f"Invalid IP control timing: {control_timing.median:.2f}s "
                                f"(no delay — delay is target-IP-specific)")

                # Apply suppressor if baseline is noisy
                if baseline_timing.stddev > 1.0:
                    mark_signal(bundle, "high_timing_variance_baseline",
                                f"Baseline stddev: {baseline_timing.stddev:.2f}s (noisy network)")

                bundle = calculate_confidence(bundle)

                detection_method = (
                    "time-based-control-confirmed"
                    if not control_anomalous
                    else "time-based"
                )

                result = SSRFResult(
                    url=_build_probe_url(target, param, probe_payload),
                    parameter=param.name,
                    param_type=param.param_type,
                    injected_target=probe_payload,
                    detection_method=detection_method,
                    bundle=bundle,
                    baseline_timing=baseline_timing,
                    probe_timing=probe_timing,
                    control_timing=control_timing,
                    confidence=bundle.combined_confidence,
                    severity=bundle.severity,
                    suppressed=bundle.suppressed,
                    evidence=timing_explanation,
                )
                result.notes.append(
                    "Timing-based SSRF requires OOB confirmation (Burp Collaborator)"
                )
                result.notes.append(
                    f"Baseline: {baseline_timing.median:.2f}s | "
                    f"Probe: {probe_timing.median:.2f}s | "
                    f"Control: {control_timing.median:.2f}s"
                )
                all_results.append(result)

                log.info(
                    "  [SSRF TIMING] param=%r confidence=%.0f%% suppressed=%s",
                    param.name, bundle.combined_confidence * 100, bundle.suppressed,
                )

    reportable = [r for r in all_results if not r.suppressed]
    log.info(
        "SSRF validation complete: %d reportable / %d total",
        len(reportable), len(all_results),
    )

    setattr(target, "ssrf_results", all_results)
    return all_results
