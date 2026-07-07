"""
modules/ssrf/ssrf_tester.py
============================
Server-Side Request Forgery (SSRF) detection engine.

Why this file exists:
    SSRF is a critical vulnerability that lets attackers make the server
    issue HTTP requests to internal infrastructure. This exposes:
        - Cloud metadata services (AWS: 169.254.169.254, GCP, Azure)
        - Internal services behind firewalls (Redis, Elasticsearch, k8s API)
        - Other hosts on the same internal network

    SSRF is notoriously hard to detect because:
        1. Responses aren't always returned to the client (blind SSRF)
        2. The vulnerable parameter might accept URLs indirectly
        3. Many WAFs don't block internal IP probes

Detection strategy (two modes):
    DIRECT:  The server fetches the URL and returns content to us.
             Detected by: response contains cloud metadata signatures,
             or response body changes significantly between baseline
             and probe.

    BLIND:   The server fetches the URL but doesn't echo content.
             Detected by: response time difference (DNS lookup delay),
             or using an out-of-band callback server (e.g. Burp Collaborator).
             Phase 2 implements time-based blind detection.
             Full OOB (out-of-band) detection comes in Phase 3.

Target parameters:
    Any parameter whose name or value suggests it carries a URL, domain,
    or resource locator is a candidate. We also include parameters that
    currently hold IP addresses or numeric port values.
"""

import time
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Tuple
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

from core.recon.url_handler import URLTarget
from core.extractor.param_extractor import Parameter, ParamType
from core.utils.http_client import safe_get, safe_post
from config.settings import CONFIG
from core.utils.logger import get_logger

log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class SSRFFinding:
    """
    Evidence record for a confirmed or probable SSRF vulnerability.

    Attributes:
        url:               Probe URL used.
        parameter:         Vulnerable parameter name.
        injected_target:   Internal URL we injected.
        evidence:          Response content snippet or timing data.
        detection_method:  'direct' | 'time-based' | 'blind'.
        response_code:     HTTP status code of probe response.
        response_size:     Response body size (for diffing).
        severity:          CRITICAL for confirmed, HIGH for probable.
        notes:             Chaining opportunities and next steps.
    """

    url: str
    parameter: str
    injected_target: str
    evidence: str
    detection_method: str
    response_code: int = 200
    response_size: int = 0
    severity: str = "HIGH"
    notes: List[str] = field(default_factory=list)

    def __repr__(self) -> str:
        return (
            f"SSRFFinding([{self.severity}] param={self.parameter!r} "
            f"→ {self.injected_target!r} via {self.detection_method})"
        )


# ---------------------------------------------------------------------------
# Parameter candidate detection
# ---------------------------------------------------------------------------

SSRF_PARAM_NAME_HINTS = {
    "url", "uri", "src", "source", "href", "link", "path",
    "file", "fetch", "load", "proxy", "request", "host",
    "endpoint", "service", "api", "target", "domain", "ip",
    "callback", "ping", "webhook", "notify", "from", "to",
    "dest", "redirect", "image", "img", "resource",
}


def _is_ssrf_candidate(param: Parameter) -> bool:
    """Return True if this parameter is a candidate for SSRF testing."""
    name_lower = param.name.lower()

    if name_lower in SSRF_PARAM_NAME_HINTS:
        return True

    for hint in ["url", "uri", "src", "host", "domain", "server", "path",
                 "proxy", "request", "fetch", "load", "api", "endpoint"]:
        if hint in name_lower:
            return True

    # Value looks like a URL
    val = param.value.lower()
    if val.startswith(("http://", "https://", "//", "ftp://")):
        return True

    # Value is an IP address (might be passed as host param)
    import re
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', param.value):
        return True

    return False


# ---------------------------------------------------------------------------
# Detection helpers
# ---------------------------------------------------------------------------

def _detect_metadata_content(response_text: str) -> Optional[str]:
    """
    Check if the response contains cloud metadata service signatures.

    These strings are highly specific — if they appear in the response
    body, we have confirmed SSRF to a metadata endpoint.

    Args:
        response_text: HTTP response body.

    Returns:
        Evidence snippet if detected, None otherwise.
    """
    cfg = CONFIG.ssrf

    for sig in cfg.success_signatures:
        if sig in response_text:
            idx = response_text.find(sig)
            start = max(0, idx - 30)
            end = min(len(response_text), idx + len(sig) + 100)
            return response_text[start:end].replace("\n", "↵")

    return None


def _measure_response_time(url: str, param: Parameter, payload: str) -> Tuple[float, Optional[object]]:
    """
    Measure how long a request takes when an SSRF payload is injected.

    For blind SSRF, the server making a DNS lookup or TCP connection to
    an internal host causes a measurable delay compared to the baseline.

    Args:
        url:     Probe URL (GET) or post target URL.
        param:   Parameter being tested.
        payload: SSRF payload to inject.

    Returns:
        (elapsed_seconds: float, response_or_None)
    """
    start = time.time()

    if param.param_type == ParamType.GET:
        response = safe_get(url, allow_redirects=False)
    else:
        post_url = url
        response = safe_post(post_url, data={param.name: payload}, allow_redirects=False)

    elapsed = time.time() - start
    return elapsed, response


def _build_probe_url(target: URLTarget, param: Parameter, payload: str) -> str:
    """Build GET probe URL with SSRF payload injected."""
    parsed = urlparse(target.normalized)
    qp = parse_qs(parsed.query, keep_blank_values=True)
    qp[param.name] = [payload]
    new_query = urlencode({k: v[0] for k, v in qp.items()})
    return urlunparse(parsed._replace(query=new_query))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_ssrf_tests(target: URLTarget) -> List[SSRFFinding]:
    """
    Run SSRF detection tests on all candidate URL-like parameters.

    Two detection modes:
        1. Direct: inject metadata URLs, look for metadata content in response
        2. Time-based: measure response time with unreachable internal IP
           — a significant delay (>2s above baseline) suggests the server
           is attempting the connection

    Args:
        target: URLTarget with .parameters populated by Phase 1.

    Returns:
        List of SSRFFinding objects.
    """
    cfg = CONFIG.ssrf
    parameters: List[Parameter] = getattr(target, "parameters", [])

    if not parameters:
        log.info("No parameters — skipping SSRF tests for %s", target.normalized)
        return []

    candidates = [p for p in parameters if _is_ssrf_candidate(p)]

    if not candidates:
        log.info("No URL-like parameters on %s — skipping SSRF tests", target.normalized)
        return []

    log.info(
        "Starting SSRF tests on %s — %d candidate(s): %s",
        target.normalized, len(candidates), [p.name for p in candidates],
    )

    all_findings: List[SSRFFinding] = []

    for param in candidates:
        log.info("  Testing SSRF: param=%r", param.name)

        # ── Mode 1: Direct detection via metadata endpoints ──────────────
        for internal_url in cfg.internal_targets:
            if param.param_type == ParamType.GET:
                probe_url = _build_probe_url(target, param, internal_url)
                response = safe_get(probe_url, allow_redirects=False)
            else:
                post_url = param.form_action or target.base_url()
                form_data = {param.name: internal_url}
                response = safe_post(post_url, data=form_data, allow_redirects=False)
                probe_url = post_url

            time.sleep(0.2)

            if response is None:
                continue

            evidence = _detect_metadata_content(response.text)

            if evidence:
                finding = SSRFFinding(
                    url=probe_url,
                    parameter=param.name,
                    injected_target=internal_url,
                    evidence=evidence,
                    detection_method="direct",
                    response_code=response.status_code,
                    response_size=len(response.content),
                    severity="CRITICAL",
                )
                finding.notes.append(
                    "Cloud metadata confirmed — extract IAM credentials immediately"
                )
                finding.notes.append(
                    f"Try: {internal_url}/latest/meta-data/iam/security-credentials/"
                )
                finding.notes.append(
                    "Pivot to internal network enumeration"
                )
                all_findings.append(finding)

                log.info(
                    "  [SSRF DIRECT CONFIRMED] param=%r target=%r",
                    param.name, internal_url,
                )
                break

        # ── Mode 2: Time-based blind SSRF detection ──────────────────────
        # We inject a non-routable RFC 5737 documentation IP.
        # Any measurable delay (>2s) above baseline means the server
        # tried to connect — proof of SSRF even without response content.
        if not any(f.parameter == param.name for f in all_findings):
            blind_target = "http://192.0.2.1:80"   # RFC 5737 TEST-NET — never routes

            if param.param_type == ParamType.GET:
                baseline_url = _build_probe_url(target, param, param.value or "test")
                probe_url = _build_probe_url(target, param, blind_target)
            else:
                baseline_url = param.form_action or target.base_url()
                probe_url = baseline_url

            # Baseline timing
            baseline_start = time.time()
            if param.param_type == ParamType.GET:
                safe_get(baseline_url, allow_redirects=False)
            else:
                safe_post(baseline_url, data={param.name: param.value or "test"}, allow_redirects=False)
            baseline_time = time.time() - baseline_start

            time.sleep(0.3)

            # Probe timing
            probe_start = time.time()
            if param.param_type == ParamType.GET:
                probe_response = safe_get(probe_url, allow_redirects=False)
            else:
                probe_response = safe_post(
                    probe_url,
                    data={param.name: blind_target},
                    allow_redirects=False,
                )
            probe_time = time.time() - probe_start

            time_delta = probe_time - baseline_time

            log.debug(
                "  SSRF timing: param=%r baseline=%.2fs probe=%.2fs delta=%.2fs",
                param.name, baseline_time, probe_time, time_delta,
            )

            # A delta >2 seconds strongly suggests the server made a TCP connection attempt
            if time_delta >= 2.0:
                finding = SSRFFinding(
                    url=probe_url,
                    parameter=param.name,
                    injected_target=blind_target,
                    evidence=f"Response delay: {time_delta:.2f}s above baseline ({baseline_time:.2f}s)",
                    detection_method="time-based",
                    response_code=probe_response.status_code if probe_response else 0,
                    severity="HIGH",
                )
                finding.notes.append(
                    f"Time delta {time_delta:.2f}s suggests server-side connection attempt"
                )
                finding.notes.append(
                    "Confirm with Burp Collaborator for out-of-band validation"
                )
                finding.notes.append(
                    "Test cloud metadata: http://169.254.169.254/latest/meta-data/"
                )
                all_findings.append(finding)

                log.info(
                    "  [SSRF TIME-BASED PROBABLE] param=%r delta=%.2fs",
                    param.name, time_delta,
                )

    log.info(
        "SSRF testing complete for %s: %d finding(s)",
        target.normalized, len(all_findings),
    )

    setattr(target, "ssrf_findings", all_findings)
    return all_findings
