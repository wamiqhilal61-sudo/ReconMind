"""
modules/idor/idor_tester.py
============================
Insecure Direct Object Reference (IDOR) detection engine.

Why this file exists:
    IDOR is the #1 finding in bug bounty programs by volume. The concept
    is simple: if a URL like /api/user?id=1234 returns your own data,
    what does /api/user?id=1235 return? If it returns someone else's data,
    that's IDOR — a broken access control vulnerability.

    Manual IDOR hunting requires:
        1. Identifying numeric/UUID parameters
        2. Noting your own baseline response for a known ID
        3. Testing adjacent IDs and comparing responses
        4. Detecting when a different object's data is returned

    This module automates steps 1-4.

Detection strategy:
    For each numeric parameter:
        1. Fetch the baseline response (the server's response to the original value)
        2. Test adjacent IDs (+1, -1, +2, -2, etc.)
        3. Compare response: size, status code, content patterns
        4. Flag when:
           - A 200 response is returned for an adjacent ID (different object exists)
           - Response size differs significantly from baseline (different data)
           - Response content matches user data patterns (email, phone, name patterns)

UUID IDOR:
    UUID-style IDs (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx) are harder to
    enumerate. We detect these and note them for manual testing / wordlist
    attacks in Phase 3.

Limitation:
    True IDOR confirmation requires two accounts (attacker + victim).
    Phase 2 detects the structural vulnerability (different data returned)
    but doesn't prove unauthorized access without a second session.
    This is intentional — we flag it as PROBABLE IDOR for manual verification.
"""

import re
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
class IDORFinding:
    """
    Evidence record for a probable IDOR vulnerability.

    Attributes:
        url:              Probe URL that returned different data.
        parameter:        The numeric/ID parameter tested.
        original_value:   The baseline parameter value.
        tested_value:     The adjacent ID that returned different data.
        original_size:    Baseline response size in bytes.
        probe_size:       Probe response size in bytes.
        size_difference:  Absolute size difference.
        original_status:  Baseline HTTP status code.
        probe_status:     Probe HTTP status code.
        evidence:         Snippet of the differing response content.
        severity:         MEDIUM (probable) → HIGH if confirmed.
        notes:            Manual verification steps.
    """

    url: str
    parameter: str
    original_value: str
    tested_value: str
    original_size: int
    probe_size: int
    size_difference: int
    original_status: int
    probe_status: int
    evidence: str = ""
    severity: str = "MEDIUM"
    notes: List[str] = field(default_factory=list)

    def __repr__(self) -> str:
        return (
            f"IDORFinding([{self.severity}] param={self.parameter!r} "
            f"id={self.original_value!r}→{self.tested_value!r} "
            f"size_diff={self.size_difference})"
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

UUID_PATTERN = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
    re.IGNORECASE,
)

# Data patterns that suggest PII was returned
PII_PATTERNS = [
    re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),  # email
    re.compile(r'\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b'),                     # phone
    re.compile(r'"password"\s*:'),                                          # password key
    re.compile(r'"email"\s*:'),                                             # email key
    re.compile(r'"ssn"\s*:'),                                               # SSN key
    re.compile(r'"credit_card"\s*:'),                                       # credit card
    re.compile(r'"token"\s*:'),                                             # auth token
    re.compile(r'"api_key"\s*:'),                                           # API key
]


def _is_numeric_param(param: Parameter) -> bool:
    """Return True if the parameter value is numeric (IDOR candidate)."""
    return param.value.isdigit() and int(param.value) > 0


def _is_uuid_param(param: Parameter) -> bool:
    """Return True if the parameter value looks like a UUID."""
    return bool(UUID_PATTERN.match(param.value))


def _detect_pii_in_response(response_text: str) -> Optional[str]:
    """Return the first PII pattern match found in response, or None."""
    for pattern in PII_PATTERNS:
        match = pattern.search(response_text)
        if match:
            start = max(0, match.start() - 20)
            end = min(len(response_text), match.end() + 50)
            return response_text[start:end].replace("\n", " ")
    return None


def _build_probe_url(target: URLTarget, param: Parameter, new_value: str) -> str:
    """Build probe URL with the parameter value replaced."""
    parsed = urlparse(target.normalized)
    qp = parse_qs(parsed.query, keep_blank_values=True)
    qp[param.name] = [new_value]
    new_query = urlencode({k: v[0] for k, v in qp.items()})
    return urlunparse(parsed._replace(query=new_query))


def _get_baseline(
    target: URLTarget, param: Parameter
) -> Tuple[int, int, str]:
    """
    Fetch the baseline response for the parameter's original value.

    Returns:
        (status_code, response_size, response_text)
    """
    if param.param_type == ParamType.GET:
        probe_url = _build_probe_url(target, param, param.value)
        response = safe_get(probe_url)
    else:
        post_url = param.form_action or target.base_url()
        form_data = {param.name: param.value}
        response = safe_post(post_url, data=form_data)

    if response is None:
        return 0, 0, ""

    return response.status_code, len(response.content), response.text


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_idor_tests(target: URLTarget) -> List[IDORFinding]:
    """
    Test all numeric and UUID parameters for IDOR vulnerabilities.

    For each numeric parameter with a positive integer value:
        1. Fetch baseline (original value)
        2. Test CONFIG.idor.adjacent_id_range adjacent IDs
        3. Compare response size and content
        4. Flag significant differences as probable IDOR

    Args:
        target: URLTarget with .parameters populated by Phase 1.

    Returns:
        List of IDORFinding objects.
    """
    cfg = CONFIG.idor
    parameters: List[Parameter] = getattr(target, "parameters", [])

    if not parameters:
        log.info("No parameters — skipping IDOR tests for %s", target.normalized)
        return []

    # Separate numeric and UUID candidates
    numeric_candidates = [p for p in parameters if _is_numeric_param(p)]
    uuid_candidates = [p for p in parameters if _is_uuid_param(p)]

    if not numeric_candidates and not uuid_candidates:
        log.info("No numeric/UUID parameters on %s — skipping IDOR tests", target.normalized)
        return []

    log.info(
        "Starting IDOR tests on %s — %d numeric, %d UUID param(s)",
        target.normalized, len(numeric_candidates), len(uuid_candidates),
    )

    all_findings: List[IDORFinding] = []

    # ── Numeric parameter testing ─────────────────────────────────────────
    for param in numeric_candidates:
        log.info("  Testing IDOR (numeric): param=%r value=%r", param.name, param.value)

        # Step 1: Fetch baseline
        orig_status, orig_size, orig_text = _get_baseline(target, param)
        time.sleep(0.2)

        if orig_status == 0 or orig_size == 0:
            log.debug("  Could not get baseline for %r — skipping", param.name)
            continue

        original_id = int(param.value)

        # Step 2: Test adjacent IDs
        adjacent_ids = []
        for i in range(1, cfg.adjacent_id_range + 1):
            if original_id - i > 0:
                adjacent_ids.append(original_id - i)
            adjacent_ids.append(original_id + i)

        for test_id in adjacent_ids:
            test_value = str(test_id)

            if param.param_type == ParamType.GET:
                probe_url = _build_probe_url(target, param, test_value)
                response = safe_get(probe_url)
            else:
                post_url = param.form_action or target.base_url()
                form_data = {param.name: test_value}
                response = safe_post(post_url, data=form_data)
                probe_url = post_url

            time.sleep(0.15)

            if response is None:
                continue

            probe_status = response.status_code
            probe_size = len(response.content)
            size_diff = abs(probe_size - orig_size)

            # Skip error responses and identical responses
            if probe_status in (403, 404, 500):
                log.debug(
                    "  id=%s → HTTP %d (access control working or error)",
                    test_value, probe_status,
                )
                continue

            if probe_status not in cfg.success_status_codes:
                continue

            # Significant size difference means different data returned
            if size_diff >= cfg.size_diff_threshold:
                evidence = _detect_pii_in_response(response.text)
                evidence_str = evidence or f"Response size changed by {size_diff} bytes"

                finding = IDORFinding(
                    url=probe_url,
                    parameter=param.name,
                    original_value=param.value,
                    tested_value=test_value,
                    original_size=orig_size,
                    probe_size=probe_size,
                    size_difference=size_diff,
                    original_status=orig_status,
                    probe_status=probe_status,
                    evidence=evidence_str,
                    severity="HIGH" if evidence else "MEDIUM",
                )
                finding.notes.append(
                    f"Response for id={test_value} differs by {size_diff} bytes from id={param.value}"
                )
                finding.notes.append(
                    "Verify manually: log in as user A, access resource belonging to user B"
                )
                if evidence:
                    finding.notes.append(
                        "PII pattern detected in response — escalate to HIGH priority"
                    )
                finding.notes.append(
                    "Check if authorization headers are required; test without Cookie/Bearer"
                )
                all_findings.append(finding)

                log.info(
                    "  [PROBABLE IDOR] param=%r id=%s→%s size_diff=%d%s",
                    param.name, param.value, test_value, size_diff,
                    " [PII DETECTED]" if evidence else "",
                )

    # ── UUID parameter notes (manual testing flag) ────────────────────────
    for param in uuid_candidates:
        log.info(
            "  UUID parameter detected: %r=%r — flagged for manual testing",
            param.name, param.value,
        )
        # We can't enumerate UUIDs automatically without a wordlist.
        # We create a LOW-severity informational finding.
        finding = IDORFinding(
            url=target.normalized,
            parameter=param.name,
            original_value=param.value,
            tested_value="(requires wordlist/second account)",
            original_size=0,
            probe_size=0,
            size_difference=0,
            original_status=0,
            probe_status=0,
            evidence="UUID-style parameter detected",
            severity="LOW",
        )
        finding.notes.append(
            "UUID IDs can't be enumerated — obtain a second account's UUID "
            "and test cross-account access"
        )
        finding.notes.append(
            "Check if UUID is predictable (v1/time-based) using uuid-analysis tools"
        )
        all_findings.append(finding)

    log.info(
        "IDOR testing complete for %s: %d finding(s)",
        target.normalized, len(all_findings),
    )

    setattr(target, "idor_findings", all_findings)
    return all_findings
