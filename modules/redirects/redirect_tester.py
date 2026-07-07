"""
modules/redirects/redirect_tester.py
======================================
Open redirect detection engine for ReconMind Phase 2.

Why this file exists:
    Open redirects are consistently underrated in bug bounty programs.
    They're HIGH severity when chained with OAuth flows (account takeover),
    used in phishing, or combined with SSRF. This module detects them
    systematically rather than by luck.

How open redirects work:
    The application takes a URL parameter like ?next=/dashboard and
    redirects the user there after an action. If not validated, an
    attacker can set ?next=https://evil.com and redirect users to
    a phishing page.

Detection strategy:
    For every parameter that looks like it could hold a URL:
        1. Inject redirect test payloads (external domain URLs)
        2. Send request WITHOUT following redirects
        3. Inspect the Location header for our injected domain
        4. If found: confirmed open redirect

    Additionally: scan for redirect-named parameters across ALL
    parameters on the target, not just the ones in the original URL.

    Why no-redirect is important:
        If we followed redirects, we'd end up at evil.com and never
        see the Location header that proves the redirect happened.

Evidence quality:
    We record the exact Location header value as evidence.
    "Location: https://evil.com" is unambiguous proof.
"""

import time
from dataclasses import dataclass, field
from typing import List, Optional, Dict
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

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
class RedirectFinding:
    """
    Evidence record for a confirmed open redirect vulnerability.

    Attributes:
        url:            The probe URL that triggered the redirect.
        parameter:      The parameter name that accepted the redirect URL.
        injected_value: The URL we injected as the test value.
        location_header: The actual Location header value in the response.
        response_code:  HTTP status code (expected 301/302/307/308).
        technique:      Description of the redirect variant tested.
        severity:       Always HIGH — open redirects are high severity.
        notes:          Analyst notes including chaining opportunities.
    """

    url: str
    parameter: str
    injected_value: str
    location_header: str
    response_code: int
    technique: str
    severity: str = "HIGH"
    notes: List[str] = field(default_factory=list)

    def __repr__(self) -> str:
        return (
            f"RedirectFinding([{self.severity}] param={self.parameter!r} "
            f"→ Location: {self.location_header!r})"
        )


# ---------------------------------------------------------------------------
# Redirect payloads — ordered from most to least likely to succeed
# ---------------------------------------------------------------------------

REDIRECT_PAYLOADS = [
    # Absolute external URL
    ("https://evil.com",                        "Absolute HTTPS URL"),
    ("http://evil.com",                         "Absolute HTTP URL"),
    # Protocol-relative
    ("//evil.com",                              "Protocol-relative URL"),
    ("//evil.com/",                             "Protocol-relative with path"),
    # Bypass via @-sign confusion
    ("https://evil.com%2F@target.com",          "@-sign confusion (URL-encoded slash)"),
    ("https://target.com@evil.com",             "@-sign host confusion"),
    # Bypass via CRLF injection in URL
    ("%0d%0ahttps://evil.com",                  "CRLF-prefixed URL"),
    # Double slash
    ("///evil.com",                             "Triple-slash URL"),
    ("////evil.com",                            "Quad-slash URL"),
    # Backslash (works in IE/Edge legacy parsers)
    ("/\\evil.com",                             "Backslash path bypass"),
    # Unicode confusables
    ("\u202e//evil.com",                        "Right-to-left override prefix"),
    # Null byte
    ("https://evil.com%00",                     "Null-byte terminated URL"),
]


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _looks_like_url_param(param: Parameter) -> bool:
    """
    Heuristic: does this parameter name suggest it carries a URL?

    We check against the list of commonly used redirect parameter names
    from CONFIG, plus check if the current value looks like a URL.

    Args:
        param: Parameter to evaluate.

    Returns:
        True if this param is a candidate for redirect testing.
    """
    cfg = CONFIG.redirects

    # Name match
    if param.name.lower() in [p.lower() for p in cfg.common_redirect_params]:
        return True

    # Value looks like a URL or path
    val = param.value.lower()
    if val.startswith(("http://", "https://", "//", "/")):
        return True

    # Name contains hint words
    hint_words = ["url", "uri", "redirect", "return", "next", "goto",
                  "link", "href", "dest", "target", "back", "ref"]
    for word in hint_words:
        if word in param.name.lower():
            return True

    return False


def _check_redirect_in_response(response, injected_value: str) -> tuple:
    """
    Check if the response redirected to our injected domain.

    Args:
        response:       requests.Response object (redirects NOT followed).
        injected_value: The URL string we injected.

    Returns:
        (confirmed: bool, location_header: str)
    """
    cfg = CONFIG.redirects

    # Must be a redirect status code
    if response.status_code not in cfg.redirect_status_codes:
        return False, ""

    location = response.headers.get("Location", "")
    if not location:
        return False, ""

    # Check if our injected domain appears in the Location header
    # We parse the injected value to extract the hostname
    try:
        injected_host = urlparse(injected_value.replace("//", "http://")).hostname or ""
    except Exception:
        injected_host = ""

    # Direct match
    if "evil.com" in location or (injected_host and injected_host in location):
        return True, location

    # Check if the path we injected appears in the Location
    if injected_value in location:
        return True, location

    return False, ""


def _build_probe_url(target: URLTarget, param: Parameter, payload: str) -> str:
    """Build the probe URL with payload injected into the target parameter."""
    parsed = urlparse(target.normalized)
    query_params = parse_qs(parsed.query, keep_blank_values=True)
    query_params[param.name] = [payload]
    new_query = urlencode({k: v[0] for k, v in query_params.items()})
    return urlunparse(parsed._replace(query=new_query))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_redirect_tests(target: URLTarget) -> List[RedirectFinding]:
    """
    Run open redirect tests on all candidate parameters of a URLTarget.

    Detection flow:
        1. Filter parameters to those that look like URL/redirect params
        2. Also scan for any parameter whose value currently contains a path
        3. For each candidate: try all redirect payloads
        4. Inspect Location header in response (redirects NOT followed)
        5. Record confirmed findings

    Args:
        target: URLTarget with .parameters populated by Phase 1.

    Returns:
        List of RedirectFinding objects for confirmed open redirects.
    """
    parameters: List[Parameter] = getattr(target, "parameters", [])

    if not parameters:
        log.info("No parameters — skipping redirect tests for %s", target.normalized)
        return []

    # Identify candidate parameters
    candidates = [p for p in parameters if _looks_like_url_param(p)]

    if not candidates:
        log.info(
            "No URL-like parameters found on %s — skipping redirect tests",
            target.normalized,
        )
        return []

    log.info(
        "Starting redirect tests on %s — %d candidate param(s): %s",
        target.normalized,
        len(candidates),
        [p.name for p in candidates],
    )

    all_findings: List[RedirectFinding] = []

    for param in candidates:
        log.info("  Testing redirect: param=%r", param.name)

        for payload_str, technique in REDIRECT_PAYLOADS:
            # Build probe URL
            if param.param_type == ParamType.GET:
                probe_url = _build_probe_url(target, param, payload_str)
                response = safe_get(probe_url, allow_redirects=False)
            else:
                # POST parameter
                post_url = param.form_action or target.base_url()
                form_data = {param.name: payload_str}
                response = safe_post(post_url, data=form_data, allow_redirects=False)
                probe_url = post_url

            time.sleep(0.1)  # Minimal delay — redirect checks are fast

            if response is None:
                continue

            confirmed, location = _check_redirect_in_response(response, payload_str)

            if confirmed:
                finding = RedirectFinding(
                    url=probe_url,
                    parameter=param.name,
                    injected_value=payload_str,
                    location_header=location,
                    response_code=response.status_code,
                    technique=technique,
                    severity="HIGH",
                )
                finding.notes.append(
                    f"HTTP {response.status_code} Location header contains injected domain"
                )
                finding.notes.append(
                    "Chain with OAuth/login flows for potential account takeover"
                )
                finding.notes.append(
                    "Chain with SSRF modules for internal network access"
                )

                all_findings.append(finding)

                log.info(
                    "  [REDIRECT CONFIRMED] param=%r technique=%r → Location: %r",
                    param.name, technique, location,
                )

                # One confirmed finding per parameter is enough for reporting
                break

    log.info(
        "Redirect testing complete for %s: %d finding(s)",
        target.normalized, len(all_findings),
    )

    setattr(target, "redirect_findings", all_findings)
    return all_findings
