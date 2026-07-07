"""
modules/csrf/csrf_validator.py
================================
CSRF detection engine for ReconMind Phase 4 by wamiqsec.

CSRF VALIDATION PHILOSOPHY:
────────────────────────────────────────────────────────────────
CSRF is fundamentally different from injection vulnerabilities.
We're not injecting malicious input — we're testing whether
state-changing requests require proof of user intent (a token,
same-site policy, or origin validation).

A vulnerable endpoint:
    - Accepts POST /transfer without a CSRF token
    - OR accepts the request with a wrong/missing token
    - AND the session cookie is SameSite=None or missing SameSite
    - → An attacker can embed a form on their site that auto-submits

Our validation pipeline:
    1. Identify state-changing endpoints (POST/PUT/DELETE/PATCH)
    2. Detect CSRF token presence and location (body, header, cookie)
    3. Test token removal → does server reject?
    4. Test wrong token → does server reject?
    5. Test token from different session (if second session available)
    6. Check SameSite cookie attribute
    7. Check Origin/Referer header validation
    8. Score confidence based on evidence signals
"""

import re
import time
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Tuple
from urllib.parse import urlparse, urlencode

import requests as req_lib

from core.recon.url_handler import URLTarget
from core.extractor.param_extractor import Parameter, ParamType
from core.utils.http_client import safe_get, safe_post, SESSION
from core.intelligence.confidence_engine import (
    create_bundle, mark_signal, calculate_confidence, EvidenceBundle,
    EvidenceSignal,
)
from config.settings import CONFIG
from core.utils.logger import get_logger

log = get_logger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Data models
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class CSRFResult:
    """
    Evidence record for a potential CSRF vulnerability.

    Attributes:
        url:                 The endpoint being tested.
        method:              HTTP method (POST, PUT, DELETE).
        parameter:           CSRF token parameter name (if found).
        token_found:         Whether a CSRF token was detected.
        token_location:      Where the token lives: "body", "header", "cookie".
        missing_token_rejected: Whether server rejects requests without token.
        wrong_token_rejected:  Whether server rejects wrong tokens.
        samesite_protection:   SameSite cookie value if present.
        origin_checked:        Whether server validates Origin header.
        bundle:              Evidence bundle with confidence.
        confidence:          Final confidence score.
        severity:            HIGH / MEDIUM / LOW / INFO.
        suppressed:          Whether finding was suppressed.
        notes:               Analyst notes.
    """
    url: str
    method: str = "POST"
    parameter: str = ""
    token_found: bool = False
    token_location: str = ""
    missing_token_rejected: bool = False
    wrong_token_rejected: bool = False
    samesite_protection: str = ""
    origin_checked: bool = False
    bundle: Optional[EvidenceBundle] = None
    confidence: float = 0.0
    severity: str = "INFO"
    suppressed: bool = True
    notes: List[str] = field(default_factory=list)
    evidence: str = ""


# ─────────────────────────────────────────────────────────────────────────────
# CSRF token detection patterns
# ─────────────────────────────────────────────────────────────────────────────

CSRF_TOKEN_FIELD_NAMES = {
    "_token", "csrf_token", "csrftoken", "csrf", "_csrf", "xsrf_token",
    "authenticity_token", "_wpnonce", "__requestverificationtoken",
    "x-csrf-token", "x-xsrf-token", "anti_csrf", "_csrf_token",
}

CSRF_HEADER_NAMES = [
    "X-CSRF-Token", "X-CSRFToken", "X-XSRF-TOKEN",
    "X-RequestVerificationToken", "X-Anti-Forgery-Token",
]

CSRF_TOKEN_PATTERN = re.compile(
    r'(?:name=["\'](?:' + '|'.join(CSRF_TOKEN_FIELD_NAMES) + r')["\'][^>]*value=["\']([^"\']{16,})["\']'
    r'|value=["\']([^"\']{16,})["\'][^>]*name=["\'](?:' + '|'.join(CSRF_TOKEN_FIELD_NAMES) + r')["\'])',
    re.I,
)

META_CSRF_PATTERN = re.compile(
    r'<meta[^>]+name=["\'](?:csrf-token|_token|csrf_token)["\'][^>]*content=["\']([^"\']{16,})["\']',
    re.I,
)

HIDDEN_TOKEN_PATTERN = re.compile(
    r'<input[^>]+type=["\']hidden["\'][^>]*name=["\']([^"\']*(?:csrf|token|_token|nonce|authenticity)[^"\']*)["\'][^>]*value=["\']([^"\']{16,})["\']',
    re.I,
)


# ─────────────────────────────────────────────────────────────────────────────
# CSRF signal factories
# ─────────────────────────────────────────────────────────────────────────────

def _make_csrf_signals() -> List[EvidenceSignal]:
    """Pre-built evidence signals for CSRF detection."""
    return [
        EvidenceSignal(
            name="no_csrf_token_present",
            observed=False,
            base_confidence=0.70,
            weight=0.25,
            evidence_text="",
        ),
        EvidenceSignal(
            name="missing_token_accepted",
            observed=False,
            base_confidence=0.85,
            weight=0.30,
            evidence_text="",
        ),
        EvidenceSignal(
            name="wrong_token_accepted",
            observed=False,
            base_confidence=0.90,
            weight=0.30,
            evidence_text="",
        ),
        EvidenceSignal(
            name="samesite_not_strict",
            observed=False,
            base_confidence=0.60,
            weight=0.15,
            evidence_text="",
        ),
        # Suppressors
        EvidenceSignal(
            name="token_correctly_rejected",
            observed=False,
            base_confidence=0.0,
            weight=0.0,
            is_suppressor=True,
            suppression_factor=0.10,
            evidence_text="CSRF token validation is working correctly",
        ),
        EvidenceSignal(
            name="samesite_strict_present",
            observed=False,
            base_confidence=0.0,
            weight=0.0,
            is_suppressor=True,
            suppression_factor=0.40,
            evidence_text="SameSite=Strict provides CSRF protection in modern browsers",
        ),
    ]


# ─────────────────────────────────────────────────────────────────────────────
# Helper functions
# ─────────────────────────────────────────────────────────────────────────────

def _extract_csrf_token(html: str) -> Tuple[str, str, str]:
    """
    Extract CSRF token from HTML page.

    Returns:
        (token_value, token_field_name, token_location)
        token_location: "form_hidden", "meta", or ""
    """
    # Check hidden form fields first
    match = HIDDEN_TOKEN_PATTERN.search(html)
    if match:
        field_name = match.group(1)
        token_value = match.group(2)
        return token_value, field_name, "form_hidden"

    # Check meta tag
    match = META_CSRF_PATTERN.search(html)
    if match:
        return match.group(1), "csrf-token", "meta"

    # Generic CSRF pattern
    match = CSRF_TOKEN_PATTERN.search(html)
    if match:
        value = match.group(1) or match.group(2) or ""
        return value, "_token", "form_hidden"

    return "", "", ""


def _get_samesite_value(response) -> str:
    """Extract SameSite attribute from session cookies in response."""
    if response is None:
        return ""

    for cookie in response.cookies:
        if cookie.name.lower() in {
            "session", "sessionid", "phpsessid", "asp.net_sessionid",
            "laravel_session", "ci_session", "connect.sid",
        }:
            # requests doesn't always expose SameSite — check raw header
            cookie_str = response.headers.get("Set-Cookie", "")
            ss_match = re.search(r'SameSite\s*=\s*(\w+)', cookie_str, re.I)
            if ss_match:
                return ss_match.group(1).capitalize()
            return "None"  # Missing = effectively None

    return ""


def _test_origin_validation(
    url: str,
    form_data: Dict[str, str],
    method: str = "POST",
) -> bool:
    """
    Test if the server validates the Origin header.

    Sends request with a fake Origin and checks if it's rejected.

    Returns:
        True if server validates Origin (rejects cross-origin requests).
    """
    fake_origin = "https://evil-attacker.com"

    try:
        if method.upper() == "POST":
            resp = req_lib.post(
                url,
                data=form_data,
                headers={"Origin": fake_origin, "Referer": fake_origin + "/attack"},
                cookies=SESSION.cookies,
                timeout=CONFIG.network.request_timeout,
                verify=False,
                allow_redirects=False,
            )
        else:
            resp = req_lib.get(
                url,
                params=form_data,
                headers={"Origin": fake_origin},
                cookies=SESSION.cookies,
                timeout=CONFIG.network.request_timeout,
                verify=False,
                allow_redirects=False,
            )

        # If server returns 403, it's checking Origin
        if resp.status_code in (403, 401):
            return True

        # Check for CSRF-related error in body
        if re.search(r'(?:csrf|forbidden|invalid.?origin|cross.?site)', resp.text, re.I):
            return True

        return False

    except Exception:
        return False


def _submit_without_token(
    url: str,
    form_data: Dict[str, str],
    token_field: str,
    method: str = "POST",
) -> Tuple[int, str]:
    """
    Submit form without the CSRF token.

    Returns:
        (status_code, response_body)
    """
    data_without_token = {k: v for k, v in form_data.items() if k != token_field}

    try:
        if method.upper() == "POST":
            resp = req_lib.post(
                url,
                data=data_without_token,
                cookies=SESSION.cookies,
                timeout=CONFIG.network.request_timeout,
                verify=False,
                allow_redirects=False,
            )
        else:
            resp = req_lib.get(
                url,
                params=data_without_token,
                cookies=SESSION.cookies,
                timeout=CONFIG.network.request_timeout,
                verify=False,
                allow_redirects=False,
            )

        return resp.status_code, resp.text

    except Exception:
        return 0, ""


def _submit_with_wrong_token(
    url: str,
    form_data: Dict[str, str],
    token_field: str,
    method: str = "POST",
) -> Tuple[int, str]:
    """
    Submit form with an invalid CSRF token.

    Returns:
        (status_code, response_body)
    """
    wrong_token = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    data_wrong_token = dict(form_data)
    data_wrong_token[token_field] = wrong_token

    try:
        if method.upper() == "POST":
            resp = req_lib.post(
                url,
                data=data_wrong_token,
                cookies=SESSION.cookies,
                timeout=CONFIG.network.request_timeout,
                verify=False,
                allow_redirects=False,
            )
        else:
            resp = req_lib.get(
                url,
                params=data_wrong_token,
                cookies=SESSION.cookies,
                timeout=CONFIG.network.request_timeout,
                verify=False,
                allow_redirects=False,
            )

        return resp.status_code, resp.text

    except Exception:
        return 0, ""


def _is_rejection_response(status_code: int, body: str) -> bool:
    """
    Determine if a response indicates the server rejected the CSRF attempt.

    Args:
        status_code: HTTP status code.
        body:        Response body.

    Returns:
        True if the response appears to be a rejection.
    """
    if status_code in (403, 401, 419):  # 419 = Laravel CSRF failure
        return True

    rejection_patterns = [
        r'(?:csrf|token).{0,30}(?:invalid|expired|mismatch|missing)',
        r'(?:forbidden|access.?denied|unauthorized)',
        r'(?:invalid.?request|bad.?request)',
        r'(?:verification.?failed|security.?check)',
    ]
    body_lower = body.lower()
    return any(re.search(p, body_lower) for p in rejection_patterns)


# ─────────────────────────────────────────────────────────────────────────────
# Core validation logic
# ─────────────────────────────────────────────────────────────────────────────

def _validate_endpoint_csrf(
    url: str,
    method: str,
    form_data: Dict[str, str],
    token_field: str,
    token_value: str,
) -> CSRFResult:
    """
    Run complete CSRF validation on a single endpoint.

    Args:
        url:         The form action URL.
        method:      HTTP method (POST/PUT/DELETE).
        form_data:   All form fields with their values.
        token_field: Name of the CSRF token field (may be "").
        token_value: Current CSRF token value (may be "").

    Returns:
        CSRFResult with full evidence.
    """
    result = CSRFResult(url=url, method=method)

    bundle = EvidenceBundle(
        module="CSRF",
        url=url,
        parameter=token_field or "body",
        param_type="POST",
        summary=f"CSRF test: {method} {url}",
    )
    bundle.signals = _make_csrf_signals()

    # ── Signal 1: No CSRF token present ───────────────────────────────────
    if not token_field:
        result.token_found = False
        mark_signal(bundle, "no_csrf_token_present",
                    f"No CSRF token found in {method} request to {url}")
    else:
        result.token_found = True
        result.token_location = "form_hidden"
        result.parameter = token_field

    # ── Signal 2: Missing token test ──────────────────────────────────────
    if token_field:
        no_token_status, no_token_body = _submit_without_token(
            url, form_data, token_field, method
        )
        time.sleep(0.3)

        if no_token_status == 0:
            log.debug("  No response for missing-token probe")
        elif _is_rejection_response(no_token_status, no_token_body):
            result.missing_token_rejected = True
            mark_signal(bundle, "token_correctly_rejected",
                        f"Missing token → HTTP {no_token_status} (token validated)")
        else:
            result.missing_token_rejected = False
            mark_signal(bundle, "missing_token_accepted",
                        f"Missing token → HTTP {no_token_status} (token NOT validated)")

        # ── Signal 3: Wrong token test ─────────────────────────────────────
        wrong_status, wrong_body = _submit_with_wrong_token(
            url, form_data, token_field, method
        )
        time.sleep(0.3)

        if wrong_status == 0:
            log.debug("  No response for wrong-token probe")
        elif _is_rejection_response(wrong_status, wrong_body):
            result.wrong_token_rejected = True
            if not result.missing_token_rejected:
                mark_signal(bundle, "token_correctly_rejected",
                            f"Wrong token → HTTP {wrong_status} (token validated)")
        else:
            result.wrong_token_rejected = False
            mark_signal(bundle, "wrong_token_accepted",
                        f"Wrong token accepted → HTTP {wrong_status}")

    # ── Signal 4: SameSite analysis ────────────────────────────────────────
    page_response = safe_get(url)
    if page_response:
        samesite = _get_samesite_value(page_response)
        result.samesite_protection = samesite

        if samesite.lower() == "strict":
            mark_signal(bundle, "samesite_strict_present",
                        "SameSite=Strict — browser blocks cross-site cookie sending")
        elif samesite.lower() == "lax":
            result.notes.append(
                "SameSite=Lax provides partial protection — "
                "top-level GET navigations still include cookies"
            )
            mark_signal(bundle, "samesite_not_strict",
                        "SameSite=Lax — partial protection only")
        else:
            mark_signal(bundle, "samesite_not_strict",
                        f"SameSite={samesite or 'missing'} — cookie sent cross-site")

    # ── Origin validation test ─────────────────────────────────────────────
    origin_validated = _test_origin_validation(url, form_data, method)
    result.origin_checked = origin_validated
    if origin_validated:
        result.notes.append(
            "Server validates Origin/Referer header — provides some CSRF protection"
        )

    # ── Calculate confidence ───────────────────────────────────────────────
    bundle = calculate_confidence(bundle)
    result.bundle = bundle
    result.confidence = bundle.combined_confidence
    result.severity = bundle.severity
    result.suppressed = bundle.suppressed

    # Build evidence string
    result.evidence = (
        f"token_found={result.token_found} "
        f"missing_rejected={result.missing_token_rejected} "
        f"wrong_rejected={result.wrong_token_rejected} "
        f"samesite={result.samesite_protection or 'missing'}"
    )

    if not result.suppressed:
        result.notes.append(
            "Create a PoC HTML page with auto-submitting form to confirm exploitability"
        )
        result.notes.append(
            "Test against a state-changing action (email change, password change, funds transfer)"
        )

    log.info(
        "  CSRF result: %s %s — confidence=%.0f%% suppressed=%s",
        method, url[:60], result.confidence * 100, result.suppressed,
    )

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Endpoint identification
# ─────────────────────────────────────────────────────────────────────────────

STATE_CHANGING_KEYWORDS = [
    "update", "edit", "save", "delete", "remove", "create",
    "add", "transfer", "send", "submit", "change", "modify",
    "register", "login", "logout", "upload", "import", "export",
    "purchase", "buy", "pay", "confirm", "approve", "reject",
    "invite", "share", "publish", "unpublish", "reset",
]


def _is_state_changing_endpoint(url: str, method: str) -> bool:
    """Return True if this endpoint likely changes server state."""
    if method.upper() in ("POST", "PUT", "DELETE", "PATCH"):
        return True

    # GET requests that look state-changing (poor practice but exists)
    url_lower = url.lower()
    return any(kw in url_lower for kw in STATE_CHANGING_KEYWORDS)


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def run_csrf_validation(target: URLTarget) -> List[CSRFResult]:
    """
    Run CSRF validation on all state-changing endpoints of a URLTarget.

    Identifies POST forms, extracts CSRF tokens, and validates
    whether token validation is properly enforced.

    Args:
        target: URLTarget with baseline_response set by Phase 1.

    Returns:
        List of CSRFResult objects.
    """
    baseline_response = getattr(target, "baseline_response", None)
    if baseline_response is None:
        log.info("No baseline response for CSRF testing: %s", target.normalized)
        return []

    html = baseline_response.text
    all_results: List[CSRFResult] = []

    # ── Find all forms on the page ─────────────────────────────────────────
    from bs4 import BeautifulSoup
    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception:
        return []

    forms = soup.find_all("form")
    if not forms:
        log.debug("No forms found on %s — skipping CSRF", target.normalized)
        return []

    log.info("CSRF validation: %s — %d form(s)", target.normalized, len(forms))

    for form in forms:
        action = form.get("action", target.base_url()).strip()
        if not action:
            action = target.base_url()
        elif not action.startswith("http"):
            from urllib.parse import urljoin
            action = urljoin(target.normalized, action)

        method = form.get("method", "GET").strip().upper()

        # Only test state-changing forms
        if not _is_state_changing_endpoint(action, method):
            log.debug("  Skipping GET form: %s", action)
            continue

        # Build form data from all fields
        form_data: Dict[str, str] = {}
        token_field = ""
        token_value = ""

        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name", "").strip()
            value = inp.get("value", "") or ""
            if not name:
                continue

            form_data[name] = value

            # Detect CSRF token field
            if name.lower() in CSRF_TOKEN_FIELD_NAMES:
                token_field = name
                token_value = value

        if not token_field:
            # Try regex extraction as fallback
            token_value, token_field, _ = _extract_csrf_token(str(form))

        log.info(
            "  Testing form: %s %s token=%r",
            method, action, token_field or "NONE",
        )

        result = _validate_endpoint_csrf(
            url=action,
            method=method,
            form_data=form_data,
            token_field=token_field,
            token_value=token_value,
        )

        all_results.append(result)

    reportable = [r for r in all_results if not r.suppressed]
    log.info(
        "CSRF validation complete: %d/%d reportable",
        len(reportable), len(all_results),
    )

    setattr(target, "csrf_results", all_results)
    return all_results
