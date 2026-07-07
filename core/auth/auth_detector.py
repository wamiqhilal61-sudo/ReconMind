"""
core/auth/auth_detector.py
============================
Authentication context detector for ReconMind Phase 3 by wamiqsec.

WHY THIS EXISTS:
────────────────────────────────────────────────────────────────
The single biggest reason IDOR detection produces false positives:
the scanner doesn't know whether it's authenticated or not.

Without authentication context:
    - Testing /post?id=1 vs /post?id=2 on a public blog = meaningless
    - Both return 200. Both have different content. Neither is a bug.
    - The scanner reports IDOR. The triager rejects it. Time wasted.

With authentication context:
    - Scanner knows: "I am authenticated as user_id=1234"
    - Scanner knows: "This endpoint requires authentication"
    - Scanner tests: "Can I access id=1235 with my session?"
    - If yes, and 1235 belongs to another user → real IDOR candidate

This module answers four questions before any module runs:
    1. Is the current session authenticated?
    2. What is OUR identity in this session? (user ID, email)
    3. Does this specific endpoint require authentication?
    4. What does the server return for a nonexistent ID? (the oracle test)

ORACLE TEST — THE KEY INNOVATION:
    For any numeric parameter, we probe an ID that almost certainly
    doesn't exist: id=0, id=-1, id=999999999.

    If id=0 → HTTP 404: The endpoint validates ID existence.
               Any id returning 200 is at least a real object.
               Different content per real ID is more suspicious.

    If id=0 → HTTP 200 with same structure: The endpoint doesn't
               validate IDs at all. Anything goes. This is actually
               MORE suspicious — it suggests poor access control overall.

    If id=0 → HTTP 403: The endpoint has some authorization check.
               This is the best signal for IDOR testing.
"""

import re
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Tuple
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

from core.recon.url_handler import URLTarget
from core.extractor.param_extractor import Parameter, ParamType
from core.utils.http_client import safe_get, safe_post
from core.utils.logger import get_logger

log = get_logger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Authentication signal patterns
# ─────────────────────────────────────────────────────────────────────────────

# Cookie names that strongly suggest an authenticated session
AUTH_COOKIE_INDICATORS = {
    "session", "sessionid", "sess", "sid", "phpsessid", "aspsessionid",
    "jsessionid", "asp.net_sessionid", ".aspxauth", "auth", "token",
    "access_token", "refresh_token", "jwt", "remember_me", "remember_token",
    "user_session", "login", "_session", "connect.sid", "laravel_session",
    "ci_session", "rack.session",
}

# HTTP header names that indicate authentication
AUTH_HEADER_INDICATORS = {
    "authorization", "x-auth-token", "x-api-key", "x-access-token",
    "x-user-token", "x-session-token", "bearer",
}

# DOM patterns that indicate a logged-in user
AUTH_DOM_PATTERNS = [
    # User-specific nav links
    re.compile(r'(?:logout|sign.?out|log.?out)', re.I),
    re.compile(r'(?:my.?profile|my.?account|my.?dashboard)', re.I),
    re.compile(r'welcome[,\s]+\w+', re.I),          # "Welcome, username"
    re.compile(r'hello[,\s]+\w+', re.I),             # "Hello, username"

    # Data attributes carrying user identity
    re.compile(r'data-user-?id=["\'](\d+)["\']', re.I),
    re.compile(r'data-current-?user=["\'](\w+)["\']', re.I),
    re.compile(r'"user_?id"\s*:\s*(\d+)'),
    re.compile(r'"current_?user"\s*:\s*\{'),
]

# Patterns to extract our own user ID from authenticated responses
OWN_ID_PATTERNS = [
    re.compile(r'data-user-?id=["\'](\d+)["\']', re.I),
    re.compile(r'data-current-?user-?id=["\'](\d+)["\']', re.I),
    re.compile(r'"user_?id"\s*:\s*(\d+)'),
    re.compile(r'"id"\s*:\s*(\d+)'),
    re.compile(r'/users?/(\d+)(?:/|"|\')'),
    re.compile(r'/profile/(\d+)(?:/|"|\')'),
    re.compile(r'/account/(\d+)(?:/|"|\')'),
    re.compile(r'currentUser\.id\s*=\s*(\d+)'),
    re.compile(r'window\.userId\s*=\s*(\d+)'),
]


@dataclass
class AuthContext:
    """
    Authentication context for a scan session.

    Attributes:
        is_authenticated:     True if session cookies or auth headers detected.
        auth_cookies:         Names of authentication cookies found.
        auth_headers:         Names of authentication headers found.
        own_user_id:          Our user ID extracted from the application.
        own_email:            Our email extracted from the application.
        auth_confidence:      How confident we are in the auth detection (0.0–1.0).
        session_cookies:      Full cookie dict for use in requests.
    """
    is_authenticated: bool = False
    auth_cookies: List[str] = field(default_factory=list)
    auth_headers: List[str] = field(default_factory=list)
    own_user_id: Optional[str] = None
    own_email: Optional[str] = None
    auth_confidence: float = 0.0
    session_cookies: Dict[str, str] = field(default_factory=dict)


@dataclass
class EndpointAccessProfile:
    """
    Access control behavior for a specific endpoint + parameter combination.

    Attributes:
        url:                    The endpoint URL.
        param_name:             The numeric parameter being profiled.
        original_value:         The original parameter value (baseline).
        requires_auth:          True if unauthenticated requests get 401/403.
        nonexistent_behavior:   HTTP status for a nonexistent ID probe.
        nonexistent_body_size:  Response size for nonexistent ID.
        access_control_signal:  Describes what kind of access control was found.
        is_public_endpoint:     True if endpoint serves public content.
        oracle_confident:       True if oracle test results are reliable.
    """
    url: str
    param_name: str
    original_value: str
    requires_auth: bool = False
    nonexistent_behavior: int = 0
    nonexistent_body_size: int = 0
    access_control_signal: str = "unknown"
    is_public_endpoint: bool = False
    oracle_confident: bool = False


# ─────────────────────────────────────────────────────────────────────────────
# Auth detection helpers
# ─────────────────────────────────────────────────────────────────────────────

def detect_auth_from_response(response) -> AuthContext:
    """
    Analyze an HTTP response to detect authentication signals.

    Called on the baseline response fetched during parameter extraction.
    This gives us auth context before any injection testing begins.

    Args:
        response: requests.Response object.

    Returns:
        AuthContext with all detected signals.
    """
    ctx = AuthContext()

    if response is None:
        return ctx

    # ── Check response cookies ─────────────────────────────────────────────
    for cookie in response.cookies:
        name_lower = cookie.name.lower()
        if any(indicator in name_lower for indicator in AUTH_COOKIE_INDICATORS):
            ctx.auth_cookies.append(cookie.name)
            ctx.session_cookies[cookie.name] = cookie.value

    # ── Check request headers that were sent ──────────────────────────────
    if hasattr(response, 'request') and response.request:
        req_headers = {k.lower(): v for k, v in response.request.headers.items()}
        for header_name in AUTH_HEADER_INDICATORS:
            if header_name in req_headers:
                ctx.auth_headers.append(header_name)

    # ── Check DOM for login indicators ────────────────────────────────────
    dom_auth_signals = 0
    for pattern in AUTH_DOM_PATTERNS:
        if pattern.search(response.text):
            dom_auth_signals += 1

    # ── Extract own user ID ───────────────────────────────────────────────
    for pattern in OWN_ID_PATTERNS:
        match = pattern.search(response.text)
        if match:
            ctx.own_user_id = match.group(1)
            log.debug("Own user ID extracted: %s", ctx.own_user_id)
            break

    # ── Calculate auth confidence ─────────────────────────────────────────
    signals = len(ctx.auth_cookies) + len(ctx.auth_headers) + min(dom_auth_signals, 3)
    ctx.auth_confidence = min(signals * 0.25, 1.0)
    ctx.is_authenticated = ctx.auth_confidence >= 0.25

    if ctx.is_authenticated:
        log.info(
            "Auth detected: cookies=%s headers=%s dom_signals=%d own_id=%s confidence=%.0f%%",
            ctx.auth_cookies, ctx.auth_headers, dom_auth_signals,
            ctx.own_user_id, ctx.auth_confidence * 100,
        )
    else:
        log.debug("No authentication detected — IDOR confidence will be reduced")

    return ctx


def probe_endpoint_access(
    target: URLTarget,
    param: Parameter,
    auth_ctx: AuthContext,
) -> EndpointAccessProfile:
    """
    Profile how an endpoint handles access control for a numeric parameter.

    This runs TWO oracle probes:
        1. Probe with a nonexistent ID (id=0, id=-1, id=999999999)
        2. Probe with the original ID but WITHOUT cookies (if authenticated)

    These two probes tell us:
        - Whether the server validates ID existence (404 vs 200)
        - Whether the server enforces authentication (403 vs 200)

    Args:
        target:   URLTarget being tested.
        param:    The numeric Parameter to probe.
        auth_ctx: Authentication context for this session.

    Returns:
        EndpointAccessProfile describing access control behavior.
    """
    profile = EndpointAccessProfile(
        url=target.normalized,
        param_name=param.name,
        original_value=param.value,
    )

    # ── Oracle probe: nonexistent ID ──────────────────────────────────────
    nonexistent_ids = ["0", "-1", "999999999", "99999999999"]

    for test_id in nonexistent_ids:
        probe_url = _build_probe_url(target, param, test_id)
        response = safe_get(probe_url, allow_redirects=False)

        if response is None:
            continue

        profile.nonexistent_behavior = response.status_code
        profile.nonexistent_body_size = len(response.content)
        profile.oracle_confident = True

        if response.status_code == 404:
            profile.access_control_signal = "validates_existence"
            log.debug("Oracle: id=%s → 404 (server validates ID existence)", test_id)
        elif response.status_code in (401, 403):
            profile.requires_auth = True
            profile.access_control_signal = "requires_authentication"
            log.debug("Oracle: id=%s → %d (endpoint requires auth)", test_id, response.status_code)
        elif response.status_code == 200:
            # Returns 200 for nonexistent ID — weak access control
            profile.access_control_signal = "no_existence_validation"
            log.debug("Oracle: id=%s → 200 (no existence validation)", test_id)
        break  # One oracle probe is enough

    # ── Public content detection ──────────────────────────────────────────
    # If the endpoint doesn't require auth and serves public content,
    # IDOR testing is less meaningful
    if not auth_ctx.is_authenticated and profile.nonexistent_behavior != 401:
        profile.is_public_endpoint = True
        log.debug(
            "Endpoint likely public: no auth in session + nonexistent ID → %d",
            profile.nonexistent_behavior,
        )

    # ── Auth-only probe: strip session cookies ────────────────────────────
    if auth_ctx.is_authenticated and not profile.requires_auth:
        # Make the same request WITHOUT auth cookies to check if auth is enforced
        probe_url = _build_probe_url(target, param, param.value)
        # We pass empty cookies via a new session
        import requests as req_lib
        try:
            no_auth_response = req_lib.get(
                probe_url,
                cookies={},
                timeout=10,
                verify=False,
                allow_redirects=False,
            )
            if no_auth_response.status_code in (401, 403):
                profile.requires_auth = True
                profile.access_control_signal = "auth_enforced_by_session"
                log.debug("Auth enforced: unauthenticated request → %d", no_auth_response.status_code)
        except Exception:
            pass

    return profile


def _build_probe_url(target: URLTarget, param: Parameter, value: str) -> str:
    """Build a probe URL with the given parameter value."""
    parsed = urlparse(target.normalized)
    qp = parse_qs(parsed.query, keep_blank_values=True)
    qp[param.name] = [value]
    new_query = urlencode({k: v[0] for k, v in qp.items()})
    return urlunparse(parsed._replace(query=new_query))
