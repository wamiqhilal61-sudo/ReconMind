"""
core/engines/response/response_classifier.py
=============================================
Response Classification Engine for ReconMind Phase 4 by wamiqsec.

WHY THIS ENGINE EXISTS:
────────────────────────────────────────────────────────────────
Every response is not equal. A login page, an admin panel, a search
endpoint, a file upload handler, and a public blog post all warrant
completely different testing strategies.

Current scanner problem:
    We apply the same payload selection logic regardless of what
    the endpoint actually does. This causes:
    - Unnecessary payloads on public read-only pages
    - Missing payloads on high-value endpoints
    - Wrong suppressors for admin panels (admin panels SHOULD be tested)
    - False positives on search pages (expected reflection)

What classification unlocks:
    PAGE_TYPE_SEARCH:
        → Reflection is EXPECTED (that's what search does)
        → Apply suppressor on XSS reflection findings
        → Test with HTML-breaking payloads specifically

    PAGE_TYPE_ADMIN:
        → Disable public-content suppressors
        → Apply aggressive testing profile
        → Flag for IDOR testing even on non-numeric params

    PAGE_TYPE_AUTH:
        → Flag for CSRF testing
        → Flag for credential brute-force resistance analysis
        → Check for sensitive data in error messages

    PAGE_TYPE_UPLOAD:
        → Flag for file upload bypass testing
        → Test for path traversal via filename parameter
        → Check content-type validation

    PAGE_TYPE_API:
        → Skip HTML context analysis (it's JSON)
        → Apply JSON injection payloads
        → Test for mass assignment
        → Check for missing auth on REST endpoints

CLASSIFICATION FACTORS:
    - URL structure (path keywords)
    - Response Content-Type header
    - HTML structure (forms, nav elements, headings)
    - HTTP method support
    - Response content keywords
    - Status code and headers
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional, Set
from urllib.parse import urlparse

from bs4 import BeautifulSoup
from core.utils.logger import get_logger

log = get_logger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Page type constants
# ─────────────────────────────────────────────────────────────────────────────

class PageType:
    """Classified response page types."""
    API           = "API"           # REST/JSON API endpoint
    AUTH          = "AUTH"          # Login, register, password reset
    ADMIN         = "ADMIN"         # Admin panel, management interface
    DASHBOARD     = "DASHBOARD"     # User dashboard, account overview
    SEARCH        = "SEARCH"        # Search results page
    UPLOAD        = "UPLOAD"        # File upload endpoint
    PROFILE       = "PROFILE"       # User profile / account settings
    PUBLIC        = "PUBLIC"        # Public content (blog, marketing)
    GRAPHQL       = "GRAPHQL"       # GraphQL endpoint
    REDIRECT      = "REDIRECT"      # Redirect handler
    ERROR         = "ERROR"         # Error page (404, 500, etc.)
    FORM          = "FORM"          # Generic form page
    UNKNOWN       = "UNKNOWN"       # Could not classify


# Testing profile: how aggressively to test each page type
# Higher = more aggressive. 1.0 = normal. 0.5 = gentler. 1.5 = aggressive.
PAGE_TYPE_AGGRESSIVENESS: Dict[str, float] = {
    PageType.API:       1.2,  # APIs are high-value, test more
    PageType.AUTH:      1.0,
    PageType.ADMIN:     1.5,  # Admin panels — go hard
    PageType.DASHBOARD: 1.1,
    PageType.SEARCH:    0.7,  # Search reflects input — reduce noise
    PageType.UPLOAD:    1.3,
    PageType.PROFILE:   1.2,  # Profile data = IDOR target
    PageType.PUBLIC:    0.5,  # Public read-only — be gentle
    PageType.GRAPHQL:   1.3,
    PageType.REDIRECT:  1.0,
    PageType.ERROR:     0.3,  # Error pages — almost never injectable
    PageType.FORM:      1.0,
    PageType.UNKNOWN:   0.8,
}


@dataclass
class ClassificationSignal:
    """A single piece of evidence contributing to page type classification."""
    signal_name: str
    page_type: str
    confidence: float
    description: str = ""


@dataclass
class ResponseClassification:
    """
    Complete classification result for an HTTP response.

    Attributes:
        page_type:          Primary classified type (from PageType).
        secondary_types:    Additional applicable types.
        confidence:         Classification confidence (0.0–1.0).
        signals:            Evidence signals that contributed.
        aggressiveness:     Testing aggressiveness multiplier.
        reflection_expected: True if reflection is expected behavior (search pages).
        is_authenticated:   True if page requires/has authentication.
        has_file_upload:    True if a file upload form was detected.
        has_sensitive_data: True if PII/sensitive data patterns found.
        recommended_modules: Which vulnerability modules to prioritize.
        suppressed_modules:  Which modules to skip for this page type.
        content_type:       HTTP Content-Type header value.
        tech_stack:         Detected technology hints.
        notes:              Analysis notes.
    """
    page_type: str = PageType.UNKNOWN
    secondary_types: List[str] = field(default_factory=list)
    confidence: float = 0.0
    signals: List[ClassificationSignal] = field(default_factory=list)
    aggressiveness: float = 0.8
    reflection_expected: bool = False
    is_authenticated: bool = False
    has_file_upload: bool = False
    has_sensitive_data: bool = False
    recommended_modules: List[str] = field(default_factory=list)
    suppressed_modules: List[str] = field(default_factory=list)
    content_type: str = ""
    tech_stack: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# Classification signal patterns
# ─────────────────────────────────────────────────────────────────────────────

URL_SIGNALS: Dict[str, List[re.Pattern]] = {
    PageType.ADMIN: [
        re.compile(r'/(?:admin|administrator|superadmin|mgmt|management|control.?panel|cp|wp-admin|phpmyadmin)', re.I),
        re.compile(r'/(?:dashboard/admin|admin/dashboard|backend|backoffice)', re.I),
    ],
    PageType.AUTH: [
        re.compile(r'/(?:login|signin|sign-in|log-in|auth|authenticate|sso)', re.I),
        re.compile(r'/(?:register|signup|sign-up|create.?account|join)', re.I),
        re.compile(r'/(?:forgot.?password|reset.?password|password.?reset|recover)', re.I),
        re.compile(r'/(?:logout|signout|sign-out)', re.I),
        re.compile(r'/(?:2fa|mfa|otp|two.?factor)', re.I),
    ],
    PageType.API: [
        re.compile(r'/api/v?\d*/', re.I),
        re.compile(r'/(?:rest|restful|json|ajax)/', re.I),
        re.compile(r'\.(json|xml)(?:\?|$)', re.I),
    ],
    PageType.GRAPHQL: [
        re.compile(r'/(?:graphql|gql|graph)(?:\?|$|/)', re.I),
    ],
    PageType.SEARCH: [
        re.compile(r'/(?:search|find|query|results|lookup)', re.I),
        re.compile(r'[?&](?:q|query|search|s|term|keyword)=', re.I),
    ],
    PageType.UPLOAD: [
        re.compile(r'/(?:upload|uploads|media|files?|attachments?|documents?)', re.I),
        re.compile(r'/(?:import|ingest)', re.I),
    ],
    PageType.PROFILE: [
        re.compile(r'/(?:profile|account|settings|preferences|me|my)', re.I),
        re.compile(r'/(?:user|users|member|members)/\d+', re.I),
    ],
    PageType.REDIRECT: [
        re.compile(r'[?&](?:redirect|return|url|next|goto|dest|target|callback)=', re.I),
    ],
    PageType.DASHBOARD: [
        re.compile(r'/dashboard(?:$|/)', re.I),
        re.compile(r'/(?:home|overview|summary|portal)(?:$|/)', re.I),
    ],
}

# HTML content signals
CONTENT_SIGNALS: Dict[str, List[re.Pattern]] = {
    PageType.AUTH: [
        re.compile(r'<input[^>]+type=["\']password["\']', re.I),
        re.compile(r'(?:forgot.?password|remember.?me)', re.I),
        re.compile(r'(?:sign.?in|log.?in)\s*with\s*(?:google|facebook|github)', re.I),
    ],
    PageType.ADMIN: [
        re.compile(r'(?:admin.?panel|administration|manage.?users|user.?management)', re.I),
        re.compile(r'(?:system.?settings|site.?configuration|bulk.?action)', re.I),
    ],
    PageType.SEARCH: [
        re.compile(r'<input[^>]+(?:placeholder=["\'][^"\']*search|name=["\'](?:q|query|search))', re.I),
        re.compile(r'(?:results? for|showing \d+ results?|no results? found)', re.I),
    ],
    PageType.UPLOAD: [
        re.compile(r'<input[^>]+type=["\']file["\']', re.I),
        re.compile(r'(?:drag.?and.?drop|choose.?file|browse.?file)', re.I),
        re.compile(r'(?:multipart/form-data|enctype)', re.I),
    ],
    PageType.DASHBOARD: [
        re.compile(r'(?:welcome.?back|your.?account|account.?overview)', re.I),
        re.compile(r'(?:recent.?activity|notifications|your.?profile)', re.I),
    ],
    PageType.ERROR: [
        re.compile(r'(?:404|page.?not.?found|not.?found)', re.I),
        re.compile(r'(?:500|internal.?server.?error|something.?went.?wrong)', re.I),
        re.compile(r'(?:403|forbidden|access.?denied)', re.I),
    ],
}

# Technology fingerprint patterns (header-based)
TECH_FINGERPRINTS: Dict[str, List[Tuple[str, re.Pattern]]] = {
    "headers": [
        ("WordPress", re.compile(r'wp-', re.I)),
        ("Drupal", re.compile(r'X-Generator.*Drupal', re.I)),
        ("Laravel", re.compile(r'laravel_session', re.I)),
        ("Django", re.compile(r'csrftoken|django', re.I)),
        ("Rails", re.compile(r'_rails_session|X-Powered-By.*Phusion', re.I)),
        ("ASP.NET", re.compile(r'ASP\.NET|ASPXAUTH|\.aspx', re.I)),
        ("Express", re.compile(r'X-Powered-By.*Express', re.I)),
        ("Nginx", re.compile(r'Server.*nginx', re.I)),
        ("Apache", re.compile(r'Server.*Apache', re.I)),
        ("Cloudflare", re.compile(r'cf-ray|__cfduid', re.I)),
        ("AWS", re.compile(r'x-amz-|AmazonS3', re.I)),
    ],
}

# Sensitive data patterns in responses
SENSITIVE_PATTERNS = [
    re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z]{2,}\b'),  # email
    re.compile(r'\b\d{3}[-.]?\d{2}[-.]?\d{4}\b'),                       # SSN-like
    re.compile(r'(?:password|passwd|pwd)\s*[=:]\s*\S+'),
    re.compile(r'(?:api[_-]?key|access[_-]?token)\s*[=:]\s*\S+'),
]

from typing import Tuple  # noqa — used in TECH_FINGERPRINTS above


# ─────────────────────────────────────────────────────────────────────────────
# Module recommendation logic
# ─────────────────────────────────────────────────────────────────────────────

PAGE_TYPE_MODULE_RECOMMENDATIONS: Dict[str, Dict] = {
    PageType.API: {
        "recommended": ["IDOR", "SQLI", "SSRF", "CSRF"],
        "suppressed": [],
        "notes": ["API endpoint — test for mass assignment, auth bypass, BOLA"],
    },
    PageType.AUTH: {
        "recommended": ["CSRF", "SQLI", "XSS"],
        "suppressed": ["IDOR"],
        "notes": ["Auth page — test CSRF token validation, credential exposure"],
    },
    PageType.ADMIN: {
        "recommended": ["IDOR", "SSRF", "LFI", "SQLI", "XSS", "CSRF"],
        "suppressed": [],
        "notes": ["Admin panel — full module suite, high priority target"],
    },
    PageType.SEARCH: {
        "recommended": ["XSS", "SQLI"],
        "suppressed": [],
        "notes": ["Search page — reflection expected, reduce XSS false positives"],
    },
    PageType.UPLOAD: {
        "recommended": ["LFI", "SSRF"],
        "suppressed": ["IDOR"],
        "notes": ["Upload endpoint — test file type bypass, path traversal in filename"],
    },
    PageType.PROFILE: {
        "recommended": ["IDOR", "XSS", "CSRF"],
        "suppressed": [],
        "notes": ["Profile page — primary IDOR target, test cross-user access"],
    },
    PageType.PUBLIC: {
        "recommended": ["XSS"],
        "suppressed": ["IDOR", "SSRF", "LFI"],
        "notes": ["Public page — reduced testing scope"],
    },
    PageType.GRAPHQL: {
        "recommended": ["SQLI", "IDOR", "SSRF"],
        "suppressed": ["XSS", "LFI"],
        "notes": ["GraphQL — test introspection, field injection, batch abuse"],
    },
    PageType.REDIRECT: {
        "recommended": ["REDIRECT", "SSRF"],
        "suppressed": ["SQLI", "LFI"],
        "notes": ["Redirect handler — open redirect and SSRF primary vectors"],
    },
    PageType.DASHBOARD: {
        "recommended": ["IDOR", "CSRF", "XSS"],
        "suppressed": [],
        "notes": ["Dashboard — authenticated surface, CSRF and IDOR are primary"],
    },
    PageType.ERROR: {
        "recommended": [],
        "suppressed": ["IDOR", "SQLI", "LFI", "SSRF", "XSS"],
        "notes": ["Error page — skip active testing, note for info disclosure"],
    },
}


# ─────────────────────────────────────────────────────────────────────────────
# Core classification logic
# ─────────────────────────────────────────────────────────────────────────────

def _score_url(url: str) -> Dict[str, float]:
    """Score a URL against all URL signal patterns."""
    scores: Dict[str, float] = {}

    for page_type, patterns in URL_SIGNALS.items():
        for pattern in patterns:
            if pattern.search(url):
                scores[page_type] = scores.get(page_type, 0) + 0.40

    return scores


def _score_content_type(content_type: str) -> Dict[str, float]:
    """Score based on HTTP Content-Type header."""
    scores: Dict[str, float] = {}
    ct_lower = content_type.lower()

    if "application/json" in ct_lower or "application/ld+json" in ct_lower:
        scores[PageType.API] = 0.60
    elif "application/graphql" in ct_lower:
        scores[PageType.GRAPHQL] = 0.80
    elif "text/html" in ct_lower:
        pass  # HTML needs content analysis
    elif "application/xml" in ct_lower or "text/xml" in ct_lower:
        scores[PageType.API] = 0.40

    return scores


def _score_html_content(html: str) -> Dict[str, float]:
    """Score HTML content against all content signal patterns."""
    scores: Dict[str, float] = {}

    for page_type, patterns in CONTENT_SIGNALS.items():
        for pattern in patterns:
            if pattern.search(html):
                scores[page_type] = scores.get(page_type, 0) + 0.30

    return scores


def _score_status_code(status_code: int) -> Dict[str, float]:
    """Score based on HTTP status code."""
    if status_code in (301, 302, 303, 307, 308):
        return {PageType.REDIRECT: 0.70}
    elif status_code in (404, 403, 500, 502, 503):
        return {PageType.ERROR: 0.80}
    return {}


def _detect_tech_stack(response_headers: Dict[str, str], html: str) -> List[str]:
    """Detect technology stack from headers and HTML."""
    detected = []

    header_str = " ".join(f"{k}: {v}" for k, v in response_headers.items())

    for tech, pattern in TECH_FINGERPRINTS["headers"]:
        if pattern.search(header_str):
            detected.append(tech)

    # HTML-based detection
    if re.search(r'wp-content|wp-includes|wordpress', html, re.I):
        if "WordPress" not in detected:
            detected.append("WordPress")
    if re.search(r'Joomla!|/components/com_', html, re.I):
        detected.append("Joomla")
    if re.search(r'ng-app|ng-controller|angular\.module', html, re.I):
        detected.append("AngularJS")
    if re.search(r'data-reactroot|__NEXT_DATA__|next/static', html, re.I):
        detected.append("React/Next.js")
    if re.search(r'data-v-|__vue__|<router-view', html, re.I):
        detected.append("Vue.js")

    return list(set(detected))


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def classify_response(
    url: str,
    html: str,
    status_code: int = 200,
    content_type: str = "text/html",
    response_headers: Optional[Dict[str, str]] = None,
) -> ResponseClassification:
    """
    Classify an HTTP response into a page type.

    This is the main entry point called by passive mode and active modules.
    The classification result affects:
        - Which modules run against this URL
        - Whether reflection is "expected" (suppresses XSS false positives)
        - Testing aggressiveness multiplier
        - Confidence suppression factors

    Args:
        url:              The full URL of the response.
        html:             Response body (HTML or JSON string).
        status_code:      HTTP status code.
        content_type:     Content-Type header value.
        response_headers: Full response headers dict.

    Returns:
        ResponseClassification with all analysis results.
    """
    result = ResponseClassification(content_type=content_type)
    response_headers = response_headers or {}

    # ── Scoring ───────────────────────────────────────────────────────────
    all_scores: Dict[str, float] = {}

    def _add_scores(new_scores: Dict[str, float], weight: float = 1.0):
        for page_type, score in new_scores.items():
            all_scores[page_type] = all_scores.get(page_type, 0) + (score * weight)

    _add_scores(_score_url(url))
    _add_scores(_score_content_type(content_type))
    _add_scores(_score_html_content(html))
    _add_scores(_score_status_code(status_code))

    # ── Determine primary classification ──────────────────────────────────
    if all_scores:
        sorted_types = sorted(all_scores.items(), key=lambda x: x[1], reverse=True)
        best_type, best_score = sorted_types[0]

        # Normalize score to 0.0–1.0
        result.page_type = best_type
        result.confidence = min(best_score, 1.0)

        # Secondary types (score >= 30% of best)
        result.secondary_types = [
            pt for pt, score in sorted_types[1:]
            if score >= best_score * 0.3
        ]
    else:
        result.page_type = PageType.UNKNOWN
        result.confidence = 0.0

    # ── Apply min confidence threshold ────────────────────────────────────
    from config.settings import CONFIG
    if result.confidence < CONFIG.classifier.min_classification_confidence:
        result.page_type = PageType.UNKNOWN

    # ── Set aggressiveness ────────────────────────────────────────────────
    result.aggressiveness = PAGE_TYPE_AGGRESSIVENESS.get(result.page_type, 0.8)

    # ── Detect file upload ────────────────────────────────────────────────
    result.has_file_upload = bool(
        re.search(r'<input[^>]+type=["\']file["\']', html, re.I)
        or result.page_type == PageType.UPLOAD
    )

    # ── Detect sensitive data ─────────────────────────────────────────────
    result.has_sensitive_data = any(p.search(html) for p in SENSITIVE_PATTERNS)

    # ── Set reflection expectation ────────────────────────────────────────
    result.reflection_expected = result.page_type == PageType.SEARCH

    # ── Tech stack detection ──────────────────────────────────────────────
    result.tech_stack = _detect_tech_stack(response_headers, html)

    # ── Module recommendations ────────────────────────────────────────────
    rec = PAGE_TYPE_MODULE_RECOMMENDATIONS.get(result.page_type, {})
    result.recommended_modules = rec.get("recommended", [])
    result.suppressed_modules = rec.get("suppressed", [])
    result.notes = rec.get("notes", [])

    log.info(
        "Classified: %s → %s (%.0f%%) aggressiveness=%.1f modules=%s",
        url[:60],
        result.page_type,
        result.confidence * 100,
        result.aggressiveness,
        result.recommended_modules,
    )

    return result
