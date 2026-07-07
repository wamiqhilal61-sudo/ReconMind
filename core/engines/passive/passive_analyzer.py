"""
core/engines/passive/passive_analyzer.py
==========================================
Passive Security Analyzer for ReconMind Phase 4 by wamiqsec.

WHY THIS ENGINE EXISTS:
────────────────────────────────────────────────────────────────
Before firing a single payload, a professional security engineer
reads the response headers. They tell you:

    - Is there a Content-Security-Policy? (affects XSS exploitability)
    - Is X-Frame-Options missing? (clickjacking risk)
    - Is HSTS configured? (SSL strip attacks)
    - Is the server leaking version info? (fingerprinting)
    - Are cookies missing HttpOnly/Secure? (session hijack risk)
    - Is CORS misconfigured? (cross-origin data theft)
    - Are cache headers exposing sensitive data? (cache poisoning)

This passive analysis:
    1. Costs zero injection requests
    2. Reveals exploitability constraints (CSP blocks XSS)
    3. Reveals low-hanging fruit (missing security headers)
    4. Informs active testing strategy
    5. Produces findings reportable on their own (bug bounty accepts misconfigs)

PASSIVE MODE GUARANTEE:
    This module NEVER sends more than the initial request.
    It only analyzes headers and body of responses already fetched.
    Zero payload injection. Zero fingerprinting probes. Zero noise.
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from urllib.parse import urlparse

from core.utils.logger import get_logger

log = get_logger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Data models
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class SecurityHeaderFinding:
    """A passive finding from security header analysis."""
    header_name: str
    issue: str
    severity: str          # HIGH / MEDIUM / LOW / INFO
    current_value: str     # What is currently set (or "MISSING")
    recommendation: str
    cwe: str = ""          # CWE reference
    owasp: str = ""        # OWASP reference
    affects_xss: bool = False       # Whether this affects XSS exploitability
    affects_clickjacking: bool = False
    affects_csrf: bool = False


@dataclass
class CSPAnalysis:
    """
    Detailed Content-Security-Policy analysis.

    CSP is the primary defense against XSS. Understanding what CSP
    allows/blocks tells us whether a reflected XSS is actually exploitable.
    """
    raw_policy: str = ""
    is_present: bool = False

    # Dangerous CSP misconfigurations
    allows_unsafe_inline: bool = False     # 'unsafe-inline' in script-src
    allows_unsafe_eval: bool = False       # 'unsafe-eval' in script-src
    allows_wildcard_src: bool = False      # * in script-src
    allows_data_uri: bool = False          # data: in script-src
    allows_http_src: bool = False          # http: scheme in script-src
    has_report_uri: bool = False           # Has reporting endpoint
    is_report_only: bool = False           # Content-Security-Policy-Report-Only

    # Bypass vectors
    bypass_vectors: List[str] = field(default_factory=list)

    # Whether XSS would be blocked by this CSP
    blocks_xss: bool = False

    # Severity of CSP configuration
    csp_severity: str = "INFO"


@dataclass
class CORSAnalysis:
    """CORS misconfiguration analysis."""
    is_present: bool = False
    origin_header: str = ""         # Access-Control-Allow-Origin value
    allows_credentials: bool = False # Access-Control-Allow-Credentials: true
    is_wildcard: bool = False        # Origin: *
    is_null_allowed: bool = False    # Origin: null allowed
    is_reflected: bool = False       # Origin is reflected (worst case)
    severity: str = "INFO"
    issue: str = ""


@dataclass
class CookieAnalysis:
    """Analysis of a single Set-Cookie header."""
    name: str
    is_session_cookie: bool = False
    has_httponly: bool = False
    has_secure: bool = False
    samesite_value: str = ""     # "Strict", "Lax", "None", or ""
    is_exposed: bool = False     # Missing security flags
    severity: str = "INFO"
    issues: List[str] = field(default_factory=list)


@dataclass
class PassiveAnalysisReport:
    """
    Complete passive security analysis for a single HTTP response.

    Produced by analyzing headers and body only — no additional requests.
    """
    url: str
    status_code: int = 200

    # Header analysis
    header_findings: List[SecurityHeaderFinding] = field(default_factory=list)
    missing_headers: List[str] = field(default_factory=list)
    leaking_headers: List[str] = field(default_factory=list)

    # CSP
    csp: Optional[CSPAnalysis] = None

    # CORS
    cors: Optional[CORSAnalysis] = None

    # Cookies
    cookie_findings: List[CookieAnalysis] = field(default_factory=list)

    # Technology fingerprint
    tech_stack: List[str] = field(default_factory=list)
    server_info: str = ""

    # Interest scoring for manual-assist mode
    interest_score: int = 0

    # Summary
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0

    @property
    def has_csp_bypass(self) -> bool:
        return bool(self.csp and self.csp.bypass_vectors)

    @property
    def xss_blocked_by_csp(self) -> bool:
        return bool(self.csp and self.csp.blocks_xss and not self.csp.bypass_vectors)


# ─────────────────────────────────────────────────────────────────────────────
# Security header definitions
# ─────────────────────────────────────────────────────────────────────────────

REQUIRED_SECURITY_HEADERS = {
    "X-Content-Type-Options": {
        "expected": "nosniff",
        "severity": "MEDIUM",
        "issue": "Missing X-Content-Type-Options — enables MIME-sniffing attacks",
        "recommendation": "Add header: X-Content-Type-Options: nosniff",
        "cwe": "CWE-16",
    },
    "X-Frame-Options": {
        "expected": ["DENY", "SAMEORIGIN"],
        "severity": "MEDIUM",
        "issue": "Missing X-Frame-Options — clickjacking vulnerability",
        "recommendation": "Add header: X-Frame-Options: DENY (or SAMEORIGIN)",
        "affects_clickjacking": True,
        "cwe": "CWE-1021",
    },
    "Strict-Transport-Security": {
        "expected": "max-age=",
        "severity": "MEDIUM",
        "issue": "Missing HSTS — users vulnerable to SSL stripping",
        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
        "cwe": "CWE-319",
    },
    "Referrer-Policy": {
        "expected": ["no-referrer", "strict-origin", "same-origin"],
        "severity": "LOW",
        "issue": "Missing Referrer-Policy — may leak sensitive URL data",
        "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
        "cwe": "CWE-116",
    },
    "Permissions-Policy": {
        "expected": None,  # Just check presence
        "severity": "LOW",
        "issue": "Missing Permissions-Policy — browser features not restricted",
        "recommendation": "Add Permissions-Policy to restrict camera, mic, geolocation",
        "cwe": "CWE-16",
    },
}

# Headers that leak server information
INFO_LEAKING_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Generator",
    "X-Drupal-Cache",
    "X-WordPress-Cache",
    "Via",
    "X-Varnish",
]

# Session cookie name patterns
SESSION_COOKIE_NAMES = {
    "phpsessid", "sessionid", "session", "sid", ".aspxauth",
    "asp.net_sessionid", "jsessionid", "laravel_session",
    "ci_session", "connect.sid", "rack.session", "_session",
}


# ─────────────────────────────────────────────────────────────────────────────
# CSP Analysis
# ─────────────────────────────────────────────────────────────────────────────

def _analyze_csp(csp_header: str, is_report_only: bool = False) -> CSPAnalysis:
    """
    Parse and analyze a Content-Security-Policy header.

    Args:
        csp_header:     Raw CSP header value.
        is_report_only: True if this is CSP-Report-Only.

    Returns:
        CSPAnalysis with exploitability assessment.
    """
    analysis = CSPAnalysis(
        raw_policy=csp_header,
        is_present=True,
        is_report_only=is_report_only,
    )

    csp_lower = csp_header.lower()

    # Extract script-src directive (fallback to default-src)
    script_src_match = re.search(r'script-src\s+([^;]+)', csp_lower)
    default_src_match = re.search(r'default-src\s+([^;]+)', csp_lower)

    script_src = ""
    if script_src_match:
        script_src = script_src_match.group(1)
    elif default_src_match:
        script_src = default_src_match.group(1)

    # Check dangerous CSP tokens
    analysis.allows_unsafe_inline = "'unsafe-inline'" in csp_lower
    analysis.allows_unsafe_eval = "'unsafe-eval'" in csp_lower
    analysis.allows_data_uri = "data:" in script_src
    analysis.allows_http_src = "http:" in script_src
    analysis.allows_wildcard_src = "* " in script_src or script_src.strip() == "*"
    analysis.has_report_uri = "report-uri" in csp_lower or "report-to" in csp_lower

    # Determine CSP bypass vectors
    if analysis.allows_unsafe_inline:
        analysis.bypass_vectors.append("'unsafe-inline' allows direct inline scripts")
    if analysis.allows_unsafe_eval:
        analysis.bypass_vectors.append("'unsafe-eval' allows eval() execution")
    if analysis.allows_wildcard_src:
        analysis.bypass_vectors.append("Wildcard (*) in script-src allows any source")
    if analysis.allows_data_uri:
        analysis.bypass_vectors.append("data: URI allowed — can encode payload")
    if analysis.allows_http_src:
        analysis.bypass_vectors.append("http: scheme allowed — load scripts from HTTP")

    # Check for JSONP/Angular bypass opportunities
    if re.search(r"'nonce-", csp_lower) and analysis.allows_unsafe_inline:
        analysis.bypass_vectors.append("Nonce present but unsafe-inline also set — nonce ineffective")

    # Determine if CSP would block XSS
    if is_report_only:
        analysis.blocks_xss = False  # Report-only never blocks
        analysis.csp_severity = "MEDIUM"
    elif analysis.bypass_vectors:
        analysis.blocks_xss = False
        analysis.csp_severity = "HIGH"
    elif not script_src:
        analysis.blocks_xss = False
        analysis.csp_severity = "HIGH"
    else:
        analysis.blocks_xss = True
        analysis.csp_severity = "INFO"

    log.debug(
        "CSP analysis: blocks_xss=%s bypasses=%d unsafe_inline=%s",
        analysis.blocks_xss, len(analysis.bypass_vectors), analysis.allows_unsafe_inline,
    )

    return analysis


# ─────────────────────────────────────────────────────────────────────────────
# CORS Analysis
# ─────────────────────────────────────────────────────────────────────────────

def _analyze_cors(headers: Dict[str, str]) -> Optional[CORSAnalysis]:
    """Analyze CORS configuration for security misconfigurations."""
    acao = headers.get("Access-Control-Allow-Origin", "")
    acac = headers.get("Access-Control-Allow-Credentials", "").lower()

    if not acao:
        return None

    analysis = CORSAnalysis(is_present=True, origin_header=acao)
    analysis.allows_credentials = acac == "true"

    if acao == "*":
        analysis.is_wildcard = True
        if analysis.allows_credentials:
            # Wildcard + credentials is invalid but some servers allow it
            analysis.severity = "HIGH"
            analysis.issue = "CORS: wildcard origin with credentials — potential data theft"
        else:
            analysis.severity = "LOW"
            analysis.issue = "CORS: wildcard origin — public API, verify intentional"

    elif acao.lower() == "null":
        analysis.is_null_allowed = True
        analysis.severity = "HIGH"
        analysis.issue = "CORS: null origin allowed — exploitable from sandboxed iframes"

    elif analysis.allows_credentials:
        # Specific origin + credentials = check if origin is validated
        analysis.severity = "MEDIUM"
        analysis.issue = (
            f"CORS: specific origin ({acao}) with credentials — "
            "verify origin validation is strict"
        )

    return analysis


# ─────────────────────────────────────────────────────────────────────────────
# Cookie Analysis
# ─────────────────────────────────────────────────────────────────────────────

def _analyze_cookies(set_cookie_headers: List[str]) -> List[CookieAnalysis]:
    """Analyze Set-Cookie headers for security flags."""
    cookie_findings = []

    for cookie_str in set_cookie_headers:
        parts = [p.strip() for p in cookie_str.split(";")]
        if not parts:
            continue

        # Extract cookie name
        name_value = parts[0].split("=", 1)
        name = name_value[0].strip().lower()

        analysis = CookieAnalysis(
            name=name,
            is_session_cookie=name in SESSION_COOKIE_NAMES,
        )

        # Check flags
        cookie_lower = cookie_str.lower()
        analysis.has_httponly = "httponly" in cookie_lower
        analysis.has_secure = "secure" in cookie_lower

        # SameSite
        samesite_match = re.search(r'samesite\s*=\s*(\w+)', cookie_lower)
        if samesite_match:
            analysis.samesite_value = samesite_match.group(1).capitalize()

        # Assess issues
        if analysis.is_session_cookie:
            if not analysis.has_httponly:
                analysis.issues.append("Missing HttpOnly — session cookie accessible via JS (XSS risk)")
                analysis.severity = "HIGH"
                analysis.is_exposed = True
            if not analysis.has_secure:
                analysis.issues.append("Missing Secure flag — cookie transmitted over HTTP")
                if analysis.severity != "HIGH":
                    analysis.severity = "MEDIUM"
                analysis.is_exposed = True
            if analysis.samesite_value == "" or analysis.samesite_value == "None":
                analysis.issues.append(
                    "Missing/None SameSite — cookie sent cross-site (CSRF risk)"
                )
                if analysis.severity not in ("HIGH",):
                    analysis.severity = "MEDIUM"

        if analysis.issues:
            cookie_findings.append(analysis)

    return cookie_findings


# ─────────────────────────────────────────────────────────────────────────────
# Technology fingerprinting
# ─────────────────────────────────────────────────────────────────────────────

TECH_HEADER_PATTERNS = [
    ("X-Powered-By", re.compile(r'PHP/(\S+)'), "PHP"),
    ("X-Powered-By", re.compile(r'Express'), "Express.js"),
    ("X-Powered-By", re.compile(r'ASP\.NET'), "ASP.NET"),
    ("Server", re.compile(r'Apache/(\S+)'), "Apache"),
    ("Server", re.compile(r'nginx/(\S+)'), "nginx"),
    ("Server", re.compile(r'Microsoft-IIS/(\S+)'), "IIS"),
    ("Server", re.compile(r'LiteSpeed'), "LiteSpeed"),
    ("Server", re.compile(r'Caddy'), "Caddy"),
    ("Via", re.compile(r'cloudflare'), "Cloudflare"),
    ("CF-Ray", re.compile(r'.'), "Cloudflare"),
    ("X-Cache", re.compile(r'.'), "Caching Layer"),
]


def _fingerprint_tech(headers: Dict[str, str]) -> Tuple[List[str], str]:
    """
    Fingerprint technology stack from response headers.

    Returns:
        (tech_stack: List[str], server_info: str)
    """
    tech = []
    server_info = headers.get("Server", "")

    for header_name, pattern, tech_name in TECH_HEADER_PATTERNS:
        header_val = headers.get(header_name, "")
        if pattern.search(header_val):
            if tech_name not in tech:
                tech.append(tech_name)

    return tech, server_info


# ─────────────────────────────────────────────────────────────────────────────
# Interest scoring
# ─────────────────────────────────────────────────────────────────────────────

def _calculate_interest_score(report: PassiveAnalysisReport) -> int:
    """
    Calculate how interesting this endpoint is for manual investigation.

    Higher score = should look at this first.
    Used by manual-assist mode to prioritize the hunting guide.
    """
    score = 0

    # Security header findings contribute
    for finding in report.header_findings:
        if finding.severity == "HIGH":
            score += 20
        elif finding.severity == "MEDIUM":
            score += 10
        elif finding.severity == "LOW":
            score += 5

    # CSP misconfigurations
    if report.csp:
        if not report.csp.is_present:
            score += 25
        elif report.csp.bypass_vectors:
            score += 15
        elif report.csp.allows_unsafe_inline:
            score += 10

    # CORS misconfigs
    if report.cors:
        if report.cors.severity == "HIGH":
            score += 30
        elif report.cors.severity == "MEDIUM":
            score += 15

    # Cookie issues
    for cookie in report.cookie_findings:
        if cookie.severity == "HIGH":
            score += 20
        elif cookie.severity == "MEDIUM":
            score += 10

    # Tech stack leakage
    if report.leaking_headers:
        score += 5

    return score


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def analyze_response_passively(
    url: str,
    status_code: int,
    headers: Dict[str, str],
    body: str = "",
) -> PassiveAnalysisReport:
    """
    Perform complete passive security analysis on an HTTP response.

    This is the main entry point called by passive mode and manual-assist mode.
    No additional requests are made — only the provided headers and body are analyzed.

    Args:
        url:         The URL that produced this response.
        status_code: HTTP response status code.
        headers:     Response headers as a dict (header_name → value).
        body:        Optional response body for additional analysis.

    Returns:
        PassiveAnalysisReport with all findings.
    """
    report = PassiveAnalysisReport(url=url, status_code=status_code)

    # Normalize header names for case-insensitive lookup
    headers_normalized = {k.lower(): v for k, v in headers.items()}

    # ── Required security headers ─────────────────────────────────────────
    for header_name, config in REQUIRED_SECURITY_HEADERS.items():
        header_val = headers_normalized.get(header_name.lower(), "")

        if not header_val:
            finding = SecurityHeaderFinding(
                header_name=header_name,
                issue=config["issue"],
                severity=config["severity"],
                current_value="MISSING",
                recommendation=config["recommendation"],
                cwe=config.get("cwe", ""),
                affects_clickjacking=config.get("affects_clickjacking", False),
            )
            report.header_findings.append(finding)
            report.missing_headers.append(header_name)

            log.debug("Missing security header: %s on %s", header_name, url)

    # ── CSP analysis ──────────────────────────────────────────────────────
    csp_value = headers_normalized.get("content-security-policy", "")
    csp_ro_value = headers_normalized.get("content-security-policy-report-only", "")

    if csp_value:
        report.csp = _analyze_csp(csp_value, is_report_only=False)
        if report.csp.bypass_vectors:
            finding = SecurityHeaderFinding(
                header_name="Content-Security-Policy",
                issue=f"CSP bypass vectors detected: {'; '.join(report.csp.bypass_vectors[:2])}",
                severity=report.csp.csp_severity,
                current_value=csp_value[:100],
                recommendation="Remove 'unsafe-inline', 'unsafe-eval', and wildcard sources",
                affects_xss=True,
            )
            report.header_findings.append(finding)
    elif csp_ro_value:
        report.csp = _analyze_csp(csp_ro_value, is_report_only=True)
        finding = SecurityHeaderFinding(
            header_name="Content-Security-Policy",
            issue="Only CSP-Report-Only present — policy does not enforce, only reports",
            severity="MEDIUM",
            current_value="CSP-Report-Only (non-enforcing)",
            recommendation="Deploy enforcing Content-Security-Policy",
            affects_xss=True,
        )
        report.header_findings.append(finding)
    else:
        report.csp = CSPAnalysis(is_present=False)
        finding = SecurityHeaderFinding(
            header_name="Content-Security-Policy",
            issue="No Content-Security-Policy — XSS not mitigated by CSP",
            severity="MEDIUM",
            current_value="MISSING",
            recommendation="Implement a strict CSP with nonces or hashes",
            affects_xss=True,
        )
        report.header_findings.append(finding)

    # ── CORS analysis ─────────────────────────────────────────────────────
    report.cors = _analyze_cors(headers_normalized)
    if report.cors and report.cors.severity in ("HIGH", "MEDIUM"):
        finding = SecurityHeaderFinding(
            header_name="Access-Control-Allow-Origin",
            issue=report.cors.issue,
            severity=report.cors.severity,
            current_value=report.cors.origin_header,
            recommendation="Validate Origin header against an allowlist; avoid wildcards with credentials",
            cwe="CWE-942",
        )
        report.header_findings.append(finding)

    # ── Cookie analysis ────────────────────────────────────────────────────
    set_cookie_headers = [
        v for k, v in headers.items()
        if k.lower() == "set-cookie"
    ]
    # requests may give multiple values joined with newlines
    expanded = []
    for h in set_cookie_headers:
        expanded.extend(h.split("\n"))

    report.cookie_findings = _analyze_cookies([c.strip() for c in expanded if c.strip()])

    # ── Information leakage headers ────────────────────────────────────────
    for header in INFO_LEAKING_HEADERS:
        if headers_normalized.get(header.lower()):
            report.leaking_headers.append(
                f"{header}: {headers_normalized[header.lower()][:80]}"
            )

    if report.leaking_headers:
        finding = SecurityHeaderFinding(
            header_name="Server/X-Powered-By",
            issue=f"Server information disclosed: {'; '.join(report.leaking_headers[:2])}",
            severity="LOW",
            current_value="; ".join(report.leaking_headers[:2]),
            recommendation="Remove or obscure Server and X-Powered-By headers",
            cwe="CWE-200",
        )
        report.header_findings.append(finding)

    # ── Technology fingerprinting ──────────────────────────────────────────
    report.tech_stack, report.server_info = _fingerprint_tech(headers_normalized)

    # ── Count severities ──────────────────────────────────────────────────
    for f in report.header_findings:
        if f.severity == "HIGH":
            report.high_count += 1
        elif f.severity == "MEDIUM":
            report.medium_count += 1
        elif f.severity == "LOW":
            report.low_count += 1

    for c in report.cookie_findings:
        if c.severity == "HIGH":
            report.high_count += 1
        elif c.severity == "MEDIUM":
            report.medium_count += 1

    # ── Interest scoring ───────────────────────────────────────────────────
    report.interest_score = _calculate_interest_score(report)

    log.info(
        "Passive analysis: %s — HIGH:%d MEDIUM:%d LOW:%d interest=%d",
        url[:60], report.high_count, report.medium_count,
        report.low_count, report.interest_score,
    )

    return report
