"""
core/engines/javascript/js_intelligence.py
============================================
JavaScript Intelligence Engine for ReconMind Phase 4 by wamiqsec.

WHY THIS ENGINE EXISTS:
────────────────────────────────────────────────────────────────
Modern web applications are JavaScript-first. The real attack surface
is no longer just HTML forms — it's buried in:

    - Webpack bundles with embedded API endpoints
    - React/Vue/Angular route definitions
    - Fetch/axios calls to internal APIs
    - Environment variables accidentally bundled
    - GraphQL query structures
    - postMessage handlers (DOM-XSS vectors)
    - eval() and innerHTML assignments (dangerous sinks)

A scanner that only reads HTML misses 60-80% of the attack surface
on a modern SPA. This engine reads JavaScript.

WHAT IT EXTRACTS:
    1.  API endpoints (fetch, axios, XMLHttpRequest URLs)
    2.  Internal routes (React Router, Vue Router, Angular routes)
    3.  GraphQL operations (queries, mutations, subscriptions)
    4.  Secrets (API keys, tokens, passwords — by entropy analysis)
    5.  Dangerous sinks (eval, innerHTML, document.write, postMessage)
    6.  Source→Sink flows (user input flowing to dangerous function)
    7.  WebSocket endpoints
    8.  CORS configuration leaks

PASSIVE MODE BEHAVIOR:
    This engine runs in PASSIVE mode — it never sends exploit payloads.
    It fetches and reads JS files, extracts intelligence, and annotates
    the target's attack surface for downstream active modules.
"""

import re
import math
import json
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Set, Tuple
from urllib.parse import urljoin, urlparse

from core.utils.http_client import safe_get
from core.recon.url_handler import URLTarget
from config.settings import CONFIG
from core.utils.logger import get_logger

log = get_logger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Data models
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class JSEndpoint:
    """An API endpoint extracted from JavaScript source."""
    url: str                          # Full or partial URL found
    method: str = "GET"              # HTTP method if detected
    source_file: str = ""            # JS file it was found in
    line_context: str = ""           # Surrounding code snippet
    has_parameters: bool = False     # Whether URL has query params
    is_graphql: bool = False         # Whether this is a GraphQL endpoint
    confidence: float = 0.8          # How confident we are this is real


@dataclass
class JSSecret:
    """A potential secret found in JavaScript source."""
    value: str                        # The secret value (truncated for safety)
    secret_type: str                  # "api_key", "token", "password", etc.
    source_file: str = ""
    line_context: str = ""
    entropy: float = 0.0             # Shannon entropy of the value
    confidence: float = 0.5


@dataclass
class JSSink:
    """A dangerous JavaScript sink that could lead to XSS."""
    sink_name: str                   # "eval", "innerHTML", "document.write", etc.
    sink_type: str                   # "code_execution", "dom_manipulation", "navigation"
    code_snippet: str = ""           # Code around the sink
    source_file: str = ""
    has_user_input: bool = False     # Whether user-controlled input reaches this sink
    is_dom_xss_vector: bool = False  # Whether this is a confirmed DOM-XSS vector
    confidence: float = 0.7


@dataclass
class JSRoute:
    """An internal application route extracted from JS routing code."""
    path: str                        # Route path e.g. "/admin/users/:id"
    component: str = ""             # Component/view name
    requires_auth: bool = False     # Whether auth guard detected
    source_file: str = ""
    is_admin_route: bool = False
    has_params: bool = False         # Whether route has dynamic params


@dataclass
class GraphQLOperation:
    """A GraphQL operation found in JavaScript."""
    operation_type: str             # "query", "mutation", "subscription"
    operation_name: str = ""
    fields: List[str] = field(default_factory=list)
    endpoint: str = ""
    source_file: str = ""


@dataclass
class JSIntelligenceReport:
    """
    Complete JavaScript analysis report for a single URL/JS file.
    Produced by the JS Intelligence Engine and consumed by:
        - Passive analyzer (surface mapping)
        - Active XSS engine (sink prioritization)
        - Manual-assist mode (hunting guide generation)
    """
    source_url: str
    js_files_analyzed: List[str] = field(default_factory=list)
    endpoints: List[JSEndpoint] = field(default_factory=list)
    secrets: List[JSSecret] = field(default_factory=list)
    sinks: List[JSSink] = field(default_factory=list)
    routes: List[JSRoute] = field(default_factory=list)
    graphql_ops: List[GraphQLOperation] = field(default_factory=list)
    websocket_urls: List[str] = field(default_factory=list)
    interesting_strings: List[str] = field(default_factory=list)
    total_js_bytes: int = 0
    analysis_errors: List[str] = field(default_factory=list)

    @property
    def has_findings(self) -> bool:
        return bool(
            self.endpoints or self.secrets or self.sinks
            or self.graphql_ops or self.routes
        )

    @property
    def high_priority_sinks(self) -> List[JSSink]:
        """Return sinks that likely have user input flowing into them."""
        return [s for s in self.sinks if s.has_user_input or s.is_dom_xss_vector]


# ─────────────────────────────────────────────────────────────────────────────
# Pattern libraries
# ─────────────────────────────────────────────────────────────────────────────

# API endpoint patterns — what fetch/axios/XHR calls look like in bundled JS
ENDPOINT_PATTERNS = [
    # fetch("...", ...) and fetch('...')
    re.compile(r'fetch\s*\(\s*["`\']((?:https?://[^"\'`]+|/[^"\'`\s]{2,}))["`\']', re.I),
    # axios.get/post/put/delete/patch("...")
    re.compile(r'axios\s*\.\s*(?:get|post|put|delete|patch|request)\s*\(\s*["`\']((?:https?://[^"\'`]+|/[^"\'`\s]{2,}))["`\']', re.I),
    # axios({url: "..."})
    re.compile(r'url\s*:\s*["`\']((?:https?://[^"\'`]+|/[^"\'`\s]{2,}))["`\']', re.I),
    # XMLHttpRequest .open("GET", "...")
    re.compile(r'\.open\s*\(\s*["`\'](?:GET|POST|PUT|DELETE|PATCH)["`\']\s*,\s*["`\']((?:https?://[^"\'`]+|/[^"\'`\s]{2,}))["`\']', re.I),
    # $http.get/post("...")  — Angular 1.x
    re.compile(r'\$http\s*\.\s*(?:get|post|put|delete)\s*\(\s*["`\']((?:https?://[^"\'`]+|/[^"\'`\s]{2,}))["`\']', re.I),
    # apiUrl = "..."  or  baseUrl = "..."  — common config patterns
    re.compile(r'(?:api|base|endpoint)(?:Url|URL|_url|_URL)\s*[=:]\s*["`\']((?:https?://[^"\'`]+|/[^"\'`\s]{2,}))["`\']', re.I),
    # Template literals with /api/ patterns
    re.compile(r'`\s*(/api/[^`\s"\']{3,})\s*`'),
    # String concatenation: "/api/" + variable
    re.compile(r'["`\'](/api/[^"\'`\s]{2,})["`\']'),
]

# GraphQL detection patterns
GRAPHQL_PATTERNS = [
    re.compile(r'(?:query|mutation|subscription)\s+(\w+)\s*\{', re.I),
    re.compile(r'gql`([^`]+)`', re.S),
    re.compile(r'graphql\s*\(\s*["`\']([^"\'`]+)["`\']', re.I),
    re.compile(r'(?:/graphql|/gql|/api/graphql)', re.I),
    re.compile(r'__typename|__schema|introspectionQuery', re.I),
]

# Route patterns for popular frameworks
ROUTE_PATTERNS = [
    # React Router: <Route path="..." /> or Route({ path: "..." })
    re.compile(r'(?:path|route)\s*:\s*["`\'](/[^"\'`\s]*)["`\']', re.I),
    re.compile(r'<Route[^>]+path\s*=\s*["{\'](\/[^"\'{}]+)["\'}]', re.I),
    # Vue Router: { path: "..." }
    re.compile(r'\{\s*path\s*:\s*["`\'](/[^"\'`]{2,})["`\']', re.I),
    # Express-style: app.get("/path", ...)
    re.compile(r'(?:app|router)\s*\.\s*(?:get|post|put|delete|patch|use)\s*\(\s*["`\'](/[^"\'`\s]+)["`\']', re.I),
    # Next.js pages directory pattern
    re.compile(r'["`\'](\/(?:api\/)?[a-zA-Z][a-zA-Z0-9_/-]*(?:\[[^\]]+\])?)["`\']'),
]

# Dangerous sink patterns for DOM-XSS detection
DANGEROUS_SINKS: Dict[str, Tuple[str, re.Pattern]] = {
    "innerHTML":         ("dom_manipulation", re.compile(r'\.innerHTML\s*[+]?=\s*(?!["\'`][\s\w])', re.I)),
    "outerHTML":         ("dom_manipulation", re.compile(r'\.outerHTML\s*[+]?=', re.I)),
    "insertAdjacentHTML":("dom_manipulation", re.compile(r'\.insertAdjacentHTML\s*\(', re.I)),
    "document.write":    ("dom_manipulation", re.compile(r'document\s*\.\s*write\s*\(', re.I)),
    "document.writeln":  ("dom_manipulation", re.compile(r'document\s*\.\s*writeln\s*\(', re.I)),
    "eval":              ("code_execution",   re.compile(r'\beval\s*\(', re.I)),
    "setTimeout_string": ("code_execution",   re.compile(r'setTimeout\s*\(\s*(?!function|async|\()', re.I)),
    "setInterval_string":("code_execution",   re.compile(r'setInterval\s*\(\s*(?!function|async|\()', re.I)),
    "Function()":        ("code_execution",   re.compile(r'new\s+Function\s*\(', re.I)),
    "location.href":     ("navigation",       re.compile(r'(?:location|window\.location)\s*\.\s*href\s*=', re.I)),
    "location.replace":  ("navigation",       re.compile(r'location\s*\.\s*replace\s*\(', re.I)),
    "location.assign":   ("navigation",       re.compile(r'location\s*\.\s*assign\s*\(', re.I)),
    "script.src":        ("dom_manipulation", re.compile(r'(?:script|img|iframe)\s*\.\s*src\s*=', re.I)),
    "postMessage":       ("communication",    re.compile(r'\.postMessage\s*\(', re.I)),
    "jQuery.html":       ("dom_manipulation", re.compile(r'\$\s*\([^)]+\)\s*\.\s*html\s*\(', re.I)),
    "jQuery.append":     ("dom_manipulation", re.compile(r'\$\s*\([^)]+\)\s*\.\s*(?:append|prepend|after|before)\s*\(', re.I)),
}

# User-input source patterns (what feeds data into sinks)
SOURCE_PATTERNS = [
    re.compile(r'location\s*\.\s*(?:hash|search|href|pathname)', re.I),
    re.compile(r'document\s*\.\s*(?:URL|referrer|cookie)', re.I),
    re.compile(r'window\s*\.\s*name', re.I),
    re.compile(r'(?:localStorage|sessionStorage)\s*\.\s*getItem', re.I),
    re.compile(r'\.value\b', re.I),
    re.compile(r'(?:URLSearchParams|searchParams)\s*\.\s*get', re.I),
    re.compile(r'event\s*\.\s*data', re.I),  # postMessage data
]

# Secret / credential patterns
SECRET_PATTERNS: Dict[str, re.Pattern] = {
    "aws_access_key":    re.compile(r'(?:AKIA|ASIA|AROA|AIDA)[A-Z0-9]{16}'),
    "aws_secret_key":    re.compile(r'(?:aws.?secret|secret.?key)\s*[=:]\s*["\']([A-Za-z0-9/+=]{40})["\']', re.I),
    "google_api_key":    re.compile(r'AIza[0-9A-Za-z_-]{35}'),
    "github_token":      re.compile(r'gh[pousr]_[A-Za-z0-9]{36,}'),
    "jwt_token":         re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'),
    "stripe_key":        re.compile(r'(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{24,}'),
    "slack_token":       re.compile(r'xox[bpoa]-[A-Za-z0-9-]+'),
    "sendgrid_key":      re.compile(r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}'),
    "private_key":       re.compile(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----'),
    "generic_api_key":   re.compile(r'(?:api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*["\']([A-Za-z0-9_\-]{20,})["\']', re.I),
    "generic_token":     re.compile(r'(?:access[_-]?token|auth[_-]?token|bearer)\s*[=:]\s*["\']([A-Za-z0-9_\-]{20,})["\']', re.I),
    "generic_password":  re.compile(r'(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{8,})["\']', re.I),
}

# Patterns that make a route look like it requires authentication
AUTH_GUARD_PATTERNS = [
    re.compile(r'(?:requiresAuth|isAuthenticated|authGuard|loginRequired|protected)', re.I),
    re.compile(r'(?:meta\s*:\s*\{[^}]*auth)', re.I),
    re.compile(r'(?:canActivate|CanActivate)', re.I),
    re.compile(r'(?:beforeEnter|beforeEach)', re.I),
]

# Admin/sensitive route indicators
ADMIN_ROUTE_PATTERNS = [
    re.compile(r'/(?:admin|administrator|superuser|management|control|panel)', re.I),
    re.compile(r'/(?:dashboard|settings|config|configuration|system)', re.I),
    re.compile(r'/(?:users|accounts|members|staff|employees)', re.I),
    re.compile(r'/(?:reports|analytics|metrics|stats|statistics)', re.I),
]

# WebSocket patterns
WEBSOCKET_PATTERNS = [
    re.compile(r'new\s+WebSocket\s*\(\s*["`\'](wss?://[^"\'`]+)["`\']', re.I),
    re.compile(r'io\s*\(\s*["`\']((?:https?://[^"\'`]+|/[^"\'`\s]+))["`\']', re.I),  # Socket.IO
]


# ─────────────────────────────────────────────────────────────────────────────
# Shannon entropy calculation (secret detection)
# ─────────────────────────────────────────────────────────────────────────────

def _shannon_entropy(text: str) -> float:
    """
    Calculate Shannon entropy of a string.

    High entropy (>3.5) = random-looking = potential secret.
    Low entropy (<3.0) = human-readable text = probably not a secret.

    Args:
        text: String to analyze.

    Returns:
        Float entropy value. Range: 0.0 (all same chars) → ~4.7 (random base64).
    """
    if not text or len(text) < 8:
        return 0.0

    freq: Dict[str, int] = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1

    entropy = 0.0
    length = len(text)
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)

    return entropy


# ─────────────────────────────────────────────────────────────────────────────
# Core extraction functions
# ─────────────────────────────────────────────────────────────────────────────

def _extract_endpoints(js_content: str, source_file: str, base_url: str) -> List[JSEndpoint]:
    """Extract API endpoint URLs from JavaScript source."""
    endpoints: List[JSEndpoint] = []
    seen_urls: Set[str] = set()

    for pattern in ENDPOINT_PATTERNS:
        for match in pattern.finditer(js_content):
            url = match.group(1).strip()

            # Skip very short paths (likely false positives)
            if len(url) < 4:
                continue

            # Skip clearly non-endpoint strings
            if any(url.endswith(ext) for ext in ['.js', '.css', '.png', '.jpg', '.gif', '.svg']):
                continue

            # Deduplicate
            if url in seen_urls:
                continue
            seen_urls.add(url)

            # Get context snippet
            start = max(0, match.start() - 40)
            end = min(len(js_content), match.end() + 40)
            context = js_content[start:end].replace("\n", " ").strip()

            # Detect HTTP method from context
            method = "GET"
            context_lower = context.lower()
            for m in ["post", "put", "delete", "patch"]:
                if m in context_lower:
                    method = m.upper()
                    break

            endpoint = JSEndpoint(
                url=url,
                method=method,
                source_file=source_file,
                line_context=context[:100],
                has_parameters="?" in url or "{" in url,
                is_graphql=bool(re.search(r'/graphql|/gql', url, re.I)),
            )
            endpoints.append(endpoint)
            log.debug("  JS endpoint found: %s %s", method, url)

    return endpoints


def _extract_secrets(js_content: str, source_file: str) -> List[JSSecret]:
    """Extract potential secrets and credentials from JavaScript source."""
    secrets: List[JSSecret] = []

    for secret_type, pattern in SECRET_PATTERNS.items():
        for match in pattern.finditer(js_content):
            # Get the actual value (group 1 if exists, otherwise whole match)
            value = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0)

            # Check entropy for generic patterns
            entropy = _shannon_entropy(value)
            min_entropy = CONFIG.js_engine.secret_min_entropy

            # Named secret types (AWS, GitHub, etc.) don't need entropy check
            is_named_pattern = secret_type not in ("generic_api_key", "generic_token", "generic_password")
            if not is_named_pattern and entropy < min_entropy:
                continue

            # Get context
            start = max(0, match.start() - 30)
            end = min(len(js_content), match.end() + 30)
            context = js_content[start:end].replace("\n", " ").strip()

            # Truncate value for safety (don't store full secrets)
            safe_value = value[:8] + "..." + value[-4:] if len(value) > 16 else value[:8] + "..."

            secret = JSSecret(
                value=safe_value,
                secret_type=secret_type,
                source_file=source_file,
                line_context=context[:100],
                entropy=entropy,
                confidence=0.90 if is_named_pattern else 0.60,
            )
            secrets.append(secret)
            log.info("  JS secret detected: type=%s entropy=%.2f", secret_type, entropy)

    return secrets


def _extract_sinks(js_content: str, source_file: str) -> List[JSSink]:
    """Extract dangerous JavaScript sinks from source."""
    sinks: List[JSSink] = []
    seen_sinks: Set[Tuple[str, int]] = set()

    for sink_name, (sink_type, pattern) in DANGEROUS_SINKS.items():
        for match in pattern.finditer(js_content):
            pos = match.start()

            # Deduplicate (same sink name + position)
            key = (sink_name, pos // 100)  # Group by ~100-char windows
            if key in seen_sinks:
                continue
            seen_sinks.add(key)

            # Get context window
            start = max(0, pos - 80)
            end = min(len(js_content), pos + 120)
            snippet = js_content[start:end].replace("\n", " ").strip()

            # Check if any user-input source appears in the same context window
            has_user_input = any(
                src_pattern.search(snippet)
                for src_pattern in SOURCE_PATTERNS
            )

            sink = JSSink(
                sink_name=sink_name,
                sink_type=sink_type,
                code_snippet=snippet[:150],
                source_file=source_file,
                has_user_input=has_user_input,
                is_dom_xss_vector=has_user_input and sink_type in ("dom_manipulation", "code_execution"),
            )
            sinks.append(sink)

            if has_user_input:
                log.info(
                    "  DOM-XSS vector: sink=%s has_user_input=True",
                    sink_name,
                )
            else:
                log.debug("  JS sink: %s (no user input detected)", sink_name)

    return sinks


def _extract_routes(js_content: str, source_file: str) -> List[JSRoute]:
    """Extract internal application routes from routing framework code."""
    routes: List[JSRoute] = []
    seen_paths: Set[str] = set()

    for pattern in ROUTE_PATTERNS:
        for match in pattern.finditer(js_content):
            path = match.group(1).strip()

            # Skip very short or obviously wrong paths
            if len(path) < 2 or path in ("/", "/*"):
                continue

            if path in seen_paths:
                continue
            seen_paths.add(path)

            # Get context to check for auth guards and admin indicators
            start = max(0, match.start() - 150)
            end = min(len(js_content), match.end() + 150)
            context = js_content[start:end]

            requires_auth = any(p.search(context) for p in AUTH_GUARD_PATTERNS)
            is_admin = any(p.search(path) for p in ADMIN_ROUTE_PATTERNS)
            has_params = ":" in path or "{" in path or "[" in path

            route = JSRoute(
                path=path,
                source_file=source_file,
                requires_auth=requires_auth,
                is_admin_route=is_admin,
                has_params=has_params,
            )
            routes.append(route)
            log.debug(
                "  JS route: %s auth=%s admin=%s params=%s",
                path, requires_auth, is_admin, has_params,
            )

    return routes


def _extract_graphql(js_content: str, source_file: str) -> List[GraphQLOperation]:
    """Extract GraphQL operations from JavaScript source."""
    ops: List[GraphQLOperation] = []

    for pattern in GRAPHQL_PATTERNS:
        for match in pattern.finditer(js_content):
            if match.lastindex and match.lastindex >= 1:
                op_content = match.group(1)
            else:
                op_content = match.group(0)

            # Try to classify operation type
            op_type = "query"
            op_name = ""
            content_lower = op_content.lower()
            if "mutation" in content_lower:
                op_type = "mutation"
            elif "subscription" in content_lower:
                op_type = "subscription"

            # Try to extract operation name
            name_match = re.search(r'(?:query|mutation|subscription)\s+(\w+)', op_content, re.I)
            if name_match:
                op_name = name_match.group(1)

            op = GraphQLOperation(
                operation_type=op_type,
                operation_name=op_name,
                source_file=source_file,
                endpoint="/graphql",
            )
            ops.append(op)
            log.debug("  GraphQL op: %s %s", op_type, op_name)

    return ops


def _extract_websockets(js_content: str) -> List[str]:
    """Extract WebSocket URLs."""
    ws_urls = []
    for pattern in WEBSOCKET_PATTERNS:
        for match in pattern.finditer(js_content):
            ws_urls.append(match.group(1))
    return list(set(ws_urls))


def _find_js_files_on_page(html: str, base_url: str) -> List[str]:
    """
    Extract all JavaScript file URLs referenced in an HTML page.
    Handles both absolute and relative URLs.
    """
    js_files = []
    pattern = re.compile(r'<script[^>]+src\s*=\s*["\']([^"\']+\.js[^"\']*)["\']', re.I)
    parsed_base = urlparse(base_url)
    base_domain = f"{parsed_base.scheme}://{parsed_base.netloc}"

    for match in pattern.finditer(html):
        src = match.group(1)
        if src.startswith("//"):
            src = parsed_base.scheme + ":" + src
        elif src.startswith("/"):
            src = base_domain + src
        elif not src.startswith("http"):
            src = urljoin(base_url, src)

        if src not in js_files:
            js_files.append(src)

    return js_files


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def analyze_js_from_url(target: URLTarget, html_response: str) -> JSIntelligenceReport:
    """
    Analyze all JavaScript referenced from an HTML page.

    This is the main entry point called by the passive mode engine.
    It:
        1. Extracts all <script src="..."> references from the HTML
        2. Fetches each JS file (respecting size limits)
        3. Runs all extraction functions on each file
        4. Also analyzes inline <script> blocks
        5. Returns a JSIntelligenceReport

    Args:
        target:        URLTarget for the page.
        html_response: HTML body of the page.

    Returns:
        JSIntelligenceReport with all extracted intelligence.
    """
    cfg = CONFIG.js_engine
    report = JSIntelligenceReport(source_url=target.normalized)

    js_files = []
    if cfg.fetch_external_js:
        js_files = _find_js_files_on_page(html_response, target.normalized)
        log.info(
            "JS Intelligence: %s — found %d JS file(s)",
            target.normalized, len(js_files),
        )

    # Also extract inline script blocks
    inline_scripts = re.findall(
        r'<script(?![^>]+src)[^>]*>(.*?)</script>',
        html_response, re.S | re.I,
    )

    # ── Analyze each external JS file ────────────────────────────────────
    for js_url in js_files:
        response = safe_get(js_url)
        if response is None:
            report.analysis_errors.append(f"Failed to fetch: {js_url}")
            continue

        if len(response.content) > cfg.max_js_file_size:
            log.debug("JS file too large (%d bytes): %s", len(response.content), js_url)
            continue

        js_content = response.text
        report.total_js_bytes += len(response.content)
        report.js_files_analyzed.append(js_url)

        _analyze_js_content(js_content, js_url, target.normalized, report, cfg)

    # ── Analyze inline scripts ─────────────────────────────────────────────
    for i, inline_js in enumerate(inline_scripts):
        if len(inline_js.strip()) < 20:
            continue
        _analyze_js_content(
            inline_js,
            f"inline_script_{i}",
            target.normalized,
            report,
            cfg,
        )

    log.info(
        "JS analysis complete: %d endpoints | %d secrets | %d sinks | "
        "%d routes | %d graphql",
        len(report.endpoints), len(report.secrets), len(report.sinks),
        len(report.routes), len(report.graphql_ops),
    )

    return report


def _analyze_js_content(
    js_content: str,
    source_file: str,
    base_url: str,
    report: JSIntelligenceReport,
    cfg,
) -> None:
    """Run all extraction functions on a single JS content string."""

    if cfg.extract_js_endpoints or True:
        report.endpoints.extend(_extract_endpoints(js_content, source_file, base_url))

    if cfg.detect_secrets:
        report.secrets.extend(_extract_secrets(js_content, source_file))

    if cfg.map_source_sink_flows:
        report.sinks.extend(_extract_sinks(js_content, source_file))

    if cfg.extract_routes:
        report.routes.extend(_extract_routes(js_content, source_file))

    if cfg.detect_graphql:
        report.graphql_ops.extend(_extract_graphql(js_content, source_file))

    report.websocket_urls.extend(_extract_websockets(js_content))


def analyze_js_string(js_content: str, source_label: str = "inline") -> JSIntelligenceReport:
    """
    Analyze a JS string directly (used for inline scripts and testing).

    Args:
        js_content:   Raw JavaScript source code string.
        source_label: Label for the source (for reporting).

    Returns:
        JSIntelligenceReport.
    """
    report = JSIntelligenceReport(source_url=source_label)
    cfg = CONFIG.js_engine

    _analyze_js_content(js_content, source_label, "", report, cfg)
    return report
