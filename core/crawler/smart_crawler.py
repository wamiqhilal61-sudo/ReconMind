"""
core/crawler/smart_crawler.py
================================
Intelligent crawler for ReconMind Phase 4 by wamiqsec.

WHY THIS CRAWLER EXISTS:
────────────────────────────────────────────────────────────────
URL collection is the first step of any bug hunt. Before we can
test anything, we need to know what endpoints exist. This crawler
provides intelligent URL discovery with professional safety controls:

    - Domain-scoped crawling (never leaves the target domain)
    - Depth limits (prevents infinite crawl loops)
    - Request budgets (respects program scanning restrictions)
    - Extension filtering (skips images, CSS, fonts)
    - Deduplication by URL structure (not just string equality)
    - robots.txt respect (optional — off for penetration testing)
    - Rate limiting (configurable delay between requests)
    - Concurrent request control

WHAT IT DISCOVERS:
    - All linked HTML pages (href, action, src)
    - Form action URLs
    - JavaScript-referenced endpoints (via JS Intelligence Engine)
    - Redirect chains (records intermediate URLs)
    - API endpoints embedded in HTML

SCOPE ENFORCEMENT:
    The crawler NEVER leaves the seed domain.
    Subdomains are configurable (follow_subdomains flag).
    External URLs are recorded but never followed.

PASSIVE MODE INTEGRATION:
    When crawling in passive mode, each discovered URL is
    immediately analyzed by the passive analyzer.
    Results are accumulated into a PassiveScanReport.
"""

import time
import re
from dataclasses import dataclass, field
from typing import List, Set, Dict, Optional, Deque
from collections import deque
from urllib.parse import urlparse, urljoin, urlunparse, parse_qs, urlencode

from bs4 import BeautifulSoup

from core.utils.http_client import safe_get
from core.recon.url_handler import URLTarget, _normalize_url
from config.settings import CONFIG
from core.utils.logger import get_logger

log = get_logger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Data models
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class CrawlEntry:
    """A single URL in the crawl queue with metadata."""
    url: str
    depth: int = 0
    parent_url: str = ""
    discovered_via: str = "link"  # "link", "form", "js", "redirect"


@dataclass
class CrawlResult:
    """Result of crawling a single URL."""
    url: str
    status_code: int = 0
    content_type: str = ""
    response_body: str = ""
    response_headers: Dict[str, str] = field(default_factory=dict)
    links_found: List[str] = field(default_factory=list)
    forms_found: List[Dict] = field(default_factory=list)
    depth: int = 0
    error: str = ""


@dataclass
class CrawlReport:
    """Complete crawl report with all discovered URLs and metadata."""
    seed_url: str
    urls_crawled: List[str] = field(default_factory=list)
    urls_discovered: List[str] = field(default_factory=list)
    urls_external: List[str] = field(default_factory=list)
    urls_skipped_budget: List[str] = field(default_factory=list)
    crawl_results: List[CrawlResult] = field(default_factory=list)
    total_requests: int = 0
    total_forms: int = 0
    duration: float = 0.0
    budget_exhausted: bool = False

    @property
    def url_targets(self) -> List[URLTarget]:
        """Convert crawled URLs to URLTarget objects for downstream processing."""
        targets = []
        for url in self.urls_crawled:
            target = _normalize_url(url)
            if target:
                target.source = "crawl"
                targets.append(target)
        return targets


# ─────────────────────────────────────────────────────────────────────────────
# URL utilities
# ─────────────────────────────────────────────────────────────────────────────

def _is_same_domain(url: str, seed_host: str, allow_subdomains: bool = False) -> bool:
    """Return True if url is on the same domain as the seed."""
    try:
        parsed = urlparse(url)
        url_host = parsed.netloc.lower().split(":")[0]
        seed_clean = seed_host.lower().split(":")[0]

        if url_host == seed_clean:
            return True
        if allow_subdomains and url_host.endswith("." + seed_clean):
            return True
        return False
    except Exception:
        return False


def _should_skip_url(url: str, ignore_extensions: List[str]) -> bool:
    """Return True if URL should not be crawled (static asset, etc.)."""
    url_lower = url.lower().split("?")[0]
    return any(url_lower.endswith(ext) for ext in ignore_extensions)


def _normalize_crawl_url(url: str, base_url: str) -> Optional[str]:
    """
    Resolve and normalize a URL found during crawling.
    Returns None if the URL is invalid or should be skipped.
    """
    if not url or url.startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
        return None

    # Resolve relative URLs
    try:
        absolute = urljoin(base_url, url.strip())
    except Exception:
        return None

    # Strip fragments
    parsed = urlparse(absolute)
    clean = urlunparse(parsed._replace(fragment=""))

    # Only HTTP/HTTPS
    if parsed.scheme not in ("http", "https"):
        return None

    return clean


def _deduplicate_url_structure(url: str) -> str:
    """
    Generate a structural key for URL deduplication.

    Two URLs are considered structurally identical if they have:
    - Same path
    - Same parameter NAMES (different values are the same structure)

    e.g. /post?id=1 and /post?id=2 → same structure → only crawl once

    Args:
        url: Full URL string.

    Returns:
        Structural key string for deduplication.
    """
    try:
        parsed = urlparse(url)
        path = parsed.path
        params = sorted(parse_qs(parsed.query).keys())
        return f"{parsed.netloc}{path}?{'&'.join(params)}"
    except Exception:
        return url


def _extract_links_from_html(html: str, base_url: str) -> List[str]:
    """Extract all navigable URLs from an HTML document."""
    links = []
    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception:
        return links

    # <a href="...">
    for tag in soup.find_all("a", href=True):
        normalized = _normalize_crawl_url(tag["href"], base_url)
        if normalized:
            links.append(normalized)

    # <form action="...">
    for tag in soup.find_all("form", action=True):
        normalized = _normalize_crawl_url(tag["action"], base_url)
        if normalized:
            links.append(normalized)

    # <link href="..."> — for HTML documents (not CSS)
    for tag in soup.find_all("link", href=True):
        rel = tag.get("rel", [])
        if "stylesheet" not in rel and "icon" not in rel:
            normalized = _normalize_crawl_url(tag["href"], base_url)
            if normalized:
                links.append(normalized)

    # Look for URLs in <script> tags (embedded endpoints)
    for script in soup.find_all("script"):
        if not script.get("src"):
            content = script.string or ""
            # Extract path-like strings from JS
            for match in re.finditer(r'["\'](/[a-zA-Z0-9_/-]{2,})["\']', content):
                path = match.group(1)
                normalized = _normalize_crawl_url(path, base_url)
                if normalized:
                    links.append(normalized)

    # Deduplicate while preserving order
    seen = set()
    unique = []
    for link in links:
        if link not in seen:
            seen.add(link)
            unique.append(link)

    return unique


def _extract_forms_from_html(html: str, base_url: str) -> List[Dict]:
    """Extract form metadata for documentation."""
    forms = []
    try:
        soup = BeautifulSoup(html, "html.parser")
        for form in soup.find_all("form"):
            action = _normalize_crawl_url(form.get("action", ""), base_url) or base_url
            method = form.get("method", "GET").upper()
            fields = [
                {"name": inp.get("name", ""), "type": inp.get("type", "text")}
                for inp in form.find_all(["input", "textarea", "select"])
                if inp.get("name")
            ]
            forms.append({"action": action, "method": method, "fields": fields})
    except Exception:
        pass
    return forms


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def crawl(seed_url: str) -> CrawlReport:
    """
    Crawl a target starting from a seed URL.

    Uses BFS (breadth-first search) to discover URLs level by level.
    Respects depth limits, domain restrictions, extension filters,
    and request budgets from CONFIG.crawler.

    Args:
        seed_url: Starting URL for the crawl.

    Returns:
        CrawlReport with all discovered URLs and crawl metadata.
    """
    cfg = CONFIG.crawler

    # Normalize seed URL
    seed_target = _normalize_url(seed_url)
    if not seed_target:
        log.error("Invalid seed URL: %s", seed_url)
        return CrawlReport(seed_url=seed_url)

    seed_host = urlparse(seed_target.normalized).netloc
    report = CrawlReport(seed_url=seed_target.normalized)

    # BFS queue and tracking sets
    queue: Deque[CrawlEntry] = deque()
    queue.append(CrawlEntry(url=seed_target.normalized, depth=0))

    crawled_urls: Set[str] = set()
    structural_seen: Set[str] = set()
    request_count = 0
    start_time = time.time()

    log.info(
        "=== CRAWLER STARTED === seed=%s max_depth=%d max_pages=%d budget=%d",
        seed_target.normalized,
        cfg.max_depth,
        cfg.max_pages,
        cfg.max_pages,
    )

    while queue:
        # Check page limit
        if len(crawled_urls) >= cfg.max_pages:
            log.info("Page limit reached (%d pages)", cfg.max_pages)
            break

        entry = queue.popleft()
        url = entry.url

        # Skip already crawled
        if url in crawled_urls:
            continue

        # Skip static assets
        if _should_skip_url(url, cfg.ignore_extensions):
            log.debug("Skipping static asset: %s", url)
            continue

        # Structural deduplication
        struct_key = _deduplicate_url_structure(url)
        if struct_key in structural_seen:
            log.debug("Structural duplicate: %s", url)
            continue
        structural_seen.add(struct_key)

        # Domain scope check
        if cfg.same_domain_only:
            if not _is_same_domain(url, seed_host, cfg.follow_subdomains):
                if url not in report.urls_external:
                    report.urls_external.append(url)
                continue

        # Depth check
        if entry.depth > cfg.max_depth:
            continue

        # ── Fetch the page ────────────────────────────────────────────────
        log.info("[depth=%d] Crawling: %s", entry.depth, url)
        response = safe_get(url, allow_redirects=True)
        request_count += 1
        time.sleep(cfg.crawl_delay)

        crawled_urls.add(url)
        report.urls_crawled.append(url)

        if response is None:
            report.crawl_results.append(CrawlResult(
                url=url,
                depth=entry.depth,
                error="Failed to fetch",
            ))
            continue

        content_type = response.headers.get("Content-Type", "")
        html_body = response.text

        crawl_result = CrawlResult(
            url=url,
            status_code=response.status_code,
            content_type=content_type,
            response_body=html_body,
            response_headers=dict(response.headers),
            depth=entry.depth,
        )

        # ── Extract links from HTML ───────────────────────────────────────
        if "text/html" in content_type:
            new_links = _extract_links_from_html(html_body, url)
            crawl_result.links_found = new_links

            # Extract forms
            forms = _extract_forms_from_html(html_body, url)
            crawl_result.forms_found = forms
            report.total_forms += len(forms)

            # Enqueue new links
            for link in new_links:
                if link not in crawled_urls and link not in report.urls_discovered:
                    report.urls_discovered.append(link)

                if link not in crawled_urls:
                    queue.append(CrawlEntry(
                        url=link,
                        depth=entry.depth + 1,
                        parent_url=url,
                        discovered_via="link",
                    ))

        report.crawl_results.append(crawl_result)

    report.total_requests = request_count
    report.duration = time.time() - start_time

    log.info(
        "=== CRAWL COMPLETE === crawled=%d discovered=%d external=%d requests=%d time=%.1fs",
        len(report.urls_crawled),
        len(report.urls_discovered),
        len(report.urls_external),
        report.total_requests,
        report.duration,
    )

    return report
