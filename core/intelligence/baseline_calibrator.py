"""
core/intelligence/baseline_calibrator.py
==========================================
Baseline calibration engine for ReconMind Phase 3 by wamiqsec.

WHY THIS MODULE EXISTS — THE ROOT PROBLEM IT SOLVES:
─────────────────────────────────────────────────────
Every false positive we generate comes from comparing ONE response
against ONE other response without knowing what "normal variation"
looks like for that specific endpoint.

Example of the problem:
    We request /post?id=1    → 8,420 bytes
    We request /post?id=2    → 9,100 bytes
    Current code: diff = 680 bytes > threshold → report IDOR
    Reality: blog posts have different content. 680 bytes difference is normal.

What baseline calibration fixes:
    We first request /post?id=1 THREE TIMES with the SAME parameters.
    Request 1: 8,420 bytes
    Request 2: 8,428 bytes  ← 8 byte difference (timestamp changed)
    Request 3: 8,415 bytes  ← 5 byte difference (ad content changed)

    Now we know:
    - Natural variance for this endpoint: ~13 bytes
    - Dynamic sections: timestamp field, ad slot
    - Stable content: everything else

    When we then test id=2 and get 9,100 bytes:
    - The 680 byte difference is ABOVE the calibrated tolerance
    - But we also strip dynamic sections first
    - After stripping: id=1 = 8,100 bytes, id=2 = 8,780 bytes
    - Still different? → proceed to semantic analysis
    - Are they different because it's different user data? → higher confidence
    - Are they different because it's different article content? → suppress

WHAT THIS MODULE PRODUCES:
    BaselineProfile — a statistical model of "normal" for one URL.
    Every other intelligence module consumes this profile.
"""

import re
import time
import statistics
import hashlib
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Tuple
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from core.utils.http_client import safe_get, safe_post
from core.extractor.param_extractor import Parameter, ParamType
from core.recon.url_handler import URLTarget
from core.utils.logger import get_logger

log = get_logger(__name__)

# How many clean requests to make for calibration
CALIBRATION_SAMPLES = 3

# Regex patterns for content that changes between requests for non-vulnerability reasons
DYNAMIC_CONTENT_PATTERNS = [
    # CSRF / nonce tokens
    re.compile(r'(?:csrf[_-]?token|_token|nonce|authenticity_token)["\s]*[:=]["\s]*([A-Za-z0-9+/=_-]{16,})', re.I),
    re.compile(r'<input[^>]+name=["\'](?:csrf|_token|nonce)["\'][^>]*value=["\']([^"\']+)["\']', re.I),

    # Session identifiers in body
    re.compile(r'(?:session_id|sessionid|PHPSESSID)["\s]*[:=]["\s]*([A-Za-z0-9]{20,})', re.I),

    # Unix timestamps
    re.compile(r'\b1[6-9]\d{8}\b'),         # Unix timestamp 2020+

    # ISO 8601 dates and times
    re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?'),
    re.compile(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}'),

    # Relative times ("2 hours ago", "just now")
    re.compile(r'\b(?:just now|\d+ (?:second|minute|hour|day|week|month|year)s? ago)\b', re.I),

    # Cache-busting query params in embedded URLs
    re.compile(r'[?&](?:v|ver|version|_|cb|cache_bust|t)=\d+'),

    # JWT tokens (three base64 segments)
    re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'),

    # Google Analytics / tracking IDs
    re.compile(r'UA-\d+-\d+'),
    re.compile(r"'UA-[^']+'\s*,\s*'[^']+'"),

    # Ad-related content (random impression IDs)
    re.compile(r'(?:ad_id|impression_id|click_id|pixel_id)=[A-Za-z0-9]{8,}', re.I),
]


@dataclass
class DynamicSection:
    """
    Represents a section of the response body that changes between requests.
    These sections are stripped during normalization.
    """
    pattern: str          # String or regex that identifies this section
    is_regex: bool = True
    description: str = ""


@dataclass
class BaselineProfile:
    """
    Statistical model of "normal" behavior for a specific URL + parameter.

    This is the most important data structure in Phase 3.
    Every other engine uses this to calibrate its analysis.

    Attributes:
        url:                  The URL this profile describes.
        param_name:           Which parameter was held constant.
        param_value:          The value used during calibration.
        sample_count:         How many requests were made (usually 3).
        lengths:              Raw response body lengths for each sample.
        stable_length:        Median body length (the "expected" length).
        length_variance:      Max - min of sample lengths.
        length_tolerance:     Acceptable deviation (2x variance).
        timing_median:        Median response time in seconds.
        timing_stddev:        Standard deviation of response times.
        dom_fingerprint:      Hash of stable DOM structure.
        dom_node_count:       Number of DOM nodes in stable baseline.
        content_tokens:       Set of words in stable (non-dynamic) content.
        dynamic_sections:     List of patterns found to be dynamic.
        is_authenticated:     Whether session cookies were detected.
        auth_cookies:         Names of auth-related cookies found.
        status_code:          Expected HTTP status code.
        content_type:         Expected Content-Type header value.
        calibration_ok:       True if calibration succeeded cleanly.
        error_message:        Set if calibration had issues.
    """
    url: str
    param_name: str = ""
    param_value: str = ""
    sample_count: int = 0

    lengths: List[int] = field(default_factory=list)
    stable_length: int = 0
    length_variance: int = 0
    length_tolerance: int = 0

    timing_samples: List[float] = field(default_factory=list)
    timing_median: float = 0.0
    timing_stddev: float = 0.0

    dom_fingerprint: str = ""
    dom_node_count: int = 0
    content_tokens: Set[str] = field(default_factory=set)

    dynamic_sections: List[DynamicSection] = field(default_factory=list)

    is_authenticated: bool = False
    auth_cookies: List[str] = field(default_factory=list)
    status_code: int = 200
    content_type: str = ""

    calibration_ok: bool = False
    error_message: str = ""

    def length_is_normal(self, length: int) -> bool:
        """Return True if a response length is within calibrated tolerance."""
        return abs(length - self.stable_length) <= self.length_tolerance

    def length_deviation(self, length: int) -> int:
        """Return how many bytes a length deviates from stable baseline."""
        return abs(length - self.stable_length)

    def timing_is_anomalous(self, timing: float, multiplier: float = 2.0) -> bool:
        """
        Return True if a response time is anomalously high.

        For SSRF blind detection: we need timing to be significantly
        higher than baseline before flagging it.

        Args:
            timing:     Measured response time in seconds.
            multiplier: How many stddevs above median counts as anomalous.
        """
        if self.timing_stddev == 0:
            return timing > self.timing_median * 3.0
        threshold = self.timing_median + (multiplier * self.timing_stddev)
        return timing > threshold


# ─────────────────────────────────────────────────────────────────────────────
# Helper functions
# ─────────────────────────────────────────────────────────────────────────────

AUTH_COOKIE_NAMES = {
    "session", "sessionid", "sess", "sid", "phpsessid", "aspsessionid",
    "jsessionid", "asp.net_sessionid", ".aspxauth", "auth", "token",
    "access_token", "refresh_token", "jwt", "remember_me", "remember_token",
    "user_session", "login", "_session",
}


def _detect_auth_cookies(response) -> Tuple[bool, List[str]]:
    """
    Check if the response sets authentication-related cookies.

    Args:
        response: requests.Response object.

    Returns:
        (is_authenticated: bool, auth_cookie_names: List[str])
    """
    if response is None:
        return False, []

    found = []
    for cookie in response.cookies:
        if cookie.name.lower() in AUTH_COOKIE_NAMES:
            found.append(cookie.name)

    # Also check existing request cookies
    is_auth = len(found) > 0
    return is_auth, found


def _extract_dom_fingerprint(html: str) -> Tuple[str, int]:
    """
    Build a stable structural fingerprint of an HTML document.

    We want a hash that:
    - Changes if the DOM STRUCTURE changes (different page type)
    - Stays the same if only CONTENT changes (same template, different data)

    Strategy:
        Parse HTML → extract tag names and class names only (not content)
        → hash the sorted list of (tag, classes) tuples

    Args:
        html: Raw HTML response body.

    Returns:
        (fingerprint_hash: str, node_count: int)
    """
    try:
        soup = BeautifulSoup(html, "html.parser")
        tags = []
        for tag in soup.find_all(True):
            tag_name = tag.name
            classes = " ".join(sorted(tag.get("class", [])))
            tags.append(f"{tag_name}:{classes}")

        tag_string = "|".join(sorted(tags))
        fingerprint = hashlib.md5(tag_string.encode()).hexdigest()
        return fingerprint, len(tags)

    except Exception as exc:
        log.debug("DOM fingerprint error: %s", exc)
        return "", 0


def _extract_stable_tokens(texts: List[str]) -> Set[str]:
    """
    Extract words that appear consistently across all response samples.

    "Stable tokens" are words that appear in EVERY sample.
    Dynamic words (timestamps, tokens) appear in some samples but not others.

    Args:
        texts: List of response body strings from calibration samples.

    Returns:
        Set of words that appear in ALL samples.
    """
    if not texts:
        return set()

    # Tokenize each text
    word_pattern = re.compile(r'\b[a-zA-Z]{3,}\b')  # 3+ letter words only
    token_sets = []
    for text in texts:
        # Strip HTML tags for text analysis
        try:
            soup = BeautifulSoup(text, "html.parser")
            plain_text = soup.get_text(separator=" ")
        except Exception:
            plain_text = text
        tokens = set(word_pattern.findall(plain_text.lower()))
        token_sets.append(tokens)

    # Intersection = tokens present in ALL samples
    stable = token_sets[0]
    for s in token_sets[1:]:
        stable = stable.intersection(s)

    return stable


def _identify_dynamic_sections(texts: List[str]) -> List[DynamicSection]:
    """
    Identify response sections that change between calibration requests.

    Strategy:
        1. Apply known dynamic patterns (CSRF tokens, timestamps)
        2. Find any string present in some samples but not others

    Args:
        texts: List of response body strings.

    Returns:
        List of DynamicSection objects.
    """
    found_sections = []

    # Check known patterns
    for pattern in DYNAMIC_CONTENT_PATTERNS:
        matches_across_samples = []
        for text in texts:
            matches = pattern.findall(text)
            matches_across_samples.append(set(matches))

        # If different values were found across samples, this is dynamic
        if len(matches_across_samples) > 1:
            all_values = set()
            for match_set in matches_across_samples:
                all_values.update(match_set)
            if len(all_values) > 1:  # More than 1 unique value = dynamic
                found_sections.append(DynamicSection(
                    pattern=pattern.pattern,
                    is_regex=True,
                    description=f"Dynamic content: {pattern.pattern[:50]}",
                ))

    return found_sections


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def calibrate_baseline(
    target: URLTarget,
    param: Parameter,
    n_samples: int = CALIBRATION_SAMPLES,
) -> BaselineProfile:
    """
    Build a BaselineProfile by making N clean requests and analyzing variance.

    This should be called BEFORE any injection testing on a parameter.
    The resulting profile calibrates all subsequent analysis for this
    URL + parameter combination.

    Args:
        target:    URLTarget to calibrate against.
        param:     The parameter to hold constant during calibration.
        n_samples: Number of calibration requests to make (default 3).

    Returns:
        BaselineProfile with all variance metrics populated.
    """
    log.info(
        "Calibrating baseline: %s param=%r value=%r (%d samples)",
        target.normalized, param.name, param.value, n_samples,
    )

    profile = BaselineProfile(
        url=target.normalized,
        param_name=param.name,
        param_value=param.value,
        sample_count=n_samples,
    )

    texts: List[str] = []
    lengths: List[int] = []
    timings: List[float] = []
    status_codes: List[int] = []

    # ── Collect N samples ──────────────────────────────────────────────────
    for i in range(n_samples):
        start = time.time()

        if param.param_type == ParamType.GET:
            from urllib.parse import urlencode, parse_qs, urlunparse
            parsed = urlparse(target.normalized)
            qp = parse_qs(parsed.query, keep_blank_values=True)
            qp[param.name] = [param.value]
            probe_url = urlunparse(parsed._replace(
                query=urlencode({k: v[0] for k, v in qp.items()})
            ))
            response = safe_get(probe_url)
        else:
            post_url = param.form_action or target.base_url()
            response = safe_post(post_url, data={param.name: param.value})

        elapsed = time.time() - start

        if response is None:
            log.warning("Calibration sample %d failed for %s", i + 1, target.normalized)
            continue

        texts.append(response.text)
        lengths.append(len(response.content))
        timings.append(elapsed)
        status_codes.append(response.status_code)

        # Detect auth cookies from first response
        if i == 0:
            is_auth, auth_cookies = _detect_auth_cookies(response)
            profile.is_authenticated = is_auth
            profile.auth_cookies = auth_cookies
            profile.content_type = response.headers.get("Content-Type", "")

        # Small delay between calibration requests to avoid rate limiting
        if i < n_samples - 1:
            time.sleep(0.3)

    # ── Compute statistics ─────────────────────────────────────────────────
    if not lengths:
        profile.calibration_ok = False
        profile.error_message = "All calibration requests failed"
        log.error("Baseline calibration failed: no successful responses")
        return profile

    profile.lengths = lengths
    profile.stable_length = int(statistics.median(lengths))
    profile.length_variance = max(lengths) - min(lengths)

    # Tolerance = 2x observed variance (minimum 50 bytes to handle tiny pages)
    profile.length_tolerance = max(profile.length_variance * 2, 50)

    profile.timing_samples = timings
    profile.timing_median = statistics.median(timings)
    if len(timings) > 1:
        profile.timing_stddev = statistics.stdev(timings)
    else:
        profile.timing_stddev = 0.5  # Conservative estimate

    if status_codes:
        profile.status_code = statistics.mode(status_codes)

    # ── Analyze content stability ──────────────────────────────────────────
    if texts:
        profile.content_tokens = _extract_stable_tokens(texts)
        profile.dynamic_sections = _identify_dynamic_sections(texts)

        # DOM fingerprint from first response
        dom_hash, dom_count = _extract_dom_fingerprint(texts[0])
        profile.dom_fingerprint = dom_hash
        profile.dom_node_count = dom_count

    profile.calibration_ok = True

    log.info(
        "Baseline calibrated: stable_length=%d±%d timing=%.2f±%.2fs "
        "dynamic_sections=%d auth=%s",
        profile.stable_length,
        profile.length_variance,
        profile.timing_median,
        profile.timing_stddev,
        len(profile.dynamic_sections),
        profile.is_authenticated,
    )

    return profile


def quick_calibrate(target: URLTarget) -> BaselineProfile:
    """
    Fast single-sample calibration for targets with no specific parameter.

    Used when we need a baseline for a URL but haven't yet extracted parameters.
    Less accurate than calibrate_baseline() but fast.

    Args:
        target: URLTarget to calibrate.

    Returns:
        BaselineProfile with basic metrics.
    """
    response = safe_get(target.normalized)

    if response is None:
        return BaselineProfile(
            url=target.normalized,
            calibration_ok=False,
            error_message="Could not fetch URL for calibration",
        )

    dom_hash, dom_count = _extract_dom_fingerprint(response.text)

    return BaselineProfile(
        url=target.normalized,
        sample_count=1,
        lengths=[len(response.content)],
        stable_length=len(response.content),
        length_variance=0,
        length_tolerance=100,  # Conservative for single sample
        timing_median=0.5,
        timing_stddev=0.5,
        dom_fingerprint=dom_hash,
        dom_node_count=dom_count,
        status_code=response.status_code,
        content_type=response.headers.get("Content-Type", ""),
        calibration_ok=True,
    )
