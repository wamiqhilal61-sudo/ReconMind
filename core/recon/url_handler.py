"""core/recon/url_handler.py — URL normalization, dedup, validation for wamiqsec/ReconMind."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional
from urllib.parse import urlparse, urlunparse, ParseResult
import re

from core.utils.logger import get_logger

log = get_logger(__name__)


@dataclass
class URLTarget:
    raw: str
    normalized: str
    scheme: str
    host: str
    path: str
    query: str = ""
    fragment: str = ""
    source: str = "cli"
    tags: List[str] = field(default_factory=list)

    def __repr__(self) -> str:
        return f"URLTarget({self.normalized!r})"

    def has_query_params(self) -> bool:
        return bool(self.query)

    def base_url(self) -> str:
        return f"{self.scheme}://{self.host}{self.path}"


def _add_scheme(url: str) -> str:
    if not re.match(r'^https?://', url, re.IGNORECASE):
        url = "https://" + url
    return url


def _normalize_url(raw: str) -> Optional[URLTarget]:
    raw = raw.strip()
    if not raw:
        return None
    raw = raw.strip("'\"")
    url_with_scheme = _add_scheme(raw)

    try:
        parsed: ParseResult = urlparse(url_with_scheme)
    except ValueError as exc:
        log.warning("Failed to parse URL %r: %s", raw, exc)
        return None

    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()

    if netloc.endswith(":80") and scheme == "http":
        netloc = netloc[:-3]
    elif netloc.endswith(":443") and scheme == "https":
        netloc = netloc[:-4]

    path = parsed.path if parsed.path else "/"

    if not scheme or not netloc:
        log.warning("Invalid URL (missing scheme or host): %r", raw)
        return None
    if scheme not in ("http", "https"):
        log.warning("Unsupported scheme %r in URL: %r", scheme, raw)
        return None

    clean_parsed = ParseResult(
        scheme=scheme, netloc=netloc, path=path,
        params=parsed.params, query=parsed.query, fragment=parsed.fragment,
    )
    normalized = urlunparse(clean_parsed)
    host = netloc.split(":")[0]

    return URLTarget(
        raw=raw, normalized=normalized, scheme=scheme,
        host=host, path=path, query=parsed.query,
        fragment=parsed.fragment, source="cli",
    )


def load_single_url(url: str) -> Optional[URLTarget]:
    target = _normalize_url(url)
    if target:
        target.source = "cli"
        log.info("Loaded URL: %s", target.normalized)
    else:
        log.error("Could not load URL: %r", url)
    return target


def load_urls_from_file(file_path: str) -> List[URLTarget]:
    path = Path(file_path)
    if not path.exists() or not path.is_file():
        log.error("URL file not found or invalid: %s", file_path)
        return []

    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            raw_lines = fh.readlines()
    except OSError as exc:
        log.error("Cannot read file %s: %s", file_path, exc)
        return []

    targets: List[URLTarget] = []
    seen = set()
    for line_number, line in enumerate(raw_lines, start=1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        target = _normalize_url(line)
        if target is None:
            log.warning("Line %d: invalid URL skipped -> %r", line_number, line)
            continue
        target.source = "file"
        if target.normalized in seen:
            continue
        seen.add(target.normalized)
        targets.append(target)

    log.info("File loaded: %d valid URL(s)", len(targets))
    return targets


def deduplicate_targets(targets: List[URLTarget]) -> List[URLTarget]:
    seen, unique = set(), []
    for t in targets:
        if t.normalized not in seen:
            seen.add(t.normalized)
            unique.append(t)
    return unique
