"""
core/reporting/phase2_reporter.py
===================================
Phase 2 reporting extension for ReconMind.

Why this file exists:
    Phase 1's cli_reporter handles XSS reflection scoring output.
    Phase 2 introduces four new finding types (XSS confirmed, redirect,
    LFI, SSRF, IDOR) that each have different fields and evidence formats.

    Rather than hacking Phase 1's reporter, we extend it here.
    This reporter handles Phase 2 module output and is called by main.py
    after Phase 1 reporting is complete for each target.

    Design: Each finding type gets its own print function so the output
    is always maximally informative — LFI findings show traversal depth,
    SSRF shows time-delta, IDOR shows size comparison, etc.
"""

import sys
from typing import List, Union, Any

from modules.xss.xss_tester import XSSFinding
from modules.redirects.redirect_tester import RedirectFinding
from modules.lfi.lfi_tester import LFIFinding
from modules.ssrf.ssrf_tester import SSRFFinding
from modules.idor.idor_tester import IDORFinding
from config.settings import CONFIG
from core.utils.logger import get_logger

log = get_logger(__name__)


# ---------------------------------------------------------------------------
# ANSI color helpers (mirrors cli_reporter — no circular import)
# ---------------------------------------------------------------------------

class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[91m"
    YELLOW  = "\033[93m"
    GREEN   = "\033[92m"
    CYAN    = "\033[96m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    WHITE   = "\033[97m"
    GRAY    = "\033[90m"
    ORANGE  = "\033[38;5;208m"


def _color(text: str, *codes: str) -> str:
    if not CONFIG.reporting.use_color or not sys.stdout.isatty():
        return text
    return "".join(codes) + text + C.RESET


SEP = "─" * 72

SEVERITY_COLORS = {
    "CRITICAL": C.RED + C.BOLD,
    "HIGH":     C.RED + C.BOLD,
    "MEDIUM":   C.YELLOW + C.BOLD,
    "LOW":      C.CYAN,
    "INFO":     C.GRAY,
}


def _sev(severity: str) -> str:
    color = SEVERITY_COLORS.get(severity.upper(), C.RESET)
    return _color(f"[{severity}]", color)


def _label(text: str) -> str:
    return _color(f"  {text:<20}", C.BOLD, C.WHITE)


# ---------------------------------------------------------------------------
# Per-module print functions
# ---------------------------------------------------------------------------

def print_xss_finding(finding: XSSFinding) -> None:
    """Print a confirmed XSS finding."""
    print(f"\n  {_sev(finding.severity)} {_color('XSS CONFIRMED', C.RED, C.BOLD)}")
    print(f"{_label('URL:')}{finding.url[:100]}")
    print(f"{_label('Parameter:')}{_color(finding.parameter, C.YELLOW, C.BOLD)}")
    print(f"{_label('Type:')}{finding.param_type}")
    print(f"{_label('Context:')}{_color(finding.context, C.MAGENTA)}")
    print(f"{_label('Tier:')}{finding.tier} — {finding.technique}")
    print(f"{_label('Payload:')}{_color(finding.payload[:80], C.RED)}")
    if finding.evidence:
        print(_color(f"\n  {SEP}", C.DIM))
        print(_color("  Evidence (response snippet):", C.BOLD))
        print(f"    {_color(finding.evidence[:120], C.DIM)}")
    for note in finding.notes:
        print(f"    {_color('→', C.GREEN)} {note}")
    print(_color(f"\n  {SEP}", C.DIM))


def print_redirect_finding(finding: RedirectFinding) -> None:
    """Print a confirmed open redirect finding."""
    print(f"\n  {_sev(finding.severity)} {_color('OPEN REDIRECT', C.ORANGE, C.BOLD)}")
    print(f"{_label('URL:')}{finding.url[:100]}")
    print(f"{_label('Parameter:')}{_color(finding.parameter, C.YELLOW, C.BOLD)}")
    print(f"{_label('Injected:')}{finding.injected_value}")
    print(f"{_label('Location Header:')}{_color(finding.location_header, C.RED)}")
    print(f"{_label('HTTP Status:')}{finding.response_code}")
    print(f"{_label('Technique:')}{finding.technique}")
    if finding.notes:
        print(_color(f"\n  {SEP}", C.DIM))
        print(_color("  Attack Chains:", C.BOLD))
        for note in finding.notes:
            print(f"    {_color('⚠', C.YELLOW)} {note}")
    print(_color(f"\n  {SEP}", C.DIM))


def print_lfi_finding(finding: LFIFinding) -> None:
    """Print a confirmed LFI/path traversal finding."""
    print(f"\n  {_sev(finding.severity)} {_color('LFI / PATH TRAVERSAL', C.RED, C.BOLD)}")
    print(f"{_label('URL:')}{finding.url[:100]}")
    print(f"{_label('Parameter:')}{_color(finding.parameter, C.YELLOW, C.BOLD)}")
    print(f"{_label('File Read:')}{_color(finding.target_file, C.RED)}")
    print(f"{_label('Technique:')}{finding.technique}")
    print(f"{_label('Payload:')}{finding.payload[:80]}")
    if finding.evidence:
        print(_color(f"\n  {SEP}", C.DIM))
        print(_color("  File Content Evidence:", C.BOLD))
        print(f"    {_color(finding.evidence[:120], C.DIM)}")
    if finding.notes:
        print(_color(f"\n  {SEP}", C.DIM))
        print(_color("  Next Steps:", C.BOLD))
        for note in finding.notes:
            print(f"    {_color('→', C.GREEN)} {note}")
    print(_color(f"\n  {SEP}", C.DIM))


def print_ssrf_finding(finding: SSRFFinding) -> None:
    """Print a confirmed or probable SSRF finding."""
    label = "SSRF CONFIRMED" if finding.detection_method == "direct" else "SSRF PROBABLE (time-based)"
    print(f"\n  {_sev(finding.severity)} {_color(label, C.RED, C.BOLD)}")
    print(f"{_label('URL:')}{finding.url[:100]}")
    print(f"{_label('Parameter:')}{_color(finding.parameter, C.YELLOW, C.BOLD)}")
    print(f"{_label('Injected Target:')}{_color(finding.injected_target, C.RED)}")
    print(f"{_label('Detection:')}{finding.detection_method}")
    if finding.evidence:
        print(_color(f"\n  {SEP}", C.DIM))
        print(_color("  Evidence:", C.BOLD))
        print(f"    {_color(finding.evidence[:120], C.DIM)}")
    if finding.notes:
        print(_color(f"\n  {SEP}", C.DIM))
        print(_color("  Next Steps:", C.BOLD))
        for note in finding.notes:
            print(f"    {_color('→', C.GREEN)} {note}")
    print(_color(f"\n  {SEP}", C.DIM))


def print_idor_finding(finding: IDORFinding) -> None:
    """Print a probable IDOR finding."""
    print(f"\n  {_sev(finding.severity)} {_color('IDOR / BROKEN ACCESS CONTROL', C.YELLOW, C.BOLD)}")
    print(f"{_label('URL:')}{finding.url[:100]}")
    print(f"{_label('Parameter:')}{_color(finding.parameter, C.YELLOW, C.BOLD)}")
    print(f"{_label('Original ID:')}{finding.original_value}")
    print(f"{_label('Tested ID:')}{_color(finding.tested_value, C.MAGENTA)}")
    if finding.size_difference > 0:
        print(f"{_label('Size Diff:')}{finding.size_difference} bytes  "
              f"({finding.original_size} → {finding.probe_size})")
    if finding.evidence:
        print(_color(f"\n  {SEP}", C.DIM))
        print(_color("  Evidence:", C.BOLD))
        print(f"    {_color(finding.evidence[:120], C.DIM)}")
    if finding.notes:
        print(_color(f"\n  {SEP}", C.DIM))
        print(_color("  Verification Steps:", C.BOLD))
        for note in finding.notes:
            print(f"    {_color('→', C.GREEN)} {note}")
    print(_color(f"\n  {SEP}", C.DIM))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def print_phase2_findings(target: Any) -> None:
    """
    Print all Phase 2 module findings attached to a URLTarget.

    Called by main.py after Phase 1 reporting is done for each target.
    Reads finding lists dynamically attached to target by each module.

    Args:
        target: URLTarget with Phase 2 finding lists attached.
    """
    xss_findings    = getattr(target, "xss_findings", [])
    redirect_findings = getattr(target, "redirect_findings", [])
    lfi_findings    = getattr(target, "lfi_findings", [])
    ssrf_findings   = getattr(target, "ssrf_findings", [])
    idor_findings   = getattr(target, "idor_findings", [])

    any_findings = any([
        xss_findings, redirect_findings, lfi_findings, ssrf_findings, idor_findings
    ])

    if not any_findings:
        return

    print(_color("\n  ── Phase 2 Module Findings ──────────────────────────────────────",
                 C.BLUE, C.BOLD))

    for f in xss_findings:
        print_xss_finding(f)

    for f in redirect_findings:
        print_redirect_finding(f)

    for f in lfi_findings:
        print_lfi_finding(f)

    for f in ssrf_findings:
        print_ssrf_finding(f)

    for f in idor_findings:
        print_idor_finding(f)


def print_phase2_summary(
    all_xss: List[XSSFinding],
    all_redirects: List[RedirectFinding],
    all_lfi: List[LFIFinding],
    all_ssrf: List[SSRFFinding],
    all_idor: List[IDORFinding],
) -> None:
    """
    Print the Phase 2 findings summary table at end of scan.

    Args:
        all_*: Combined finding lists across all targets.
    """
    total = len(all_xss) + len(all_redirects) + len(all_lfi) + len(all_ssrf) + len(all_idor)
    if total == 0:
        return

    print(_color("\n  ── Phase 2 Module Summary ───────────────────────────────────────",
                 C.BLUE, C.BOLD))
    print()

    rows = [
        ("XSS",      len(all_xss),      C.RED),
        ("Redirect", len(all_redirects), C.ORANGE),
        ("LFI",      len(all_lfi),       C.RED),
        ("SSRF",     len(all_ssrf),      C.RED),
        ("IDOR",     len(all_idor),       C.YELLOW),
    ]

    for module_name, count, color in rows:
        bar = "█" * min(count, 40)
        print(f"  {_color(f'{module_name:<10}', C.BOLD)} "
              f"{_color(str(count).rjust(3), color)}  "
              f"{_color(bar, color)}")

    print()
    print(f"  {_color('Total Phase 2 findings:', C.BOLD, C.WHITE)} "
          f"{_color(str(total), C.RED, C.BOLD)}")
    print()
