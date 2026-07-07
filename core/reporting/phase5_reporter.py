"""
core/reporting/phase5_reporter.py
====================================
Phase 5 XSS Pipeline Reporter for wamiqsec/ReconMind.

Shows full evidence chain for every XSS finding: context, encoding
status, breakout feasibility, CSP impact, confidence reasoning, and
suggested exploit payload.
"""

import sys
from typing import List, Any
from config.settings import CONFIG
from core.utils.logger import get_logger

log = get_logger(__name__)


class C:
    RESET, BOLD, DIM = "\033[0m", "\033[1m", "\033[2m"
    RED, YELLOW, GREEN, CYAN, BLUE, MAGENTA, WHITE, GRAY, ORANGE = (
        "\033[91m", "\033[93m", "\033[92m", "\033[96m", "\033[94m",
        "\033[95m", "\033[97m", "\033[90m", "\033[38;5;208m",
    )


def _c(text: str, *codes: str) -> str:
    if not CONFIG.reporting.use_color or not sys.stdout.isatty():
        return text
    return "".join(codes) + text + C.RESET


SEP = "-" * 72


def _conf_bar(confidence: float) -> str:
    filled = int(confidence * 20)
    bar = "#" * filled + "." * (20 - filled)
    color = C.RED if confidence >= 0.70 else (C.YELLOW if confidence >= 0.50 else C.GRAY)
    return _c(f"[{bar}] {confidence:.0%}", color)


def _encoding_badge(encoding_status: str) -> str:
    badges = {
        "RAW": _c("NONE (raw)", C.RED, C.BOLD),
        "PARTIAL": _c("PARTIAL", C.YELLOW),
        "HTML_ENCODED": _c("HTML entities", C.GREEN),
        "JS_ENCODED": _c("JS \\u escape", C.GREEN),
        "URL_ENCODED": _c("URL %xx", C.CYAN),
        "DOUBLE_ENCODED": _c("Double-encoded", C.GREEN),
        "FILTERED": _c("FILTERED", C.GREEN),
        "NOT_REFLECTED": _c("NOT REFLECTED", C.GRAY),
    }
    return badges.get(encoding_status, _c(encoding_status, C.GRAY))


def _breakout_badge(breakout_status: str) -> str:
    if breakout_status == "FEASIBLE":
        return _c("FEASIBLE (confirmed)", C.RED, C.BOLD)
    elif breakout_status == "NOT_FEASIBLE":
        return _c("NOT FEASIBLE", C.GREEN)
    elif breakout_status == "NOT_TESTED":
        return _c("NOT TESTED", C.GRAY)
    return _c(breakout_status, C.GRAY)


def _csp_badge(csp_impact: str) -> str:
    badges = {
        "BLOCKING": _c("BLOCKING (reduces exploitability)", C.GREEN),
        "BYPASSABLE": _c("BYPASSABLE (unsafe-inline present)", C.YELLOW),
        "NONE": _c("NONE (XSS not mitigated by CSP)", C.RED),
    }
    return badges.get(csp_impact, _c(csp_impact, C.GRAY))


def print_xss_pipeline_finding(finding: Any) -> None:
    """Print a single XSSPipelineFinding with full Phase 5 detail."""
    if finding.suppressed:
        print(
            f"  {_c('[SUPPRESSED]', C.GRAY)} "
            f"{_c(finding.parameter, C.GRAY)} -- "
            f"{_c(finding.verdict, C.GRAY)} "
            f"({finding.confidence:.0%}) context={finding.context_type}"
        )
        return

    sev_color = C.RED if finding.severity in ("HIGH", "CRITICAL") else C.YELLOW
    print(f"\n  {_c('['+finding.severity+']', sev_color, C.BOLD)} "
          f"{_c('XSS', C.RED, C.BOLD)} -- "
          f"{_c(finding.verdict, sev_color, C.BOLD)}")

    lw = 22
    print(f"  {_c('URL:', C.BOLD):<{lw}} {finding.url[:90]}")
    print(f"  {_c('Parameter:', C.BOLD):<{lw}} {_c(finding.parameter, C.YELLOW, C.BOLD)} [{finding.param_type}]")
    print(f"  {_c('Context:', C.BOLD):<{lw}} {_c(finding.context_type, C.MAGENTA)}")
    print(f"  {_c('Encoding:', C.BOLD):<{lw}} {_encoding_badge(finding.encoding_status)}")
    print(f"  {_c('Breakout:', C.BOLD):<{lw}} {_breakout_badge(finding.breakout_status)}")
    print(f"  {_c('CSP Impact:', C.BOLD):<{lw}} {_csp_badge(finding.csp_impact)}")

    if finding.confirmed_payload:
        print(f"  {_c('Confirmed Payload:', C.BOLD):<{lw}} {_c(finding.confirmed_payload[:70], C.RED)}")
        print(f"  {_c('Technique:', C.BOLD):<{lw}} {finding.confirmed_technique} (Tier {finding.payload_tier})")

    if finding.evidence_lines:
        print(_c(f"\n  {SEP}", C.DIM))
        print(_c("  Evidence Chain:", C.BOLD))
        for line in finding.evidence_lines:
            if line.startswith("Confidence:"):
                continue
            print(f"    {line}")

    print(_c(f"\n  {SEP}", C.DIM))
    print(f"  {_c('Confidence:', C.BOLD):<{lw}} {_conf_bar(finding.confidence)}")

    if finding.notes:
        print(_c(f"\n  {SEP}", C.DIM))
        print(_c("  Next Steps:", C.BOLD))
        for note in finding.notes:
            print(f"    {_c('->', C.GREEN)} {note}")

    print(_c(f"\n  {SEP}", C.DIM))


def print_xss_pipeline_summary(findings: List[Any], url: str) -> None:
    """Print summary for all XSS pipeline results on a target."""
    if not findings:
        return

    reportable = [f for f in findings if not f.suppressed]
    suppressed = [f for f in findings if f.suppressed]
    rate = (len(reportable) / len(findings) * 100) if findings else 0

    print(_c(f"\n  -- XSS Pipeline Results ({rate:.0f}% signal rate) --", C.BLUE))
    print(f"  {_c('Reportable:', C.BOLD)} {len(reportable)} | {_c('Suppressed:', C.BOLD)} {len(suppressed)}")

    for f in reportable:
        print_xss_pipeline_finding(f)

    if suppressed:
        print(_c("\n  Suppressed (harmless reflections):", C.DIM))
        for f in suppressed:
            print_xss_pipeline_finding(f)


def print_phase5_xss_banner() -> None:
    print(_c("\n  +========================================================+", C.MAGENTA))
    print(_c("  |  Phase 5 XSS Engine  --  wamiqsec/ReconMind             |", C.MAGENTA, C.BOLD))
    print(_c("  |  Context-Aware . Breakout-Verified . Evidence-Driven     |", C.DIM))
    print(_c("  +========================================================+\n", C.MAGENTA))
