"""
core/reporting/phase4_reporter.py
====================================
Phase 4 reporting engine for ReconMind by wamiqsec.

Handles output for:
    - Passive Mode results (surface map, JS findings, security headers)
    - Active Mode results (IDOR/SSRF/SQLi/CSRF with confidence scores)
    - Manual-Assist hunting guide references
    - Three-mode scan summaries
"""

import sys
from typing import List, Optional, Any, Dict
from datetime import datetime

from config.settings import CONFIG
from core.utils.logger import get_logger

log = get_logger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# ANSI colors
# ─────────────────────────────────────────────────────────────────────────────

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


def _c(text: str, *codes: str) -> str:
    if not CONFIG.reporting.use_color or not sys.stdout.isatty():
        return text
    return "".join(codes) + text + C.RESET


SEP  = "─" * 72
TSEP = "═" * 72

SEVERITY_COLORS = {
    "CRITICAL": C.RED + C.BOLD,
    "HIGH":     C.RED + C.BOLD,
    "MEDIUM":   C.YELLOW + C.BOLD,
    "LOW":      C.CYAN,
    "INFO":     C.GRAY,
}

CONFIDENCE_COLORS = {
    "AUTO_HIGH":  C.RED + C.BOLD,
    "MEDIUM":     C.YELLOW,
    "LOW":        C.CYAN,
    "SUPPRESSED": C.GRAY,
}


def _sev(s: str) -> str:
    return _c(f"[{s}]", SEVERITY_COLORS.get(s.upper(), C.RESET))


def _conf(pct: float) -> str:
    """Render confidence percentage with color."""
    if pct >= 0.85:
        return _c(f"{pct:.0%}", C.RED, C.BOLD)
    elif pct >= 0.65:
        return _c(f"{pct:.0%}", C.YELLOW)
    elif pct >= 0.45:
        return _c(f"{pct:.0%}", C.CYAN)
    return _c(f"{pct:.0%}", C.GRAY)


def _label(text: str) -> str:
    return _c(f"  {text:<22}", C.BOLD, C.WHITE)


def _section(text: str) -> str:
    return _c(f"\n  {'─'*68}\n  {text}", C.BLUE, C.BOLD)


# ─────────────────────────────────────────────────────────────────────────────
# Mode banner
# ─────────────────────────────────────────────────────────────────────────────

def print_mode_banner(mode: str) -> None:
    """Print which operating mode is active."""
    mode_labels = {
        "passive":       ("PASSIVE RECON MODE",  C.GREEN,  "Safe surface mapping — no payloads"),
        "active":        ("ACTIVE VALIDATION MODE", C.RED, "Intelligent payload testing"),
        "manual":        ("MANUAL-ASSIST MODE",  C.CYAN,   "Hunting guide generation"),
        "full":          ("FULL SCAN MODE",       C.YELLOW, "Passive + Active + Guide"),
    }
    label, color, desc = mode_labels.get(mode, ("SCAN MODE", C.WHITE, ""))
    print(_c(f"\n  ╔{'═'*70}╗", color))
    print(_c(f"  ║  {label:<68}║", color, C.BOLD))
    print(_c(f"  ║  {desc:<68}║", C.DIM))
    print(_c(f"  ╚{'═'*70}╝\n", color))


# ─────────────────────────────────────────────────────────────────────────────
# Passive Mode reporting
# ─────────────────────────────────────────────────────────────────────────────

def print_passive_target_summary(result: Any) -> None:
    """Print passive analysis summary for one target."""
    classification = result.classification
    page_type = getattr(classification, "page_type", "UNKNOWN") if classification else "UNKNOWN"
    confidence = getattr(classification, "confidence", 0) if classification else 0

    type_color = {
        "ADMIN": C.RED, "API": C.CYAN, "AUTH": C.YELLOW,
        "UPLOAD": C.ORANGE, "GRAPHQL": C.MAGENTA,
    }.get(page_type, C.WHITE)

    print(f"\n  {_c('URL:', C.BOLD)} {result.url[:80]}")
    print(f"  {_c('Type:', C.BOLD)} {_c(page_type, type_color)} "
          f"({confidence:.0%}) | "
          f"{_c('Priority:', C.BOLD)} {_sev(result.priority_label)} "
          f"| Score: {result.interest_score}")

    # Parameters
    if result.parameters:
        p_count = len(result.parameters)
        numeric = sum(1 for p in result.parameters if p.value.isdigit())
        print(f"  {_c('Params:', C.BOLD)} {p_count} total | {numeric} numeric")

    # JS findings
    if result.js_intelligence and result.js_intelligence.has_findings:
        js = result.js_intelligence
        parts = []
        if js.endpoints:
            parts.append(f"{len(js.endpoints)} endpoints")
        if js.secrets:
            parts.append(_c(f"{len(js.secrets)} SECRETS", C.RED, C.BOLD))
        if js.high_priority_sinks:
            parts.append(_c(f"{len(js.high_priority_sinks)} DOM-XSS sinks", C.YELLOW))
        if js.routes:
            admin_r = [r for r in js.routes if r.is_admin_route]
            if admin_r:
                parts.append(_c(f"{len(admin_r)} admin routes", C.RED))
        if parts:
            print(f"  {_c('JS Intel:', C.BOLD)} {' | '.join(parts)}")

    # Security header issues
    if result.passive_analysis:
        pa = result.passive_analysis
        if pa.high_count or pa.medium_count:
            print(f"  {_c('Headers:', C.BOLD)} "
                  f"{_c(f'{pa.high_count} HIGH', C.RED)} | "
                  f"{_c(f'{pa.medium_count} MEDIUM', C.YELLOW)}")
        if pa.csp and pa.csp.bypass_vectors:
            print(f"  {_c('CSP:', C.BOLD)} "
                  f"{_c('BYPASS VECTORS: ' + str(len(pa.csp.bypass_vectors)), C.RED)}")
        if pa.cors and pa.cors.severity in ("HIGH", "MEDIUM"):
            print(f"  {_c('CORS:', C.BOLD)} "
                  f"{_c(pa.cors.issue[:60], C.YELLOW)}")

    # Why interesting
    if result.priority_reasons:
        print(f"  {_c('Why:', C.BOLD)}", end="")
        for i, reason in enumerate(result.priority_reasons[:3]):
            prefix = "\n              " if i > 0 else " "
            print(f"{prefix}{_c('•', C.CYAN)} {reason}")


def print_passive_scan_report(report: Any) -> None:
    """Print the complete passive scan report."""
    print(_section("PASSIVE RECON — SURFACE MAP"))
    print()

    # Stats bar
    print(f"  {_c('URLs analyzed:', C.BOLD)}    {report.total_urls_analyzed}")
    print(f"  {_c('Requests made:', C.BOLD)}    {report.total_requests_made}")
    print(f"  {_c('Params found:', C.BOLD)}     {report.total_params_found}")
    print(f"  {_c('JS secrets:', C.BOLD)}       "
          f"{_c(str(report.total_js_secrets), C.RED if report.total_js_secrets else C.WHITE)}")
    print(f"  {_c('DOM-XSS sinks:', C.BOLD)}   "
          f"{_c(str(report.total_dom_sinks), C.YELLOW if report.total_dom_sinks else C.WHITE)}")
    print(f"  {_c('JS endpoints:', C.BOLD)}    {len(report.all_endpoints_found)}")
    print(f"  {_c('GraphQL:', C.BOLD)}          "
          f"{_c(str(len(report.graphql_endpoints)), C.MAGENTA) if report.graphql_endpoints else '0'}")
    print(f"  {_c('CORS issues:', C.BOLD)}      "
          f"{_c(str(report.cors_misconfigs), C.RED) if report.cors_misconfigs else '0'}")
    print(f"  {_c('Duration:', C.BOLD)}         {report.scan_duration:.1f}s")

    if report.tech_stack:
        print(f"  {_c('Tech Stack:', C.BOLD)}     {', '.join(sorted(report.tech_stack))}")

    # Missing security headers
    if report.missing_security_headers:
        print(f"\n  {_c('Missing Security Headers:', C.BOLD, C.YELLOW)}")
        for header, count in sorted(report.missing_security_headers.items(), key=lambda x: -x[1]):
            print(f"    {_c('!', C.YELLOW)} {header} — missing on {count} URL(s)")

    # HIGH priority targets
    if report.high_priority_targets:
        print(_section(f"HIGH PRIORITY TARGETS ({len(report.high_priority_targets)})"))
        for result in report.high_priority_targets[:10]:
            print_passive_target_summary(result)

    # Discovered endpoints from JS
    if report.all_endpoints_found:
        print(_section(f"JS-EXTRACTED ENDPOINTS ({len(report.all_endpoints_found)})"))
        for ep in report.all_endpoints_found[:20]:
            print(f"    {_c('→', C.CYAN)} {ep}")
        if len(report.all_endpoints_found) > 20:
            print(f"    {_c(f'... and {len(report.all_endpoints_found)-20} more', C.DIM)}")

    # Discovered routes
    if report.all_routes:
        unique_routes = list(set(report.all_routes))
        admin_routes = [r for r in unique_routes if any(
            kw in r.lower() for kw in ["admin", "management", "dashboard", "config"]
        )]
        if admin_routes:
            print(_section(f"ADMIN ROUTES IN JS ({len(admin_routes)})"))
            for route in admin_routes[:15]:
                print(f"    {_c('★', C.RED)} {route}")

    print()


# ─────────────────────────────────────────────────────────────────────────────
# Active Mode reporting
# ─────────────────────────────────────────────────────────────────────────────

def print_idor_result(result: Any) -> None:
    """Print a Phase 3 IDOR result."""
    if result.suppressed:
        return
    print(f"\n  {_sev(result.severity)} {_c('IDOR CANDIDATE', C.YELLOW, C.BOLD)} "
          f"— confidence: {_conf(result.confidence)}")
    print(f"{_label('URL:')}{result.url[:90]}")
    print(f"{_label('Parameter:')}{_c(result.parameter, C.YELLOW, C.BOLD)}")
    print(f"{_label('IDs tested:')}{result.original_id} → {_c(result.tested_id, C.MAGENTA)}")
    print(f"{_label('FP Risk:')}{result.false_positive_risk}")
    if result.bundle and result.bundle.full_evidence:
        print(_c(f"\n  {SEP}", C.DIM))
        print(_c("  Evidence Chain:", C.BOLD))
        for line in result.bundle.full_evidence[:6]:
            print(f"    {line}")
    if result.notes:
        print(_c(f"\n  {SEP}", C.DIM))
        print(_c("  Next Steps:", C.BOLD))
        for note in result.notes[:3]:
            print(f"    {_c('→', C.GREEN)} {note}")
    print(_c(f"\n  {SEP}", C.DIM))


def print_ssrf_result(result: Any) -> None:
    """Print a Phase 3 SSRF result."""
    if result.suppressed:
        return
    method_label = "SSRF CONFIRMED" if result.detection_method == "direct" else "SSRF PROBABLE"
    print(f"\n  {_sev(result.severity)} {_c(method_label, C.RED, C.BOLD)} "
          f"— confidence: {_conf(result.confidence)}")
    print(f"{_label('URL:')}{result.url[:90]}")
    print(f"{_label('Parameter:')}{_c(result.parameter, C.YELLOW, C.BOLD)}")
    print(f"{_label('Target:')}{_c(result.injected_target, C.RED)}")
    print(f"{_label('Method:')}{result.detection_method}")
    if result.evidence:
        print(_c(f"\n  {SEP}", C.DIM))
        print(_c("  Evidence:", C.BOLD))
        print(f"    {_c(result.evidence[:120], C.DIM)}")
    if result.notes:
        print(_c(f"\n  {SEP}", C.DIM))
        for note in result.notes[:3]:
            print(f"    {_c('→', C.GREEN)} {note}")
    print(_c(f"\n  {SEP}", C.DIM))


def print_sqli_result(result: Any) -> None:
    """Print a Phase 3 SQLi result."""
    if result.suppressed:
        return
    print(f"\n  {_sev(result.severity)} {_c('SQL INJECTION', C.RED, C.BOLD)} "
          f"— confidence: {_conf(result.confidence)}")
    print(f"{_label('URL:')}{result.url[:90]}")
    print(f"{_label('Parameter:')}{_c(result.parameter, C.YELLOW, C.BOLD)}")
    print(f"{_label('Database:')}{_c(result.detected_database, C.MAGENTA)}")
    print(f"{_label('Techniques:')}{', '.join(result.techniques_confirmed)}")
    if result.bundle and result.bundle.full_evidence:
        print(_c(f"\n  {SEP}", C.DIM))
        print(_c("  Evidence Chain:", C.BOLD))
        for line in result.bundle.full_evidence[:5]:
            print(f"    {line}")
    if result.notes:
        print(_c(f"\n  {SEP}", C.DIM))
        for note in result.notes[:3]:
            print(f"    {_c('→', C.GREEN)} {note}")
    print(_c(f"\n  {SEP}", C.DIM))


def print_csrf_result(result: Any) -> None:
    """Print a CSRF result."""
    if result.suppressed:
        return
    print(f"\n  {_sev(result.severity)} {_c('CSRF', C.ORANGE, C.BOLD)} "
          f"— confidence: {_conf(result.confidence)}")
    print(f"{_label('URL:')}{result.url[:90]}")
    print(f"{_label('Method:')}{result.method}")
    print(f"{_label('Token found:')}{_c('YES', C.GREEN) if result.token_found else _c('NO', C.RED)}")
    print(f"{_label('Missing rejected:')}"
          f"{_c('YES', C.GREEN) if result.missing_token_rejected else _c('NO — VULNERABLE', C.RED)}")
    print(f"{_label('Wrong rejected:')}"
          f"{_c('YES', C.GREEN) if result.wrong_token_rejected else _c('NO — VULNERABLE', C.RED)}")
    print(f"{_label('SameSite:')}{result.samesite_protection or _c('MISSING', C.RED)}")
    if result.evidence:
        print(_c(f"\n  {SEP}", C.DIM))
        print(f"    {_c(result.evidence, C.DIM)}")
    if result.notes:
        print(_c(f"\n  {SEP}", C.DIM))
        for note in result.notes[:3]:
            print(f"    {_c('→', C.GREEN)} {note}")
    print(_c(f"\n  {SEP}", C.DIM))


def print_active_scan_result(result: Any) -> None:
    """Print complete active scan result for one target."""
    classification = result.classification
    page_type = getattr(classification, "page_type", "UNKNOWN") if classification else "UNKNOWN"

    print(_section(f"ACTIVE RESULTS — {result.url[:60]}"))
    print(f"  {_c('Page type:', C.BOLD)} {page_type} | "
          f"{_c('Modules run:', C.BOLD)} {', '.join(result.modules_run) or 'none'}")
    print(f"  {_c('Reportable:', C.BOLD)} {result.total_reportable} | "
          f"{_c('Suppressed:', C.BOLD)} {result.total_suppressed} | "
          f"{_c('Duration:', C.BOLD)} {result.scan_duration:.1f}s")

    if not result.all_reportable:
        print(f"  {_c('No reportable findings for this target.', C.DIM)}")
        return

    for r in result.idor_results:
        print_idor_result(r)
    for r in result.ssrf_results:
        print_ssrf_result(r)
    for r in result.sqli_results:
        print_sqli_result(r)
    for r in result.csrf_results:
        print_csrf_result(r)

    # Phase 2 findings (XSS, LFI, Redirect)
    from core.reporting.phase2_reporter import (
        print_xss_finding, print_lfi_finding, print_redirect_finding,
    )
    for f in result.xss_findings:
        print_xss_finding(f)
    for f in result.lfi_findings:
        print_lfi_finding(f)
    for f in result.redirect_findings:
        print_redirect_finding(f)


# ─────────────────────────────────────────────────────────────────────────────
# Full scan summary
# ─────────────────────────────────────────────────────────────────────────────

def print_phase4_final_summary(
    mode: str,
    passive_report: Optional[Any],
    active_results: Optional[List[Any]],
    hunting_guide: Optional[Any],
    elapsed: float,
) -> None:
    """
    Print the complete final summary for a Phase 4 scan.

    Args:
        mode:           Operating mode string.
        passive_report: PassiveScanReport (if passive/full/manual mode).
        active_results: List of ActiveScanResult (if active/full mode).
        hunting_guide:  HuntingGuide (if manual/full mode).
        elapsed:        Total scan duration in seconds.
    """
    print(_c(f"\n  {'═'*70}", C.BLUE))
    print(_c("  RECONMIND SCAN COMPLETE — wamiqsec", C.BLUE, C.BOLD))
    print(_c(f"  {'═'*70}\n", C.BLUE))

    print(f"  {_c('Mode:', C.BOLD)}         {mode.upper()}")
    print(f"  {_c('Duration:', C.BOLD)}     {elapsed:.1f}s")
    print(f"  {_c('Completed:', C.BOLD)}    "
          f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    # Passive summary
    if passive_report:
        print(f"  {_c('── PASSIVE RECON ──────────────────────────────────', C.GREEN)}")
        print(f"  URLs analyzed:      {passive_report.total_urls_analyzed}")
        print(f"  Requests made:      {passive_report.total_requests_made}")
        print(f"  Parameters found:   {passive_report.total_params_found}")
        print(f"  JS secrets found:   "
              f"{_c(str(passive_report.total_js_secrets), C.RED if passive_report.total_js_secrets else C.WHITE)}")
        print(f"  DOM-XSS sinks:     "
              f"{_c(str(passive_report.total_dom_sinks), C.YELLOW if passive_report.total_dom_sinks else C.WHITE)}")
        print(f"  HIGH priority:      {len(passive_report.high_priority_targets)}")
        print(f"  MEDIUM priority:    {len(passive_report.medium_priority_targets)}")
        print()

    # Active summary
    if active_results:
        total_r = sum(r.total_reportable for r in active_results)
        total_s = sum(r.total_suppressed for r in active_results)
        total_tested = len(active_results)
        reduction = total_s / max(1, total_s + total_r) * 100

        # Count by type
        idor_r   = sum(1 for r in active_results for f in r.idor_results if not f.suppressed)
        ssrf_r   = sum(1 for r in active_results for f in r.ssrf_results if not f.suppressed)
        sqli_r   = sum(1 for r in active_results for f in r.sqli_results if not f.suppressed)
        csrf_r   = sum(1 for r in active_results for f in r.csrf_results if not f.suppressed)
        xss_r    = sum(len(r.xss_findings) for r in active_results)
        lfi_r    = sum(len(r.lfi_findings) for r in active_results)
        redir_r  = sum(len(r.redirect_findings) for r in active_results)

        print(f"  {_c('── ACTIVE VALIDATION ──────────────────────────────', C.RED)}")
        print(f"  Targets tested:     {total_tested}")
        print(f"  Total reportable:   {_c(str(total_r), C.RED if total_r else C.WHITE)}")
        print(f"  Suppressed:         {total_s} ({reduction:.0f}% FP reduction)")
        print()
        if idor_r:
            print(f"    {_c('IDOR:', C.YELLOW)}       {idor_r} candidate(s) — manual verify required")
        if ssrf_r:
            print(f"    {_c('SSRF:', C.RED)}       {ssrf_r} finding(s)")
        if sqli_r:
            print(f"    {_c('SQLi:', C.RED)}       {sqli_r} finding(s)")
        if csrf_r:
            print(f"    {_c('CSRF:', C.ORANGE)}       {csrf_r} finding(s)")
        if xss_r:
            print(f"    {_c('XSS:', C.RED)}        {xss_r} finding(s)")
        if lfi_r:
            print(f"    {_c('LFI:', C.RED)}        {lfi_r} finding(s)")
        if redir_r:
            print(f"    {_c('Redirect:', C.YELLOW)}   {redir_r} finding(s)")
        print()

    # Hunting guide
    if hunting_guide:
        print(f"  {_c('── MANUAL-ASSIST GUIDE ────────────────────────────', C.CYAN)}")
        print(f"  Priority targets:   {len(hunting_guide.targets)}")
        print(f"  Quick wins:         {len(hunting_guide.quick_wins)}")
        print(f"  Chain suggestions:  {len(hunting_guide.chain_suggestions)}")
        print()
        if hunting_guide.quick_wins:
            print(f"  {_c('Top Quick Wins:', C.BOLD)}")
            for win in hunting_guide.quick_wins[:3]:
                print(f"    {_c('★', C.YELLOW)} {win[:80]}")
        print()

    print(_c(f"  {'═'*70}", C.BLUE))
    print()
