"""
core/reporting/json_reporter.py
=================================
JSON report exporter for ReconMind by wamiqsec.

Why this file exists:
    CLI output is for humans reading a terminal. JSON output is for:
        1. Importing into Burp Suite, Jira, or custom dashboards
        2. CI/CD pipelines that parse findings and block on HIGH severity
        3. Sharing findings with the bug bounty program in structured format
        4. Feeding data into Phase 3's AI analysis layer
        5. Diffing scan results between runs ("what's new since yesterday?")

Report structure:
    {
        "meta": {scan metadata},
        "summary": {counts by severity and module},
        "targets": [{url, params_found, findings: []}],
        "findings": [{all finding fields flattened}]
    }

The report is written to reports/wamiqsec_reconmind_<timestamp>.json
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

from config.settings import CONFIG
from core.utils.logger import get_logger

log = get_logger(__name__)

TOOL_NAME = "wamiqsec-ReconMind"
TOOL_VERSION = "2.0.0"
TOOL_AUTHOR = "wamiqsec"


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------

def _finding_to_dict(finding: Any, module: str) -> Dict[str, Any]:
    """
    Convert any finding dataclass to a JSON-serializable dict.

    Uses __dict__ for the base data and adds a 'module' key.
    Handles non-serializable types (datetime, bytes) gracefully.

    Args:
        finding: Any Phase 1 or Phase 2 finding dataclass.
        module:  Module name string for tagging.

    Returns:
        JSON-serializable dict.
    """
    try:
        base = finding.__dict__.copy()
    except AttributeError:
        base = dict(finding)

    # Add module tag
    base["module"] = module
    base["tool"] = TOOL_NAME

    # Convert any non-serializable values to strings
    for key, val in base.items():
        if hasattr(val, "__dict__"):
            # Nested dataclass — recurse one level
            base[key] = str(val)
        elif isinstance(val, bytes):
            base[key] = val.decode("utf-8", errors="replace")

    return base


def _extract_url(finding: Any) -> str:
    """Extract URL from any finding object."""
    return getattr(finding, "url", getattr(finding, "normalized", "unknown"))


def _extract_severity(finding: Any) -> str:
    """Extract severity from any finding object."""
    return getattr(finding, "severity", "INFO")


# ---------------------------------------------------------------------------
# Report builder
# ---------------------------------------------------------------------------

def build_json_report(
    targets: List[Any],
    phase1_findings: List[Any],
    xss_findings: List[Any],
    redirect_findings: List[Any],
    lfi_findings: List[Any],
    ssrf_findings: List[Any],
    idor_findings: List[Any],
    scan_duration: float,
    command_used: str = "",
) -> Dict[str, Any]:
    """
    Build the complete JSON report structure.

    Args:
        targets:           All URLTarget objects that were scanned.
        phase1_findings:   Phase 1 ScoredFinding list.
        xss_findings:      Phase 2 XSSFinding list.
        redirect_findings: Phase 2 RedirectFinding list.
        lfi_findings:      Phase 2 LFIFinding list.
        ssrf_findings:     Phase 2 SSRFFinding list.
        idor_findings:     Phase 2 IDORFinding list.
        scan_duration:     Total seconds the scan ran.
        command_used:      CLI command string (for audit trail).

    Returns:
        Full report as a dict ready for json.dumps().
    """
    now = datetime.utcnow().isoformat() + "Z"

    # Flatten all findings into one list with module tags
    all_findings_raw = (
        [_finding_to_dict(f, "XSS_REFLECT") for f in phase1_findings] +
        [_finding_to_dict(f, "XSS") for f in xss_findings] +
        [_finding_to_dict(f, "REDIRECT") for f in redirect_findings] +
        [_finding_to_dict(f, "LFI") for f in lfi_findings] +
        [_finding_to_dict(f, "SSRF") for f in ssrf_findings] +
        [_finding_to_dict(f, "IDOR") for f in idor_findings]
    )

    # Build severity counts
    severity_counts: Dict[str, int] = {
        "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0
    }
    module_counts: Dict[str, int] = {}
    for f in all_findings_raw:
        sev = f.get("severity", "INFO").upper()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        mod = f.get("module", "UNKNOWN")
        module_counts[mod] = module_counts.get(mod, 0) + 1

    # Build per-target summary
    target_summaries = []
    for t in targets:
        t_params = len(getattr(t, "parameters", []))
        t_url = getattr(t, "normalized", str(t))
        t_findings = [f for f in all_findings_raw if t_url in f.get("url", "")]
        target_summaries.append({
            "url": t_url,
            "host": getattr(t, "host", ""),
            "scheme": getattr(t, "scheme", ""),
            "parameters_found": t_params,
            "http_status": getattr(t, "http_status", 0),
            "finding_count": len(t_findings),
        })

    report = {
        "meta": {
            "tool": TOOL_NAME,
            "version": TOOL_VERSION,
            "author": TOOL_AUTHOR,
            "generated_at": now,
            "scan_duration_seconds": round(scan_duration, 2),
            "command": command_used,
            "targets_scanned": len(targets),
        },
        "summary": {
            "total_findings": len(all_findings_raw),
            "by_severity": severity_counts,
            "by_module": module_counts,
        },
        "targets": target_summaries,
        "findings": all_findings_raw,
    }

    return report


# ---------------------------------------------------------------------------
# File writer
# ---------------------------------------------------------------------------

def save_json_report(
    report: Dict[str, Any],
    output_dir: Optional[str] = None,
    filename: Optional[str] = None,
) -> str:
    """
    Write the JSON report to disk.

    File naming: wamiqsec_reconmind_<YYYYMMDD_HHMMSS>.json

    Args:
        report:     Report dict from build_json_report().
        output_dir: Directory to write to (defaults to CONFIG.reporting.output_dir).
        filename:   Override filename (auto-generated if None).

    Returns:
        Absolute path of the written file.
    """
    out_dir = Path(output_dir or CONFIG.reporting.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    if not filename:
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"wamiqsec_reconmind_{ts}.json"

    output_path = out_dir / filename

    try:
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, ensure_ascii=False, default=str)

        size_kb = output_path.stat().st_size / 1024
        log.info(
            "JSON report saved: %s (%.1f KB, %d findings)",
            output_path, size_kb, report["summary"]["total_findings"],
        )
        return str(output_path.resolve())

    except OSError as exc:
        log.error("Failed to write JSON report: %s", exc)
        return ""


def save_markdown_report(
    report: Dict[str, Any],
    output_dir: Optional[str] = None,
    filename: Optional[str] = None,
) -> str:
    """
    Write a Markdown summary report for easy sharing.

    Generates a clean .md file suitable for:
        - Bug bounty submission reports
        - GitHub/GitLab issue tracking
        - Team Slack/Discord sharing

    Args:
        report:     Report dict from build_json_report().
        output_dir: Output directory.
        filename:   Override filename.

    Returns:
        Absolute path of the written Markdown file.
    """
    out_dir = Path(output_dir or CONFIG.reporting.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    if not filename:
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"wamiqsec_reconmind_{ts}.md"

    output_path = out_dir / filename
    meta = report["meta"]
    summary = report["summary"]
    findings = report["findings"]

    lines = [
        f"# wamiqsec — ReconMind Scan Report",
        f"",
        f"**Generated:** {meta['generated_at']}  ",
        f"**Tool:** {meta['tool']} v{meta['version']}  ",
        f"**Author:** {meta['author']}  ",
        f"**Duration:** {meta['scan_duration_seconds']}s  ",
        f"**Targets:** {meta['targets_scanned']}  ",
        f"",
        f"---",
        f"",
        f"## Summary",
        f"",
        f"| Severity | Count |",
        f"|----------|-------|",
    ]

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = summary["by_severity"].get(sev, 0)
        lines.append(f"| {sev} | {count} |")

    lines += [
        f"",
        f"| Module | Count |",
        f"|--------|-------|",
    ]
    for mod, count in sorted(summary["by_module"].items()):
        lines.append(f"| {mod} | {count} |")

    lines += [
        f"",
        f"---",
        f"",
        f"## Findings",
        f"",
    ]

    # Group by severity
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        sev_findings = [f for f in findings if f.get("severity", "").upper() == sev]
        if not sev_findings:
            continue

        lines.append(f"### {sev} ({len(sev_findings)})")
        lines.append("")

        for i, f in enumerate(sev_findings, 1):
            module = f.get("module", "?")
            param = f.get("parameter", "?")
            url = f.get("url", "?")
            payload = f.get("payload", "")
            evidence = f.get("evidence", "")
            context = f.get("context", "")
            notes = f.get("notes", [])
            reasons = f.get("reasons", [])

            lines.append(f"#### {i}. [{module}] Parameter: `{param}`")
            lines.append(f"")
            lines.append(f"- **URL:** `{url}`")
            if context:
                lines.append(f"- **Context:** {context}")
            if payload:
                lines.append(f"- **Payload:** `{payload[:100]}`")
            if evidence:
                lines.append(f"- **Evidence:** `{evidence[:120]}`")
            if reasons:
                lines.append(f"")
                lines.append(f"**Why it was flagged:**")
                for r in reasons[:5]:
                    lines.append(f"  - {r}")
            if notes:
                lines.append(f"")
                lines.append(f"**Analyst Notes:**")
                for n in notes[:3]:
                    lines.append(f"  - {n}")
            lines.append("")

    lines += [
        f"---",
        f"",
        f"*Report generated by [wamiqsec/ReconMind](https://github.com/wamiqsec)*",
        f"",
        f"> **Legal notice:** This tool is for authorized security testing only.",
    ]

    try:
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))

        log.info("Markdown report saved: %s", output_path)
        return str(output_path.resolve())

    except OSError as exc:
        log.error("Failed to write Markdown report: %s", exc)
        return ""
