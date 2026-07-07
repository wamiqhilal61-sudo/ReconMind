"""
main.py
========
wamiqsec — ReconMind
Phase 5 — Context-Aware Exploitability & Intelligent XSS Validation

Pipeline:
    URL Input -> Parameter Extraction -> Reflection Probing
        -> [Phase 5] Encoding Analysis -> Context Detection
        -> Breakout Analysis -> Exploitability Scoring
        -> Payload Confirmation -> Reporting

USAGE:
    python main.py -u "https://target.com/page?q=test"
    python main.py -f urls.txt --save-json
    python main.py -u "https://target.com/page?q=test" --debug
    python main.py --query --query-severity HIGH

LEGAL:
    For authorized security testing and educational use only.
"""

import argparse
import sys
import time
from typing import List, Optional

from config.settings import CONFIG
from core.recon.url_handler import URLTarget, load_single_url, load_urls_from_file, deduplicate_targets
from core.extractor.param_extractor import extract_parameters
from modules.reflection.reflection_engine import run_reflection_probes
from modules.xss.xss_pipeline import run_xss_pipeline_for_target, XSSPipelineFinding
from core.reporting.cli_reporter import print_banner, print_scan_summary
from core.reporting.phase5_reporter import (
    print_phase5_xss_banner, print_xss_pipeline_summary,
)
from database.db_manager import DB
from core.utils.logger import get_logger

log = get_logger(__name__)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reconmind",
        description=(
            "wamiqsec — ReconMind: Context-Aware Exploitability & "
            "Intelligent XSS Validation\n"
            "For authorized security testing and educational use only."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python main.py -u 'https://target.com/page?q=test'\n"
            "  python main.py -f urls.txt --save-json\n"
            "  python main.py --query --query-severity HIGH\n"
        ),
    )

    target_group = parser.add_mutually_exclusive_group()
    target_group.add_argument("-u", "--url", metavar="URL", help="Single target URL")
    target_group.add_argument("-f", "--file", metavar="FILE", help="File with one URL per line")
    target_group.add_argument("--query", action="store_true", help="Query saved findings and exit")

    parser.add_argument("--timeout", type=int, default=CONFIG.network.request_timeout)
    parser.add_argument("--proxy", metavar="URL", help="Proxy URL, e.g. http://127.0.0.1:8080")
    parser.add_argument("--waf-bypass", action="store_true", help="Enable Tier 3 WAF bypass payloads")
    parser.add_argument("--skip-payload-stage", action="store_true",
                         help="Stop after exploitability scoring; do not fire confirmation payloads")

    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--save-json", action="store_true")
    parser.add_argument("--save-markdown", action="store_true")
    parser.add_argument("--no-db", action="store_true")
    parser.add_argument("--min-score", type=int, default=CONFIG.reporting.min_display_score)

    parser.add_argument("--query-host", metavar="HOST")
    parser.add_argument("--query-severity", metavar="SEV")
    parser.add_argument("--query-module", metavar="MOD")

    return parser


def apply_config(args: argparse.Namespace) -> None:
    if args.debug:
        CONFIG.logging.level = "DEBUG"
    if args.no_color:
        CONFIG.reporting.use_color = False
    if args.timeout != CONFIG.network.request_timeout:
        CONFIG.network.request_timeout = args.timeout
    if args.proxy:
        CONFIG.network.proxies = {"http": args.proxy, "https": args.proxy}
    if args.waf_bypass:
        CONFIG.xss.enable_waf_bypass_payloads = True
    if args.min_score != CONFIG.reporting.min_display_score:
        CONFIG.reporting.min_display_score = args.min_score


def run_query_mode(args: argparse.Namespace) -> int:
    findings = DB.get_findings(
        severity=getattr(args, "query_severity", None),
        module=getattr(args, "query_module", None),
        host=getattr(args, "query_host", None),
    )
    stats = DB.get_summary_stats()
    print(f"\n  ReconMind Database — {stats.get('total', 0)} total finding(s)\n")
    if not findings:
        print("  No findings match the query filters.\n")
        return 0
    for row in findings:
        sev = row.get("severity", "INFO")
        mod = row.get("module", "?")
        param = row.get("parameter", "?")
        url = row.get("url", "?")[:80]
        ts = row.get("discovered_at", "?")[:19]
        print(f"  [{sev:<8}] [{mod:<10}] {param:<20} {url}  ({ts})")
    print()
    return 0


def process_target(target: URLTarget, args: argparse.Namespace, session_id: int,
                    save_to_db: bool) -> List[XSSPipelineFinding]:
    """Run Phase 1 recon + Phase 5 XSS validation pipeline on one target."""
    print(f"\n  Target: {target.normalized}")

    log.info("[1/4] Parameter extraction")
    target = extract_parameters(target)
    params = getattr(target, "parameters", [])
    print(f"  Parameters found: {len(params)}")

    target_id = 0
    if save_to_db:
        target_id = DB.save_target(
            url=target.normalized, host=target.host, scheme=target.scheme,
            session_id=session_id, param_count=len(params),
            http_status=getattr(target, "http_status", 0),
        )

    if not params:
        log.info("No parameters — skipping.")
        return []

    log.info("[2/4] Reflection probing")
    reflection_results = run_reflection_probes(target)
    reflected = [r for r in reflection_results if r.reflected]
    print(f"  Reflected parameters: {len(reflected)}/{len(params)}")

    if not reflected:
        return []

    log.info("[3-6/4] Phase 5 XSS validation pipeline")
    print_phase5_xss_banner()
    findings = run_xss_pipeline_for_target(target)

    print_xss_pipeline_summary(findings, target.normalized)

    if save_to_db:
        for f in findings:
            if not f.suppressed:
                DB.save_finding(f, module="XSS", session_id=session_id, target_id=target_id)

    return findings


def main() -> int:
    parser = build_parser()
    if len(sys.argv) == 1:
        parser.print_help()
        return 2

    args = parser.parse_args()
    apply_config(args)

    print_banner()

    if args.query:
        return run_query_mode(args)

    if not args.url and not args.file:
        parser.error("Provide -u URL or -f FILE, or --query to view results.")

    targets: List[URLTarget] = []
    if args.url:
        t = load_single_url(args.url)
        if not t:
            log.error("Invalid URL: %s", args.url)
            return 1
        targets = [t]
    elif args.file:
        targets = load_urls_from_file(args.file)
        if not targets:
            log.error("No valid URLs in: %s", args.file)
            return 1

    targets = deduplicate_targets(targets)
    log.info("Loaded %d unique target(s)", len(targets))

    save_to_db = not args.no_db and CONFIG.database.auto_save
    session_id = 0
    if save_to_db:
        session_id = DB.start_session(notes=f"{args.url or args.file}")

    start_time = time.time()
    all_findings: List[XSSPipelineFinding] = []

    for i, target in enumerate(targets, 1):
        log.info("Processing target %d/%d: %s", i, len(targets), target.normalized)
        try:
            findings = process_target(target, args, session_id, save_to_db)
            all_findings.extend(findings)
        except KeyboardInterrupt:
            log.warning("Interrupted by user")
            break
        except Exception as exc:
            log.error("Error processing %s: %s", target.normalized, exc, exc_info=True)
            continue

    elapsed = time.time() - start_time
    reportable = [f for f in all_findings if not f.suppressed]

    print_scan_summary(targets, reportable, elapsed)

    if save_to_db and session_id:
        DB.end_session(session_id, len(targets), len(reportable))
        stats = DB.get_summary_stats()
        if stats.get("total", 0):
            print(f"  Database: {stats['total']} finding(s) in {CONFIG.database.db_path}\n")

    if args.save_json or args.save_markdown:
        import json
        from pathlib import Path
        from datetime import datetime

        Path(CONFIG.reporting.output_dir).mkdir(parents=True, exist_ok=True)
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

        if args.save_json:
            json_path = Path(CONFIG.reporting.output_dir) / f"wamiqsec_reconmind_{ts}.json"
            data = {
                "meta": {"tool": "wamiqsec-ReconMind", "phase": 5, "generated_at": ts},
                "findings": [f.to_dict() for f in reportable],
            }
            json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
            print(f"  JSON report: {json_path}")

        if args.save_markdown:
            md_path = Path(CONFIG.reporting.output_dir) / f"wamiqsec_reconmind_{ts}.md"
            lines = ["# wamiqsec — ReconMind XSS Findings", ""]
            for f in reportable:
                lines += [
                    f"## {f.parameter} — {f.severity} ({f.confidence:.0%})",
                    f"- URL: `{f.url}`",
                    f"- Context: `{f.context_type}`",
                    f"- Encoding: `{f.encoding_status}`",
                    f"- Breakout: `{f.breakout_status}`",
                ]
                if f.confirmed_payload:
                    lines.append(f"- Confirmed payload: `{f.confirmed_payload}`")
                lines.append("")
            md_path.write_text("\n".join(lines), encoding="utf-8")
            print(f"  Markdown report: {md_path}")

    print()
    high_count = sum(1 for f in reportable if f.severity in ("HIGH", "CRITICAL"))
    return 1 if high_count > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
