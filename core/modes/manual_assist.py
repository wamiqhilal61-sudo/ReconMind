"""
core/modes/manual_assist.py
=============================
Manual-Assist Mode for ReconMind Phase 4 by wamiqsec.

WHAT MANUAL-ASSIST MODE IS:
────────────────────────────────────────────────────────────────
The professional bug hunter's co-pilot. It doesn't replace your
judgment — it amplifies it. Manual-Assist Mode:

    1. Runs passive recon on all targets
    2. Runs light active analysis (reflection only, no payloads)
    3. Synthesizes everything into a PRIORITIZED HUNTING GUIDE
    4. Tells you exactly: "Start here. Test this. Look for that."
    5. Suggests vulnerability chains worth investigating
    6. Highlights what's new vs previously seen

OUTPUT:
    A structured hunting guide (Markdown + JSON) that contains:
    - Prioritized target list (most interesting first)
    - Per-target: attack surface summary, interesting params, tech stack
    - Vulnerability chain suggestions
    - Quick-hit checklist (low-hanging fruit)
    - Manual testing notes per endpoint type
"""

import time
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from pathlib import Path
from datetime import datetime

from core.modes.passive_mode import PassiveScanReport, PassiveTargetResult
from core.engines.response.response_classifier import PageType
from config.settings import CONFIG
from core.utils.logger import get_logger

log = get_logger(__name__)


@dataclass
class HuntingTarget:
    """A prioritized target for manual investigation."""
    rank: int
    url: str
    priority: str
    page_type: str
    interest_score: int
    why_interesting: List[str]
    attack_vectors: List[str]
    params_to_test: List[str]
    tech_stack: List[str]
    quick_tests: List[str]
    chain_opportunities: List[str]


@dataclass
class HuntingGuide:
    """Complete hunting guide produced by Manual-Assist Mode."""
    generated_at: str
    scope_summary: str
    total_targets: int
    high_priority_count: int
    medium_priority_count: int
    targets: List[HuntingTarget] = field(default_factory=list)
    quick_wins: List[str] = field(default_factory=list)
    chain_suggestions: List[str] = field(default_factory=list)
    js_findings_summary: List[str] = field(default_factory=list)
    security_posture_notes: List[str] = field(default_factory=list)
    recon_notes: List[str] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# Attack vector recommendations per page type
# ─────────────────────────────────────────────────────────────────────────────

ATTACK_VECTORS_BY_TYPE = {
    PageType.ADMIN: [
        "Test IDOR on all numeric IDs — admin panels often lack per-object auth checks",
        "Check if admin endpoints enforce authentication — try unauthenticated access",
        "Test for SSRF via URL parameters — admin tooling often fetches remote resources",
        "Check for mass-assignment in bulk operations",
        "Test for privilege escalation via hidden parameters",
    ],
    PageType.API: [
        "Test all numeric IDs for IDOR (Broken Object Level Authorization - BOLA)",
        "Check for missing authentication on undocumented endpoints",
        "Test JSON body parameter tampering",
        "Look for mass-assignment vulnerabilities in POST/PUT endpoints",
        "Check for verb tampering (GET → POST, read-only → write)",
        "Test for excessive data exposure in responses",
    ],
    PageType.AUTH: [
        "Test for CSRF on login, registration, password reset",
        "Check if session token is invalidated on logout",
        "Test for username enumeration via response differences",
        "Look for password in API response or error messages",
        "Test OAuth token theft via redirect_uri manipulation",
        "Check for account takeover via password reset flow",
    ],
    PageType.SEARCH: [
        "Test for XSS — search reflects input (check for unencoded reflection)",
        "Test for SQLi on the search query parameter",
        "Look for search-based IDOR (searching for other users' data)",
        "Test for stored XSS if search queries are saved/shared",
    ],
    PageType.UPLOAD: [
        "Test for file type bypass (change Content-Type header, use double extensions)",
        "Test for path traversal in filename parameter",
        "Check if uploaded files are served with original Content-Type",
        "Test for SSRF via file URL if server fetches remote files",
        "Look for stored XSS via SVG file upload",
        "Test for zip/archive path traversal (zip slip)",
    ],
    PageType.PROFILE: [
        "Test IDOR — can you access other users' profiles? Read? Write?",
        "Check for stored XSS in profile fields (name, bio, social links)",
        "Test for CSRF on profile update endpoints",
        "Look for PII exposure in API responses",
    ],
    PageType.REDIRECT: [
        "Test for open redirect with external domain",
        "If OAuth uses this redirect: test for authorization code theft",
        "Test for SSRF if redirect fetches the target URL server-side",
        "Try: //evil.com, https://target.com@evil.com, %0d%0ahttps://evil.com",
    ],
    PageType.GRAPHQL: [
        "Run introspection: query { __schema { types { name fields { name } } } }",
        "Test for IDOR in object IDs",
        "Test for batch query abuse (many queries in one request)",
        "Look for field-level authorization issues",
        "Check for information disclosure via error messages",
    ],
    PageType.DASHBOARD: [
        "Test IDOR on dashboard data requests",
        "Check for stored XSS in notifications or activity feed",
        "Test CSRF on key dashboard actions",
        "Look for SSRF in any 'external integration' features",
    ],
}

QUICK_TESTS_BY_TYPE = {
    PageType.AUTH: [
        "curl -X POST /login -d 'username=admin&password=' — empty password",
        "curl -X POST /login -d 'username=admin'%27-- — SQL quote",
        "curl -X GET /logout — check if CSRF protection applies to GET logout",
    ],
    PageType.API: [
        "curl /api/v1/users — remove auth header, check if still returns data",
        "curl /api/v1/user/1 → /api/v1/user/2 — IDOR test",
        "Change Content-Type to text/plain — check for type-confusion",
    ],
    PageType.ADMIN: [
        "Access /admin/ without cookies — check if redirect or 200",
        "Try /admin/users — common admin endpoint",
        "Check source for data-user-role attributes",
    ],
    PageType.UPLOAD: [
        "Upload .php file with Content-Type: image/jpeg",
        "Try filename: ../../shell.php",
        "Upload SVG with <script> tag",
    ],
}


# ─────────────────────────────────────────────────────────────────────────────
# Chain opportunity detection
# ─────────────────────────────────────────────────────────────────────────────

def _detect_chains(report: PassiveScanReport) -> List[str]:
    """Identify potential vulnerability chain opportunities from passive scan."""
    chains = []

    has_redirect = any(
        r.classification and r.classification.page_type == PageType.REDIRECT
        for r in report.target_results
    )
    has_auth = any(
        r.classification and r.classification.page_type == PageType.AUTH
        for r in report.target_results
    )
    has_upload = any(
        r.classification and r.classification.page_type == PageType.UPLOAD
        for r in report.target_results
    )
    has_admin = any(
        r.classification and r.classification.page_type == PageType.ADMIN
        for r in report.target_results
    )
    has_api = any(
        r.classification and r.classification.page_type == PageType.API
        for r in report.target_results
    )

    if has_redirect and has_auth:
        chains.append(
            "⛓ CHAIN: Open Redirect + OAuth → Account Takeover\n"
            "   If OAuth redirect_uri validation is loose, steal auth codes via redirect"
        )

    if has_upload and has_admin:
        chains.append(
            "⛓ CHAIN: File Upload (SVG/HTML) → Stored XSS → Admin Panel Compromise\n"
            "   Upload XSS payload, trigger admin view of the file"
        )

    if has_api and report.all_dom_sinks:
        chains.append(
            "⛓ CHAIN: API Data → DOM XSS Sink\n"
            "   API data flows into DOM via detected sink — inject XSS via API parameter"
        )

    if has_api and report.graphql_endpoints:
        chains.append(
            "⛓ CHAIN: GraphQL Introspection → Field IDOR\n"
            "   Map schema via introspection, then test each object's ID for BOLA"
        )

    if report.total_js_secrets > 0:
        chains.append(
            "⛓ CHAIN: JS Hardcoded API Key → Direct API Access\n"
            "   Use extracted key to make authenticated API calls, potentially admin-level"
        )

    if report.cors_misconfigs > 0:
        chains.append(
            "⛓ CHAIN: CORS Misconfiguration → Cross-Origin Data Theft\n"
            "   Craft malicious page that makes cross-origin requests and reads responses"
        )

    return chains


# ─────────────────────────────────────────────────────────────────────────────
# Quick wins identification
# ─────────────────────────────────────────────────────────────────────────────

def _identify_quick_wins(report: PassiveScanReport) -> List[str]:
    """Identify quick-win findings that likely require minimal effort."""
    wins = []

    if report.total_js_secrets > 0:
        wins.append(
            f"🎯 {report.total_js_secrets} potential secret(s) in JavaScript files — "
            "verify and report immediately (often $$$)"
        )

    if "Content-Security-Policy" in report.missing_security_headers:
        count = report.missing_security_headers["Content-Security-Policy"]
        wins.append(
            f"🎯 {count} URLs missing CSP — XSS findings here are more impactful"
        )

    if report.cors_misconfigs > 0:
        wins.append(
            f"🎯 {report.cors_misconfigs} CORS misconfiguration(s) — "
            "verify null origin or credential leakage"
        )

    if report.cookie_issues > 0:
        wins.append(
            f"🎯 {report.cookie_issues} session cookies missing security flags — "
            "HttpOnly/Secure/SameSite issues"
        )

    if report.graphql_endpoints:
        wins.append(
            f"🎯 GraphQL endpoint(s) found: {report.graphql_endpoints[:2]} — "
            "test introspection, batch queries, field authorization"
        )

    if report.websocket_endpoints:
        wins.append(
            f"🎯 WebSocket endpoint(s): {report.websocket_endpoints[:2]} — "
            "check for authentication on WS upgrade"
        )

    if report.total_dom_sinks > 0:
        wins.append(
            f"🎯 {report.total_dom_sinks} DOM-XSS sink(s) with user input — "
            "trace data flows manually for exploitation"
        )

    return wins


# ─────────────────────────────────────────────────────────────────────────────
# Hunting guide generation
# ─────────────────────────────────────────────────────────────────────────────

def _build_hunting_target(
    rank: int,
    result: PassiveTargetResult,
) -> HuntingTarget:
    """Build a HuntingTarget from a PassiveTargetResult."""
    page_type = PageType.UNKNOWN
    if result.classification:
        page_type = result.classification.page_type

    # Attack vectors for this page type
    vectors = ATTACK_VECTORS_BY_TYPE.get(page_type, [
        "Test all parameters for injection",
        "Check response for sensitive data exposure",
    ])

    # Quick tests
    quick = QUICK_TESTS_BY_TYPE.get(page_type, [])

    # Parameters to focus on
    interesting_params = []
    for p in result.parameters:
        if p.value.isdigit():
            interesting_params.append(f"{p.name}={p.value} (numeric — IDOR candidate)")
        elif any(h in p.name.lower() for h in ["url", "redirect", "next", "src"]):
            interesting_params.append(f"{p.name} (URL param — redirect/SSRF candidate)")
        elif any(h in p.name.lower() for h in ["file", "path", "template", "page"]):
            interesting_params.append(f"{p.name} (file param — LFI candidate)")
        else:
            interesting_params.append(f"{p.name}")

    # Tech stack
    tech = []
    if result.passive_analysis:
        tech = result.passive_analysis.tech_stack

    # Chain opportunities specific to this target
    chains = []
    if result.js_intelligence and result.js_intelligence.high_priority_sinks:
        chains.append("DOM-XSS: user-controlled data flows into executable sink")
    if result.passive_analysis and result.passive_analysis.cors and result.passive_analysis.cors.severity == "HIGH":
        chains.append("CORS chain: cross-origin request with credentials")

    return HuntingTarget(
        rank=rank,
        url=result.url,
        priority=result.priority_label,
        page_type=page_type,
        interest_score=result.interest_score,
        why_interesting=result.priority_reasons[:5],
        attack_vectors=vectors[:4],
        params_to_test=interesting_params[:8],
        tech_stack=tech,
        quick_tests=quick[:3],
        chain_opportunities=chains,
    )


def _render_markdown_guide(guide: HuntingGuide) -> str:
    """Render the hunting guide as a Markdown document."""
    lines = [
        "# wamiqsec — ReconMind Hunting Guide",
        f"",
        f"**Generated:** {guide.generated_at}  ",
        f"**Scope:** {guide.scope_summary}  ",
        f"**Targets:** {guide.total_targets} analyzed  ",
        f"",
        "---",
        "",
        "## Quick Wins",
        "",
    ]

    for win in guide.quick_wins:
        lines.append(f"- {win}")

    lines += [
        "",
        "---",
        "",
        "## Vulnerability Chain Opportunities",
        "",
    ]

    for chain in guide.chain_suggestions:
        lines.append(f"- {chain}")
        lines.append("")

    lines += [
        "---",
        "",
        f"## HIGH Priority Targets ({guide.high_priority_count})",
        "",
    ]

    for target in [t for t in guide.targets if t.priority == "HIGH"]:
        lines += [
            f"### {target.rank}. `{target.url}`",
            f"",
            f"**Type:** `{target.page_type}` | **Score:** {target.interest_score}",
            f"",
            f"**Why interesting:**",
        ]
        for reason in target.why_interesting:
            lines.append(f"- {reason}")

        if target.tech_stack:
            lines.append(f"")
            lines.append(f"**Tech Stack:** {', '.join(target.tech_stack)}")

        if target.params_to_test:
            lines += ["", "**Parameters to test:**"]
            for p in target.params_to_test[:6]:
                lines.append(f"- `{p}`")

        if target.attack_vectors:
            lines += ["", "**Attack vectors:**"]
            for v in target.attack_vectors:
                lines.append(f"- {v}")

        if target.chain_opportunities:
            lines += ["", "**Chain opportunities:**"]
            for c in target.chain_opportunities:
                lines.append(f"- {c}")

        if target.quick_tests:
            lines += ["", "**Quick tests:**"]
            for q in target.quick_tests:
                lines.append(f"```")
                lines.append(q)
                lines.append(f"```")

        lines.append("")
        lines.append("---")
        lines.append("")

    if guide.js_findings_summary:
        lines += ["## JavaScript Intelligence Findings", ""]
        for finding in guide.js_findings_summary:
            lines.append(f"- {finding}")
        lines.append("")

    if guide.security_posture_notes:
        lines += ["## Security Posture Notes", ""]
        for note in guide.security_posture_notes:
            lines.append(f"- {note}")
        lines.append("")

    lines += [
        "---",
        "",
        "*Generated by wamiqsec/ReconMind — Intelligent Offensive Security Intelligence Platform*",
        "",
        "> For authorized security testing only.",
    ]

    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def generate_hunting_guide(
    passive_report: PassiveScanReport,
    output_path: Optional[str] = None,
) -> HuntingGuide:
    """
    Generate a complete Manual-Assist hunting guide from a passive scan report.

    Args:
        passive_report: PassiveScanReport from passive mode.
        output_path:    Optional path to write the Markdown guide.

    Returns:
        HuntingGuide dataclass with all prioritized findings.
    """
    cfg = CONFIG.manual

    guide = HuntingGuide(
        generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        scope_summary=f"{len(passive_report.seed_urls)} seed URL(s)",
        total_targets=passive_report.total_urls_analyzed,
        high_priority_count=len(passive_report.high_priority_targets),
        medium_priority_count=len(passive_report.medium_priority_targets),
    )

    # Build prioritized target list
    rank = 1
    all_priority_results = (
        passive_report.high_priority_targets +
        passive_report.medium_priority_targets
    )

    for result in all_priority_results:
        if result.interest_score < cfg.min_interest_score:
            continue
        hunting_target = _build_hunting_target(rank, result)
        guide.targets.append(hunting_target)
        rank += 1

    # Quick wins
    guide.quick_wins = _identify_quick_wins(passive_report)

    # Chain suggestions
    if cfg.suggest_chains:
        guide.chain_suggestions = _detect_chains(passive_report)

    # JS findings summary
    if passive_report.total_js_secrets > 0:
        guide.js_findings_summary.append(
            f"{passive_report.total_js_secrets} potential secrets found in JavaScript"
        )
    if passive_report.all_endpoints_found:
        guide.js_findings_summary.append(
            f"{len(passive_report.all_endpoints_found)} API endpoints extracted from JS"
        )
    if passive_report.total_dom_sinks > 0:
        guide.js_findings_summary.append(
            f"{passive_report.total_dom_sinks} DOM-XSS sinks with user-controlled input"
        )

    # Security posture notes
    for header, count in sorted(passive_report.missing_security_headers.items(), key=lambda x: -x[1]):
        guide.security_posture_notes.append(
            f"{header} missing on {count} URL(s)"
        )
    if passive_report.cors_misconfigs > 0:
        guide.security_posture_notes.append(
            f"CORS misconfiguration on {passive_report.cors_misconfigs} endpoint(s)"
        )

    # Write Markdown output
    if output_path or cfg.generate_hunting_guide:
        md_content = _render_markdown_guide(guide)
        if not output_path:
            ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            output_path = f"reports/wamiqsec_hunting_guide_{ts}.md"

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        Path(output_path).write_text(md_content, encoding="utf-8")
        log.info("Hunting guide written: %s", output_path)

    log.info(
        "Hunting guide generated: %d targets | %d quick wins | %d chains",
        len(guide.targets), len(guide.quick_wins), len(guide.chain_suggestions),
    )

    return guide
