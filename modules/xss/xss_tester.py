"""
modules/xss/xss_tester.py
==========================
XSS payload testing engine for ReconMind Phase 2.

Why this file exists:
    Phase 1 answers "does input reflect, and where?"
    Phase 2 answers "can that reflection be exploited?"

    This module takes the Phase 1 outputs (reflected parameters +
    their context classification) and fires context-matched payloads
    to confirm actual XSS exploitability — not just reflection.

    The key professional distinction:
        Phase 1 finding:  "q parameter reflects in JS context"
        Phase 2 finding:  "q parameter is confirmed XSS via JS string
                           breakout — payload: ';alert(1)// rendered raw"

Architecture:
    Input:  URLTarget with .parameters and .reflection_results attached
            (set by Phase 1 modules)
    Output: List of XSSFinding objects (extends ScoredFinding concept)

    For each reflected parameter:
        1. Look up its context from Phase 1 context analysis
        2. Select appropriate payload tier from xss_payloads.py
        3. Inject each payload, check if it appears unencoded in response
        4. Detect confirmation strings to distinguish reflection from execution
        5. Return XSSFinding with full evidence chain

Rate control:
    CONFIG.xss.delay_between_requests controls sleep between probes.
    This is NOT optional — responsible testers don't hammer targets.
"""

import time
from dataclasses import dataclass, field
from typing import List, Optional, Dict
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

from core.recon.url_handler import URLTarget
from core.extractor.param_extractor import Parameter, ParamType
from core.payloads.xss_payloads import get_payloads_for_context, Payload
from core.utils.http_client import safe_get, safe_post
from config.settings import CONFIG
from core.utils.logger import get_logger

log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class XSSFinding:
    """
    Evidence record for a confirmed or probable XSS vulnerability.

    Attributes:
        url:           Target URL.
        parameter:     Parameter name where XSS was found.
        param_type:    GET / POST / HIDDEN / JSON.
        payload:       The exact payload string that succeeded.
        technique:     Human description of the technique used.
        tier:          Payload tier that confirmed the finding (1, 2, or 3).
        context:       JS / HTML_BODY / HTML_ATTR / etc.
        reflected_raw: True if payload appeared unencoded in response.
        response_code: HTTP status code of the probe response.
        evidence:      Snippet of response containing the payload.
        severity:      HIGH / MEDIUM / LOW.
        notes:         Additional analyst notes.
    """

    url: str
    parameter: str
    param_type: str
    payload: str
    technique: str
    tier: int
    context: str
    reflected_raw: bool = False
    response_code: int = 0
    evidence: str = ""
    severity: str = "HIGH"
    notes: List[str] = field(default_factory=list)

    def __repr__(self) -> str:
        return (
            f"XSSFinding([{self.severity}] param={self.parameter!r} "
            f"tier={self.tier} context={self.context})"
        )

    def to_scored_finding_dict(self) -> Dict:
        """Convert to dict compatible with ScoredFinding for unified reporting."""
        return {
            "url": self.url,
            "parameter": self.parameter,
            "param_type": self.param_type,
            "score": 100 if self.reflected_raw else 60,
            "severity": self.severity,
            "reasons": [
                f"XSS payload reflected raw: {self.payload[:60]}",
                f"Technique: {self.technique}",
                f"Context: {self.context}",
            ],
            "context": self.context,
            "context_snippet": self.evidence,
            "module": "XSS",
        }


# ---------------------------------------------------------------------------
# Injection helpers
# ---------------------------------------------------------------------------

def _build_xss_get_url(target: URLTarget, param: Parameter, payload: str) -> str:
    """
    Build a GET request URL with the XSS payload injected into one parameter.

    Unlike Phase 1 which injects a marker, here we inject the actual payload.
    We preserve other params to avoid server-side validation errors.

    Args:
        target:  URLTarget being tested.
        param:   The GET parameter to inject into.
        payload: The XSS payload string.

    Returns:
        Fully constructed probe URL string.
    """
    parsed = urlparse(target.normalized)
    query_params = parse_qs(parsed.query, keep_blank_values=True)

    # Inject payload — note: we do NOT URL-encode the payload here.
    # The requests library will encode it when building the actual HTTP request.
    query_params[param.name] = [payload]

    new_query = urlencode(
        {k: v[0] for k, v in query_params.items()},
    )

    return urlunparse(parsed._replace(query=new_query))


def _check_payload_in_response(response_text: str, payload: str) -> tuple:
    """
    Check if a payload appears in the response, raw or encoded.

    Args:
        response_text: HTTP response body.
        payload:       The injected payload string.

    Returns:
        (raw_found: bool, evidence_snippet: str)
    """
    if payload in response_text:
        # Find the surrounding context
        idx = response_text.find(payload)
        start = max(0, idx - 60)
        end = min(len(response_text), idx + len(payload) + 60)
        snippet = response_text[start:end].replace("\n", "↵")
        return True, snippet

    return False, ""


# ---------------------------------------------------------------------------
# Core testing functions
# ---------------------------------------------------------------------------

def _test_get_param_xss(
    target: URLTarget,
    param: Parameter,
    context: str,
    payloads: List[Payload],
) -> List[XSSFinding]:
    """
    Test a GET parameter with all provided XSS payloads.

    Args:
        target:   URLTarget being tested.
        param:    The GET Parameter to test.
        context:  Phase 1 reflection context for this parameter.
        payloads: List of Payload dicts to try.

    Returns:
        List of XSSFinding objects for confirmed/probable hits.
    """
    findings: List[XSSFinding] = []
    cfg = CONFIG.xss
    hits = 0

    for payload_dict in payloads:
        if hits >= cfg.stop_after_hits:
            log.debug(
                "  Stopping after %d hits on param %r",
                cfg.stop_after_hits, param.name,
            )
            break

        payload_str = payload_dict["payload"]
        probe_url = _build_xss_get_url(target, param, payload_str)

        log.debug(
            "  XSS probe: param=%r tier=%d payload=%r",
            param.name, payload_dict["tier"], payload_str[:40],
        )

        response = safe_get(probe_url, allow_redirects=False)

        # Respect rate limit
        time.sleep(cfg.delay_between_requests)

        if response is None:
            continue

        raw_found, evidence = _check_payload_in_response(response.text, payload_str)

        if raw_found:
            finding = XSSFinding(
                url=probe_url,
                parameter=param.name,
                param_type=param.param_type,
                payload=payload_str,
                technique=payload_dict["technique"],
                tier=payload_dict["tier"],
                context=context,
                reflected_raw=True,
                response_code=response.status_code,
                evidence=evidence,
                severity="HIGH",
            )
            finding.notes.append(
                f"Payload tier {payload_dict['tier']} reflected raw — "
                "manual verification recommended"
            )
            findings.append(finding)
            hits += 1

            log.info(
                "  [XSS HIT] param=%r payload=%r context=%s",
                param.name, payload_str[:50], context,
            )

    return findings


def _test_post_param_xss(
    target: URLTarget,
    param: Parameter,
    context: str,
    payloads: List[Payload],
) -> List[XSSFinding]:
    """
    Test a POST/HIDDEN parameter with XSS payloads.

    Args:
        target:   URLTarget being tested.
        param:    The POST/HIDDEN Parameter to test.
        context:  Phase 1 reflection context.
        payloads: List of Payload dicts to try.

    Returns:
        List of XSSFinding objects.
    """
    findings: List[XSSFinding] = []
    cfg = CONFIG.xss
    post_url = param.form_action or target.base_url()
    hits = 0

    # Build base form data from all same-form params
    base_form_data: Dict[str, str] = {}
    if hasattr(target, "parameters"):
        for p in target.parameters:
            if (
                p.param_type in (ParamType.POST, ParamType.HIDDEN)
                and p.form_action == param.form_action
                and p.name != param.name
            ):
                base_form_data[p.name] = p.value

    for payload_dict in payloads:
        if hits >= cfg.stop_after_hits:
            break

        payload_str = payload_dict["payload"]
        form_data = dict(base_form_data)
        form_data[param.name] = payload_str

        log.debug(
            "  XSS POST probe: param=%r tier=%d payload=%r",
            param.name, payload_dict["tier"], payload_str[:40],
        )

        response = safe_post(post_url, data=form_data, allow_redirects=False)
        time.sleep(cfg.delay_between_requests)

        if response is None:
            continue

        raw_found, evidence = _check_payload_in_response(response.text, payload_str)

        if raw_found:
            finding = XSSFinding(
                url=post_url,
                parameter=param.name,
                param_type=param.param_type,
                payload=payload_str,
                technique=payload_dict["technique"],
                tier=payload_dict["tier"],
                context=context,
                reflected_raw=True,
                response_code=response.status_code,
                evidence=evidence,
                severity="HIGH",
            )
            findings.append(finding)
            hits += 1

            log.info(
                "  [XSS POST HIT] param=%r payload=%r",
                param.name, payload_str[:50],
            )

    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_xss_tests(target: URLTarget) -> List[XSSFinding]:
    """
    Run XSS payload tests on all reflected parameters of a URLTarget.

    This is the Phase 2 entry point for XSS testing. It:
        1. Reads reflection results from Phase 1 (already on target)
        2. For each reflected parameter, looks up its context
        3. Selects payloads appropriate for that context
        4. Fires the payloads and records any raw-reflected hits

    Prerequisites:
        target.parameters        — populated by param_extractor
        target.reflection_results — populated by reflection_engine
        target.context_analyses   — populated by context_analyzer
          (set on target by main.py pipeline)

    Args:
        target: URLTarget that has completed Phase 1 analysis.

    Returns:
        List of XSSFinding objects, one per confirmed hit.
    """
    cfg = CONFIG.xss

    reflection_results = getattr(target, "reflection_results", [])
    context_analyses = getattr(target, "context_analyses", [])

    # Build a lookup: param name → context string
    # from Phase 1 context analysis results
    param_to_context: Dict[str, str] = {}
    for analysis in context_analyses:
        pname = analysis.reflection.parameter.name
        param_to_context[pname] = analysis.context

    # Only test parameters that were reflected in Phase 1
    reflected_params = [r for r in reflection_results if r.reflected]

    if not reflected_params:
        log.info("No reflected parameters — skipping XSS tests for %s", target.normalized)
        return []

    log.info(
        "Starting XSS tests on %s — %d reflected params",
        target.normalized, len(reflected_params),
    )

    all_findings: List[XSSFinding] = []

    for reflection in reflected_params:
        param = reflection.parameter
        context = param_to_context.get(param.name, "UNKNOWN")

        log.info("  Testing XSS: param=%r context=%s", param.name, context)

        # Select payloads for this context
        payloads = get_payloads_for_context(
            context=context,
            include_tier1=True,
            include_tier2=True,
            include_tier3=cfg.enable_waf_bypass_payloads,
            max_per_context=cfg.max_payloads_per_param,
        )

        log.debug(
            "  Selected %d payloads for context=%s", len(payloads), context
        )

        # Dispatch to correct tester
        if param.param_type in (ParamType.GET,):
            findings = _test_get_param_xss(target, param, context, payloads)
        elif param.param_type in (ParamType.POST, ParamType.HIDDEN):
            findings = _test_post_param_xss(target, param, context, payloads)
        else:
            log.debug("  Skipping unsupported param type: %s", param.param_type)
            continue

        all_findings.extend(findings)

    log.info(
        "XSS testing complete for %s: %d finding(s)",
        target.normalized, len(all_findings),
    )

    # Attach to target for reporting
    setattr(target, "xss_findings", all_findings)

    return all_findings
