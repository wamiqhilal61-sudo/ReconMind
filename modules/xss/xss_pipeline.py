"""
modules/xss/xss_pipeline.py
==============================
Phase 5 XSS Validation Pipeline for wamiqsec/ReconMind.

Six staged functions, each a pure profile_in -> profile_out transform:
    1. reflection probe
    2. encoding analysis
    3. context detection
    4. breakout analysis
    5. exploitability scoring
    6. payload testing (only if promising)
"""

import time
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

from core.recon.url_handler import URLTarget
from core.extractor.param_extractor import Parameter, ParamType
from core.utils.http_client import safe_get, safe_post
from models.response_profile import ResponseProfile
from models.evidence import VerdictLevel
from core.engines.xss.encoding_detector import analyze_encoding
from core.engines.xss.context_engine import detect_context, XSSContext
from core.engines.xss.breakout_analyzer import analyze_breakout
from core.engines.xss.exploitability_scorer import score_exploitability
from core.payloads.xss.payload_selector import select_payloads
from config.settings import CONFIG
from core.utils.logger import get_logger

log = get_logger(__name__)


@dataclass
class XSSPipelineFinding:
    """Final output of the Phase 5 XSS pipeline."""
    url: str
    parameter: str
    param_type: str

    chain: Optional[object] = None
    profile: Optional[ResponseProfile] = None

    confirmed_payload: str = ""
    confirmed_technique: str = ""
    payload_tier: int = 0

    confidence: float = 0.0
    severity: str = "INFO"
    verdict: str = "UNLIKELY"
    suppressed: bool = True

    context_type: str = XSSContext.UNKNOWN
    encoding_status: str = "UNKNOWN"
    breakout_status: str = "UNKNOWN"
    csp_impact: str = "UNKNOWN"
    evidence_lines: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    @property
    def is_reportable(self) -> bool:
        return not self.suppressed and self.confidence >= 0.45

    def to_dict(self) -> dict:
        return {
            "module": "XSS", "url": self.url, "parameter": self.parameter,
            "param_type": self.param_type, "confidence": round(self.confidence, 4),
            "severity": self.severity, "verdict": self.verdict,
            "context": self.context_type, "encoding": self.encoding_status,
            "breakout": self.breakout_status, "confirmed_payload": self.confirmed_payload,
            "technique": self.confirmed_technique, "evidence": self.evidence_lines,
            "notes": self.notes,
        }


def _build_probe_url(target: URLTarget, param: Parameter, value: str) -> str:
    parsed = urlparse(target.normalized)
    qp = parse_qs(parsed.query, keep_blank_values=True)
    qp[param.name] = [value]
    return urlunparse(parsed._replace(query=urlencode({k: v[0] for k, v in qp.items()})))


def _fetch(target: URLTarget, param: Parameter, value: str):
    if param.param_type == ParamType.GET:
        url = _build_probe_url(target, param, value)
        return safe_get(url, allow_redirects=False), url
    else:
        post_url = param.form_action or target.base_url()
        return safe_post(post_url, data={param.name: value}, allow_redirects=False), post_url


def _check_payload_raw(body: str, payload: str) -> tuple:
    if payload in body:
        idx = body.find(payload)
        s, e = max(0, idx - 60), min(len(body), idx + len(payload) + 60)
        return True, body[s:e].replace("\n", "|")
    return False, ""


def _stage1_reflection_probe(target: URLTarget, param: Parameter, marker: str) -> Optional[ResponseProfile]:
    """Inject marker and confirm reflection."""
    response, probe_url = _fetch(target, param, marker)
    time.sleep(CONFIG.active.probe_delay)

    if response is None or marker not in response.text:
        return None

    return ResponseProfile.from_http_response(
        response=response, url=probe_url, param_name=param.name,
        param_type=param.param_type, injected_value=marker,
    )


def _stage6_payload_testing(
    target: URLTarget, param: Parameter, profile: ResponseProfile, finding: XSSPipelineFinding,
) -> XSSPipelineFinding:
    """Fire context-selected payloads to confirm execution."""
    cfg = CONFIG.active
    payloads = select_payloads(
        profile=profile, max_payloads=cfg.max_payloads_per_param,
        include_waf_bypass=CONFIG.xss.enable_waf_bypass_payloads,
    )
    if not payloads:
        return finding

    hits = 0
    for payload_dict in payloads:
        if hits >= CONFIG.xss.stop_after_hits:
            break

        payload_str = payload_dict["payload"]
        response, probe_url = _fetch(target, param, payload_str)
        time.sleep(CONFIG.active.probe_delay)

        if response is None:
            continue

        found, snippet = _check_payload_raw(response.text, payload_str)
        if found:
            hits += 1
            finding.confirmed_payload = payload_str
            finding.confirmed_technique = payload_dict.get("technique", "")
            finding.payload_tier = payload_dict.get("tier", 0)

            if finding.chain:
                finding.chain.observe(
                    "payload_reflected_raw",
                    f"Payload tier {payload_dict['tier']} reflected raw: {payload_str[:50]}",
                )
                finding.chain.calculate()
                finding.confidence = finding.chain.combined_confidence
                finding.severity = finding.chain.severity
                finding.verdict = finding.chain.verdict.value
                finding.suppressed = not finding.chain.is_reportable

            log.info("  [XSS PAYLOAD HIT] param=%r tier=%d payload=%r",
                      param.name, payload_dict["tier"], payload_str[:50])

    return finding


def run_xss_pipeline(
    target: URLTarget, param: Parameter, marker: str = None, skip_payload_stage: bool = False,
) -> Optional[XSSPipelineFinding]:
    """Run the full Phase 5 XSS validation pipeline on a single parameter."""
    if marker is None:
        marker = CONFIG.payloads.reflection_marker

    log.info("XSS pipeline: param=%r type=%s", param.name, param.param_type)

    profile = _stage1_reflection_probe(target, param, marker)
    if profile is None:
        log.debug("  Stage 1: No reflection -> skip")
        return None

    profile = analyze_encoding(profile, marker)
    profile = detect_context(profile, marker)
    ctx_type = profile.context_info.context_type if profile.context_info else XSSContext.UNKNOWN
    profile = analyze_breakout(profile, target, param, marker, ctx_type)
    breakout_ok = profile.breakout_info.feasible if profile.breakout_info else False

    chain = score_exploitability(profile)

    ri, bi, ci = profile.reflection_info, profile.breakout_info, profile.context_info
    encoding_status = ri.reflection_type.value if ri else "UNKNOWN"
    breakout_status = "FEASIBLE" if breakout_ok else ("NOT_TESTED" if not bi or not bi.was_tested else "NOT_FEASIBLE")
    csp_impact = "BLOCKING" if profile.csp_blocks_xss else ("BYPASSABLE" if profile.csp_bypass_available else "NONE")

    finding = XSSPipelineFinding(
        url=profile.url, parameter=param.name, param_type=param.param_type,
        chain=chain, profile=profile, confidence=chain.combined_confidence,
        severity=chain.severity, verdict=chain.verdict.value,
        suppressed=not chain.is_reportable, context_type=ctx_type,
        encoding_status=encoding_status, breakout_status=breakout_status,
        csp_impact=csp_impact, evidence_lines=chain.to_report_lines(), notes=list(chain.notes),
    )

    if (not skip_payload_stage
            and chain.verdict in (VerdictLevel.PROBABLE, VerdictLevel.POSSIBLE, VerdictLevel.CONFIRMED)
            and ctx_type not in {XSSContext.HTML_TITLE, XSSContext.HTML_NOSCRIPT, XSSContext.UNKNOWN}):
        finding = _stage6_payload_testing(target, param, profile, finding)

    log.info(
        "XSS pipeline result: param=%r confidence=%.0f%% verdict=%s suppressed=%s",
        param.name, finding.confidence * 100, finding.verdict, finding.suppressed,
    )
    return finding


def run_xss_pipeline_for_target(target: URLTarget) -> List[XSSPipelineFinding]:
    """Run the XSS pipeline on all reflected parameters of a URLTarget."""
    parameters: List[Parameter] = getattr(target, "parameters", [])
    if not parameters:
        return []

    reflection_results = getattr(target, "reflection_results", [])
    reflected_names = {r.parameter.name for r in reflection_results if r.reflected}

    if not reflected_names:
        log.info("No reflected parameters — skipping XSS pipeline for %s", target.normalized)
        return []

    log.info("XSS pipeline: %s — %d reflected param(s)", target.normalized, len(reflected_names))

    findings: List[XSSPipelineFinding] = []
    for param in parameters:
        if param.name not in reflected_names:
            continue
        finding = run_xss_pipeline(target, param)
        if finding is not None:
            findings.append(finding)

    reportable = [f for f in findings if not f.suppressed]
    log.info("XSS pipeline complete: %d reportable | %d suppressed",
              len(reportable), len(findings) - len(reportable))

    setattr(target, "xss_pipeline_findings", findings)
    return findings
