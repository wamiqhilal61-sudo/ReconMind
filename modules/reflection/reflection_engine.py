"""modules/reflection/reflection_engine.py — Reflection probing engine for wamiqsec/ReconMind."""

from dataclasses import dataclass, field
from typing import List, Optional, Dict
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse, quote

from core.recon.url_handler import URLTarget
from core.extractor.param_extractor import Parameter, ParamType
from core.utils.http_client import safe_get, safe_post
from config.settings import CONFIG
from core.utils.logger import get_logger

log = get_logger(__name__)


@dataclass
class ReflectionResult:
    parameter: Parameter
    marker: str
    reflected: bool = False
    raw_reflected: bool = False
    reflection_count: int = 0
    snippets: List[str] = field(default_factory=list)
    response_code: int = 0
    reflected_in_header: bool = False

    def __repr__(self) -> str:
        status = "REFLECTED" if self.reflected else "not reflected"
        return f"ReflectionResult({self.parameter.param_type}:{self.parameter.name!r} -> {status})"


def _inject_get_param(target: URLTarget, param: Parameter, marker: str) -> Optional[str]:
    parsed = urlparse(target.normalized)
    query_params = parse_qs(parsed.query, keep_blank_values=True)
    query_params[param.name] = [marker]
    new_query = urlencode(
        {k: v[0] for k, v in sorted(query_params.items())},
        quote_via=lambda s, safe, encoding, errors: s,
    )
    return urlunparse(parsed._replace(query=new_query))


def _extract_snippets(text: str, marker: str, radius: int) -> List[str]:
    snippets = []
    start = 0
    while True:
        idx = text.find(marker, start)
        if idx == -1:
            break
        s = max(0, idx - radius)
        e = min(len(text), idx + len(marker) + radius)
        snippets.append(text[s:e].replace("\n", "↵").replace("\r", ""))
        start = idx + 1
    return snippets


def _check_encoding(response_text: str, marker: str) -> tuple:
    raw_found = marker in response_text
    html_encoded_marker = (
        marker.replace("&", "&amp;").replace("<", "&lt;")
        .replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#x27;")
    )
    encoded_found = html_encoded_marker in response_text
    url_encoded_marker = quote(marker, safe="")
    url_encoded_found = url_encoded_marker in response_text
    return raw_found, (encoded_found or url_encoded_found)


def probe_get_parameter(target: URLTarget, param: Parameter) -> ReflectionResult:
    marker = CONFIG.payloads.reflection_marker
    radius = CONFIG.payloads.context_snippet_radius
    result = ReflectionResult(parameter=param, marker=marker)

    probe_url = _inject_get_param(target, param, marker)
    if not probe_url:
        return result

    response = safe_get(probe_url, allow_redirects=False)
    if response is None:
        return result

    result.response_code = response.status_code
    response_text = response.text
    raw_found, encoded_found = _check_encoding(response_text, marker)

    if raw_found:
        result.reflected = True
        result.raw_reflected = True
        result.snippets = _extract_snippets(response_text, marker, radius)
        result.reflection_count = response_text.count(marker)
    elif encoded_found:
        result.reflected = True
        result.raw_reflected = False

    for header_name, header_val in response.headers.items():
        if marker in header_val:
            result.reflected = True
            result.reflected_in_header = True
            break

    return result


def probe_post_parameter(target: URLTarget, param: Parameter) -> ReflectionResult:
    marker = CONFIG.payloads.reflection_marker
    radius = CONFIG.payloads.context_snippet_radius
    result = ReflectionResult(parameter=param, marker=marker)

    post_url = param.form_action or target.base_url()
    form_data: Dict[str, str] = {param.name: marker}

    if hasattr(target, "parameters"):
        for p in target.parameters:
            if (p.param_type in (ParamType.POST, ParamType.HIDDEN)
                    and p.form_action == param.form_action and p.name != param.name):
                form_data[p.name] = p.value

    response = safe_post(post_url, data=form_data, allow_redirects=False)
    if response is None:
        return result

    result.response_code = response.status_code
    response_text = response.text
    raw_found, encoded_found = _check_encoding(response_text, marker)

    if raw_found:
        result.reflected = True
        result.raw_reflected = True
        result.snippets = _extract_snippets(response_text, marker, radius)
        result.reflection_count = response_text.count(marker)
    elif encoded_found:
        result.reflected = True
        result.raw_reflected = False

    return result


def run_reflection_probes(target: URLTarget) -> List[ReflectionResult]:
    parameters: List[Parameter] = getattr(target, "parameters", [])
    if not parameters:
        return []

    log.info("Starting reflection probes on %s (%d params)", target.normalized, len(parameters))
    results: List[ReflectionResult] = []

    for param in parameters:
        if param.param_type in (ParamType.GET, ParamType.JSON):
            result = probe_get_parameter(target, param)
        elif param.param_type in (ParamType.POST, ParamType.HIDDEN):
            result = probe_post_parameter(target, param)
        else:
            continue
        results.append(result)

    reflected_count = sum(1 for r in results if r.reflected)
    log.info("Reflection probing complete: %d/%d params reflected", reflected_count, len(results))

    setattr(target, "reflection_results", results)
    return results
