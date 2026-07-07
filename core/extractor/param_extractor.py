"""core/extractor/param_extractor.py — GET/POST/HIDDEN/JSON parameter extraction for wamiqsec/ReconMind."""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from urllib.parse import parse_qs
import json
import re

from bs4 import BeautifulSoup

from core.recon.url_handler import URLTarget
from core.utils.http_client import safe_get
from core.utils.logger import get_logger

log = get_logger(__name__)


class ParamType:
    GET = "GET"
    POST = "POST"
    JSON = "JSON"
    HIDDEN = "HIDDEN"


@dataclass
class Parameter:
    name: str
    value: str = ""
    param_type: str = ParamType.GET
    form_action: Optional[str] = None
    is_numeric: bool = False
    notes: List[str] = field(default_factory=list)

    def __repr__(self) -> str:
        return f"Parameter({self.param_type}:{self.name!r}={self.value!r})"

    def flag_numeric(self) -> None:
        self.is_numeric = True
        self.notes.append("Numeric value")


def _extract_get_params(target: URLTarget) -> List[Parameter]:
    if not target.query:
        return []
    params = []
    parsed = parse_qs(target.query, keep_blank_values=True)
    for name, values in parsed.items():
        value = values[0] if values else ""
        p = Parameter(name=name, value=value, param_type=ParamType.GET)
        if value.isdigit():
            p.flag_numeric()
        params.append(p)
    return params


def _extract_form_params(html: str, base_url: str) -> List[Parameter]:
    if not html:
        return []
    params = []
    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception as exc:
        log.warning("BeautifulSoup parse error: %s", exc)
        return []

    for form in soup.find_all("form"):
        action = form.get("action", "").strip()
        form_method = form.get("method", "get").strip().upper()
        form_action_url = action if action else base_url

        for tag in form.find_all(["input", "textarea", "select"]):
            name = tag.get("name", "").strip()
            if not name:
                continue
            value = tag.get("value", "") or ""
            input_type = tag.get("type", "text").lower()

            if input_type == "hidden":
                p = Parameter(name=name, value=value, param_type=ParamType.HIDDEN, form_action=form_action_url)
            elif form_method == "POST":
                p = Parameter(name=name, value=value, param_type=ParamType.POST, form_action=form_action_url)
            else:
                p = Parameter(name=name, value=value, param_type=ParamType.GET, form_action=form_action_url)

            if value.isdigit():
                p.flag_numeric()
            params.append(p)

    return params


def _flatten_json_keys(data: Any, depth: int, prefix: str = "", max_depth: int = 2) -> List[Parameter]:
    params = []
    if depth > max_depth:
        return params
    if isinstance(data, dict):
        for key, val in data.items():
            full_key = f"{prefix}.{key}" if prefix else key
            if isinstance(val, (dict, list)) and depth < max_depth:
                params.extend(_flatten_json_keys(val, depth + 1, prefix=full_key))
            else:
                str_val = str(val) if val is not None else ""
                p = Parameter(name=full_key, value=str_val, param_type=ParamType.JSON)
                if str_val.isdigit():
                    p.flag_numeric()
                params.append(p)
    elif isinstance(data, list) and depth < max_depth:
        for i, item in enumerate(data[:5]):
            params.extend(_flatten_json_keys(item, depth + 1, prefix=f"{prefix}[{i}]"))
    return params


def _extract_json_params(response_text: str, content_type: str) -> List[Parameter]:
    is_json_ct = "application/json" in content_type.lower()
    looks_json = response_text.strip().startswith(("{", "["))
    if not is_json_ct and not looks_json:
        return []
    try:
        data = json.loads(response_text)
    except (json.JSONDecodeError, ValueError):
        params = []
        for blob in re.findall(r'\{[^{}]{10,}\}', response_text)[:3]:
            try:
                data = json.loads(blob)
                params.extend(_flatten_json_keys(data, depth=0))
            except (json.JSONDecodeError, ValueError):
                continue
        return params
    return _flatten_json_keys(data, depth=0)


def _attach_parameters(target: URLTarget, params: List[Parameter]) -> None:
    setattr(target, "parameters", params)
    param_map = {f"{p.param_type}:{p.name}": p for p in params}
    setattr(target, "param_map", param_map)


def extract_parameters(target: URLTarget) -> URLTarget:
    log.info("Extracting parameters from: %s", target.normalized)
    all_params: List[Parameter] = _extract_get_params(target)

    response = safe_get(target.normalized)
    if response is None:
        log.warning("Could not fetch %s", target.normalized)
        _attach_parameters(target, all_params)
        return target

    setattr(target, "baseline_response", response)
    setattr(target, "http_status", response.status_code)

    html_body = response.text
    content_type = response.headers.get("Content-Type", "")

    all_params.extend(_extract_form_params(html_body, target.base_url()))
    all_params.extend(_extract_json_params(html_body, content_type))

    _attach_parameters(target, all_params)
    log.info("Parameter extraction complete: %d total", len(all_params))
    return target
