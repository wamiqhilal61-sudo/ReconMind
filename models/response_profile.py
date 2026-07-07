"""
models/response_profile.py
============================
Central Response Profile model for wamiqsec/ReconMind Phase 5.

Single rich object accumulating everything we know about a response
as the XSS pipeline executes. Eliminates re-fetching and re-parsing
between pipeline stages.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Set
from enum import Enum


class ReflectionType(Enum):
    NOT_REFLECTED  = "NOT_REFLECTED"
    RAW            = "RAW"
    HTML_ENCODED   = "HTML_ENCODED"
    JS_ENCODED     = "JS_ENCODED"
    URL_ENCODED    = "URL_ENCODED"
    DOUBLE_ENCODED = "DOUBLE_ENCODED"
    PARTIAL        = "PARTIAL"
    FILTERED       = "FILTERED"


@dataclass
class ReflectionInfo:
    reflection_type: ReflectionType = ReflectionType.NOT_REFLECTED
    is_raw: bool = False
    positions: List[int] = field(default_factory=list)
    snippets: List[str] = field(default_factory=list)
    count: int = 0
    encoding_forms: List[str] = field(default_factory=list)
    chars_encoded: List[str] = field(default_factory=list)
    chars_blocked: List[str] = field(default_factory=list)
    chars_raw: List[str] = field(default_factory=list)
    in_header: bool = False
    header_name: str = ""

    @property
    def was_reflected(self) -> bool:
        return self.reflection_type != ReflectionType.NOT_REFLECTED

    @property
    def partially_sanitized(self) -> bool:
        return self.reflection_type == ReflectionType.PARTIAL or bool(self.chars_encoded and self.chars_raw)


@dataclass
class ContextInfo:
    context_type: str = "UNKNOWN"
    confidence: float = 0.0
    snippet: str = ""
    parent_tag: str = ""
    attribute_name: str = ""
    is_event_handler: bool = False
    is_url_attr: bool = False
    is_executable: bool = False
    is_in_script_block: bool = False
    is_in_style_block: bool = False
    is_in_template: bool = False
    detection_method: str = ""


@dataclass
class BreakoutInfo:
    was_tested: bool = False
    chars_tested: List[str] = field(default_factory=list)
    chars_raw: List[str] = field(default_factory=list)
    chars_encoded: List[str] = field(default_factory=list)
    chars_blocked: List[str] = field(default_factory=list)
    required_chars: Set[str] = field(default_factory=set)
    feasible: bool = False
    confidence: float = 0.0
    reason: str = ""

    @property
    def all_required_survived(self) -> bool:
        return bool(self.required_chars and self.required_chars.issubset(set(self.chars_raw)))

    @property
    def any_required_survived(self) -> bool:
        return bool(self.required_chars and self.required_chars.intersection(set(self.chars_raw)))


@dataclass
class ResponseProfile:
    """Central carrier object for the XSS validation pipeline."""
    url: str = ""
    param_name: str = ""
    param_type: str = "GET"
    injected_value: str = ""
    http_status: int = 200
    content_type: str = ""
    raw_body: str = ""
    normalized_body: str = ""
    body_length: int = 0
    response_headers: Dict[str, str] = field(default_factory=dict)

    reflection_info: Optional[ReflectionInfo] = None
    context_info: Optional[ContextInfo] = None
    breakout_info: Optional[BreakoutInfo] = None

    csp_header: str = ""
    csp_blocks_xss: bool = False
    csp_bypass_available: bool = False

    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_http_response(
        cls, response: Any, url: str, param_name: str, param_type: str, injected_value: str,
    ) -> "ResponseProfile":
        if response is None:
            return cls(url=url, param_name=param_name, param_type=param_type, injected_value=injected_value)

        headers = {k.lower(): v for k, v in response.headers.items()}

        profile = cls(
            url=url, param_name=param_name, param_type=param_type,
            injected_value=injected_value, http_status=response.status_code,
            content_type=headers.get("content-type", ""), raw_body=response.text,
            body_length=len(response.content), response_headers=headers,
            csp_header=headers.get("content-security-policy", ""),
        )

        if profile.csp_header:
            csp_lower = profile.csp_header.lower()
            has_unsafe = "'unsafe-inline'" in csp_lower
            has_wildcard = "* " in csp_lower
            profile.csp_blocks_xss = not (has_unsafe or has_wildcard)
            profile.csp_bypass_available = has_unsafe or has_wildcard

        return profile

    @property
    def is_html_response(self) -> bool:
        return "text/html" in self.content_type.lower()

    @property
    def is_json_response(self) -> bool:
        return "application/json" in self.content_type.lower()

    @property
    def was_reflected(self) -> bool:
        return self.reflection_info is not None and self.reflection_info.was_reflected

    @property
    def is_raw_reflected(self) -> bool:
        return self.reflection_info is not None and self.reflection_info.is_raw

    @property
    def context_is_executable(self) -> bool:
        return self.context_info is not None and self.context_info.is_executable

    @property
    def breakout_feasible(self) -> bool:
        return self.breakout_info is not None and self.breakout_info.feasible

    def summary(self) -> str:
        parts = [f"param={self.param_name!r}"]
        if self.reflection_info:
            parts.append(f"reflection={self.reflection_info.reflection_type.value}")
        if self.context_info:
            parts.append(f"context={self.context_info.context_type}")
        if self.breakout_info:
            parts.append(f"breakout={self.breakout_info.feasible}")
        return " | ".join(parts)
