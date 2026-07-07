"""
config/settings.py
====================
wamiqsec — ReconMind central configuration.
Single source of truth for every tunable value across all phases.
"""

from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class NetworkConfig:
    request_timeout: int = 15
    max_redirects: int = 5
    max_concurrent_requests: int = 10
    default_headers: Dict[str, str] = field(default_factory=lambda: {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "close",
    })
    verify_ssl: bool = False
    proxies: Dict[str, str] = field(default_factory=dict)


@dataclass
class PayloadConfig:
    reflection_marker: str = "XSS123TEST"
    html_probe: str = "<XSS123TEST>"
    js_probe: str = "XSS123TEST`"
    context_snippet_radius: int = 80


@dataclass
class ScoringConfig:
    reflected_input: int = 20
    unencoded_reflection: int = 30
    js_context: int = 50
    dangerous_sink: int = 40
    html_attribute_context: int = 25
    json_context: int = 15
    html_comment_context: int = 10


@dataclass
class ReportingConfig:
    output_dir: str = "reports"
    min_display_score: int = 10
    high_threshold: int = 70
    medium_threshold: int = 40
    low_threshold: int = 10
    use_color: bool = True


@dataclass
class LoggingConfig:
    level: str = "INFO"
    log_to_file: bool = False
    log_file_path: str = "reports/reconmind.log"
    log_format: str = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"


@dataclass
class XSSConfig:
    max_payloads_per_param: int = 10
    enable_waf_bypass_payloads: bool = False
    stop_after_hits: int = 3
    xss_confirmation_string: str = "XSS_CONFIRMED_RM"
    delay_between_requests: float = 0.2


@dataclass
class RedirectConfig:
    redirect_test_domains: List[str] = field(default_factory=lambda: [
        "https://evil.com", "//evil.com",
        "https://evil.com%2F@target.com", "https://target.com.evil.com",
    ])
    redirect_status_codes: List[int] = field(default_factory=lambda: [301, 302, 303, 307, 308])
    common_redirect_params: List[str] = field(default_factory=lambda: [
        "url", "redirect", "redirect_url", "next", "return", "return_url",
        "returnUrl", "goto", "go", "target", "destination", "dest",
        "forward", "location", "callback", "continue", "redir", "ref", "back",
    ])


@dataclass
class LFIConfig:
    max_traversal_depth: int = 8
    target_files: List[str] = field(default_factory=lambda: [
        "/etc/passwd", "/etc/hosts", "/etc/shadow",
        "/proc/self/environ", "/proc/self/cmdline",
        "C:/Windows/win.ini", "C:/Windows/System32/drivers/etc/hosts",
        "C:/boot.ini",
    ])
    linux_signatures: List[str] = field(default_factory=lambda: [
        "root:x:0:0", "127.0.0.1", "root:!:",
    ])
    windows_signatures: List[str] = field(default_factory=lambda: [
        "[extensions]", "[boot loader]",
    ])
    test_php_wrappers: bool = True


@dataclass
class SSRFConfig:
    internal_targets: List[str] = field(default_factory=lambda: [
        "http://127.0.0.1", "http://localhost",
        "http://169.254.169.254", "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal", "http://100.100.100.200",
        "http://192.168.0.1", "http://10.0.0.1",
    ])
    common_url_params: List[str] = field(default_factory=lambda: [
        "url", "uri", "src", "source", "href", "link", "path",
        "file", "fetch", "load", "proxy", "request", "host",
        "endpoint", "service", "api", "target", "domain",
    ])
    success_signatures: List[str] = field(default_factory=lambda: [
        "ami-id", "instance-id", "computeMetadata", "latest/meta-data", "hostname",
    ])


@dataclass
class IDORConfig:
    adjacent_id_range: int = 5
    test_uuid_params: bool = True
    success_status_codes: List[int] = field(default_factory=lambda: [200, 201])
    size_diff_threshold: int = 50


@dataclass
class DatabaseConfig:
    db_path: str = "database/reconmind.db"
    auto_save: bool = True
    max_findings: int = 10000


@dataclass
class PassiveModeConfig:
    max_urls: int = 200
    max_crawl_depth: int = 3
    request_delay: float = 1.5
    max_concurrent: int = 3
    restrict_to_seed_domain: bool = True
    analyze_js_files: bool = True
    fingerprint_technologies: bool = True
    analyze_security_headers: bool = True
    extract_js_endpoints: bool = True
    classify_responses: bool = True
    detect_js_secrets: bool = True
    map_dangerous_sinks: bool = True
    request_budget: int = 500


@dataclass
class ActiveModeConfig:
    min_confidence_to_test: float = 0.30
    multi_stage_validation: bool = True
    validation_stages: int = 3
    max_concurrent_probes: int = 5
    probe_delay: float = 0.3
    stop_on_first_hit: bool = False
    xss_execution_validation: bool = True
    headless_browser_enabled: bool = False
    sqli_extract_data: bool = False
    max_payloads_per_param: int = 15


@dataclass
class ManualAssistConfig:
    generate_hunting_guide: bool = True
    burp_export: bool = False
    min_interest_score: int = 30
    suggest_chains: bool = True
    highlight_new_surface: bool = True


@dataclass
class JavaScriptEngineConfig:
    max_js_file_size: int = 2_000_000
    fetch_external_js: bool = True
    detect_graphql: bool = True
    detect_secrets: bool = True
    secret_min_entropy: float = 3.5
    map_source_sink_flows: bool = True
    extract_routes: bool = True


@dataclass
class ResponseClassifierConfig:
    min_classification_confidence: float = 0.60
    affect_payload_selection: bool = True
    affect_suppressors: bool = True
    detect_admin_panels: bool = True
    detect_upload_endpoints: bool = True


@dataclass
class XSSEngineConfig:
    parser_aware_context: bool = True
    breakout_analysis: bool = True
    executable_context_validation: bool = True
    detect_dom_xss_sinks: bool = True
    breakout_probe_chars: List[str] = field(default_factory=lambda: [
        "'", '"', "<", ">", "`", "\\", "}", "{", ";", "/",
    ])
    distinguish_harmless_reflection: bool = True
    min_breakout_chars_unencoded: int = 2


@dataclass
class CrawlerConfig:
    max_depth: int = 4
    max_pages: int = 300
    same_domain_only: bool = True
    follow_subdomains: bool = False
    respect_robots_txt: bool = True
    extract_from_comments: bool = True
    extract_from_js: bool = True
    crawl_delay: float = 0.8
    max_concurrent: int = 5
    ignore_extensions: List[str] = field(default_factory=lambda: [
        ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".woff",
        ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".pdf", ".zip",
        ".gz", ".tar", ".css",
    ])


@dataclass
class ReconMindConfig:
    network: NetworkConfig = field(default_factory=NetworkConfig)
    payloads: PayloadConfig = field(default_factory=PayloadConfig)
    scoring: ScoringConfig = field(default_factory=ScoringConfig)
    reporting: ReportingConfig = field(default_factory=ReportingConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    xss: XSSConfig = field(default_factory=XSSConfig)
    redirects: RedirectConfig = field(default_factory=RedirectConfig)
    lfi: LFIConfig = field(default_factory=LFIConfig)
    ssrf: SSRFConfig = field(default_factory=SSRFConfig)
    idor: IDORConfig = field(default_factory=IDORConfig)
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    passive: PassiveModeConfig = field(default_factory=PassiveModeConfig)
    active: ActiveModeConfig = field(default_factory=ActiveModeConfig)
    manual: ManualAssistConfig = field(default_factory=ManualAssistConfig)
    js_engine: JavaScriptEngineConfig = field(default_factory=JavaScriptEngineConfig)
    classifier: ResponseClassifierConfig = field(default_factory=ResponseClassifierConfig)
    xss_engine: XSSEngineConfig = field(default_factory=XSSEngineConfig)
    crawler: CrawlerConfig = field(default_factory=CrawlerConfig)


CONFIG = ReconMindConfig()
