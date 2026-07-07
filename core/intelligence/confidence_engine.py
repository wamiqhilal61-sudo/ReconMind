"""
core/intelligence/confidence_engine.py
=========================================
Confidence scoring engine for ReconMind Phase 3 by wamiqsec.

WHY CONFIDENCE REPLACES POINT SCORES:
──────────────────────────────────────────────────────────────
Current system:   score = +20 + +30 + +50 = 100 → "HIGH"
Problem:          Points are LINEAR. Security evidence is not linear.
                  Two signals that each have 70% reliability don't
                  produce 140% certainty — that's impossible.
                  They produce 91% certainty (0.7 * 0.7 = 0.49 independent,
                  or ~0.91 combined as non-independent evidence).

New system:       Each evidence signal has:
                    - observed: was this signal triggered?
                    - base_confidence: if observed, how reliable is this signal?
                    - weight: how much does this signal matter?

                  Combined confidence = weighted average of active signals.
                  If no signals: confidence = 0.0 (no evidence).
                  If all signals: confidence approaches 1.0.

REPORTING THRESHOLDS:
    ≥ 0.85: AUTO_HIGH — Report as HIGH, high confidence, likely real
    ≥ 0.65: REPORT_MEDIUM — Report as MEDIUM, manual verification needed
    ≥ 0.45: FLAG_LOW — Flag as LOW, interesting but unconfirmed
    < 0.45: SUPPRESS — Too many false positives at this level

EVIDENCE SIGNALS BY MODULE:
    Each module registers its signals with this engine.
    The engine aggregates them into a final confidence score.

FALSE POSITIVE SUPPRESSION:
    We also track "suppression signals" — things that REDUCE confidence.
    Example: if the baseline shows very high natural variance,
    the confidence in any difference is reduced automatically.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict
from core.utils.logger import get_logger

log = get_logger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Reporting thresholds
# ─────────────────────────────────────────────────────────────────────────────

class ConfidenceLevel:
    AUTO_HIGH  = "AUTO_HIGH"    # ≥ 0.85 — report immediately
    MEDIUM     = "MEDIUM"       # ≥ 0.65 — report with manual verify note
    LOW        = "LOW"          # ≥ 0.45 — flag for review
    SUPPRESSED = "SUPPRESSED"   # < 0.45 — suppress, too risky


CONFIDENCE_THRESHOLDS = {
    ConfidenceLevel.AUTO_HIGH:  0.85,
    ConfidenceLevel.MEDIUM:     0.65,
    ConfidenceLevel.LOW:        0.45,
}

SEVERITY_MAP = {
    ConfidenceLevel.AUTO_HIGH:  "HIGH",
    ConfidenceLevel.MEDIUM:     "MEDIUM",
    ConfidenceLevel.LOW:        "LOW",
    ConfidenceLevel.SUPPRESSED: "INFO",
}


# ─────────────────────────────────────────────────────────────────────────────
# Data models
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class EvidenceSignal:
    """
    A single piece of evidence for or against a vulnerability.

    Each module creates EvidenceSignal objects and registers them.
    The confidence engine aggregates them.

    Attributes:
        name:             Unique identifier for this signal type.
        observed:         True if this signal was triggered during testing.
        base_confidence:  How reliable is this signal when observed? (0.0–1.0)
                          0.3 = weak (many false positives)
                          0.6 = moderate (sometimes false positive)
                          0.85 = strong (rarely false positive)
                          0.95 = near-certain (highly specific indicator)
        weight:           Relative importance of this signal (0.0–1.0).
                          All weights in a module should sum to ~1.0.
        evidence_text:    Human-readable description of what was observed.
        is_suppressor:    If True, this signal REDUCES confidence rather
                          than increasing it (for false positive suppression).
        suppression_factor: How much to reduce confidence if is_suppressor (0.0–1.0).
    """
    name: str
    observed: bool = False
    base_confidence: float = 0.5
    weight: float = 0.2
    evidence_text: str = ""
    is_suppressor: bool = False
    suppression_factor: float = 0.5  # Multiplies confidence by this if suppressor triggers


@dataclass
class EvidenceBundle:
    """
    Complete evidence record for a potential vulnerability finding.

    This is what modules produce instead of simple Finding objects.
    The reporting layer consumes EvidenceBundles and decides what to report.

    Attributes:
        module:                Which module produced this (IDOR, XSS, etc.).
        url:                   Target URL.
        parameter:             Parameter name being tested.
        param_type:            GET/POST/HIDDEN/JSON.
        signals:               All EvidenceSignal objects for this finding.
        combined_confidence:   Final calculated confidence (0.0–1.0).
        confidence_level:      AUTO_HIGH/MEDIUM/LOW/SUPPRESSED.
        severity:              HIGH/MEDIUM/LOW/INFO (from confidence).
        requires_manual:       True if human verification is needed.
        false_positive_risk:   "LOW"/"MEDIUM"/"HIGH" risk of false positive.
        summary:               One-line finding description.
        full_evidence:         Complete evidence chain for reporting.
        suppressed:            True if this finding was suppressed.
        suppression_reason:    Why it was suppressed.
    """
    module: str
    url: str
    parameter: str
    param_type: str = "UNKNOWN"
    signals: List[EvidenceSignal] = field(default_factory=list)

    combined_confidence: float = 0.0
    confidence_level: str = ConfidenceLevel.SUPPRESSED
    severity: str = "INFO"

    requires_manual: bool = True
    false_positive_risk: str = "HIGH"
    summary: str = ""
    full_evidence: List[str] = field(default_factory=list)
    suppressed: bool = True
    suppression_reason: str = ""

    def add_signal(self, signal: EvidenceSignal) -> None:
        """Register an evidence signal with this bundle."""
        self.signals.append(signal)

    def get_active_signals(self) -> List[EvidenceSignal]:
        """Return only the signals that were observed."""
        return [s for s in self.signals if s.observed and not s.is_suppressor]

    def get_active_suppressors(self) -> List[EvidenceSignal]:
        """Return suppressor signals that were triggered."""
        return [s for s in self.signals if s.observed and s.is_suppressor]


# ─────────────────────────────────────────────────────────────────────────────
# Pre-built signal libraries for each module
# ─────────────────────────────────────────────────────────────────────────────

def make_idor_signals() -> List[EvidenceSignal]:
    """
    Pre-built evidence signals for IDOR detection.

    Each signal represents one thing we can observe during IDOR testing.
    They are returned UNOBSERVED — the IDOR module marks them observed
    as it runs its tests.
    """
    return [
        EvidenceSignal(
            name="status_200_for_adjacent_id",
            observed=False,
            base_confidence=0.25,  # Weak: public content also returns 200
            weight=0.08,
            evidence_text="",
        ),
        EvidenceSignal(
            name="semantic_similarity_low",
            observed=False,
            base_confidence=0.30,  # Weak: content differs but could be blog posts
            weight=0.10,
            evidence_text="",
        ),
        EvidenceSignal(
            name="semantic_field_changed",
            observed=False,
            base_confidence=0.60,  # Moderate: response type changed
            weight=0.18,
            evidence_text="",
        ),
        EvidenceSignal(
            name="pii_pattern_detected",
            observed=False,
            base_confidence=0.80,  # Strong: actual PII found in different-ID response
            weight=0.28,
            evidence_text="",
        ),
        EvidenceSignal(
            name="nonexistent_id_returns_404",
            observed=False,
            base_confidence=0.70,  # Strong: server validates IDs, just not ownership
            weight=0.20,
            evidence_text="",
        ),
        EvidenceSignal(
            name="endpoint_requires_auth",
            observed=False,
            base_confidence=0.65,  # Moderate: confirmed endpoint needs login
            weight=0.16,
            evidence_text="",
        ),
        # ── Suppressors ── (reduce confidence when public content is likely)
        EvidenceSignal(
            name="endpoint_is_public",
            observed=False,
            base_confidence=0.0,
            weight=0.0,
            is_suppressor=True,
            suppression_factor=0.30,  # Reduces confidence to 30% of calculated
            evidence_text="Endpoint appears to serve public content",
        ),
        EvidenceSignal(
            name="high_natural_variance",
            observed=False,
            base_confidence=0.0,
            weight=0.0,
            is_suppressor=True,
            suppression_factor=0.50,  # Reduces confidence by half
            evidence_text="Baseline shows high natural length variance",
        ),
        EvidenceSignal(
            name="content_matches_public_pattern",
            observed=False,
            base_confidence=0.0,
            weight=0.0,
            is_suppressor=True,
            suppression_factor=0.40,
            evidence_text="Response content matches public article/blog pattern",
        ),
    ]


def make_ssrf_signals() -> List[EvidenceSignal]:
    """Pre-built evidence signals for SSRF detection."""
    return [
        EvidenceSignal(
            name="metadata_signature_direct",
            observed=False,
            base_confidence=0.95,  # Near-certain: metadata strings are highly specific
            weight=0.60,
            evidence_text="",
        ),
        EvidenceSignal(
            name="internal_service_signature",
            observed=False,
            base_confidence=0.85,
            weight=0.25,
            evidence_text="",
        ),
        EvidenceSignal(
            name="timing_delay_consistent",
            observed=False,
            base_confidence=0.50,  # Moderate: network variance is real
            weight=0.10,
            evidence_text="",
        ),
        EvidenceSignal(
            name="timing_delay_ip_specific",
            observed=False,
            base_confidence=0.65,  # Better: delay only for real IPs, not invalid ones
            weight=0.05,
            evidence_text="",
        ),
        EvidenceSignal(
            name="high_timing_variance_baseline",
            observed=False,
            base_confidence=0.0,
            weight=0.0,
            is_suppressor=True,
            suppression_factor=0.40,
            evidence_text="Baseline timing shows high variance (noisy network)",
        ),
    ]


def make_xss_signals() -> List[EvidenceSignal]:
    """Pre-built evidence signals for XSS detection."""
    return [
        EvidenceSignal(
            name="marker_reflected_raw",
            observed=False,
            base_confidence=0.70,  # Moderate alone: needs context to confirm
            weight=0.20,
            evidence_text="",
        ),
        EvidenceSignal(
            name="js_context_confirmed",
            observed=False,
            base_confidence=0.85,
            weight=0.30,
            evidence_text="",
        ),
        EvidenceSignal(
            name="dangerous_sink_nearby",
            observed=False,
            base_confidence=0.75,
            weight=0.20,
            evidence_text="",
        ),
        EvidenceSignal(
            name="payload_reflected_raw",
            observed=False,
            base_confidence=0.90,  # Strong: actual XSS payload reflected unencoded
            weight=0.30,
            evidence_text="",
        ),
        EvidenceSignal(
            name="reflection_is_encoded",
            observed=False,
            base_confidence=0.0,
            weight=0.0,
            is_suppressor=True,
            suppression_factor=0.35,
            evidence_text="Reflection was HTML-encoded (reduces exploitability)",
        ),
    ]


def make_sqli_signals() -> List[EvidenceSignal]:
    """Pre-built evidence signals for SQL injection detection."""
    return [
        EvidenceSignal(
            name="db_error_string_detected",
            observed=False,
            base_confidence=0.90,
            weight=0.35,
            evidence_text="",
        ),
        EvidenceSignal(
            name="boolean_true_matches_baseline",
            observed=False,
            base_confidence=0.70,
            weight=0.20,
            evidence_text="",
        ),
        EvidenceSignal(
            name="boolean_false_differs_from_baseline",
            observed=False,
            base_confidence=0.70,
            weight=0.20,
            evidence_text="",
        ),
        EvidenceSignal(
            name="time_delay_consistent",
            observed=False,
            base_confidence=0.65,
            weight=0.15,
            evidence_text="",
        ),
        EvidenceSignal(
            name="db_fingerprinted",
            observed=False,
            base_confidence=0.85,  # Bonus: we know which database
            weight=0.10,
            evidence_text="",
        ),
        EvidenceSignal(
            name="generic_error_page",
            observed=False,
            base_confidence=0.0,
            weight=0.0,
            is_suppressor=True,
            suppression_factor=0.50,
            evidence_text="Application returns generic errors (reduces error-based confidence)",
        ),
    ]


# ─────────────────────────────────────────────────────────────────────────────
# Core confidence calculation
# ─────────────────────────────────────────────────────────────────────────────

def calculate_confidence(bundle: EvidenceBundle) -> EvidenceBundle:
    """
    Calculate the final confidence score for an EvidenceBundle.

    Algorithm:
        1. Collect all observed (non-suppressor) signals
        2. Calculate weighted average confidence of active signals
        3. Apply suppressor penalties
        4. Map to confidence level and severity
        5. Determine false positive risk
        6. Build evidence chain for reporting

    Args:
        bundle: EvidenceBundle with all signals registered.

    Returns:
        The same bundle with confidence, level, severity, and evidence populated.
    """
    active = bundle.get_active_signals()
    suppressors = bundle.get_active_suppressors()

    # ── Step 1: Weighted average of active signals ────────────────────────
    if not active:
        bundle.combined_confidence = 0.0
    else:
        total_weight = sum(s.weight for s in active)
        if total_weight == 0:
            bundle.combined_confidence = 0.0
        else:
            weighted_sum = sum(s.base_confidence * s.weight for s in active)
            bundle.combined_confidence = weighted_sum / total_weight

    # ── Step 2: Apply suppressor penalties ───────────────────────────────
    for suppressor in suppressors:
        bundle.combined_confidence *= suppressor.suppression_factor
        log.debug(
            "Suppressor applied: %s → factor=%.2f → new confidence=%.2f",
            suppressor.name, suppressor.suppression_factor, bundle.combined_confidence,
        )

    # Clamp to valid range
    bundle.combined_confidence = max(0.0, min(1.0, bundle.combined_confidence))

    # ── Step 3: Map to confidence level ──────────────────────────────────
    if bundle.combined_confidence >= CONFIDENCE_THRESHOLDS[ConfidenceLevel.AUTO_HIGH]:
        bundle.confidence_level = ConfidenceLevel.AUTO_HIGH
    elif bundle.combined_confidence >= CONFIDENCE_THRESHOLDS[ConfidenceLevel.MEDIUM]:
        bundle.confidence_level = ConfidenceLevel.MEDIUM
    elif bundle.combined_confidence >= CONFIDENCE_THRESHOLDS[ConfidenceLevel.LOW]:
        bundle.confidence_level = ConfidenceLevel.LOW
    else:
        bundle.confidence_level = ConfidenceLevel.SUPPRESSED

    bundle.suppressed = (bundle.confidence_level == ConfidenceLevel.SUPPRESSED)

    # ── Step 4: Map to severity ───────────────────────────────────────────
    bundle.severity = SEVERITY_MAP[bundle.confidence_level]

    # ── Step 5: Determine false positive risk ─────────────────────────────
    if bundle.combined_confidence >= 0.80:
        bundle.false_positive_risk = "LOW"
    elif bundle.combined_confidence >= 0.55:
        bundle.false_positive_risk = "MEDIUM"
    else:
        bundle.false_positive_risk = "HIGH"

    # ── Step 6: Determine if manual verification needed ───────────────────
    # AUTO_HIGH from direct evidence (metadata, db errors) doesn't need verify
    # Everything else does
    has_near_certain_signal = any(
        s.observed and s.base_confidence >= 0.90 for s in active
    )
    bundle.requires_manual = not has_near_certain_signal

    # ── Step 7: Build evidence chain for reporting ────────────────────────
    evidence_lines = []
    evidence_lines.append(
        f"Combined confidence: {bundle.combined_confidence:.0%} "
        f"[{bundle.confidence_level}]"
    )

    for signal in active:
        evidence_lines.append(
            f"  ✓ [{signal.base_confidence:.0%}] {signal.name}: {signal.evidence_text}"
        )

    for suppressor in suppressors:
        evidence_lines.append(
            f"  ⚠ [SUPPRESSOR] {suppressor.name}: {suppressor.evidence_text}"
        )

    if bundle.suppressed:
        bundle.suppression_reason = (
            f"Confidence {bundle.combined_confidence:.0%} below threshold "
            f"({CONFIDENCE_THRESHOLDS[ConfidenceLevel.LOW]:.0%} minimum). "
            "Suppressed to avoid false positive report."
        )
        evidence_lines.append(f"  → SUPPRESSED: {bundle.suppression_reason}")

    bundle.full_evidence = evidence_lines

    log.info(
        "[%s] %s param=%r confidence=%.0f%% [%s] fp_risk=%s",
        bundle.module,
        bundle.url[:60],
        bundle.parameter,
        bundle.combined_confidence * 100,
        bundle.confidence_level,
        bundle.false_positive_risk,
    )

    return bundle


def create_bundle(
    module: str,
    url: str,
    parameter: str,
    param_type: str = "GET",
    summary: str = "",
) -> EvidenceBundle:
    """
    Factory function to create a new EvidenceBundle with pre-built signals.

    Args:
        module:     Module name (IDOR, XSS, SSRF, SQLI, REDIRECT, LFI, CSRF).
        url:        Target URL being tested.
        parameter:  Parameter name being tested.
        param_type: GET/POST/HIDDEN/JSON.
        summary:    One-line description of what's being tested.

    Returns:
        EvidenceBundle with appropriate signals pre-registered.
    """
    SIGNAL_FACTORIES = {
        "IDOR":     make_idor_signals,
        "SSRF":     make_ssrf_signals,
        "XSS":      make_xss_signals,
        "SQLI":     make_sqli_signals,
    }

    bundle = EvidenceBundle(
        module=module,
        url=url,
        parameter=parameter,
        param_type=param_type,
        summary=summary or f"{module} test: {url} [{parameter}]",
    )

    # Pre-register signals for known modules
    factory = SIGNAL_FACTORIES.get(module.upper())
    if factory:
        bundle.signals = factory()

    return bundle


def mark_signal(bundle: EvidenceBundle, signal_name: str, evidence_text: str = "") -> None:
    """
    Mark a signal as observed in an EvidenceBundle.

    Args:
        bundle:       The EvidenceBundle to update.
        signal_name:  Name of the signal to mark observed.
        evidence_text: What was actually observed (for the report).
    """
    for signal in bundle.signals:
        if signal.name == signal_name:
            signal.observed = True
            if evidence_text:
                signal.evidence_text = evidence_text
            return

    # If signal not pre-registered, add it dynamically
    log.warning("Signal %r not found in bundle for %s — adding dynamically", signal_name, bundle.module)
    bundle.signals.append(EvidenceSignal(
        name=signal_name,
        observed=True,
        base_confidence=0.5,
        weight=0.1,
        evidence_text=evidence_text,
    ))
