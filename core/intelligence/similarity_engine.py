"""
core/intelligence/similarity_engine.py
=========================================
Semantic similarity engine for ReconMind Phase 3 by wamiqsec.

WHY THIS REPLACES SIZE DIFF:
──────────────────────────────────────────────────────────────
Current scanner:   if abs(size_A - size_B) > 50: flag_vulnerability()
This scanner:      compute_similarity(normalized_A, normalized_B) → 0.0–1.0

The difference:
    Size diff only measures QUANTITY of change.
    Similarity measures QUALITY and TYPE of change.

    /post?id=1  → 8,420 bytes (article about Python)
    /post?id=2  → 9,100 bytes (article about JavaScript)
    Size diff:  680 bytes → OLD SCANNER REPORTS IDOR
    Token similarity: {"python", "flask", "web"} vs {"javascript", "node", "react"}
    Jaccard similarity: 0.05 (very different words — but it's just different articles)
    Semantic field: both "public_content" → NOT suspicious

    /api/user?id=1  → {"name": "Alice", "email": "alice@corp.com"}
    /api/user?id=2  → {"name": "Bob",   "email": "bob@corp.com"}
    Size diff:  same size → OLD SCANNER MIGHT MISS THIS
    Token similarity: low (different names/emails)
    Semantic field: both "user_data" → SUSPICIOUS (different user data)
    PII both present → HIGH confidence IDOR

SIMILARITY METRICS USED:
    1. Jaccard Token Similarity   — word overlap between normalized bodies
    2. Structural DOM Similarity  — HTML tree structure comparison
    3. Length Ratio               — relative size relationship
    4. Semantic Consistency       — do both responses have the same content type?
    5. Numeric Drift Analysis     — which numbers changed and where

COMPOSITE FORMULA:
    similarity = (
        0.35 * jaccard +
        0.25 * structural +
        0.20 * length_ratio_score +
        0.20 * semantic_consistency
    )
    Range: 0.0 (completely different) → 1.0 (identical content)
"""

from dataclasses import dataclass, field
from typing import Set, Optional, Dict, List

from core.intelligence.normalizer import NormalizedResponse
from core.utils.logger import get_logger

log = get_logger(__name__)


@dataclass
class SimilarityReport:
    """
    Complete similarity analysis between two normalized responses.

    Attributes:
        jaccard_similarity:      Token-level word overlap (0.0–1.0).
        structural_similarity:   DOM structure similarity (0.0–1.0).
        length_ratio_score:      How similar the lengths are (0.0–1.0).
        semantic_consistency:    Do both have the same semantic field? (0.0 or 1.0).
        composite_similarity:    Weighted combination (0.0–1.0).
        is_suspiciously_different: True if difference seems non-trivial.
        semantic_field_changed:  True if semantic fields differ.
        pii_introduced:          PII types that appeared in B but not in A.
        numeric_drift:           Numbers that changed position or value.
        interpretation:          Human-readable explanation of the result.
        confidence_contribution: How much this report adds to evidence confidence.
    """

    jaccard_similarity: float = 0.0
    structural_similarity: float = 0.0
    length_ratio_score: float = 0.0
    semantic_consistency: float = 0.0
    composite_similarity: float = 0.0

    is_suspiciously_different: bool = False
    semantic_field_changed: bool = False
    pii_introduced: List[str] = field(default_factory=list)
    numeric_drift: Dict[str, str] = field(default_factory=dict)

    interpretation: str = ""
    confidence_contribution: float = 0.0


def _jaccard_similarity(set_a: Set[str], set_b: Set[str]) -> float:
    """
    Compute Jaccard similarity between two token sets.

    Jaccard = |A ∩ B| / |A ∪ B|

    Returns:
        Float between 0.0 (nothing in common) and 1.0 (identical sets).
    """
    if not set_a and not set_b:
        return 1.0  # Both empty = identical
    if not set_a or not set_b:
        return 0.0  # One empty, one not = completely different

    intersection = len(set_a & set_b)
    union = len(set_a | set_b)

    return intersection / union if union > 0 else 0.0


def _structural_similarity(fp_a: str, fp_b: str, count_a: int, count_b: int) -> float:
    """
    Compute structural similarity between two DOM fingerprints.

    If fingerprints are identical: 1.0 (same HTML structure)
    If fingerprints differ but node counts are close: partial similarity
    If fingerprints differ completely: 0.0

    Args:
        fp_a, fp_b:         MD5 hashes of DOM structures.
        count_a, count_b:   Number of DOM nodes in each response.

    Returns:
        Float 0.0–1.0.
    """
    # Identical structure
    if fp_a and fp_b and fp_a == fp_b:
        return 1.0

    # No DOM structure (non-HTML response)
    if not fp_a and not fp_b:
        return 1.0

    if not fp_a or not fp_b:
        return 0.0

    # Different structure — check if node counts are similar
    # Similar node count with different fingerprint = same template, different content
    if count_a > 0 and count_b > 0:
        count_ratio = min(count_a, count_b) / max(count_a, count_b)
        # If 90%+ of nodes match in count, it's likely the same template
        return 0.8 * count_ratio
    else:
        return 0.1  # Different fingerprints and one has no DOM = very different


def _length_ratio_score(len_a: int, len_b: int, tolerance: int = 0) -> float:
    """
    Score how similar two response lengths are.

    Perfect ratio (equal lengths): 1.0
    Very different (10x or more): 0.0
    The score degrades linearly between these extremes.

    Args:
        len_a, len_b: Normalized response lengths.
        tolerance:    Known acceptable variance (from baseline). Lengths within
                      this range are treated as identical.

    Returns:
        Float 0.0–1.0.
    """
    if len_a == 0 and len_b == 0:
        return 1.0
    if len_a == 0 or len_b == 0:
        return 0.0

    # Within calibrated tolerance = treat as identical
    if tolerance > 0 and abs(len_a - len_b) <= tolerance:
        return 1.0

    # Compute ratio
    larger = max(len_a, len_b)
    smaller = min(len_a, len_b)
    ratio = smaller / larger  # 0.0 (huge difference) → 1.0 (identical)

    return ratio


def _semantic_consistency_score(field_a: str, field_b: str) -> float:
    """
    Score how consistent the semantic fields are between two responses.

    Same field: 1.0 (responses are the same type of content)
    Different fields: 0.0 (response type changed — suspicious)

    Field changes that indicate vulnerability:
        public_content → user_data: suspicious (accessed private data)
        error_data → user_data: suspicious (error bypassed, got data)
        auth_data → user_data: suspicious (auth check bypassed)

    Args:
        field_a: Semantic field of baseline response.
        field_b: Semantic field of probe response.

    Returns:
        Float 0.0–1.0.
    """
    if field_a == field_b:
        return 1.0

    # Some field transitions are expected and less suspicious
    low_suspicion_transitions = {
        ("unknown", "public_content"),
        ("public_content", "unknown"),
        ("unknown", "unknown"),
    }

    if (field_a, field_b) in low_suspicion_transitions or (field_b, field_a) in low_suspicion_transitions:
        return 0.5

    # High-suspicion transitions (different content type appeared)
    return 0.0


def _analyze_numeric_drift(
    map_a: Dict[int, str],
    map_b: Dict[int, str],
) -> Dict[str, str]:
    """
    Identify numbers that changed between two responses.

    We compare numbers at the same structural positions.
    Numbers that change are potential ID/data drift indicators.

    Args:
        map_a: {position: value} from baseline.
        map_b: {position: value} from probe.

    Returns:
        Dict of {position_str: "old_value → new_value"} for changed numbers.
    """
    drift = {}

    # Find positions that exist in both and have different values
    common_positions = set(map_a.keys()) & set(map_b.keys())
    for pos in common_positions:
        if map_a[pos] != map_b[pos]:
            drift[str(pos)] = f"{map_a[pos]} → {map_b[pos]}"

    return drift


def _interpret_similarity(report: SimilarityReport, context: str = "IDOR") -> str:
    """
    Generate a human-readable interpretation of the similarity analysis.

    Args:
        report:  The SimilarityReport to interpret.
        context: Which vulnerability module is asking (affects interpretation).

    Returns:
        String interpretation for reports and logs.
    """
    cs = report.composite_similarity

    if cs >= 0.90:
        return "Responses are essentially identical — no meaningful difference detected"

    if cs >= 0.70:
        return (
            f"Responses are similar ({cs:.0%}) — minor differences likely from "
            "dynamic content or normal variance"
        )

    if cs >= 0.40:
        base = f"Responses differ significantly ({cs:.0%})"
        if report.semantic_field_changed:
            base += " — semantic field changed (suspicious)"
        if report.pii_introduced:
            base += f" — PII introduced: {', '.join(report.pii_introduced)}"
        return base

    if cs < 0.40:
        base = f"Responses are very different ({cs:.0%})"
        if context == "IDOR":
            if report.pii_introduced:
                return base + " — PII found in different ID response — HIGH confidence IDOR signal"
            elif report.semantic_field_changed:
                return base + " — Content type changed — MEDIUM confidence IDOR signal"
            else:
                return base + " — Could be public paginated content — verify semantics"
        return base

    return f"Similarity: {cs:.0%}"


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def compute_similarity(
    baseline: NormalizedResponse,
    probe: NormalizedResponse,
    context: str = "IDOR",
    length_tolerance: int = 0,
) -> SimilarityReport:
    """
    Compute comprehensive semantic similarity between two normalized responses.

    This is the core comparison function used by IDOR, SSRF, and
    all other modules that need to determine if responses are "meaningfully different".

    Args:
        baseline:          NormalizedResponse for the original/baseline request.
        probe:             NormalizedResponse for the injection/probe request.
        context:           Which module is asking (affects interpretation).
        length_tolerance:  Known acceptable length variance from baseline calibration.

    Returns:
        SimilarityReport with all metrics and interpretation.
    """
    report = SimilarityReport()

    # ── Metric 1: Jaccard token similarity ──────────────────────────────────
    report.jaccard_similarity = _jaccard_similarity(
        baseline.content_tokens,
        probe.content_tokens,
    )

    # ── Metric 2: Structural similarity ─────────────────────────────────────
    report.structural_similarity = _structural_similarity(
        baseline.dom_fingerprint,
        probe.dom_fingerprint,
        baseline.dom_node_count,
        probe.dom_node_count,
    )

    # ── Metric 3: Length ratio ───────────────────────────────────────────────
    report.length_ratio_score = _length_ratio_score(
        baseline.normalized_length,
        probe.normalized_length,
        length_tolerance,
    )

    # ── Metric 4: Semantic consistency ───────────────────────────────────────
    report.semantic_consistency = _semantic_consistency_score(
        baseline.semantic_field,
        probe.semantic_field,
    )

    # ── Composite score ──────────────────────────────────────────────────────
    report.composite_similarity = (
        0.35 * report.jaccard_similarity +
        0.25 * report.structural_similarity +
        0.20 * report.length_ratio_score +
        0.20 * report.semantic_consistency
    )

    # ── Semantic field change detection ─────────────────────────────────────
    report.semantic_field_changed = (baseline.semantic_field != probe.semantic_field)

    # ── PII introduced by the probe ─────────────────────────────────────────
    # PII types present in probe but NOT in baseline = newly introduced data
    report.pii_introduced = [
        pii for pii in probe.pii_found
        if pii not in baseline.pii_found
    ]

    # ── Numeric drift ────────────────────────────────────────────────────────
    report.numeric_drift = _analyze_numeric_drift(
        baseline.numeric_map,
        probe.numeric_map,
    )

    # ── Suspicious difference determination ─────────────────────────────────
    # A difference is "suspicious" when it's large AND not explained by
    # normal content variation
    report.is_suspiciously_different = (
        report.composite_similarity < 0.40
        or report.pii_introduced  # Any new PII is suspicious
        or (report.semantic_field_changed and report.composite_similarity < 0.70)
    )

    # ── Confidence contribution ──────────────────────────────────────────────
    # How much does this similarity analysis contribute to vulnerability confidence?
    if report.pii_introduced:
        report.confidence_contribution = 0.80  # Very strong signal
    elif report.semantic_field_changed and report.composite_similarity < 0.40:
        report.confidence_contribution = 0.65  # Strong signal
    elif report.composite_similarity < 0.30:
        report.confidence_contribution = 0.45  # Moderate signal (could be public content)
    elif report.composite_similarity < 0.60:
        report.confidence_contribution = 0.25  # Weak signal
    else:
        report.confidence_contribution = 0.05  # Not suspicious

    # ── Human interpretation ─────────────────────────────────────────────────
    report.interpretation = _interpret_similarity(report, context)

    log.debug(
        "Similarity: jaccard=%.2f structural=%.2f length=%.2f semantic=%.2f → "
        "composite=%.2f suspicious=%s",
        report.jaccard_similarity,
        report.structural_similarity,
        report.length_ratio_score,
        report.semantic_consistency,
        report.composite_similarity,
        report.is_suspiciously_different,
    )

    return report
