"""
models/evidence.py
====================
Central Evidence model for wamiqsec/ReconMind Phase 5.

Evidence is the raw observation layer. A Finding is what gets reported
AFTER aggregating evidence and applying confidence thresholds.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any
from enum import Enum


class SignalStrength(Enum):
    DEFINITIVE = "DEFINITIVE"
    STRONG     = "STRONG"
    MODERATE   = "MODERATE"
    WEAK       = "WEAK"
    SUPPRESSOR = "SUPPRESSOR"
    NOISE      = "NOISE"


class VerdictLevel(Enum):
    CONFIRMED = "CONFIRMED"
    PROBABLE  = "PROBABLE"
    POSSIBLE  = "POSSIBLE"
    UNLIKELY  = "UNLIKELY"
    HARMLESS  = "HARMLESS"


@dataclass
class EvidenceSignal:
    """One atomic observation during vulnerability analysis."""
    name: str
    observed: bool = False
    strength: SignalStrength = SignalStrength.MODERATE
    base_confidence: float = 0.50
    weight: float = 0.20
    source_engine: str = ""
    reasoning: str = ""
    raw_evidence: str = ""
    is_suppressor: bool = False
    suppression_factor: float = 0.50

    def __repr__(self) -> str:
        status = "OK" if self.observed else "--"
        if self.is_suppressor:
            return f"EvidenceSignal[SUPPRESSOR:{status}] {self.name}"
        return f"EvidenceSignal[{self.strength.value}:{status}] {self.name} ({self.base_confidence:.0%})"

    @property
    def effective_confidence(self) -> float:
        return self.base_confidence if self.observed else 0.0


@dataclass
class EvidenceChain:
    """Ordered collection of EvidenceSignals for one parameter + module."""
    module: str
    url: str
    parameter: str
    param_type: str = "GET"
    signals: List[EvidenceSignal] = field(default_factory=list)
    combined_confidence: float = 0.0
    verdict: VerdictLevel = VerdictLevel.UNLIKELY
    false_positive_risk: str = "HIGH"
    notes: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add(self, signal: EvidenceSignal) -> "EvidenceChain":
        self.signals.append(signal)
        return self

    def observe(self, name: str, raw_evidence: str = "") -> bool:
        for sig in self.signals:
            if sig.name == name:
                sig.observed = True
                if raw_evidence:
                    sig.raw_evidence = raw_evidence
                return True
        return False

    def active_signals(self) -> List[EvidenceSignal]:
        return [s for s in self.signals if s.observed and not s.is_suppressor]

    def active_suppressors(self) -> List[EvidenceSignal]:
        return [s for s in self.signals if s.observed and s.is_suppressor]

    def calculate(self) -> "EvidenceChain":
        """Calculate combined_confidence and verdict from observed signals."""
        active = self.active_signals()
        suppressors = self.active_suppressors()

        if not active:
            self.combined_confidence = 0.0
        else:
            total_weight = sum(s.weight for s in active)
            if total_weight > 0:
                weighted_sum = sum(s.base_confidence * s.weight for s in active)
                self.combined_confidence = weighted_sum / total_weight
            else:
                self.combined_confidence = 0.0

        for sup in suppressors:
            self.combined_confidence *= sup.suppression_factor

        self.combined_confidence = max(0.0, min(1.0, self.combined_confidence))

        c = self.combined_confidence
        if c >= 0.90:
            self.verdict = VerdictLevel.CONFIRMED
            self.false_positive_risk = "VERY_LOW"
        elif c >= 0.70:
            self.verdict = VerdictLevel.PROBABLE
            self.false_positive_risk = "LOW"
        elif c >= 0.50:
            self.verdict = VerdictLevel.POSSIBLE
            self.false_positive_risk = "MEDIUM"
        elif c >= 0.30:
            self.verdict = VerdictLevel.UNLIKELY
            self.false_positive_risk = "HIGH"
        else:
            self.verdict = VerdictLevel.HARMLESS
            self.false_positive_risk = "VERY_HIGH"

        return self

    def to_report_lines(self) -> List[str]:
        lines = [f"Confidence: {self.combined_confidence:.0%} [{self.verdict.value}]"]
        for sig in self.active_signals():
            lines.append(f"  + [{sig.strength.value}] {sig.name}: {sig.raw_evidence or sig.reasoning}")
        for sup in self.active_suppressors():
            lines.append(f"  - [SUPPRESSOR] {sup.name}: {sup.raw_evidence or sup.reasoning}")
        for note in self.notes:
            lines.append(f"  -> {note}")
        return lines

    def to_dict(self) -> Dict[str, Any]:
        return {
            "module": self.module,
            "url": self.url,
            "parameter": self.parameter,
            "param_type": self.param_type,
            "combined_confidence": round(self.combined_confidence, 4),
            "verdict": self.verdict.value,
            "false_positive_risk": self.false_positive_risk,
            "active_signals": [
                {"name": s.name, "strength": s.strength.value, "confidence": s.base_confidence,
                 "evidence": s.raw_evidence, "reasoning": s.reasoning}
                for s in self.active_signals()
            ],
            "suppressors": [
                {"name": s.name, "factor": s.suppression_factor, "reasoning": s.reasoning}
                for s in self.active_suppressors()
            ],
            "notes": self.notes,
        }

    @property
    def is_reportable(self) -> bool:
        return self.combined_confidence >= 0.45

    @property
    def severity(self) -> str:
        return {
            VerdictLevel.CONFIRMED: "HIGH",
            VerdictLevel.PROBABLE:  "HIGH",
            VerdictLevel.POSSIBLE:  "MEDIUM",
            VerdictLevel.UNLIKELY:  "LOW",
            VerdictLevel.HARMLESS:  "INFO",
        }.get(self.verdict, "INFO")
