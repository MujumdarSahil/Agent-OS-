"""
M13 Correlation & Root-Cause Models.

Defines strongly-typed domain models for evidence correlation, confidence scoring,
root cause categorization, and correlated findings.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Dict, Any, Optional, Tuple


class RootCauseCategory(str, Enum):
    """Primary root vulnerability categories for evidence-driven correlation."""
    COMMAND_INJECTION       = "COMMAND_INJECTION"
    CODE_INJECTION          = "CODE_INJECTION"
    SQL_INJECTION           = "SQL_INJECTION"
    XSS                     = "XSS"
    SSRF                    = "SSRF"
    PATH_TRAVERSAL          = "PATH_TRAVERSAL"
    UNSAFE_DESERIALIZATION  = "UNSAFE_DESERIALIZATION"
    SENSITIVE_DATA_EXPOSURE = "SENSITIVE_DATA_EXPOSURE"
    EXCEPTION_SWALLOWING    = "EXCEPTION_SWALLOWING"
    PERFORMANCE_ANTI_PATTERN = "PERFORMANCE_ANTI_PATTERN"
    ARCHITECTURE_COUPLING   = "ARCHITECTURE_COUPLING"
    UNKNOWN                 = "UNKNOWN"


@dataclass
class EvidenceChain:
    """Consolidated evidence from all investigation, graph, semantic, taint, and verification sources."""
    source_evidence: List[Dict[str, Any]] = field(default_factory=list)
    propagation_evidence: List[Dict[str, Any]] = field(default_factory=list)
    sink_evidence: List[Dict[str, Any]] = field(default_factory=list)
    semantic_evidence: List[Dict[str, Any]] = field(default_factory=list)
    graph_evidence: List[Dict[str, Any]] = field(default_factory=list)
    agent_evidence: List[Dict[str, Any]] = field(default_factory=list)
    verification_evidence: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EvidenceChain":
        return cls(**data)


@dataclass
class ConfidenceExplanation:
    """Explainable confidence breakdown detailing rationale for the numerical score."""
    score: float
    rationale: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ConfidenceExplanation":
        return cls(**data)


@dataclass
class CorrelatedFinding:
    """
    Unified finding representing correlated evidence, deterministic root cause,
    explainable confidence, and affected code scope.
    """
    finding_id: str
    vulnerability_category: str
    severity: str
    confidence: float
    confidence_explanation: ConfidenceExplanation
    evidence_chain: EvidenceChain
    related_finding_ids: List[str] = field(default_factory=list)
    root_cause: RootCauseCategory = RootCauseCategory.UNKNOWN
    affected_file: str = ""
    affected_function: Optional[str] = None
    affected_lines: Optional[Tuple[int, int]] = None
    remediation_recommendation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["root_cause"] = self.root_cause.value if isinstance(self.root_cause, Enum) else self.root_cause
        d["confidence_explanation"] = self.confidence_explanation.to_dict()
        d["evidence_chain"] = self.evidence_chain.to_dict()
        if self.affected_lines is not None:
            d["affected_lines"] = list(self.affected_lines)
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CorrelatedFinding":
        data = data.copy()
        if "root_cause" in data and isinstance(data["root_cause"], str):
            data["root_cause"] = RootCauseCategory(data["root_cause"])
        if "confidence_explanation" in data and isinstance(data["confidence_explanation"], dict):
            data["confidence_explanation"] = ConfidenceExplanation.from_dict(data["confidence_explanation"])
        if "evidence_chain" in data and isinstance(data["evidence_chain"], dict):
            data["evidence_chain"] = EvidenceChain.from_dict(data["evidence_chain"])
        if "affected_lines" in data and data["affected_lines"] is not None:
            data["affected_lines"] = tuple(data["affected_lines"])
        return cls(**data)
