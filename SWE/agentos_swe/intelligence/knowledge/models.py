"""
M21 Security Knowledge & Learning Models.

Defines domain models, enums, dataclasses, and data structures for persistent
knowledge records, vulnerability patterns, remediation effectiveness, attack path patterns,
outcomes, human feedback, and adaptive recommendations.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Dict, Any, Optional
from datetime import datetime


class SecurityOutcome(str, Enum):
    """Execution outcomes recorded for security findings and repair strategies."""
    SUCCESSFUL_REPAIR = "SUCCESSFUL_REPAIR"
    FAILED_VALIDATION = "FAILED_VALIDATION"
    INTRODUCED_REGRESSION = "INTRODUCED_REGRESSION"
    REOPENED_FINDING = "REOPENED_FINDING"
    RELEASE_BLOCKED = "RELEASE_BLOCKED"
    CONFLICT_DETECTED = "CONFLICT_DETECTED"
    UNCHECKED = "UNCHECKED"


@dataclass
class SecurityPattern:
    """Dataclass representing a recurring security vulnerability structure."""
    pattern_id: str
    vulnerability_family: str
    root_cause: str
    source_type: str
    sink_type: str
    framework: str
    confidence: str = "HIGH"
    recurrence_count: int = 1
    repositories_seen: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RemediationPattern:
    """Remediation effectiveness record tracking success and regression rates."""
    strategy_id: str
    vulnerability_family: str
    root_cause: str
    recommended_fix: str
    attempts: int = 0
    successes: int = 0
    failures: int = 0
    regressions: int = 0
    success_rate: float = 1.0
    confidence_level: str = "HIGH"  # HIGH, MEDIUM, LOW

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AttackPathPattern:
    """Recurring attack-path structural pattern across trust boundaries."""
    pattern_id: str
    entrypoint_type: str
    authentication_state: str
    source_type: str
    sink_type: str
    severity: str
    historical_frequency: int = 1
    repositories_seen: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class KnowledgeFeedback:
    """Auditable human review feedback record for knowledge persistence."""
    feedback_id: str
    knowledge_id: str
    reviewer: str
    decision: str  # CONFIRMED, REJECTED, USEFUL, NOT_USEFUL
    reason: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CrossRepositorySecurityPattern:
    """Cross-repository intelligence pattern aggregated across multiple repos."""
    pattern_id: str
    vulnerability_family: str
    root_cause: str
    frequency: int
    repositories: List[str]
    common_source: str
    common_sink: str
    common_remediation: str
    successful_remediation_rate: float
    regression_rate: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RemediationRecommendation:
    """Explainable adaptive remediation recommendation based on historical learning."""
    strategy: str
    confidence: str  # HIGH, MEDIUM, LOW
    historical_attempts: int
    historical_successes: int
    historical_failures: int
    historical_regressions: int
    compatibility: str
    expected_risk_reduction: int
    explanation: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SecurityKnowledgeRecord:
    """Persistent knowledge record capturing historical vulnerability outcomes."""
    knowledge_id: str
    vulnerability_family: str
    root_cause: str
    source_pattern: str
    sink_pattern: str
    attack_path_pattern: str
    affected_framework: str
    affected_language: str
    remediation_strategy: str
    validation_result: str
    regression_result: str
    release_outcome: str
    confidence: float = 1.0
    recurrence_count: int = 1
    successful_repairs: int = 0
    failed_repairs: int = 0
    repositories_seen: List[str] = field(default_factory=list)
    first_seen: str = field(default_factory=lambda: datetime.now().isoformat())
    last_seen: str = field(default_factory=lambda: datetime.now().isoformat())
    evidence: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
