"""
Domain models, data structures, and Enums for M25 Continuous Security Learning,
Trend Intelligence & Adaptive Risk Engine.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Dict, Any, Optional
from datetime import datetime


class SecurityPatternType(str, Enum):
    """Catalog of security pattern types detected across historical scan data."""
    RECURRING_VULNERABILITY = "RECURRING_VULNERABILITY"
    REOPENED_VULNERABILITY = "REOPENED_VULNERABILITY"
    REPEATED_ROOT_CAUSE = "REPEATED_ROOT_CAUSE"
    REPEATED_FILE_PATTERN = "REPEATED_FILE_PATTERN"
    REPEATED_ATTACK_PATH = "REPEATED_ATTACK_PATH"
    REPEATED_SECURITY_DRIFT = "REPEATED_SECURITY_DRIFT"
    FAILED_REMEDIATION = "FAILED_REMEDIATION"
    SUCCESSFUL_REMEDIATION = "SUCCESSFUL_REMEDIATION"
    PERSISTENT_VULNERABILITY = "PERSISTENT_VULNERABILITY"
    NEW_EMERGING_PATTERN = "NEW_EMERGING_PATTERN"


class TrendDirection(str, Enum):
    """Overall security posture trend classification over scan history."""
    RAPIDLY_IMPROVING = "RAPIDLY_IMPROVING"
    IMPROVING = "IMPROVING"
    STABLE = "STABLE"
    DEGRADING = "DEGRADING"
    RAPIDLY_DEGRADING = "RAPIDLY_DEGRADING"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"


class RecurrenceClassification(str, Enum):
    """Categorization of vulnerability recurrence and lifecycle behavior."""
    FIRST_SEEN = "FIRST_SEEN"
    OCCASIONAL = "OCCASIONAL"
    RECURRING = "RECURRING"
    PERSISTENT = "PERSISTENT"
    CHRONIC = "CHRONIC"


class RemediationStatus(str, Enum):
    """Status classification for historical remediation/repair strategies."""
    SUCCESSFUL = "SUCCESSFUL"
    PARTIALLY_SUCCESSFUL = "PARTIALLY_SUCCESSFUL"
    FAILED = "FAILED"
    REGRESSION = "REGRESSION"
    NOT_ATTEMPTED = "NOT_ATTEMPTED"


@dataclass
class SecurityPattern:
    """Represents a detected security pattern across historical repository scans."""
    pattern_type: SecurityPatternType
    title: str
    description: str
    confidence: float = 1.0
    occurrences: int = 1
    affected_files: List[str] = field(default_factory=list)
    affected_root_causes: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["pattern_type"] = self.pattern_type.value if isinstance(self.pattern_type, Enum) else self.pattern_type
        return d


@dataclass
class SecurityTrend:
    """Security score and vulnerability metric trends over repository history."""
    current_score: int = 100
    previous_score: Optional[int] = None
    score_delta: int = 0
    average_score: float = 100.0
    minimum_score: int = 100
    maximum_score: int = 100
    trend: TrendDirection = TrendDirection.STABLE
    volatility: float = 0.0
    critical_count_trend: str = "STABLE"
    high_count_trend: str = "STABLE"
    reopened_trend: str = "STABLE"
    recurrence_trend: str = "STABLE"

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["trend"] = self.trend.value if isinstance(self.trend, Enum) else self.trend
        return d


@dataclass
class FindingRecurrence:
    """Recurrence analysis metrics for a specific vulnerability fingerprint."""
    fingerprint: str
    root_cause: str
    file: str
    recurrence_count: int = 1
    reopen_count: int = 0
    persistence_duration: float = 0.0  # In days or scan iterations
    average_time_to_fix: float = 0.0
    average_time_to_reopen: float = 0.0
    failed_repair_count: int = 0
    successful_repair_count: int = 0
    classification: RecurrenceClassification = RecurrenceClassification.FIRST_SEEN

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["classification"] = self.classification.value if isinstance(self.classification, Enum) else self.classification
        return d


@dataclass
class RemediationLearningRecord:
    """Historical efficacy record for a specific repair strategy applied to a root cause."""
    root_cause: str
    repair_strategy: str
    status: RemediationStatus = RemediationStatus.NOT_ATTEMPTED
    successful_repairs: int = 0
    failed_repairs: int = 0
    regressions: int = 0
    success_rate: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value if isinstance(self.status, Enum) else self.status
        return d


@dataclass
class AdaptiveRiskSignal:
    """Adaptive risk adjustment signal generated for a specific finding."""
    finding_id: str
    fingerprint: str
    root_cause: str
    base_risk_score: float
    adapted_risk_score: float
    risk_multiplier: float
    adaptation_reasons: List[str] = field(default_factory=list)
    priority_boost: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class LearningExplainabilityReport:
    """Structured explainability output describing learning and adaptation rationale."""
    summary: str
    detected_patterns: List[SecurityPattern] = field(default_factory=list)
    trend: Optional[SecurityTrend] = None
    recurrence_insights: List[FindingRecurrence] = field(default_factory=list)
    remediation_lessons: List[RemediationLearningRecord] = field(default_factory=list)
    adaptive_risk_signals: List[AdaptiveRiskSignal] = field(default_factory=list)
    explanation_details: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        if self.trend:
            d["trend"] = self.trend.to_dict()
        d["detected_patterns"] = [p.to_dict() for p in self.detected_patterns]
        d["recurrence_insights"] = [r.to_dict() for r in self.recurrence_insights]
        d["remediation_lessons"] = [rl.to_dict() for rl in self.remediation_lessons]
        d["adaptive_risk_signals"] = [ars.to_dict() for ars in self.adaptive_risk_signals]
        return d


@dataclass
class LearningEngineResult:
    """Master output container for ContinuousSecurityLearningEngine execution."""
    repository_name: str
    commit_sha: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    scan_count: int = 1
    memory_records: int = 0
    detected_patterns: List[SecurityPattern] = field(default_factory=list)
    trend: Optional[SecurityTrend] = None
    recurrence_analysis: List[FindingRecurrence] = field(default_factory=list)
    remediation_learning: List[RemediationLearningRecord] = field(default_factory=list)
    adaptive_signals: List[AdaptiveRiskSignal] = field(default_factory=list)
    explainability: Optional[LearningExplainabilityReport] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        if self.trend:
            d["trend"] = self.trend.to_dict()
        if self.explainability:
            d["explainability"] = self.explainability.to_dict()
        d["detected_patterns"] = [p.to_dict() for p in self.detected_patterns]
        d["recurrence_analysis"] = [r.to_dict() for r in self.recurrence_analysis]
        d["remediation_learning"] = [rl.to_dict() for rl in self.remediation_learning]
        d["adaptive_signals"] = [s.to_dict() for s in self.adaptive_signals]
        return d
