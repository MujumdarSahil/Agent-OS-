"""
Domain models, Enums, and data containers for M26 Continuous Security Monitoring
& Security Drift Engine.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Dict, Any, Optional
from datetime import datetime


class DriftType(str, Enum):
    """Catalog of security drift event types."""
    NEW_VULNERABILITY = "NEW_VULNERABILITY"
    FIXED_VULNERABILITY = "FIXED_VULNERABILITY"
    REOPENED_VULNERABILITY = "REOPENED_VULNERABILITY"
    NEW_ATTACK_PATH = "NEW_ATTACK_PATH"
    REMOVED_ATTACK_PATH = "REMOVED_ATTACK_PATH"
    ATTACK_PATH_CHANGED = "ATTACK_PATH_CHANGED"
    NEW_INTERNET_EXPOSURE = "NEW_INTERNET_EXPOSURE"
    REMOVED_INTERNET_EXPOSURE = "REMOVED_INTERNET_EXPOSURE"
    NEW_TRUST_BOUNDARY = "NEW_TRUST_BOUNDARY"
    TRUST_BOUNDARY_CHANGED = "TRUST_BOUNDARY_CHANGED"
    NEW_SENSITIVE_SINK = "NEW_SENSITIVE_SINK"
    SECURITY_SCORE_DROP = "SECURITY_SCORE_DROP"
    SECURITY_SCORE_IMPROVEMENT = "SECURITY_SCORE_IMPROVEMENT"
    PRIORITY_ESCALATION = "PRIORITY_ESCALATION"
    RISK_MULTIPLIER_INCREASE = "RISK_MULTIPLIER_INCREASE"
    SECURITY_PATTERN_EMERGENCE = "SECURITY_PATTERN_EMERGENCE"


class DriftSeverity(str, Enum):
    """Severity classification for security drift events and impact."""
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DriftDirection(str, Enum):
    """Directional movement of repository security posture."""
    IMPROVEMENT = "IMPROVEMENT"
    STABLE = "STABLE"
    DEGRADATION = "DEGRADATION"
    SEVERE_DEGRADATION = "SEVERE_DEGRADATION"


@dataclass
class SecurityDriftEvent:
    """Individual security drift event representing a discrete posture change."""
    event_id: str
    drift_type: DriftType
    severity: DriftSeverity
    title: str
    description: str
    finding_id: Optional[str] = None
    fingerprint: Optional[str] = None
    root_cause: Optional[str] = None
    file: Optional[str] = None
    previous_state: Dict[str, Any] = field(default_factory=dict)
    current_state: Dict[str, Any] = field(default_factory=dict)
    evidence: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["drift_type"] = self.drift_type.value if isinstance(self.drift_type, Enum) else self.drift_type
        d["severity"] = self.severity.value if isinstance(self.severity, Enum) else self.severity
        return d


@dataclass
class ChangedSecuritySurface:
    """Analysis of security-sensitive code changes across git commits."""
    changed_files: List[str] = field(default_factory=list)
    changed_functions: List[str] = field(default_factory=list)
    lines_added: int = 0
    lines_removed: int = 0
    intersects_finding: bool = False
    intersects_source: bool = False
    intersects_sink: bool = False
    intersects_attack_path: bool = False
    intersects_trust_boundary: bool = False
    intersects_internet_exposure: bool = False
    relevance_summary: str = "No security-sensitive changes detected."
    surface_entries: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DriftImpact:
    """Quantitative impact score and direction resulting from security drift."""
    drift_score: float = 0.0
    severity: DriftSeverity = DriftSeverity.NONE
    direction: DriftDirection = DriftDirection.STABLE
    security_score_delta: int = 0
    risk_multiplier_delta: float = 0.0
    new_findings_count: int = 0
    fixed_findings_count: int = 0
    reopened_findings_count: int = 0
    rationale: str = "No security posture change detected."

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value if isinstance(self.severity, Enum) else self.severity
        d["direction"] = self.direction.value if isinstance(self.direction, Enum) else self.direction
        return d


@dataclass
class DriftComparisonResult:
    """Differential security comparison between a baseline scan and current scan."""
    baseline_scan_id: Optional[str]
    current_scan_id: str
    baseline_commit: Optional[str]
    current_commit: str
    new_findings: List[Dict[str, Any]] = field(default_factory=list)
    fixed_findings: List[Dict[str, Any]] = field(default_factory=list)
    reopened_findings: List[Dict[str, Any]] = field(default_factory=list)
    new_attack_paths: List[Dict[str, Any]] = field(default_factory=list)
    removed_attack_paths: List[Dict[str, Any]] = field(default_factory=list)
    exposure_changes: List[Dict[str, Any]] = field(default_factory=list)
    trust_boundary_changes: List[Dict[str, Any]] = field(default_factory=list)
    score_before: int = 100
    score_after: int = 100
    score_delta: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DriftSummary:
    """High-level summary overview of repository security drift state."""
    overall_status: str = "NO_DRIFT"
    drift_score: float = 0.0
    drift_severity: DriftSeverity = DriftSeverity.NONE
    drift_direction: DriftDirection = DriftDirection.STABLE
    total_drift_events: int = 0
    critical_events_count: int = 0
    high_events_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["drift_severity"] = self.drift_severity.value if isinstance(self.drift_severity, Enum) else self.drift_severity
        d["drift_direction"] = self.drift_direction.value if isinstance(self.drift_direction, Enum) else self.drift_direction
        return d


@dataclass
class DriftInvestigationReport:
    """Detailed root-cause analysis explaining why security posture drifted."""
    event_id: str
    what_changed: str
    where_it_changed: str
    security_impact: str
    previous_state: str
    current_state: str
    evidence: List[str] = field(default_factory=list)
    related_findings: List[str] = field(default_factory=list)
    related_attack_paths: List[str] = field(default_factory=list)
    related_history: List[str] = field(default_factory=list)
    related_learning_signals: List[str] = field(default_factory=list)
    recommended_action: str = "MONITOR"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DriftEngineResult:
    """Master output container produced by SecurityMonitoringDriftEngine."""
    repository_name: str
    commit_sha: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    summary: Optional[DriftSummary] = None
    impact: Optional[DriftImpact] = None
    drift_events: List[SecurityDriftEvent] = field(default_factory=list)
    changed_surface: Optional[ChangedSecuritySurface] = None
    comparison: Optional[DriftComparisonResult] = None
    investigations: List[DriftInvestigationReport] = field(default_factory=list)
    governance_verdict: str = "ALLOW"

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        if self.summary:
            d["summary"] = self.summary.to_dict()
        if self.impact:
            d["impact"] = self.impact.to_dict()
        if self.changed_surface:
            d["changed_surface"] = self.changed_surface.to_dict()
        if self.comparison:
            d["comparison"] = self.comparison.to_dict()
        d["drift_events"] = [e.to_dict() for e in self.drift_events]
        d["investigations"] = [inv.to_dict() for inv in self.investigations]
        d["drift"] = {
            "category": self.summary.overall_status if self.summary else "NO_DRIFT",
            "drift_score": self.impact.drift_score if self.impact else 0.0,
        }
        return d

    def get(self, key: str, default: Any = None) -> Any:
        d = self.to_dict()
        return d.get(key, default)

    def __getitem__(self, key: str) -> Any:
        d = self.to_dict()
        return d[key]
