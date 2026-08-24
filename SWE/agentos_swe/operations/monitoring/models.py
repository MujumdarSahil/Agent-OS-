"""
M18 & M23 Security Monitoring Models.

Defines domain models, enums, dataclasses, and data structures for continuous security monitoring,
regression classification, attack-path changes, security drift detection, change impact, alerts, and snapshots.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Dict, Any, Optional
from datetime import datetime


# --- M18 Enums ---

class RegressionSeverity(str, Enum):
    """Classification of security regression severity between scans."""
    NO_REGRESSION = "NO_REGRESSION"
    MINOR_REGRESSION = "MINOR_REGRESSION"
    SIGNIFICANT_REGRESSION = "SIGNIFICANT_REGRESSION"
    CRITICAL_REGRESSION = "CRITICAL_REGRESSION"


class AlertSeverity(str, Enum):
    """Severity classification for security alerts."""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlertCategory(str, Enum):
    """Deterministic category of a security monitoring alert."""
    CRITICAL_SECURITY_REGRESSION = "CRITICAL_SECURITY_REGRESSION"
    NEW_CRITICAL_FINDING = "NEW_CRITICAL_FINDING"
    NEW_HIGH_FINDING = "NEW_HIGH_FINDING"
    NEW_ATTACK_PATH = "NEW_ATTACK_PATH"
    AUTHENTICATION_WEAKENED = "AUTHENTICATION_WEAKENED"
    EXPOSURE_INCREASED = "EXPOSURE_INCREASED"
    REMEDIATION_INVALIDATED = "REMEDIATION_INVALIDATED"
    REOPENED_VULNERABILITY = "REOPENED_VULNERABILITY"
    SECURITY_SCORE_DROP = "SECURITY_SCORE_DROP"
    NO_REGRESSION = "NO_REGRESSION"


class AttackPathChangeType(str, Enum):
    """Type of structural change detected in an attack path across scans."""
    NEW_ATTACK_PATH = "NEW_ATTACK_PATH"
    REMOVED_ATTACK_PATH = "REMOVED_ATTACK_PATH"
    UNCHANGED_ATTACK_PATH = "UNCHANGED_ATTACK_PATH"
    MODIFIED_ATTACK_PATH = "MODIFIED_ATTACK_PATH"
    REOPENED_ATTACK_PATH = "REOPENED_ATTACK_PATH"


class RemediationPlanStatus(str, Enum):
    """Validity state of an M17 remediation plan following code modifications."""
    VALID = "VALID"
    STALE = "STALE"
    INVALIDATED = "INVALIDATED"
    REQUIRES_REPLAN = "REQUIRES_REPLAN"


class TrendDirection(str, Enum):
    """Overall security posture trend across historical scans."""
    IMPROVING = "IMPROVING"
    STABLE = "STABLE"
    DEGRADING = "DEGRADING"
    VOLATILE = "VOLATILE"


# --- Reconciled Models ---

@dataclass
class SecurityAlert:
    """Actionable security monitoring alert entry supporting both M18 and M23."""
    alert_id: str
    category: Optional[Any] = None
    severity: Optional[Any] = None
    title: str = "Security Alert"
    repository: str = "UNKNOWN"
    commit: str = "N/A"
    reason: str = ""
    evidence: Any = ""
    affected_files: List[str] = field(default_factory=list)
    affected_findings: List[str] = field(default_factory=list)
    affected_attack_paths: List[str] = field(default_factory=list)
    recommended_action: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    alert_type: Optional[str] = None
    commit_sha: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        if self.category and isinstance(self.category, Enum):
            d["category"] = self.category.value
        if self.severity and isinstance(self.severity, Enum):
            d["severity"] = self.severity.value
        return d


@dataclass
class SecurityChangeImpact:
    """Correlates git code changes with affected findings and attack paths for both M18 and M23."""
    commit: str = ""
    file: str = ""
    affected_findings_count: int = 0
    affected_attack_paths_count: int = 0
    affected_remediation_items_count: int = 0
    risk_score_delta: int = 0
    status_description: str = ""
    modified_files: List[str] = field(default_factory=list)
    security_sensitive_files: List[str] = field(default_factory=list)
    added_lines: int = 0
    removed_lines: int = 0
    affected_findings: List[Dict[str, Any]] = field(default_factory=list)
    affected_attack_paths: List[Dict[str, Any]] = field(default_factory=list)
    rationale: str = "No code change impact detected."

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AttackPathChange:
    """Structural delta between historical and current attack paths."""
    path_id: str
    change_type: AttackPathChangeType
    description: str
    previous_risk_score: int = 0
    current_risk_score: int = 0
    auth_weakened: bool = False
    exposure_increased: bool = False
    affected_file: str = ""
    root_cause: str = "UNKNOWN"

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["change_type"] = self.change_type.value if isinstance(self.change_type, Enum) else self.change_type
        return d


@dataclass
class RemediationImpact:
    """Impact of recent code changes on an M17 Remediation Plan."""
    plan_id: str
    status: RemediationPlanStatus
    reason: str
    invalidated_items: List[str] = field(default_factory=list)
    affected_files: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value if isinstance(self.status, Enum) else self.status
        return d


@dataclass
class SecurityTimelineEntry:
    """A chronological entry in the repository security evolution timeline."""
    commit: str
    timestamp: str
    code_changes_summary: str
    finding_changes_summary: str
    attack_path_changes_summary: str
    score_before: int
    score_after: int
    score_delta: int
    remediation_status_summary: str
    regression_severity: RegressionSeverity

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["regression_severity"] = self.regression_severity.value if isinstance(self.regression_severity, Enum) else self.regression_severity
        return d


@dataclass
class SecurityMonitoringResult:
    """Complete container for continuous security monitoring analysis."""
    repository: str
    current_commit: str
    previous_commit: str
    scan_timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    security_score_before: int = 100
    security_score_after: int = 100
    score_delta: int = 0
    risk_trend: TrendDirection = TrendDirection.STABLE
    regression_severity: RegressionSeverity = RegressionSeverity.NO_REGRESSION
    new_findings: List[Dict[str, Any]] = field(default_factory=list)
    fixed_findings: List[Dict[str, Any]] = field(default_factory=list)
    unchanged_findings: List[Dict[str, Any]] = field(default_factory=list)
    reopened_findings: List[Dict[str, Any]] = field(default_factory=list)
    new_attack_paths: List[Dict[str, Any]] = field(default_factory=list)
    removed_attack_paths: List[Dict[str, Any]] = field(default_factory=list)
    changed_attack_paths: List[AttackPathChange] = field(default_factory=list)
    remediation_impact: Optional[RemediationImpact] = None
    change_impacts: List[SecurityChangeImpact] = field(default_factory=list)
    timeline: List[SecurityTimelineEntry] = field(default_factory=list)
    alerts: List[SecurityAlert] = field(default_factory=list)
    monitoring_status: str = "COMPLETE"
    governance_verdict: str = "ALLOW"
    summary_explanation: str = "Zero security regressions detected."

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["risk_trend"] = self.risk_trend.value if isinstance(self.risk_trend, Enum) else self.risk_trend
        d["regression_severity"] = self.regression_severity.value if isinstance(self.regression_severity, Enum) else self.regression_severity
        d["changed_attack_paths"] = [cap.to_dict() for cap in self.changed_attack_paths]
        if self.remediation_impact:
            d["remediation_impact"] = self.remediation_impact.to_dict()
        d["change_impacts"] = [ci.to_dict() for ci in self.change_impacts]
        d["timeline"] = [t.to_dict() for t in self.timeline]
        d["alerts"] = [a.to_dict() for a in self.alerts]
        return d


@dataclass
class CrossRepositoryMonitoringResult:
    """Container for batch monitoring across multiple repositories."""
    scan_timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    repository_results: Dict[str, SecurityMonitoringResult] = field(default_factory=dict)
    total_repositories: int = 0
    degrading_repositories_count: int = 0
    critical_regressions_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_timestamp": self.scan_timestamp,
            "repository_results": {repo: res.to_dict() for repo, res in self.repository_results.items()},
            "total_repositories": self.total_repositories,
            "degrading_repositories_count": self.degrading_repositories_count,
            "critical_regressions_count": self.critical_regressions_count,
        }


# --- M23 Models ---

class DriftScoreCategory(str, Enum):
    """Categorization for security drift scores."""
    NO_DRIFT = "NO_DRIFT"
    LOW_DRIFT = "LOW_DRIFT"
    MEDIUM_DRIFT = "MEDIUM_DRIFT"
    HIGH_DRIFT = "HIGH_DRIFT"
    CRITICAL_DRIFT = "CRITICAL_DRIFT"


@dataclass
class SecuritySnapshot:
    """Serializable security posture snapshot for a repository commit."""
    snapshot_id: str
    repository: str
    commit_sha: str
    branch: str = "main"
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    files_analyzed: int = 0
    findings: List[Dict[str, Any]] = field(default_factory=list)
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    security_score: float = 100.0
    risk_score: float = 0.0
    attack_paths: List[Dict[str, Any]] = field(default_factory=list)
    exploitable_paths: List[Dict[str, Any]] = field(default_factory=list)
    simulation_results: Optional[Dict[str, Any]] = None
    repair_results: List[Dict[str, Any]] = field(default_factory=list)
    release_blockers: List[Dict[str, Any]] = field(default_factory=list)
    knowledge_patterns: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SecurityDrift:
    """Calculated drift between baseline and current security snapshots."""
    drift_id: str
    repository: str
    baseline_commit: str
    current_commit: str
    drift_score: float = 0.0
    category: DriftScoreCategory = DriftScoreCategory.NO_DRIFT
    new_findings: List[Dict[str, Any]] = field(default_factory=list)
    fixed_findings: List[Dict[str, Any]] = field(default_factory=list)
    reopened_findings: List[Dict[str, Any]] = field(default_factory=list)
    severity_increases: List[Dict[str, Any]] = field(default_factory=list)
    severity_decreases: List[Dict[str, Any]] = field(default_factory=list)
    new_attack_paths: List[Dict[str, Any]] = field(default_factory=list)
    removed_attack_paths: List[Dict[str, Any]] = field(default_factory=list)
    new_exploitable_paths: List[Dict[str, Any]] = field(default_factory=list)
    security_score_delta: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["category"] = self.category.value if isinstance(self.category, Enum) else self.category
        return d


@dataclass
class ReleaseDriftAssessment:
    """Release drift assessment outcome."""
    release_safe: bool
    drift_level: DriftScoreCategory
    blockers: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    required_actions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["drift_level"] = self.drift_level.value if isinstance(self.drift_level, Enum) else self.drift_level
        return d


@dataclass
class HistoricalDriftContext:
    """M14/M21 historical context for security drift occurrences."""
    previous_occurrence_found: bool = False
    previous_commit: Optional[str] = None
    previous_remediation: Optional[str] = None
    historical_success_rate: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# --- M28 Continuous Monitoring Events & Health Models ---

class MonitoringEventType(str, Enum):
    """M28 Continuous Security Monitoring event types."""
    NO_CHANGE = "NO_CHANGE"
    CHANGE_DETECTED = "CHANGE_DETECTED"
    SCAN_STARTED = "SCAN_STARTED"
    SCAN_COMPLETED = "SCAN_COMPLETED"
    SCAN_FAILED = "SCAN_FAILED"
    SECURITY_IMPROVED = "SECURITY_IMPROVED"
    SECURITY_DEGRADED = "SECURITY_DEGRADED"
    NEW_CRITICAL_FINDING = "NEW_CRITICAL_FINDING"
    NEW_HIGH_FINDING = "NEW_HIGH_FINDING"
    FINDING_FIXED = "FINDING_FIXED"
    FINDING_REOPENED = "FINDING_REOPENED"
    DRIFT_DETECTED = "DRIFT_DETECTED"
    GOVERNANCE_BLOCKED = "GOVERNANCE_BLOCKED"
    REPAIR_RECOMMENDED = "REPAIR_RECOMMENDED"
    MONITORING_DISABLED = "MONITORING_DISABLED"


class MonitoringHealthStatus(str, Enum):
    """Execution status of the monitoring infrastructure."""
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    FAILED = "FAILED"
    STALE = "STALE"


@dataclass
class MonitoringEvent:
    """Strongly typed M28 continuous monitoring telemetry event."""
    event_id: str
    repository_name: str
    timestamp: str
    event_type: MonitoringEventType
    severity: str = "INFO"
    previous_commit: Optional[str] = None
    current_commit: Optional[str] = None
    previous_state: Optional[str] = None
    current_state: Optional[str] = None
    reason: str = ""
    evidence: List[str] = field(default_factory=list)
    correlation_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["event_type"] = self.event_type.value if isinstance(self.event_type, Enum) else self.event_type
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MonitoringEvent":
        ev_type = data.get("event_type", MonitoringEventType.SCAN_COMPLETED.value)
        if isinstance(ev_type, str):
            try:
                ev_type = MonitoringEventType(ev_type)
            except ValueError:
                ev_type = MonitoringEventType.SCAN_COMPLETED

        return cls(
            event_id=data.get("event_id", "ev_unknown"),
            repository_name=data.get("repository_name", "UNKNOWN"),
            timestamp=data.get("timestamp", datetime.now().isoformat()),
            event_type=ev_type,
            severity=data.get("severity", "INFO"),
            previous_commit=data.get("previous_commit"),
            current_commit=data.get("current_commit"),
            previous_state=data.get("previous_state"),
            current_state=data.get("current_state"),
            reason=data.get("reason", ""),
            evidence=data.get("evidence", []),
            correlation_id=data.get("correlation_id", ""),
        )


@dataclass
class MonitoringHealth:
    """Differentiates security posture health from monitoring infrastructure health."""
    security_health: str = "HEALTHY"
    monitoring_health: str = MonitoringHealthStatus.HEALTHY.value
    repositories_monitored: int = 0
    repositories_due: int = 0
    successful_scans: int = 0
    failed_scans: int = 0
    last_successful_scan: Optional[str] = None
    next_scheduled_scan: Optional[str] = None
    failures_count: int = 0
    stale_repos_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
