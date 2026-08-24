"""
Domain models, Enums, and data containers for M27 Security Operations Control Plane.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Dict, Any, Optional
from datetime import datetime


class OperationalStatus(str, Enum):
    """High-level repository operational status rating."""
    HEALTHY = "HEALTHY"
    AT_RISK = "AT_RISK"
    DEGRADED = "DEGRADED"
    CRITICAL = "CRITICAL"
    BLOCKED = "BLOCKED"
    UNKNOWN = "UNKNOWN"


class OperationalMode(str, Enum):
    """Current operational execution mode of repository control plane."""
    IDLE = "IDLE"
    SCANNING = "SCANNING"
    ANALYZING = "ANALYZING"
    INVESTIGATING = "INVESTIGATING"
    VERIFYING = "VERIFYING"
    REPAIRING = "REPAIRING"
    MONITORING = "MONITORING"
    WAITING_APPROVAL = "WAITING_APPROVAL"
    BLOCKED = "BLOCKED"
    COMPLETE = "COMPLETE"
    FAILED = "FAILED"


class ControlPlaneAction(str, Enum):
    """Action recommendations selected by control plane."""
    RUN_SCAN = "RUN_SCAN"
    INVESTIGATE = "INVESTIGATE"
    GENERATE_REPAIR = "GENERATE_REPAIR"
    VALIDATE_REPAIR = "VALIDATE_REPAIR"
    REQUEST_APPROVAL = "REQUEST_APPROVAL"
    APPLY_APPROVED_REPAIR = "APPLY_APPROVED_REPAIR"
    RESCAN = "RESCAN"
    MONITOR = "MONITOR"
    BLOCK_RELEASE = "BLOCK_RELEASE"
    RELEASE_ALLOWED = "RELEASE_ALLOWED"
    NO_ACTION = "NO_ACTION"


class ControlPlaneEvent(str, Enum):
    """Event types logged in control plane audit trail."""
    SCAN_STARTED = "SCAN_STARTED"
    SCAN_COMPLETED = "SCAN_COMPLETED"
    FINDING_CREATED = "FINDING_CREATED"
    FINDING_FIXED = "FINDING_FIXED"
    FINDING_REOPENED = "FINDING_REOPENED"
    DRIFT_DETECTED = "DRIFT_DETECTED"
    ATTACK_PATH_CREATED = "ATTACK_PATH_CREATED"
    ATTACK_PATH_REMOVED = "ATTACK_PATH_REMOVED"
    DECISION_CREATED = "DECISION_CREATED"
    REPAIR_GENERATED = "REPAIR_GENERATED"
    REPAIR_VALIDATED = "REPAIR_VALIDATED"
    REPAIR_FAILED = "REPAIR_FAILED"
    APPROVAL_REQUESTED = "APPROVAL_REQUESTED"
    APPROVAL_GRANTED = "APPROVAL_GRANTED"
    APPROVAL_DECLINED = "APPROVAL_DECLINED"
    RELEASE_BLOCKED = "RELEASE_BLOCKED"
    RELEASE_ALLOWED = "RELEASE_ALLOWED"
    MONITORING_STARTED = "MONITORING_STARTED"
    MONITORING_STOPPED = "MONITORING_STOPPED"


@dataclass
class SecurityPostureSnapshot:
    """Current posture snapshot combining security scores and finding counts."""
    security_score: int = 100
    risk_score: float = 0.0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    p0_count: int = 0
    p1_count: int = 0
    p2_count: int = 0
    p3_count: int = 0
    p4_count: int = 0
    active_attack_paths_count: int = 0
    internet_exposed_paths_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ActiveSecurityIssue:
    """Consolidated record of an active vulnerability issue across all engines."""
    issue_id: str
    root_cause: str
    severity: str
    priority: str
    file: str
    exploitability: float = 0.0
    exposure: str = "INTERNAL"
    recurrence_classification: str = "FIRST_SEEN"
    risk_multiplier: float = 1.0
    governance_decision: str = "MONITOR"
    remediation_status: str = "UNPATCHED"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class OperationalAction:
    """Next action recommendation selected by control plane with rationale."""
    action: ControlPlaneAction
    target_finding_id: Optional[str] = None
    target_file: Optional[str] = None
    reason: str = "No operation required."
    evidence: List[str] = field(default_factory=list)
    risk_level: str = "LOW"
    governance_decision: str = "ALLOW"

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["action"] = self.action.value if isinstance(self.action, Enum) else self.action
        return d


@dataclass
class ApprovalState:
    """Human approval state for security actions."""
    request_id: str
    finding_id: str
    proposed_action: str
    risk_level: str
    reason: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    status: str = "PENDING"  # PENDING, APPROVED, DECLINED, EXPIRED

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ControlPlaneEventRecord:
    """Individual entry in control plane audit trail."""
    event_id: str
    timestamp: str
    repository: str
    event: ControlPlaneEvent
    severity: str
    actor: str
    reason: str
    evidence_ref: str
    resulting_state: str

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["event"] = self.event.value if isinstance(self.event, Enum) else self.event
        return d


@dataclass
class SecurityOperationsSummary:
    """Unified operational summary of repository security posture and intelligence."""
    repository_name: str
    commit_sha: str
    operational_status: OperationalStatus
    operational_mode: OperationalMode
    health_score: float = 100.0
    security_score: int = 100
    risk_score: float = 0.0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0
    p0_findings: int = 0
    p1_findings: int = 0
    p2_findings: int = 0
    active_attack_paths: int = 0
    internet_exposed_paths: int = 0
    reopened_vulnerabilities: int = 0
    recurring_vulnerabilities: int = 0
    chronic_vulnerabilities: int = 0
    drift_score: float = 0.0
    drift_severity: str = "NONE"
    drift_direction: str = "STABLE"
    adaptive_risk_multiplier: float = 1.0
    pending_repairs: int = 0
    validated_repairs: int = 0
    failed_repairs: int = 0
    pending_approvals: int = 0
    governance_status: str = "ALLOW"
    release_status: str = "RELEASE_ALLOWED"

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["operational_status"] = self.operational_status.value if isinstance(self.operational_status, Enum) else self.operational_status
        d["operational_mode"] = self.operational_mode.value if isinstance(self.operational_mode, Enum) else self.operational_mode
        return d


@dataclass
class ControlPlaneHealth:
    """Health score (0-100) and operational rating with explicit explanations."""
    health_score: float = 100.0
    status: OperationalStatus = OperationalStatus.HEALTHY
    explanation: str = "Repository operation clean and healthy."
    risk_factors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value if isinstance(self.status, Enum) else self.status
        return d


@dataclass
class RepositoryOperationalState:
    """Full operational state model maintained in-memory for a repository."""
    repository_name: str
    commit_sha: str
    branch: str = "main"
    last_scan_timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    operational_status: OperationalStatus = OperationalStatus.HEALTHY
    operational_mode: OperationalMode = OperationalMode.IDLE
    lifecycle_stage: str = "IDLE"
    snapshot: SecurityPostureSnapshot = field(default_factory=SecurityPostureSnapshot)
    active_issues: List[ActiveSecurityIssue] = field(default_factory=list)
    pending_approvals: List[ApprovalState] = field(default_factory=list)
    next_recommended_action: Optional[OperationalAction] = None
    health: ControlPlaneHealth = field(default_factory=ControlPlaneHealth)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["operational_status"] = self.operational_status.value if isinstance(self.operational_status, Enum) else self.operational_status
        d["operational_mode"] = self.operational_mode.value if isinstance(self.operational_mode, Enum) else self.operational_mode
        d["snapshot"] = self.snapshot.to_dict()
        d["active_issues"] = [i.to_dict() for i in self.active_issues]
        d["pending_approvals"] = [a.to_dict() for a in self.pending_approvals]
        if self.next_recommended_action:
            d["next_recommended_action"] = self.next_recommended_action.to_dict()
        d["health"] = self.health.to_dict()
        return d


@dataclass
class ControlPlaneResult:
    """Master output container produced by SecurityOperationsControlPlane."""
    repository_name: str
    commit_sha: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    summary: Optional[SecurityOperationsSummary] = None
    state: Optional[RepositoryOperationalState] = None
    recommended_action: Optional[OperationalAction] = None
    health: Optional[ControlPlaneHealth] = None
    audit_trail: List[ControlPlaneEventRecord] = field(default_factory=list)
    timeline: List[Dict[str, Any]] = field(default_factory=list)
    governance_verdict: str = "ALLOW"

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        if self.summary:
            d["summary"] = self.summary.to_dict()
        if self.state:
            d["state"] = self.state.to_dict()
        if self.recommended_action:
            d["recommended_action"] = self.recommended_action.to_dict()
        if self.health:
            d["health"] = self.health.to_dict()
        d["audit_trail"] = [a.to_dict() for a in self.audit_trail]
        return d

    def get(self, key: str, default: Any = None) -> Any:
        d = self.to_dict()
        return d.get(key, default)

    def __getitem__(self, key: str) -> Any:
        d = self.to_dict()
        return d[key]
