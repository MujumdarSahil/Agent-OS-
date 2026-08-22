"""
M20 Security Engineering Orchestration & Workflow Models.

Defines domain models, enums, dataclasses, and data structures for workflow states,
action decisions, security case statuses, action items, workflow plans, timelines,
security cases, human review requests, and global posture summaries.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Dict, Any, Optional
from datetime import datetime


class WorkflowState(str, Enum):
    """Deterministic states of the security engineering workflow."""
    INTAKE = "INTAKE"
    SCANNING = "SCANNING"
    ANALYZING = "ANALYZING"
    CORRELATING = "CORRELATING"
    PRIORITIZING = "PRIORITIZING"
    ATTACK_PATH_ANALYSIS = "ATTACK_PATH_ANALYSIS"
    REMEDIATION_PLANNING = "REMEDIATION_PLANNING"
    REPAIR_VALIDATION = "REPAIR_VALIDATION"
    SECURITY_REGRESSION_CHECK = "SECURITY_REGRESSION_CHECK"
    HISTORICAL_COMPARISON = "HISTORICAL_COMPARISON"
    MONITORING = "MONITORING"
    RELEASE_READINESS = "RELEASE_READINESS"
    GOVERNANCE = "GOVERNANCE"
    COMPLETED = "COMPLETED"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"


class NextActionDecision(str, Enum):
    """Deterministic next-action decisions determined by the ActionDecisionEngine."""
    NO_ACTION_REQUIRED = "NO_ACTION_REQUIRED"
    RUN_SECURITY_SCAN = "RUN_SECURITY_SCAN"
    INVESTIGATE_FINDING = "INVESTIGATE_FINDING"
    ANALYZE_ATTACK_PATH = "ANALYZE_ATTACK_PATH"
    CREATE_REMEDIATION_PLAN = "CREATE_REMEDIATION_PLAN"
    VALIDATE_REPAIR = "VALIDATE_REPAIR"
    REPLAN_REMEDIATION = "REPLAN_REMEDIATION"
    RUN_SECURITY_REGRESSION = "RUN_SECURITY_REGRESSION"
    UPDATE_HISTORY = "UPDATE_HISTORY"
    RUN_RELEASE_READINESS = "RUN_RELEASE_READINESS"
    REQUIRE_HUMAN_REVIEW = "REQUIRE_HUMAN_REVIEW"
    BLOCK_RELEASE = "BLOCK_RELEASE"


class SecurityCaseStatus(str, Enum):
    """Status of an individual SecurityCase lifecycle."""
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    REMEDIATION_PLANNED = "REMEDIATION_PLANNED"
    VALIDATING = "VALIDATING"
    REMEDIATION_FAILED = "REMEDIATION_FAILED"
    REMEDIATED = "REMEDIATED"
    REGRESSED = "REGRESSED"
    BLOCKED = "BLOCKED"
    CLOSED = "CLOSED"


@dataclass
class ActionItem:
    """Individual workflow step action item in a SecurityWorkflowPlan."""
    action_id: str
    action_type: str
    reason: str
    dependencies: List[str] = field(default_factory=list)
    required_inputs: List[str] = field(default_factory=list)
    expected_outputs: List[str] = field(default_factory=list)
    status: str = "PENDING"  # PENDING, IN_PROGRESS, COMPLETED, SKIPPED, FAILED

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SecurityWorkflowPlan:
    """Ordered dependency-aware action plan for security orchestration."""
    plan_id: str
    repository: str
    commit: str
    actions: List[ActionItem] = field(default_factory=list)
    is_adaptive: bool = True
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "repository": self.repository,
            "commit": self.commit,
            "actions": [a.to_dict() for a in self.actions],
            "is_adaptive": self.is_adaptive,
            "created_at": self.created_at,
        }


@dataclass
class SecurityCaseTimelineEntry:
    """Timestamped event log entry in a SecurityCaseTimeline."""
    entry_id: str
    timestamp: str
    event: str
    details: str
    state: WorkflowState

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["state"] = self.state.value if isinstance(self.state, Enum) else self.state
        return d


@dataclass
class HumanReviewRequest:
    """Escalation payload requesting human security review."""
    review_id: str
    reason: str
    severity: str
    affected_files: List[str] = field(default_factory=list)
    evidence: str = ""
    attempted_actions: List[str] = field(default_factory=list)
    recommended_next_step: str = ""
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SecurityCase:
    """Complete lifecycle model for a single security issue."""
    case_id: str
    repository: str
    finding: Optional[Dict[str, Any]] = None
    priority: str = "P3"
    attack_path: Optional[Dict[str, Any]] = None
    root_cause: str = "UNKNOWN"
    remediation: Optional[Dict[str, Any]] = None
    validation: Optional[Dict[str, Any]] = None
    regression: Optional[Dict[str, Any]] = None
    monitoring: Optional[Dict[str, Any]] = None
    release_decision: Optional[str] = None
    governance_decision: Optional[str] = None
    current_status: SecurityCaseStatus = SecurityCaseStatus.OPEN
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    timeline: List[SecurityCaseTimelineEntry] = field(default_factory=list)
    human_review_request: Optional[HumanReviewRequest] = None
    remediation_attempts: int = 0
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["current_status"] = self.current_status.value if isinstance(self.current_status, Enum) else self.current_status
        d["timeline"] = [t.to_dict() for t in self.timeline]
        if self.human_review_request:
            d["human_review_request"] = self.human_review_request.to_dict()
        return d


@dataclass
class SecurityEngineeringSummary:
    """Global multi-repository posture overview."""
    repositories_scanned: int = 0
    total_findings: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    active_attack_paths: int = 0
    open_remediations: int = 0
    regressions: int = 0
    blocked_releases: int = 0
    review_required: int = 0
    repositories_release_ready: int = 0
    repositories_degraded: int = 0
    repositories_improved: int = 0
    generated_at: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SecurityOrchestrationResult:
    """Complete container for an orchestrated security engineering run."""
    workflow_id: str
    repository: str
    commit: str
    current_state: WorkflowState
    previous_state: Optional[WorkflowState]
    state_history: List[WorkflowState]
    plan: SecurityWorkflowPlan
    cases: List[SecurityCase]
    next_action: NextActionDecision
    next_action_reason: str
    human_review: Optional[HumanReviewRequest] = None
    summary: Optional[SecurityEngineeringSummary] = None
    started_at: str = field(default_factory=lambda: datetime.now().isoformat())
    completed_at: Optional[str] = None
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "workflow_id": self.workflow_id,
            "repository": self.repository,
            "commit": self.commit,
            "current_state": self.current_state.value if isinstance(self.current_state, Enum) else self.current_state,
            "previous_state": self.previous_state.value if self.previous_state and isinstance(self.previous_state, Enum) else (self.previous_state or None),
            "state_history": [s.value if isinstance(s, Enum) else s for s in self.state_history],
            "plan": self.plan.to_dict(),
            "cases": [c.to_dict() for c in self.cases],
            "next_action": self.next_action.value if isinstance(self.next_action, Enum) else self.next_action,
            "next_action_reason": self.next_action_reason,
            "human_review": self.human_review.to_dict() if self.human_review else None,
            "summary": self.summary.to_dict() if self.summary else None,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "errors": self.errors,
            "warnings": self.warnings,
        }
