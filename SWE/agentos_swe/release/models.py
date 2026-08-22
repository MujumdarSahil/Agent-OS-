"""
M19 Security Release Readiness & Decision Engine Models.

Defines domain models, enums, dataclasses, and data structures for release decision states,
security gate verdicts, release diffs, release blockers, evidence chains, executive scorecards,
and cross-repository release posture.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Dict, Any, Optional
from datetime import datetime


class ReleaseDecisionState(str, Enum):
    """Deterministic security release decision state."""
    GO = "GO"
    GO_WITH_WARNINGS = "GO_WITH_WARNINGS"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    NO_GO = "NO_GO"
    BLOCKED = "BLOCKED"


class SecurityGateVerdict(str, Enum):
    """Deterministic SecurityReleaseGate verdict."""
    ALLOW_RELEASE = "ALLOW_RELEASE"
    ALLOW_WITH_WARNINGS = "ALLOW_WITH_WARNINGS"
    REQUIRE_REVIEW = "REQUIRE_REVIEW"
    DENY_RELEASE = "DENY_RELEASE"


class ReleaseDeltaState(str, Enum):
    """Release decision delta relative to previous release evaluation."""
    IMPROVED = "IMPROVED"
    UNCHANGED = "UNCHANGED"
    DEGRADED = "DEGRADED"
    RECOVERED = "RECOVERED"


@dataclass
class ReleaseBlocker:
    """A specific security condition blocking or preventing release."""
    blocker_id: str
    severity: str
    category: str
    title: str
    file: str
    line: Optional[int] = None
    finding_id: Optional[str] = None
    attack_path_id: Optional[str] = None
    remediation_id: Optional[str] = None
    reason: str = ""
    evidence: str = ""
    recommended_action: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DecisionEvidence:
    """An explainable evidence entry supporting a release decision."""
    evidence_id: str
    policy_rule: str
    finding_id: Optional[str] = None
    evidence_text: str = ""
    attack_path_id: Optional[str] = None
    historical_context: Optional[str] = None
    remediation_id: Optional[str] = None
    validation_status: str = "UNVALIDATED"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ExecutiveScorecard:
    """Executive summary scorecard of repository security metrics and release posture."""
    security_score: int
    risk_score: int
    exploitability: str
    internet_exposure: str
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    attack_paths: int
    regressions: int
    p0_remediations: int
    p1_remediations: int
    governance_status: str
    release_decision: ReleaseDecisionState

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["release_decision"] = self.release_decision.value if isinstance(self.release_decision, Enum) else self.release_decision
        return d


@dataclass
class ReleaseDiff:
    """Differential analysis between previous and current release decisions."""
    previous_decision: ReleaseDecisionState
    current_decision: ReleaseDecisionState
    release_delta_state: ReleaseDeltaState
    explanation: str

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["previous_decision"] = self.previous_decision.value if isinstance(self.previous_decision, Enum) else self.previous_decision
        d["current_decision"] = self.current_decision.value if isinstance(self.current_decision, Enum) else self.current_decision
        d["release_delta_state"] = self.release_delta_state.value if isinstance(self.release_delta_state, Enum) else self.release_delta_state
        return d


@dataclass
class SecurityReleaseDecision:
    """Complete container for security release readiness analysis and decision verdict."""
    repository: str
    commit: str
    decision: ReleaseDecisionState
    release_status: str
    security_score: int
    risk_score: int
    scorecard: ExecutiveScorecard
    blockers: List[ReleaseBlocker] = field(default_factory=list)
    blocking_findings: List[str] = field(default_factory=list)
    blocking_attack_paths: List[str] = field(default_factory=list)
    blocking_remediations: List[str] = field(default_factory=list)
    regressions: List[str] = field(default_factory=list)
    governance_status: str = "ALLOW"
    evidence_chain: List[DecisionEvidence] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    release_diff: Optional[ReleaseDiff] = None
    generated_at: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["decision"] = self.decision.value if isinstance(self.decision, Enum) else self.decision
        d["scorecard"] = self.scorecard.to_dict()
        d["blockers"] = [b.to_dict() for b in self.blockers]
        d["evidence_chain"] = [e.to_dict() for e in self.evidence_chain]
        if self.release_diff:
            d["release_diff"] = self.release_diff.to_dict()
        return d


@dataclass
class CrossRepositoryReleasePosture:
    """Container for multi-repository release readiness matrix."""
    generated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    repository_decisions: Dict[str, SecurityReleaseDecision] = field(default_factory=dict)
    total_repositories: int = 0
    go_count: int = 0
    blocked_count: int = 0
    no_go_count: int = 0
    review_required_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "repository_decisions": {repo: dec.to_dict() for repo, dec in self.repository_decisions.items()},
            "total_repositories": self.total_repositories,
            "go_count": self.go_count,
            "blocked_count": self.blocked_count,
            "no_go_count": self.no_go_count,
            "review_required_count": self.review_required_count,
        }
