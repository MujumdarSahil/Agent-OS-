"""
Domain models for M5 GitHub PR Automation & Risk Governance.
Includes RiskLevel, GovernanceDecision, RiskAssessment, and PRResult.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Dict, Any, Optional


class RiskLevel(str, Enum):
    """Risk classification level for a proposed repair patch."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class GovernanceDecision(str, Enum):
    """Governance engine decision for PR creation."""
    ALLOW = "ALLOW"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    DENY = "DENY"


@dataclass
class RiskAssessment:
    """Deterministic risk analysis result for a validated patch."""
    finding_id: str
    risk_level: RiskLevel
    risk_score: float
    risk_signals: List[str] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["risk_level"] = self.risk_level.value if isinstance(self.risk_level, Enum) else self.risk_level
        return data


@dataclass
class PRResult:
    """Result of PR automation pipeline execution."""
    success: bool
    pr_number: Optional[int] = None
    pr_url: Optional[str] = None
    branch_name: str = ""
    governance_decision: GovernanceDecision = GovernanceDecision.ALLOW
    risk_level: RiskLevel = RiskLevel.LOW
    dry_run: bool = False
    pr_title: str = ""
    pr_body: str = ""
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "pr_number": self.pr_number,
            "pr_url": self.pr_url,
            "branch_name": self.branch_name,
            "governance_decision": self.governance_decision.value if isinstance(self.governance_decision, Enum) else self.governance_decision,
            "risk_level": self.risk_level.value if isinstance(self.risk_level, Enum) else self.risk_level,
            "dry_run": self.dry_run,
            "pr_title": self.pr_title,
            "pr_body": self.pr_body,
            "error": self.error,
        }
