"""
GovernanceGate - AgentOS GovernanceEngine integration for M5 PR Automation.
Evaluates RiskAssessment against registered AgentOS Governance Policies.
"""

import logging
from typing import Dict, Any, Optional

from agentos.core.governance import GovernanceEngine, Policy, PolicyType
from agentos_swe.pr.models import RiskLevel, RiskAssessment, GovernanceDecision

logger = logging.getLogger(__name__)


class GovernanceGate:
    """
    Evaluates PR creation against AgentOS GovernanceEngine policies.
    """

    def __init__(self, governance_engine: Optional[GovernanceEngine] = None):
        self.governance = governance_engine or GovernanceEngine()

        # Register default PR automation policy
        pr_policy = Policy(
            id="pr_automation_risk_policy",
            policy_type=PolicyType.ACTION,
            name="PR Automation Risk Policy",
            check_func=self._governance_policy_check,
        )
        self.governance.register_policy(pr_policy)

    def _governance_policy_check(self, agent_id: str, action: str, context: Dict[str, Any]) -> bool:
        """
        Policy check callback:
        - LOW / MEDIUM risk -> True (Allowed)
        - HIGH / CRITICAL risk -> False (Deny automatic PR creation, requires manual review)
        """
        if action == "github_pr_create":
            risk_level = context.get("risk_level", "LOW")
            if risk_level in ("HIGH", "CRITICAL"):
                return False
        return True

    def evaluate(self, risk: RiskAssessment) -> GovernanceDecision:
        """
        Evaluate RiskAssessment with AgentOS GovernanceEngine registered policies.
        Returns ALLOW, REVIEW_REQUIRED, or DENY.
        """
        context = {
            "risk_level": risk.risk_level.value,
            "risk_score": risk.risk_score,
            "finding_id": risk.finding_id,
        }

        allowed = True
        for policy in self.governance.policies.values():
            try:
                res = policy.check_func("AgentOS-SWE-PRPipeline", "github_pr_create", context)
                if res is False:
                    allowed = False
                    break
            except Exception as ex:
                logger.debug(f"[GovernanceGate] Policy check exception: {ex}")

        if allowed:
            if risk.risk_level == RiskLevel.LOW:
                decision = GovernanceDecision.ALLOW
            elif risk.risk_level == RiskLevel.MEDIUM:
                decision = GovernanceDecision.REVIEW_REQUIRED
            else:
                decision = GovernanceDecision.ALLOW
        else:
            if risk.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
                decision = GovernanceDecision.REVIEW_REQUIRED
            else:
                decision = GovernanceDecision.DENY

        logger.info(f"[GovernanceGate] Decision for finding '{risk.finding_id}': {decision.value} (Risk: {risk.risk_level.value})")
        return decision
