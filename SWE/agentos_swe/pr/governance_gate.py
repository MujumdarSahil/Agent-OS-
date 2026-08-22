"""
GovernanceGate - AgentOS GovernanceEngine integration for M5 PR Automation, M13 & M13.1 Repair Validation.
Evaluates RiskAssessment, CorrelatedFinding, and RepairValidationResult against registered AgentOS Governance Policies.
"""

import logging
from typing import Dict, Any, Optional

from agentos.core.governance import GovernanceEngine, Policy, PolicyType
from agentos_swe.pr.models import RiskLevel, RiskAssessment, GovernanceDecision
from agentos_swe.correlation.models import CorrelatedFinding
from agentos_swe.repair.models import RepairValidationResult, RepairVerdict

logger = logging.getLogger(__name__)


class GovernanceGate:
    """
    Evaluates PR creation and correlated repair proposals against AgentOS GovernanceEngine policies.
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
        if action in ("github_pr_create", "apply_security_repair"):
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

    def evaluate_correlated_finding(self, correlated_finding: CorrelatedFinding) -> GovernanceDecision:
        """
        Evaluate M13 CorrelatedFinding against governance policies.
        """
        severity_str = (correlated_finding.severity or "medium").upper()
        if severity_str in ("HIGH", "CRITICAL"):
            decision = GovernanceDecision.REVIEW_REQUIRED
        elif severity_str == "MEDIUM":
            decision = GovernanceDecision.REVIEW_REQUIRED
        else:
            decision = GovernanceDecision.ALLOW

        logger.info(f"[GovernanceGate] M13 Decision for correlated finding '{correlated_finding.finding_id}': {decision.value} (Severity: {severity_str})")
        return decision

    def evaluate_repair_validation(self, validation_result: RepairValidationResult) -> GovernanceDecision:
        """
        Evaluate M13.1 RepairValidationResult against governance policies.
        """
        if validation_result.final_verdict == RepairVerdict.REGRESSION_DETECTED:
            return GovernanceDecision.DENY
        elif validation_result.final_verdict == RepairVerdict.NO_REPAIR_REQUIRED:
            return GovernanceDecision.ALLOW
        elif validation_result.final_verdict == RepairVerdict.REPAIRED:
            sev = (validation_result.original_severity or "MEDIUM").upper()
            if sev in ("HIGH", "CRITICAL"):
                return GovernanceDecision.REVIEW_REQUIRED
            return GovernanceDecision.ALLOW
        else:
            return GovernanceDecision.REVIEW_REQUIRED
