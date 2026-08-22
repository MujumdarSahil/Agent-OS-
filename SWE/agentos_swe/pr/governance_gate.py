"""
GovernanceGate - AgentOS GovernanceEngine integration for M5 PR Automation, M13 Repair Validation, M14 History, M15 Intelligence, and M16 Attack Paths.
Evaluates RiskAssessment, CorrelatedFinding, RepairValidationResult, ScanComparisonResult, PrioritizedFinding, and AttackPath against registered policies.
"""

import logging
from typing import Dict, Any, Optional, List

from agentos.core.governance import GovernanceEngine, Policy, PolicyType
from agentos_swe.pr.models import RiskLevel, RiskAssessment, GovernanceDecision
from agentos_swe.correlation.models import CorrelatedFinding
from agentos_swe.repair.models import RepairValidationResult, RepairVerdict
from agentos_swe.history.models import ScanComparisonResult, RiskTrend
from agentos_swe.intelligence.models import PrioritizedFinding, PriorityTier
from agentos_swe.attackpath.models import AttackPath, PathClassification

logger = logging.getLogger(__name__)


class GovernanceGate:
    """
    Evaluates PR creation, correlated repairs, historical comparisons, priority security findings, and attack paths against policies.
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

    def evaluate_historical_comparison(self, comparison: ScanComparisonResult) -> GovernanceDecision:
        """
        Evaluate M14 ScanComparisonResult against governance policies.
        """
        if comparison.risk_trend == RiskTrend.DEGRADING or len(comparison.reopened_findings) > 0:
            return GovernanceDecision.REVIEW_REQUIRED
        elif comparison.score_delta < 0:
            return GovernanceDecision.REVIEW_REQUIRED
        else:
            return GovernanceDecision.ALLOW


    def evaluate_security_intelligence(self, prioritized_findings: List[PrioritizedFinding]) -> GovernanceDecision:
        """
        Evaluate M15 PrioritizedFindings against governance policies.
        """
        if any(p.priority_tier in (PriorityTier.P0, PriorityTier.P1) for p in prioritized_findings):
            return GovernanceDecision.REVIEW_REQUIRED
        return GovernanceDecision.ALLOW

    def evaluate_attack_paths(self, attack_paths: List[AttackPath]) -> GovernanceDecision:
        """
        Evaluate M16 AttackPaths against governance policies.
        """
        if any(p.classification == PathClassification.EXPLOITABLE and p.risk_score >= 70 for p in attack_paths):
            return GovernanceDecision.REVIEW_REQUIRED
        return GovernanceDecision.ALLOW

    def evaluate_remediation_plan(self, plan: Any) -> GovernanceDecision:
        """
        Evaluate M17 RemediationPlan against governance policies.
        """
        if getattr(plan, "conflicts", None):
            return GovernanceDecision.REVIEW_REQUIRED
        if getattr(plan, "governance_status", "") in ("NEEDS_REVIEW", "REJECT"):
            return GovernanceDecision.REVIEW_REQUIRED
        items = getattr(plan, "remediation_items", [])
        if any(getattr(item, "priority_tier", "") in ("P0", "P1") for item in items):
            return GovernanceDecision.REVIEW_REQUIRED
        return GovernanceDecision.ALLOW

    def evaluate_security_monitoring(self, result: Any) -> GovernanceDecision:
        """
        Evaluate M18 SecurityMonitoringResult against governance policies.
        """
        reg_sev = str(getattr(result, "regression_severity", "")).upper()
        if "CRITICAL" in reg_sev or "SIGNIFICANT" in reg_sev:
            return GovernanceDecision.REVIEW_REQUIRED

        alerts = getattr(result, "alerts", [])
        for alt in alerts:
            cat = str(getattr(alt, "category", "")).upper()
            sev = str(getattr(alt, "severity", "")).upper()
            if sev == "CRITICAL" or cat in ("CRITICAL_SECURITY_REGRESSION", "AUTHENTICATION_WEAKENED", "NEW_CRITICAL_FINDING"):
                return GovernanceDecision.REVIEW_REQUIRED

        return GovernanceDecision.ALLOW

    def evaluate_release_readiness(self, release_decision: Any) -> GovernanceDecision:
        """
        Evaluate M19 SecurityReleaseDecision against governance policies.
        """
        dec_val = str(getattr(release_decision, "decision", "")).upper()
        if dec_val in ("BLOCKED", "NO_GO"):
            return GovernanceDecision.DENY
        elif dec_val == "REVIEW_REQUIRED":
            return GovernanceDecision.REVIEW_REQUIRED
        else:
            return GovernanceDecision.ALLOW

    def evaluate_security_workflow(self, workflow_result: Any) -> GovernanceDecision:
        """
        Evaluate M20 SecurityOrchestrationResult against governance policies.
        """
        if getattr(workflow_result, "human_review", None) is not None:
            return GovernanceDecision.REVIEW_REQUIRED

        cur_state = str(getattr(workflow_result, "current_state", "")).upper()
        if "BLOCKED" in cur_state:
            return GovernanceDecision.DENY
        elif "FAILED" in cur_state or "GOVERNANCE" in cur_state:
            return GovernanceDecision.REVIEW_REQUIRED

        next_act = str(getattr(workflow_result, "next_action", "")).upper()
        if next_act == "BLOCK_RELEASE":
            return GovernanceDecision.DENY
        elif next_act in ("REQUIRE_HUMAN_REVIEW", "REPLAN_REMEDIATION"):
            return GovernanceDecision.REVIEW_REQUIRED

        return GovernanceDecision.ALLOW
