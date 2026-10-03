"""
M20 Security Workflow Executor.

Executes SecurityWorkflowPlan items, enforces bounded remediation retry loops (MAX_REMEDIATION_ATTEMPTS = 3),
handles plan invalidation (REQUIRES_REPLAN), and manages human review escalations.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime
from agentos_swe.operations.orchestration.models import (
    WorkflowState,
    NextActionDecision,
    SecurityWorkflowPlan,
    SecurityCase,
    HumanReviewRequest,
)
from agentos_swe.operations.orchestration.state import WorkflowStateTracker
from agentos_swe.operations.orchestration.decisions import ActionDecisionEngine
from agentos_swe.operations.orchestration.evidence import SecurityCaseEvidenceBuilder


class SecurityWorkflowExecutor:
    """
    Executes dependency-aware workflow steps and coordinates remediation loops.
    """

    MAX_REMEDIATION_ATTEMPTS: int = 3

    def __init__(self):
        self.decision_engine = ActionDecisionEngine()
        self.evidence_builder = SecurityCaseEvidenceBuilder()

    def execute_workflow(
        self,
        repository_name: str,
        commit_sha: str,
        plan: SecurityWorkflowPlan,
        verified_findings: List[Dict[str, Any]],
        prioritized_findings: List[Dict[str, Any]],
        attack_paths: List[Dict[str, Any]],
        remediation_plan: Optional[Dict[str, Any]],
        monitoring_result: Optional[Dict[str, Any]],
        release_decision: Optional[Dict[str, Any]],
        governance_decision: str = "ALLOW",
        remediation_attempts: int = 0,
        force_human_review: bool = False,
    ) -> Dict[str, Any]:
        """
        Executes workflow steps and returns orchestration state dictionary.
        """
        state_tracker = WorkflowStateTracker(WorkflowState.INTAKE)
        errors: List[str] = []
        warnings: List[str] = []
        human_review: Optional[HumanReviewRequest] = None

        # Enforce Bounded Remediation Loop (Max 3 attempts)
        if remediation_attempts >= self.MAX_REMEDIATION_ATTEMPTS or force_human_review:
            human_review = self.evidence_builder.create_human_review_request(
                reason=f"Remediation attempts ({remediation_attempts}) reached maximum threshold ({self.MAX_REMEDIATION_ATTEMPTS}).",
                severity="HIGH",
                affected_files=[f.get("affected_file", "repository") for f in prioritized_findings[:3]],
                evidence="Multiple candidate repairs failed validation or required manual review.",
                attempted_actions=["Generate candidate patch", "Run reproduction sandbox", "Run regression tests"],
                recommended_next_step="Human security architect code review required.",
            )
            warnings.append("Human review escalation triggered: Bounded remediation limit reached.")

        # Determine Next Action Decision
        next_action, next_action_reason = self.decision_engine.determine_next_action(
            verified_findings=verified_findings,
            prioritized_findings=prioritized_findings,
            attack_paths=attack_paths,
            remediation_plan=remediation_plan,
            monitoring_result=monitoring_result,
            release_decision=release_decision,
            remediation_attempts=remediation_attempts,
            human_review_requested=human_review is not None,
        )

        # Transition States along Plan
        for action in plan.actions:
            state_tracker.transition_to(WorkflowState(action.action_type))

        # Final State Determination
        rel_dec = str((release_decision or {}).get("decision") or "").upper()
        if rel_dec == "BLOCKED":
            state_tracker.transition_to(WorkflowState.BLOCKED)
        elif human_review is not None:
            state_tracker.transition_to(WorkflowState.GOVERNANCE)
        else:
            state_tracker.transition_to(WorkflowState.COMPLETED)

        # Build Security Cases
        cases: List[SecurityCase] = []
        if prioritized_findings:
            for top_f in prioritized_findings[:3]:
                top_path = attack_paths[0] if attack_paths else None
                c = self.evidence_builder.build_security_case(
                    repository_name=repository_name,
                    finding=top_f,
                    attack_path=top_path,
                    remediation_plan=remediation_plan,
                    monitoring_result=monitoring_result,
                    release_decision=release_decision,
                    governance_decision=governance_decision,
                    remediation_attempts=remediation_attempts,
                    human_review=human_review,
                )
                cases.append(c)

        return {
            "current_state": state_tracker.current_state,
            "previous_state": state_tracker.previous_state,
            "state_history": state_tracker.state_history,
            "next_action": next_action,
            "next_action_reason": next_action_reason,
            "cases": cases,
            "human_review": human_review,
            "errors": errors,
            "warnings": warnings,
        }
