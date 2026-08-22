"""
M19 / M20 Dependency-Aware Adaptive Security Workflow Planner.

Constructs ordered ActionItem sequences and SecurityWorkflowPlan objects tailored
to repository context and security findings.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime
from agentos_swe.orchestration.models import ActionItem, SecurityWorkflowPlan, WorkflowState


class SecurityWorkflowPlanner:
    """
    Dependency-aware planner creating adaptive workflow plans.
    """

    def construct_plan(
        self,
        repository_name: str,
        commit_sha: str,
        findings: Optional[List[Dict[str, Any]]] = None,
        is_clean_scan: bool = False,
    ) -> SecurityWorkflowPlan:
        """
        Creates an ordered SecurityWorkflowPlan for a repository run.
        """
        findings = findings or []
        actions: List[ActionItem] = []

        # Step 1: Intake & Scan
        actions.append(
            ActionItem(
                action_id="act_1_intake_scan",
                action_type=WorkflowState.SCANNING.value,
                reason="Execute static AST analysis and deterministic taint scanning.",
                dependencies=[],
                required_inputs=["repository_target_path"],
                expected_outputs=["verified_findings", "taint_findings"],
                status="COMPLETED",
            )
        )

        if is_clean_scan or not findings:
            # Adaptive Short Circuit for Clean Scan
            actions.append(
                ActionItem(
                    action_id="act_2_historical",
                    action_type=WorkflowState.HISTORICAL_COMPARISON.value,
                    reason="Compare clean posture against historical baseline.",
                    dependencies=["act_1_intake_scan"],
                    required_inputs=["verified_findings"],
                    expected_outputs=["historical_comparison"],
                    status="COMPLETED",
                )
            )
            actions.append(
                ActionItem(
                    action_id="act_3_monitoring",
                    action_type=WorkflowState.MONITORING.value,
                    reason="Verify posture stability and alert engine.",
                    dependencies=["act_2_historical"],
                    required_inputs=["historical_comparison"],
                    expected_outputs=["monitoring_result"],
                    status="COMPLETED",
                )
            )
            actions.append(
                ActionItem(
                    action_id="act_4_release",
                    action_type=WorkflowState.RELEASE_READINESS.value,
                    reason="Evaluate clean release readiness gate.",
                    dependencies=["act_3_monitoring"],
                    required_inputs=["monitoring_result"],
                    expected_outputs=["release_decision"],
                    status="COMPLETED",
                )
            )
            return SecurityWorkflowPlan(
                plan_id=f"plan_clean_{repository_name}",
                repository=repository_name,
                commit=commit_sha,
                actions=actions,
                is_adaptive=True,
                created_at=datetime.now().isoformat(),
            )

        # Step 2: Full Vulnerability Pipeline
        actions.append(
            ActionItem(
                action_id="act_2_correlate",
                action_type=WorkflowState.CORRELATING.value,
                reason="Group findings by root cause and module context.",
                dependencies=["act_1_intake_scan"],
                required_inputs=["verified_findings"],
                expected_outputs=["correlated_findings"],
                status="COMPLETED",
            )
        )
        actions.append(
            ActionItem(
                action_id="act_3_prioritize",
                action_type=WorkflowState.PRIORITIZING.value,
                reason="Calculate exploitability, reachability, and priority tiers.",
                dependencies=["act_2_correlate"],
                required_inputs=["correlated_findings"],
                expected_outputs=["prioritized_findings"],
                status="COMPLETED",
            )
        )
        actions.append(
            ActionItem(
                action_id="act_4_attack_paths",
                action_type=WorkflowState.ATTACK_PATH_ANALYSIS.value,
                reason="Discover entrypoints, trust boundaries, and attack graphs.",
                dependencies=["act_3_prioritize"],
                required_inputs=["prioritized_findings", "taint_findings"],
                expected_outputs=["attack_paths"],
                status="COMPLETED",
            )
        )
        actions.append(
            ActionItem(
                action_id="act_5_remediation_plan",
                action_type=WorkflowState.REMEDIATION_PLANNING.value,
                reason="Generate root-cause remediation plan and fix ordering.",
                dependencies=["act_4_attack_paths"],
                required_inputs=["prioritized_findings", "attack_paths"],
                expected_outputs=["remediation_plan"],
                status="COMPLETED",
            )
        )
        actions.append(
            ActionItem(
                action_id="act_6_repair_validation",
                action_type=WorkflowState.REPAIR_VALIDATION.value,
                reason="Validate candidate repairs in empirical sandbox.",
                dependencies=["act_5_remediation_plan"],
                required_inputs=["remediation_plan"],
                expected_outputs=["repair_validations"],
                status="COMPLETED",
            )
        )
        actions.append(
            ActionItem(
                action_id="act_7_historical",
                action_type=WorkflowState.HISTORICAL_COMPARISON.value,
                reason="Compare scan posture against historical record.",
                dependencies=["act_6_repair_validation"],
                required_inputs=["prioritized_findings"],
                expected_outputs=["historical_comparison"],
                status="COMPLETED",
            )
        )
        actions.append(
            ActionItem(
                action_id="act_8_monitoring",
                action_type=WorkflowState.MONITORING.value,
                reason="Assess security regression and attack path deltas.",
                dependencies=["act_7_historical"],
                required_inputs=["historical_comparison", "attack_paths"],
                expected_outputs=["monitoring_result"],
                status="COMPLETED",
            )
        )
        actions.append(
            ActionItem(
                action_id="act_9_release",
                action_type=WorkflowState.RELEASE_READINESS.value,
                reason="Evaluate multi-factor release readiness and blockers.",
                dependencies=["act_8_monitoring"],
                required_inputs=["monitoring_result", "remediation_plan"],
                expected_outputs=["release_decision"],
                status="COMPLETED",
            )
        )

        return SecurityWorkflowPlan(
            plan_id=f"plan_full_{repository_name}",
            repository=repository_name,
            commit=commit_sha,
            actions=actions,
            is_adaptive=True,
            created_at=datetime.now().isoformat(),
        )
