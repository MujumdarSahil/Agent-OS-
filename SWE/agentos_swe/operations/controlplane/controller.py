"""
M27 Security Operations Control Plane Master Controller.

Master facade orchestrating intake, state management, health calculation, drift evaluation,
decision processing, action selection, lifecycle transitions, and audit logging.
"""

import logging
from typing import List, Dict, Any, Optional
from datetime import datetime

from agentos_swe.operations.controlplane.models import (
    ControlPlaneResult,
    OperationalMode,
    OperationalStatus,
    ControlPlaneEvent,
)
from agentos_swe.operations.controlplane.state import RepositoryOperationalStateManager
from agentos_swe.operations.controlplane.aggregator import SecurityOperationsAggregator
from agentos_swe.operations.controlplane.lifecycle import RepositoryLifecycleEngine
from agentos_swe.operations.controlplane.health import SecurityOperationsHealthEngine
from agentos_swe.operations.controlplane.actions import ControlPlaneActionSelector
from agentos_swe.operations.controlplane.approvals import ControlPlaneApprovalManager
from agentos_swe.operations.controlplane.scheduler import SecurityMonitoringScheduler
from agentos_swe.operations.controlplane.audit import SecurityAuditTrailEngine

logger = logging.getLogger(__name__)


class SecurityOperationsControlPlane:
    """
    Master control plane controller uniting M14-M26 security intelligence into one operational state.
    """

    def __init__(self):
        self.state_manager = RepositoryOperationalStateManager()
        self.aggregator = SecurityOperationsAggregator()
        self.lifecycle_engine = RepositoryLifecycleEngine()
        self.health_engine = SecurityOperationsHealthEngine()
        self.action_selector = ControlPlaneActionSelector()
        self.approval_manager = ControlPlaneApprovalManager()
        self.scheduler = SecurityMonitoringScheduler()
        self.audit_engine = SecurityAuditTrailEngine()

    def process_repository_operations(
        self,
        repository_name: str,
        commit_sha: str = "HEAD",
        verified_findings: Optional[List[Any]] = None,
        prioritized_findings: Optional[List[Any]] = None,
        attack_paths: Optional[List[Any]] = None,
        decision_result: Optional[Any] = None,
        learning_result: Optional[Any] = None,
        drift_result: Optional[Any] = None,
    ) -> ControlPlaneResult:
        """
        Executes control plane processing over scan results and intelligence layers.
        """
        # 1. Update in-memory operational state
        state = self.state_manager.update_state_from_pipeline(
            repository_name=repository_name,
            commit_sha=commit_sha,
            verified_findings=verified_findings,
            prioritized_findings=prioritized_findings,
            attack_paths=attack_paths,
            decision_result=decision_result,
            learning_result=learning_result,
            drift_result=drift_result,
        )

        # 2. Aggregate summary metrics across M14-M26
        summary = self.aggregator.aggregate_summary(
            repository_name=repository_name,
            commit_sha=commit_sha,
            state=state,
            decision_result=decision_result,
            learning_result=learning_result,
            drift_result=drift_result,
        )

        # 3. Evaluate operational health
        health = self.health_engine.compute_health(summary=summary, state=state)
        state.health = health
        state.operational_status = health.status
        summary.operational_status = health.status

        if summary.critical_findings > 0 or summary.governance_status in ["DENY", "BLOCK_RELEASE"] or health.status == OperationalStatus.BLOCKED:
            summary.release_status = "RELEASE_BLOCKED"

        # 4. Select next recommended operational action
        recommended_action = self.action_selector.select_next_action(
            summary=summary, state=state, decision_result=decision_result
        )
        state.next_recommended_action = recommended_action

        # 5. Transition lifecycle stage based on selected action
        if recommended_action.action.value in ["BLOCK_RELEASE"]:
            state.operational_mode = OperationalMode.BLOCKED
            state.lifecycle_stage = "BLOCKED"
        elif recommended_action.action.value in ["REQUEST_APPROVAL"]:
            state.operational_mode = OperationalMode.WAITING_APPROVAL
            state.lifecycle_stage = "APPROVAL_PENDING"
        elif recommended_action.action.value in ["GENERATE_REPAIR", "VALIDATE_REPAIR"]:
            state.operational_mode = OperationalMode.REPAIRING
            state.lifecycle_stage = "REPAIR_PENDING"
        elif recommended_action.action.value in ["RESCAN"]:
            state.operational_mode = OperationalMode.SCANNING
            state.lifecycle_stage = "RESCAN_REQUIRED"
        elif recommended_action.action.value in ["MONITOR"]:
            state.operational_mode = OperationalMode.MONITORING
            state.lifecycle_stage = "MONITORING"
        else:
            state.operational_mode = OperationalMode.COMPLETE
            state.lifecycle_stage = "COMPLETE"

        # 6. Audit event logging
        self.audit_engine.record_event(
            repository_name=repository_name,
            event=ControlPlaneEvent.SCAN_COMPLETED,
            severity=health.status.value,
            actor="ControlPlaneController",
            reason=health.explanation,
            evidence_ref=f"Score: {summary.security_score}, Drift: {summary.drift_score}",
            resulting_state=state.lifecycle_stage,
        )

        audit_trail = self.audit_engine.get_audit_trail(repository_name)

        # 7. Construct complete operational timeline
        timeline = [
            {"stage": "1. Intake", "status": "COMPLETED", "details": f"Repository '{repository_name}' @ {commit_sha[:7]}"},
            {"stage": "2. Analysis", "status": "COMPLETED", "details": f"{summary.critical_findings + summary.high_findings + summary.medium_findings + summary.low_findings} findings verified"},
            {"stage": "3. Intelligence", "status": "COMPLETED", "details": f"{summary.active_attack_paths} attack paths, {summary.internet_exposed_paths} exposed"},
            {"stage": "4. Drift & Learning", "status": "COMPLETED", "details": f"Drift Score {summary.drift_score}/100, Trend: {summary.drift_direction}"},
            {"stage": "5. Decision", "status": "COMPLETED", "details": f"Governance verdict: {summary.governance_status}"},
            {"stage": "6. Control Plane", "status": state.lifecycle_stage, "details": f"Next Action: {recommended_action.action.value}"},
        ]

        gov_verdict = summary.governance_status

        return ControlPlaneResult(
            repository_name=repository_name,
            commit_sha=commit_sha,
            timestamp=datetime.now().isoformat(),
            summary=summary,
            state=state,
            recommended_action=recommended_action,
            health=health,
            audit_trail=audit_trail,
            timeline=timeline,
            governance_verdict=gov_verdict,
        )
