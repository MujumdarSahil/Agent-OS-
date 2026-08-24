"""
M27 Control Plane Action Selector.

Evaluates multi-milestone intelligence to recommend the next operational action with explainable rationale.
"""

from typing import List, Dict, Any, Optional

from agentos_swe.operations.controlplane.models import (
    OperationalAction,
    ControlPlaneAction,
    SecurityOperationsSummary,
    RepositoryOperationalState,
)


class ControlPlaneActionSelector:
    """
    Selects next recommended operational action based on M14-M26 intelligence state.
    """

    def select_next_action(
        self,
        summary: SecurityOperationsSummary,
        state: RepositoryOperationalState,
        decision_result: Optional[Any] = None,
    ) -> OperationalAction:
        """
        Determines next recommended ControlPlaneAction with clear rationale and evidence.
        """
        dec_dict = decision_result.to_dict() if hasattr(decision_result, "to_dict") else (decision_result or {})

        # 1. Governance / Policy Block
        if summary.governance_status in ["DENY", "BLOCK_RELEASE"] or summary.critical_findings > 0:
            target_f = next((i for i in state.active_issues if i.severity == "CRITICAL"), None)
            fid = target_f.issue_id if target_f else None
            fpath = target_f.file if target_f else None

            return OperationalAction(
                action=ControlPlaneAction.BLOCK_RELEASE,
                target_finding_id=fid,
                target_file=fpath,
                reason="Governance policy mandates release block due to active CRITICAL vulnerability or policy denial.",
                evidence=[
                    f"Governance status: {summary.governance_status}",
                    f"Critical findings count: {summary.critical_findings}",
                    f"Release status: {summary.release_status}",
                ],
                risk_level="CRITICAL",
                governance_decision="DENY",
            )

        # 2. Pending Human Approval
        if len(state.pending_approvals) > 0 or summary.pending_approvals > 0 or dec_dict.get("overall_decision") == "HUMAN_REVIEW":
            app = state.pending_approvals[0] if state.pending_approvals else None
            return OperationalAction(
                action=ControlPlaneAction.REQUEST_APPROVAL,
                target_finding_id=app.finding_id if app else None,
                reason="Autonomous patch generated or decision orchestrator flagged human review required.",
                evidence=[f"Pending approval request / decision: {app.request_id if app else 'HUMAN_REVIEW'}"],
                risk_level="HIGH",
                governance_decision="REVIEW_REQUIRED",
            )

        # 3. Approved Repair -> Apply Approved Repair
        approved_items = [a for a in state.pending_approvals if getattr(a, "status", "") == "APPROVED"]
        if approved_items:
            app = approved_items[0]
            return OperationalAction(
                action=ControlPlaneAction.APPLY_APPROVED_REPAIR,
                target_finding_id=app.finding_id,
                reason="Security patch approved by human authority; ready to apply in sandbox.",
                evidence=[f"Approved request: {app.request_id}"],
                risk_level="MEDIUM",
                governance_decision="ALLOW",
            )

        # 4. Failed Repair -> Investigate
        if summary.failed_repairs > 0:
            return OperationalAction(
                action=ControlPlaneAction.INVESTIGATE,
                reason="Patch validation failed during sandbox regression testing; re-investigation required.",
                evidence=[f"Failed repairs count: {summary.failed_repairs}"],
                risk_level="HIGH",
                governance_decision="REVIEW_REQUIRED",
            )

        # 5. Pending Remediation Queue -> Generate Repair
        if summary.pending_repairs > 0 or summary.high_findings > 0:
            target_f = next((i for i in state.active_issues if i.severity == "HIGH" or i.priority in ["P0", "P1"]), None)
            fid = target_f.issue_id if target_f else None
            fpath = target_f.file if target_f else None

            return OperationalAction(
                action=ControlPlaneAction.GENERATE_REPAIR,
                target_finding_id=fid,
                target_file=fpath,
                reason="Unpatched HIGH/P1 vulnerability queued for autonomous remediation patch generation.",
                evidence=[f"Pending repair queue items: {summary.pending_repairs}"],
                risk_level="HIGH",
                governance_decision="ALLOW",
            )

        # 6. Validated Repair -> Rescan
        if summary.validated_repairs > 0:
            return OperationalAction(
                action=ControlPlaneAction.RESCAN,
                reason="Repair successfully validated in sandbox; verification rescan recommended.",
                evidence=[f"Validated repairs count: {summary.validated_repairs}"],
                risk_level="LOW",
                governance_decision="ALLOW",
            )

        # 7. Low / Medium Drift -> Monitor
        if summary.drift_score > 0 or summary.medium_findings > 0 or summary.low_findings > 0:
            return OperationalAction(
                action=ControlPlaneAction.MONITOR,
                reason="Minor security findings or drift observed; active monitoring active.",
                evidence=[f"Drift score: {summary.drift_score}"],
                risk_level="LOW",
                governance_decision="ALLOW",
            )

        # 8. Clean Repository -> Release Allowed
        return OperationalAction(
            action=ControlPlaneAction.RELEASE_ALLOWED,
            reason="Zero active security vulnerabilities, drift, or unpatched risks detected. Repository clear for release.",
            evidence=["Security score: 100", "Critical/High findings: 0", "Governance status: ALLOW"],
            risk_level="NONE",
            governance_decision="ALLOW",
        )
