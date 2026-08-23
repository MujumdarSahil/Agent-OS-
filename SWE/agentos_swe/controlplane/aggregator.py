"""
M27 Security Operations Aggregator.

Aggregates multi-milestone intelligence across M14-M26 into a unified SecurityOperationsSummary.
"""

from typing import Dict, Any, Optional

from agentos_swe.controlplane.models import (
    SecurityOperationsSummary,
    OperationalStatus,
    OperationalMode,
    RepositoryOperationalState,
)


class SecurityOperationsAggregator:
    """
    Combines intelligence streams from M14-M26 into one SecurityOperationsSummary.
    """

    def aggregate_summary(
        self,
        repository_name: str,
        commit_sha: str,
        state: RepositoryOperationalState,
        decision_result: Optional[Any] = None,
        learning_result: Optional[Any] = None,
        drift_result: Optional[Any] = None,
    ) -> SecurityOperationsSummary:
        """
        Produces a consolidated SecurityOperationsSummary without inventing metrics.
        """
        snapshot = state.snapshot

        # M25 Learning Signals
        learning_dict = learning_result.to_dict() if hasattr(learning_result, "to_dict") else (learning_result or {})
        recs = learning_dict.get("recurrence_analysis", [])
        reopened_count = sum(1 for r in recs if r.get("reopened_count", 0) > 0)
        recurring_count = sum(1 for r in recs if r.get("classification") in ["RECURRING", "PERSISTENT"])
        chronic_count = sum(1 for r in recs if r.get("classification") == "CHRONIC")

        adaptive_mult = 1.0
        signals = learning_dict.get("adaptive_signals", [])
        if signals:
            adaptive_mult = max([float(s.get("multiplier", 1.0)) for s in signals] + [1.0])

        # M26 Drift Signals
        drift_dict = drift_result.to_dict() if hasattr(drift_result, "to_dict") else (drift_result or {})
        drift_sum = drift_dict.get("summary", {})
        drift_imp = drift_dict.get("impact", {})

        drift_score = float(drift_imp.get("drift_score") or drift_sum.get("drift_score") or 0.0)
        drift_sev = str(drift_sum.get("drift_severity") or drift_imp.get("severity") or "NONE")
        drift_dir = str(drift_sum.get("drift_direction") or drift_imp.get("direction") or "STABLE")

        # M24 Decisions & Governance
        dec_dict = decision_result.to_dict() if hasattr(decision_result, "to_dict") else (decision_result or {})
        gov_status = str(dec_dict.get("overall_decision") or dec_dict.get("final_governance_verdict") or "ALLOW")
        rel_status = "RELEASE_BLOCKED" if gov_status in ["DENY", "BLOCK_RELEASE"] else "RELEASE_ALLOWED"

        # Repairs & Validations
        validations = dec_dict.get("repair_validations", [])
        validated_repairs = sum(1 for v in validations if v.get("final_verdict") in ["CONFIRMED_VALIDATED", "APPROVED"])
        failed_repairs = sum(1 for v in validations if v.get("final_verdict") in ["REJECTED", "FAILED"])
        pending_repairs = len(dec_dict.get("remediation_queue", [])) - validated_repairs - failed_repairs
        pending_repairs = max(pending_repairs, 0)

        # Pending Approvals
        pending_approvals = len(state.pending_approvals)

        return SecurityOperationsSummary(
            repository_name=repository_name,
            commit_sha=commit_sha,
            operational_status=state.operational_status,
            operational_mode=state.operational_mode,
            health_score=state.health.health_score,
            security_score=snapshot.security_score,
            risk_score=snapshot.risk_score,
            critical_findings=snapshot.critical_count,
            high_findings=snapshot.high_count,
            medium_findings=snapshot.medium_count,
            low_findings=snapshot.low_count,
            p0_findings=snapshot.p0_count,
            p1_findings=snapshot.p1_count,
            p2_findings=snapshot.p2_count,
            active_attack_paths=snapshot.active_attack_paths_count,
            internet_exposed_paths=snapshot.internet_exposed_paths_count,
            reopened_vulnerabilities=reopened_count,
            recurring_vulnerabilities=recurring_count,
            chronic_vulnerabilities=chronic_count,
            drift_score=drift_score,
            drift_severity=drift_sev,
            drift_direction=drift_dir,
            adaptive_risk_multiplier=adaptive_mult,
            pending_repairs=pending_repairs,
            validated_repairs=validated_repairs,
            failed_repairs=failed_repairs,
            pending_approvals=pending_approvals,
            governance_status=gov_status,
            release_status=rel_status,
        )
