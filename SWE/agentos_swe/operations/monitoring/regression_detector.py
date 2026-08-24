"""
M18 Security Regression Detector.

Evaluates multi-factor regression rules combining finding severity, exploitability, internet reachability,
authentication boundary weakening, attack path creation, historical recurrence, and remediation plan validity.
"""

from typing import List, Dict, Any, Optional, Tuple
from agentos_swe.operations.monitoring.models import (
    RegressionSeverity,
    AttackPathChange,
    RemediationImpact,
    RemediationPlanStatus,
)


class RegressionDetector:
    """
    Deterministic security regression classification engine.
    """

    def evaluate_regression(
        self,
        new_findings: List[Dict[str, Any]],
        reopened_findings: List[Dict[str, Any]],
        attack_path_changes: List[AttackPathChange],
        remediation_impact: Optional[RemediationImpact],
        score_delta: int,
    ) -> Tuple[RegressionSeverity, str]:
        """
        Determines regression severity level and explanatory summary.
        """
        # 1. Critical Regression Triggers
        has_new_critical = any(
            str(f.get("severity") or "").upper() == "CRITICAL" or str(f.get("priority_tier") or "") in ("P0", "PriorityTier.P0")
            for f in new_findings
        )
        has_reopened = len(reopened_findings) > 0
        has_new_attack_path = any(
            c.change_type.value == "NEW_ATTACK_PATH" if hasattr(c.change_type, "value") else str(c.change_type) == "NEW_ATTACK_PATH"
            for c in attack_path_changes
        )
        has_auth_weakened = any(c.auth_weakened for c in attack_path_changes)

        if has_new_critical or has_reopened or has_new_attack_path or has_auth_weakened or score_delta <= -20:
            reasons = []
            if has_new_critical:
                reasons.append("New CRITICAL security finding introduced")
            if has_reopened:
                reasons.append(f"{len(reopened_findings)} previously fixed vulnerability re-opened")
            if has_new_attack_path:
                reasons.append("New exploitable autonomous attack path detected")
            if has_auth_weakened:
                reasons.append("Authentication boundary weakened")
            if score_delta <= -20:
                reasons.append(f"Security score dropped significantly ({score_delta} pts)")

            return RegressionSeverity.CRITICAL_REGRESSION, "; ".join(reasons)

        # 2. Significant Regression Triggers
        has_new_high = any(
            str(f.get("severity") or "").upper() == "HIGH" or str(f.get("priority_tier") or "") in ("P1", "PriorityTier.P1")
            for f in new_findings
        )
        has_exposure_increased = any(c.exposure_increased for c in attack_path_changes)

        if has_new_high or has_exposure_increased or score_delta <= -10:
            reasons = []
            if has_new_high:
                reasons.append("New HIGH severity finding introduced")
            if has_exposure_increased:
                reasons.append("Entrypoint internet exposure scope increased")
            if score_delta <= -10:
                reasons.append(f"Security score dropped ({score_delta} pts)")

            return RegressionSeverity.SIGNIFICANT_REGRESSION, "; ".join(reasons)

        # 3. Minor Regression Triggers
        has_new_medium = any(
            str(f.get("severity") or "").upper() == "MEDIUM" or str(f.get("priority_tier") or "") in ("P2", "PriorityTier.P2")
            for f in new_findings
        )
        remediation_invalidated = (
            remediation_impact is not None and remediation_impact.status == RemediationPlanStatus.REQUIRES_REPLAN
        )

        if has_new_medium or remediation_invalidated or score_delta < 0:
            reasons = []
            if has_new_medium:
                reasons.append("New MEDIUM severity finding introduced")
            if remediation_invalidated:
                reasons.append("Active remediation plan invalidated by code modifications")
            if score_delta < 0:
                reasons.append(f"Security score dropped slightly ({score_delta} pts)")

            return RegressionSeverity.MINOR_REGRESSION, "; ".join(reasons)

        # 4. No Regression
        return RegressionSeverity.NO_REGRESSION, "Zero security regressions detected across recent code changes."
