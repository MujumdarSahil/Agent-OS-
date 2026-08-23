"""
M26 Security Drift Impact Scorer.

Computes a deterministic 0-100 drift impact score and maps severity and directionality.
"""

from typing import List, Dict, Any

from agentos_swe.drift.models import (
    DriftImpact,
    DriftSeverity,
    DriftDirection,
    SecurityDriftEvent,
    DriftType,
)


class SecurityDriftScorer:
    """
    Computes quantitative drift impact scores and directionality deterministically.
    """

    def compute_drift_impact(
        self,
        events: List[SecurityDriftEvent],
        score_delta: int = 0,
        new_findings_count: int = 0,
        fixed_findings_count: int = 0,
        reopened_findings_count: int = 0,
    ) -> DriftImpact:
        """
        Calculates DriftImpact score, severity rating, direction, and explainable rationale.
        """
        if not events and score_delta == 0:
            return DriftImpact(
                drift_score=0.0,
                severity=DriftSeverity.NONE,
                direction=DriftDirection.STABLE,
                security_score_delta=0,
                risk_multiplier_delta=0.0,
                new_findings_count=0,
                fixed_findings_count=0,
                reopened_findings_count=0,
                rationale="NO_DRIFT: Zero security posture changes or drift events detected.",
            )

        crit_count = sum(1 for e in events if e.severity == DriftSeverity.CRITICAL)
        high_count = sum(1 for e in events if e.severity == DriftSeverity.HIGH)
        med_count = sum(1 for e in events if e.severity == DriftSeverity.MEDIUM)

        improvement_events = sum(
            1 for e in events
            if e.drift_type in [DriftType.FIXED_VULNERABILITY, DriftType.REMOVED_ATTACK_PATH, DriftType.SECURITY_SCORE_IMPROVEMENT, DriftType.REMOVED_INTERNET_EXPOSURE]
        )

        # Base drift score calculation (0 - 100)
        raw_score = (
            (crit_count * 35.0) +
            (high_count * 20.0) +
            (med_count * 10.0) +
            (reopened_findings_count * 25.0) +
            (max(abs(score_delta), 0) if score_delta < 0 else 0) * 1.5
        )

        drift_score = min(round(raw_score, 2), 100.0)

        # Determine Severity and Direction
        if crit_count > 0 or drift_score >= 70.0 or score_delta <= -20:
            severity = DriftSeverity.CRITICAL
            direction = DriftDirection.SEVERE_DEGRADATION
        elif high_count > 0 or drift_score >= 40.0 or score_delta <= -10:
            severity = DriftSeverity.HIGH
            direction = DriftDirection.DEGRADATION
        elif med_count > 0 or drift_score >= 15.0 or score_delta < 0:
            severity = DriftSeverity.MEDIUM
            direction = DriftDirection.DEGRADATION
        elif improvement_events > 0 or score_delta > 0:
            severity = DriftSeverity.LOW
            direction = DriftDirection.IMPROVEMENT
        else:
            severity = DriftSeverity.LOW
            direction = DriftDirection.STABLE

        rationale = (
            f"Drift Score {drift_score}/100 ({severity.value}): "
            f"{crit_count} Critical, {high_count} High, {med_count} Medium drift events. "
            f"Score Delta: {score_delta:+d}, Reopened: {reopened_findings_count}."
        )

        return DriftImpact(
            drift_score=drift_score,
            severity=severity,
            direction=direction,
            security_score_delta=score_delta,
            risk_multiplier_delta=round((crit_count * 0.3) + (high_count * 0.15), 2),
            new_findings_count=new_findings_count,
            fixed_findings_count=fixed_findings_count,
            reopened_findings_count=reopened_findings_count,
            rationale=rationale,
        )
