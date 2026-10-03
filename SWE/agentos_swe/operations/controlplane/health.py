"""
M27 Security Operations Health Engine.

Computes a 0-100 operational health score with deterministic, explainable risk factors.
"""

from typing import List, Dict, Any, Optional

from agentos_swe.operations.controlplane.models import (
    ControlPlaneHealth,
    OperationalStatus,
    SecurityOperationsSummary,
    RepositoryOperationalState,
)


class SecurityOperationsHealthEngine:
    """
    Computes explainable operational health scores and maps to OperationalStatus.
    """

    def compute_health(
        self,
        summary: SecurityOperationsSummary,
        state: Optional[RepositoryOperationalState] = None,
    ) -> ControlPlaneHealth:
        """
        Calculates 0-100 health score with explicit risk factor breakdowns.
        """
        score = 100.0
        factors: List[str] = []

        # 1. Critical & High Vulnerabilities
        if summary.critical_findings > 0:
            penalty = summary.critical_findings * 30.0
            score -= penalty
            factors.append(f"{summary.critical_findings} Critical vulnerabilities active (-{penalty:.0f} pts).")

        if summary.high_findings > 0:
            penalty = summary.high_findings * 15.0
            score -= penalty
            factors.append(f"{summary.high_findings} High severity vulnerabilities active (-{penalty:.0f} pts).")

        # 2. Priority & Attack Paths
        if summary.p0_findings > 0:
            penalty = summary.p0_findings * 15.0
            score -= penalty
            factors.append(f"{summary.p0_findings} P0 priority issues (-{penalty:.0f} pts).")

        if summary.internet_exposed_paths > 0:
            penalty = summary.internet_exposed_paths * 10.0
            score -= penalty
            factors.append(f"{summary.internet_exposed_paths} Internet-exposed attack paths (-{penalty:.0f} pts).")

        # 3. Security Drift & Recurrence
        if summary.drift_score > 0:
            penalty = summary.drift_score * 0.5
            score -= penalty
            factors.append(f"Security drift score {summary.drift_score:.1f} (-{penalty:.1f} pts).")

        if summary.chronic_vulnerabilities > 0:
            penalty = summary.chronic_vulnerabilities * 15.0
            score -= penalty
            factors.append(f"{summary.chronic_vulnerabilities} Chronic recurring vulnerabilities (-{penalty:.0f} pts).")

        if summary.reopened_vulnerabilities > 0:
            penalty = summary.reopened_vulnerabilities * 10.0
            score -= penalty
            factors.append(f"{summary.reopened_vulnerabilities} Reopened vulnerabilities (-{penalty:.0f} pts).")

        # 4. Governance & Release Blocking
        if summary.governance_status in ["DENY", "BLOCK_RELEASE"]:
            score = min(score, 20.0)
            factors.append("Governance policy mandated RELEASE BLOCK.")

        health_score = max(round(score, 1), 0.0)

        # Map to OperationalStatus
        if summary.governance_status in ["DENY", "BLOCK_RELEASE"]:
            status = OperationalStatus.BLOCKED
            explanation = "Repository operation BLOCKED by security governance policy."
        elif health_score <= 40.0 or summary.critical_findings > 0:
            status = OperationalStatus.CRITICAL
            explanation = "Repository operational health CRITICAL due to severe vulnerability posture."
        elif health_score <= 65.0 or summary.high_findings > 0 or summary.drift_score >= 40.0:
            status = OperationalStatus.DEGRADED
            explanation = "Repository operational health DEGRADED. High severity findings or drift active."
        elif health_score <= 85.0 or summary.medium_findings > 0:
            status = OperationalStatus.AT_RISK
            explanation = "Repository operational health AT_RISK. Medium severity findings present."
        else:
            status = OperationalStatus.HEALTHY
            explanation = "Repository operation HEALTHY. Security posture stable."

        return ControlPlaneHealth(
            health_score=health_score,
            status=status,
            explanation=explanation,
            risk_factors=factors or ["Zero active risk factors."],
        )
