"""
M14 Security Scoring & Risk Trend Analysis Engine.

Calculates deterministic, explainable internal repository security risk scores (0 - 100),
score deltas, severity weights, and RiskTrend classifications across scans.
"""

from typing import List, Dict, Any, Tuple
from agentos_swe.intelligence.history.models import RiskTrend

SEVERITY_WEIGHTS = {
    "CRITICAL": 25,
    "HIGH": 15,
    "MEDIUM": 5,
    "LOW": 1,
    "INFO": 0,
}


class SecurityScorer:
    """
    Deterministic Security Scoring Engine evaluating repository risk points (0 - 100).
    """

    def calculate_score(self, findings: List[Dict[str, Any]]) -> Tuple[int, Dict[str, int]]:
        """
        Calculates Security Score (0 - 100) and severity counts breakdown.
        Formula: Score = max(0, 100 - sum(count * weight))
        """
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

        for f in findings:
            sev = (f.get("severity") or "MEDIUM").upper()
            if sev in counts:
                counts[sev] += 1
            else:
                counts["MEDIUM"] += 1

        risk_points = sum(counts[s] * SEVERITY_WEIGHTS[s] for s in counts)
        score = max(0, 100 - risk_points)
        return score, counts

    def evaluate_trend(
        self,
        score_before: int,
        score_after: int,
        new_critical_or_high: bool = False,
        reopened_count: int = 0,
    ) -> Tuple[RiskTrend, str]:
        """
        Evaluates RiskTrend (IMPROVING, DEGRADING, STABLE) and explanation.
        """
        delta = score_after - score_before

        if new_critical_or_high or reopened_count > 0 or delta < 0:
            trend = RiskTrend.DEGRADING
            reasons = []
            if delta < 0:
                reasons.append(f"Security score dropped by {abs(delta)} points ({score_before} -> {score_after})")
            if new_critical_or_high:
                reasons.append("New Critical/High severity vulnerability introduced")
            if reopened_count > 0:
                reasons.append(f"{reopened_count} previously fixed vulnerability reopened")
            explanation = " | ".join(reasons)
        elif delta > 0:
            trend = RiskTrend.IMPROVING
            explanation = f"Security score improved by {delta} points ({score_before} -> {score_after})"
        else:
            trend = RiskTrend.STABLE
            explanation = f"Security score unchanged at {score_after}"

        return trend, explanation
