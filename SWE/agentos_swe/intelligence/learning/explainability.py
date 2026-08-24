"""
M25 Learning Explainability Engine.

Generates transparent, audit-ready human-readable explanations for all historical pattern
detections, security posture trends, recurrence classifications, and risk adaptation signals.
"""

from typing import List, Dict, Any, Optional

from agentos_swe.intelligence.learning.models import (
    LearningExplainabilityReport,
    SecurityPattern,
    SecurityTrend,
    FindingRecurrence,
    RemediationLearningRecord,
    AdaptiveRiskSignal,
)


class LearningExplainabilityEngine:
    """
    Generates deterministic explainability reports for M25 continuous security learning outputs.
    """

    def generate_explainability_report(
        self,
        repository_name: str,
        detected_patterns: List[SecurityPattern],
        trend: Optional[SecurityTrend],
        recurrence_insights: List[FindingRecurrence],
        remediation_lessons: List[RemediationLearningRecord],
        adaptive_signals: List[AdaptiveRiskSignal],
    ) -> LearningExplainabilityReport:
        """
        Synthesizes M25 sub-component metrics into a comprehensive explainability report.
        """
        details: List[str] = []

        # 1. Trend Summary
        if trend:
            t_val = trend.trend.value if hasattr(trend.trend, "value") else str(trend.trend)
            details.append(
                f"Security Posture Trend for '{repository_name}': {t_val} "
                f"(Current: {trend.current_score}, Previous: {trend.previous_score or 'N/A'}, Delta: {trend.score_delta:+d}, Volatility: {trend.volatility})."
            )

        # 2. Pattern Detections
        if detected_patterns:
            details.append(f"Detected {len(detected_patterns)} security patterns across repository scan history:")
            for p in detected_patterns:
                p_type = p.pattern_type.value if hasattr(p.pattern_type, "value") else str(p.pattern_type)
                details.append(f"  - [{p_type}] {p.title}: {p.description}")
        else:
            details.append("No recurring or adverse security patterns detected in repository history.")

        # 3. Recurrence Insights
        chronic = [r for r in recurrence_insights if r.classification.value == "CHRONIC"]
        persistent = [r for r in recurrence_insights if r.classification.value == "PERSISTENT"]
        if chronic or persistent:
            details.append(f"Vulnerability Recurrence Warnings: {len(chronic)} Chronic and {len(persistent)} Persistent findings identified.")
            for r in chronic + persistent:
                details.append(f"  - Fingerprint '{r.fingerprint[:12]}' ({r.root_cause}) classified as {r.classification.value} (recurred {r.recurrence_count}x, reopened {r.reopen_count}x).")

        # 4. Remediation Lessons
        if remediation_lessons:
            details.append(f"Remediation Strategy Lessons Learned ({len(remediation_lessons)} records):")
            for rl in remediation_lessons:
                status_str = rl.status.value if hasattr(rl.status, "value") else str(rl.status)
                details.append(f"  - Strategy '{rl.repair_strategy}' for '{rl.root_cause}': Status={status_str}, Success Rate={int(rl.success_rate * 100)}% ({rl.successful_repairs} pass, {rl.failed_repairs} fail, {rl.regressions} regressions).")

        # 5. Adaptive Risk Signals
        boosted = [s for s in adaptive_signals if s.priority_boost]
        if boosted:
            details.append(f"Adaptive Risk Priority Boosts ({len(boosted)} findings boosted):")
            for s in boosted:
                reasons_str = "; ".join(s.adaptation_reasons)
                details.append(f"  - Finding '{s.finding_id}' ({s.root_cause}): Risk multiplier escalated to {s.risk_multiplier}x ({s.base_risk_score} -> {s.adapted_risk_score}). Reasons: {reasons_str}.")

        summary_text = (
            f"M25 Continuous Security Learning analysis complete for repository '{repository_name}'. "
            f"Evaluated {len(detected_patterns)} patterns, posture trend '{trend.trend.value if trend else 'N/A'}', "
            f"{len(recurrence_insights)} recurrence histories, and {len(adaptive_signals)} adaptive risk signals."
        )

        return LearningExplainabilityReport(
            summary=summary_text,
            detected_patterns=detected_patterns,
            trend=trend,
            recurrence_insights=recurrence_insights,
            remediation_lessons=remediation_lessons,
            adaptive_risk_signals=adaptive_signals,
            explanation_details=details,
        )
