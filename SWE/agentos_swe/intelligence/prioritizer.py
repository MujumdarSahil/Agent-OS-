"""
M15 Security Priority Engine.

Calculates deterministic, explainable priority scores (0 - 100) and priority tiers (P0–P4)
for confirmed findings using documented evidence weights.
"""

from typing import List, Dict, Any, Optional
from agentos_swe.intelligence.models import (
    PrioritizedFinding,
    PriorityTier,
    ExploitabilityLevel,
    ExposureLevel,
    BlastRadiusLevel,
    RecurrenceLevel,
)
from agentos_swe.intelligence.exploitability import ExploitabilityAnalyzer
from agentos_swe.intelligence.exposure import ExposureAnalyzer
from agentos_swe.intelligence.blast_radius import BlastRadiusAnalyzer
from agentos_swe.intelligence.recurrence import HistoricalRecurrenceAnalyzer
from agentos_swe.intelligence.recommendation import SecurityRecommendationEngine


class SecurityPriorityEngine:
    """
    Deterministic Security Priority Engine prioritizing findings by risk & exploitability.
    """

    def __init__(self):
        self.exploitability_analyzer = ExploitabilityAnalyzer()
        self.exposure_analyzer = ExposureAnalyzer()
        self.blast_radius_analyzer = BlastRadiusAnalyzer()
        self.recurrence_analyzer = HistoricalRecurrenceAnalyzer()
        self.recommendation_engine = SecurityRecommendationEngine()

    def prioritize_findings(
        self,
        findings: List[Dict[str, Any]],
        historical_comparison: Optional[Any] = None,
        context: Optional[Any] = None,
        taint_findings: Optional[List[Dict[str, Any]]] = None,
    ) -> List[PrioritizedFinding]:
        """
        Calculates priority score (0 - 100), tier (P0-P4), rank (#1, #2...), and remediation guidance.
        """
        prioritized = []
        taint_findings = taint_findings or []

        for idx, f in enumerate(findings):
            fid = f.get("finding_id") or f.get("id") or f"f_{idx+1}"
            sev = str(f.get("severity") or "MEDIUM").upper()
            rc = str(f.get("root_cause") or f.get("category") or "UNKNOWN").upper()
            conf = float(f.get("confidence") or 0.85)

            # Match taint finding if available
            matching_taint = next((t for t in taint_findings if t.get("finding_id") == fid), None)

            # Run analyzer sub-engines
            exploitability = self.exploitability_analyzer.analyze_exploitability(f, matching_taint)
            code_ctx = str(f.get("code_context") or f.get("title") or "")
            exposure = self.exposure_analyzer.analyze_exposure(f, code_ctx)
            blast_radius = self.blast_radius_analyzer.analyze_blast_radius(f, context)
            recurrence = self.recurrence_analyzer.analyze_recurrence(f, historical_comparison)

            # Calculate deterministic score breakdown
            breakdown = {}

            # 1. Severity contribution
            sev_weights = {"CRITICAL": 25, "HIGH": 20, "MEDIUM": 10, "LOW": 5}
            breakdown["severity_contribution"] = sev_weights.get(sev, 10)

            # 2. Exploitability contribution
            exp_weights = {
                ExploitabilityLevel.CRITICAL: 25,
                ExploitabilityLevel.HIGH: 20,
                ExploitabilityLevel.MEDIUM: 10,
                ExploitabilityLevel.LOW: 5,
                ExploitabilityLevel.NOT_EXPLOITABLE: 0,
            }
            breakdown["exploitability_contribution"] = exp_weights.get(exploitability, 10)

            # 3. Exposure contribution
            expo_weights = {
                ExposureLevel.INTERNET_EXPOSED: 20,
                ExposureLevel.USER_CONTROLLED: 15,
                ExposureLevel.INTERNAL: 5,
                ExposureLevel.UNKNOWN: 5,
            }
            breakdown["exposure_contribution"] = expo_weights.get(exposure, 5)

            # 4. Sink danger contribution
            if rc in ("COMMAND_INJECTION", "CODE_INJECTION", "SQL_INJECTION"):
                breakdown["sink_danger_contribution"] = 20
            elif rc in ("SSRF", "PATH_TRAVERSAL", "UNSAFE_DESERIALIZATION"):
                breakdown["sink_danger_contribution"] = 15
            else:
                breakdown["sink_danger_contribution"] = 5

            # 5. Recurrence contribution
            rec_weights = {
                RecurrenceLevel.REOPENED: 10,
                RecurrenceLevel.RECURRING: 5,
                RecurrenceLevel.REGRESSION: 10,
                RecurrenceLevel.FIRST_SEEN: 5,
            }
            breakdown["recurrence_contribution"] = rec_weights.get(recurrence, 5)

            # 6. Blast radius contribution
            blast_weights = {
                BlastRadiusLevel.SYSTEM_WIDE: 10,
                BlastRadiusLevel.BROAD: 5,
                BlastRadiusLevel.LIMITED: 2,
                BlastRadiusLevel.LOCAL: 0,
            }
            breakdown["blast_radius_contribution"] = blast_weights.get(blast_radius, 0)

            raw_score = sum(breakdown.values())

            # Special Override: NOT_EXPLOITABLE or safe lookup caps score at 35
            if exploitability == ExploitabilityLevel.NOT_EXPLOITABLE or rc == "DICT_LOOKUP":
                final_score = min(35, raw_score)
            else:
                final_score = int(round(min(100, raw_score) * conf))

            # Assign Priority Tier
            if final_score >= 90:
                tier = PriorityTier.P0
            elif final_score >= 75:
                tier = PriorityTier.P1
            elif final_score >= 60:
                tier = PriorityTier.P2
            elif final_score >= 40:
                tier = PriorityTier.P3
            else:
                tier = PriorityTier.P4

            # Generate recommendation details
            rec_dict = self.recommendation_engine.generate_recommendation(
                finding=f,
                priority_tier=tier,
                priority_score=final_score,
                exploitability=exploitability,
                exposure=exposure,
                blast_radius=blast_radius,
            )

            p_finding = PrioritizedFinding(
                rank=0,  # Assigned after sorting
                finding_id=fid,
                vulnerability_category=f.get("vulnerability_category") or f.get("category") or "security",
                severity=sev,
                priority_score=final_score,
                priority_tier=tier,
                score_breakdown=breakdown,
                exploitability=exploitability,
                exposure=exposure,
                blast_radius=blast_radius,
                recurrence=recurrence,
                affected_file=f.get("affected_file") or f.get("file") or "N/A",
                affected_function=f.get("affected_function"),
                affected_lines=f.get("affected_lines"),
                root_cause=rc,
                confidence=conf,
                fingerprint=f.get("fingerprint"),
                why_this_matters=rec_dict["why_this_matters"],
                what_to_fix=rec_dict["what_to_fix"],
                why_it_is_prioritized=rec_dict["why_it_is_prioritized"],
                recommended_action=rec_dict["recommended_action"],
                expected_risk_reduction=rec_dict["expected_risk_reduction"],
                repair_strategy=rec_dict["repair_strategy"],
            )
            prioritized.append(p_finding)

        # Sort findings by priority_score descending
        prioritized.sort(key=lambda p: p.priority_score, reverse=True)

        # Assign ranks (#1, #2...)
        for rank_idx, pf in enumerate(prioritized, start=1):
            pf.rank = rank_idx

        return prioritized
