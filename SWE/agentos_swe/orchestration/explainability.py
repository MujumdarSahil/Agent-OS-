"""
M24 Decision Explainability Engine.

Builds step-by-step trace explanations for decisions, policy rule triggers, and confidence models.
"""

from typing import Dict, Any, List
from agentos_swe.orchestration.models import DecisionRecommendation


class DecisionExplainabilityEngine:
    """
    Generates explainable decision traces.
    """

    def generate_trace_explanation(
        self,
        finding: Dict[str, Any],
        recommendation: DecisionRecommendation,
    ) -> List[Dict[str, Any]]:
        """
        Builds a step-by-step decision trace timeline.
        """
        fid = recommendation.finding_id
        rc = str(finding.get("root_cause") or "UNKNOWN").upper()
        act = recommendation.recommended_action.value if hasattr(recommendation.recommended_action, "value") else str(recommendation.recommended_action)

        return [
            {"step": "Evidence Collection", "details": f"Finding '{fid}' evidence collected ({rc})."},
            {"step": "Semantic Classification", "details": f"Root cause classified as '{rc}'."},
            {"step": "Taint Analysis", "details": f"Taint flow {'sanitized' if finding.get('sanitized') else 'active'}."},
            {"step": "Policy Evaluation", "details": f"Rules triggered: {', '.join(recommendation.triggered_rules or ['Default'])}."},
            {"step": "Confidence Scoring", "details": recommendation.confidence.rationale if recommendation.confidence else "N/A"},
            {"step": "Decision Selection", "details": f"Action selected: '{act}' (Governance Effect: {recommendation.governance_effect})."},
        ]
