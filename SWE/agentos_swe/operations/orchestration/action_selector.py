"""
M24 Action Selector.

Selects recommended decision actions, maps approval requirements, and constructs
DecisionRecommendation objects.
"""

from typing import Dict, Any, List, Optional
from agentos_swe.operations.orchestration.models import (
    DecisionAction,
    DecisionConfidence,
    DecisionRecommendation,
)


class ActionSelector:
    """
    Constructs DecisionRecommendation objects.
    """

    def select_action(
        self,
        finding: Dict[str, Any],
        action: DecisionAction,
        confidence: DecisionConfidence,
        reasons: List[str],
        triggered_rules: List[str],
    ) -> DecisionRecommendation:
        """
        Builds a DecisionRecommendation instance.
        """
        fid = str(finding.get("finding_id") or finding.get("id") or "f1")
        sev = str(finding.get("severity") or "HIGH").upper()

        req_approval = action in (DecisionAction.GENERATE_REPAIR, DecisionAction.BLOCK_RELEASE, DecisionAction.HUMAN_REVIEW)
        repair_avail = action == DecisionAction.GENERATE_REPAIR or sev in ("CRITICAL", "HIGH")

        gov_effect = "DENY" if action == DecisionAction.BLOCK_RELEASE else ("REVIEW_REQUIRED" if action == DecisionAction.HUMAN_REVIEW else "ALLOW")

        return DecisionRecommendation(
            finding_id=fid,
            recommended_action=action,
            priority=sev,
            confidence=confidence,
            reasons=reasons,
            triggered_rules=triggered_rules,
            required_human_approval=req_approval,
            repair_available=repair_avail,
            governance_effect=gov_effect,
        )
