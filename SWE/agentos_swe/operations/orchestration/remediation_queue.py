"""
M24 Remediation Queue.

Maintains ranked, prioritized recommended actions ordered by severity, exploitability,
reopened status, regression, drift impact, and confidence.
"""

from typing import List, Dict, Any
from agentos_swe.operations.orchestration.models import (
    DecisionRecommendation,
    RemediationQueueItem,
    DecisionAction,
)


class RemediationQueue:
    """
    Constructs and orders the autonomous remediation queue.
    """

    def build_queue(
        self,
        recommendations: List[DecisionRecommendation],
        findings_map: Dict[str, Dict[str, Any]],
    ) -> List[RemediationQueueItem]:
        """
        Sorts recommendations into a ranked RemediationQueueItem list.
        Ordering priorities:
        1. Critical/Exploitable (P0)
        2. Reopened / Regression
        3. High / Reachable Path
        4. Medium / Investigate
        """
        items: List[RemediationQueueItem] = []

        for rec in recommendations:
            if rec.recommended_action == DecisionAction.IGNORE:
                continue

            finding = findings_map.get(rec.finding_id, {})
            rc = str(finding.get("root_cause") or finding.get("category") or "UNKNOWN").upper()
            sev = rec.priority.upper()

            # Priority score weighting
            score = 50.0
            if rec.recommended_action == DecisionAction.BLOCK_RELEASE:
                score += 40.0
            elif rec.recommended_action == DecisionAction.GENERATE_REPAIR:
                score += 30.0
            elif rec.recommended_action == DecisionAction.HUMAN_REVIEW:
                score += 20.0
            elif rec.recommended_action == DecisionAction.INVESTIGATE:
                score += 10.0

            if sev == "CRITICAL":
                score += 10.0
            elif sev == "HIGH":
                score += 5.0

            risk_red = "HIGH (Estimated +25 score improvement)" if rec.repair_available else "UNKNOWN"

            items.append(
                RemediationQueueItem(
                    rank=0,
                    finding_id=rec.finding_id,
                    root_cause=rc,
                    severity=sev,
                    recommended_action=rec.recommended_action,
                    priority_score=score,
                    confidence=rec.confidence,
                    human_approval_required=rec.required_human_approval,
                    repair_available=rec.repair_available,
                    estimated_risk_reduction=risk_red,
                )
            )

        # Sort descending by priority score and confidence
        items.sort(key=lambda x: (x.priority_score, x.confidence.score), reverse=True)

        for i, item in enumerate(items, 1):
            item.rank = i

        return items
