"""
M17 Fix Ordering Engine.

Orders remediation items deterministically incorporating priority tier, exploitability,
internet exposure, authentication status, blast radius, attack-path position, historical recurrence,
shared-file dependencies, and expected risk reduction.
"""

from typing import List, Dict, Any
from agentos_swe.remediation.models import RemediationItem, RemediationStatus


class FixOrderingEngine:
    """
    Deterministic Fix Sequencing Engine.
    """

    def order_remediation_items(self, items: List[RemediationItem]) -> List[RemediationItem]:
        """
        Sorts remediation items by multi-factor score and dependency sequence.
        """
        def calculate_ordering_score(item: RemediationItem) -> float:
            score = float(item.priority_score)

            # Priority tier weight
            tier_weights = {"P0": 100, "P1": 80, "P2": 60, "P3": 40, "P4": 20}
            score += tier_weights.get(item.priority_tier, 30)

            # Unauthenticated Internet exposure bonus
            if "UNAUTHENTICATED" in str(item.evidence_summary.get("auth_status", "")).upper() or "INTERNET" in str(item.evidence_summary.get("entrypoint_type", "")).upper():
                score += 30

            # Reopened / Recurring vulnerability bonus
            if "REOPENED" in str(item.evidence_summary.get("recurrence", "")).upper() or "RECURRING" in str(item.evidence_summary.get("recurrence", "")).upper():
                score += 20

            # Grouped findings bonus (higher ROI fixes come earlier)
            score += len(item.affected_finding_ids) * 5 + len(item.affected_attack_path_ids) * 5

            # Deduct for conflicts / unvalidated dependencies so prerequisites run first
            if item.dependencies:
                score -= 15
            if item.governance_status == RemediationStatus.CONFLICT:
                score -= 50

            return score

        # Primary sort by ordering score descending
        sorted_items = sorted(items, key=calculate_ordering_score, reverse=True)

        # Topological sorting adjustment for explicit dependencies
        ordered: List[RemediationItem] = []
        visited = set()

        def visit(item: RemediationItem):
            if item.item_id in visited:
                return
            # Visit prerequisites first
            for dep_id in item.dependencies:
                dep_item = next((it for it in items if it.item_id == dep_id), None)
                if dep_item and dep_item.item_id not in visited:
                    visit(dep_item)
            visited.add(item.item_id)
            ordered.append(item)

        for item in sorted_items:
            visit(item)

        return ordered
