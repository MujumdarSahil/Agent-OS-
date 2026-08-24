"""
M17 Conflict Detector.

Detects incompatible remediation items targeting the same file or symbol with conflicting fix strategies.
Marking affected items as RemediationStatus.CONFLICT and requiring human review.
"""

from typing import List, Dict, Any
from agentos_swe.remediation.models import RemediationItem, RemediationStatus


class ConflictDetector:
    """
    Deterministic Conflict Detector identifying incompatible fix proposals.
    """

    def detect_conflicts(self, items: List[RemediationItem]) -> List[Dict[str, Any]]:
        """
        Scans items for file/symbol overlap and incompatible repair strategies.
        Returns a list of conflict records.
        """
        conflicts: List[Dict[str, Any]] = []

        for i in range(len(items)):
            for j in range(i + 1, len(items)):
                item_a = items[i]
                item_b = items[j]

                # Check shared files / symbols
                shared_files = set(item_a.affected_files).intersection(set(item_b.affected_files))
                shared_symbols = set(item_a.affected_symbols).intersection(set(item_b.affected_symbols))

                # Conflict if modifying same symbol with different fix strategies or incompatible root causes
                is_conflicting_strategy = (
                    item_a.repair_strategy != item_b.repair_strategy
                    and item_a.root_cause != item_b.root_cause
                )

                if (shared_symbols and is_conflicting_strategy) or (
                    "CONFLICT" in item_a.recommended_fix or "CONFLICT" in item_b.recommended_fix
                ):
                    conflict_record = {
                        "conflict_id": f"conflict_{item_a.item_id}_{item_b.item_id}",
                        "item_a_id": item_a.item_id,
                        "item_b_id": item_b.item_id,
                        "shared_files": list(shared_files),
                        "shared_symbols": list(shared_symbols),
                        "reason": f"Incompatible fix strategies ('{item_a.repair_strategy}' vs '{item_b.repair_strategy}') on shared targets",
                    }
                    conflicts.append(conflict_record)

                    item_a.conflicts.append(item_b.item_id)
                    item_b.conflicts.append(item_a.item_id)
                    item_a.governance_status = RemediationStatus.CONFLICT
                    item_b.governance_status = RemediationStatus.CONFLICT

        return conflicts
