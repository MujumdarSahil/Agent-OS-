"""
M17 Dependency Analyzer.

Identifies prerequisite fix relationships between RemediationItems (e.g., input validation helper prior to command execution replacement).
"""

from typing import List, Dict, Any
from agentos_swe.remediation.models import RemediationItem


class DependencyAnalyzer:
    """
    Deterministic Dependency Analyzer mapping prerequisite relationships between items.
    """

    def analyze_dependencies(self, items: List[RemediationItem]) -> Dict[str, List[str]]:
        """
        Populates item.dependencies and returns a dict mapping item_id -> list of prerequisite item_ids.
        """
        dep_map: Dict[str, List[str]] = {item.item_id: [] for item in items}

        # Check for explicit prerequisite types
        # E.g., Helper / Validator creations must precede Sink Replacements
        validator_items = [it for it in items if "VALIDATOR" in it.title or "HELPER" in it.title or "SANITIZER" in it.title]
        sink_items = [it for it in items if it.root_cause in ("COMMAND_INJECTION", "SQL_INJECTION", "CODE_INJECTION")]

        for s_item in sink_items:
            for v_item in validator_items:
                if v_item.item_id != s_item.item_id and any(f in s_item.affected_files for f in v_item.affected_files):
                    if v_item.item_id not in s_item.dependencies:
                        s_item.dependencies.append(v_item.item_id)
                        dep_map[s_item.item_id].append(v_item.item_id)

        return dep_map
