"""
M17 Effort Estimator.

Categorizes engineering effort into TRIVIAL, SMALL, MEDIUM, LARGE, COMPLEX
based on affected files, symbols, dependencies, API surface impact, and validation scope.
"""

from typing import List, Dict, Any
from agentos_swe.remediation.models import EffortCategory, RemediationItem


class EffortEstimator:
    """
    Deterministic effort estimation engine.
    """

    def estimate_item_effort(self, item: RemediationItem, is_public_api: bool = False) -> EffortCategory:
        """
        Calculates EffortCategory for an individual RemediationItem.
        """
        file_count = len(item.affected_files)
        symbol_count = len(item.affected_symbols)
        dep_count = len(item.dependencies)

        # Public API / architectural changes are COMPLEX or LARGE
        if is_public_api or "PUBLIC_API" in item.validation_requirements or "API_BREAK" in item.recommended_fix:
            return EffortCategory.COMPLEX if dep_count > 0 or file_count > 2 else EffortCategory.LARGE

        if file_count >= 4 or symbol_count >= 5 or dep_count >= 2:
            return EffortCategory.LARGE
        elif file_count >= 2 or symbol_count >= 3 or dep_count >= 1:
            return EffortCategory.MEDIUM
        elif file_count == 1 and (symbol_count <= 2 or "REPLACE_SHELL" in item.repair_strategy):
            return EffortCategory.SMALL
        elif file_count <= 1 and symbol_count <= 1 and dep_count == 0:
            return EffortCategory.TRIVIAL
        
        return EffortCategory.SMALL

    def calculate_total_effort(self, items: List[RemediationItem]) -> EffortCategory:
        """
        Calculates cumulative effort category for the entire RemediationPlan.
        """
        if not items:
            return EffortCategory.TRIVIAL

        efforts = [item.effort for item in items]
        if EffortCategory.COMPLEX in efforts:
            return EffortCategory.COMPLEX
        elif efforts.count(EffortCategory.LARGE) >= 1 or efforts.count(EffortCategory.MEDIUM) >= 3:
            return EffortCategory.LARGE
        elif efforts.count(EffortCategory.MEDIUM) >= 1 or len(items) >= 3:
            return EffortCategory.MEDIUM
        elif efforts.count(EffortCategory.SMALL) >= 1 or len(items) >= 2:
            return EffortCategory.SMALL
        else:
            return EffortCategory.TRIVIAL
