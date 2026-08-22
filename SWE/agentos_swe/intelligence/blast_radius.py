"""
M15 Blast Radius Analyzer.

Estimates the breadth of system impact if a vulnerable function or module is compromised
by analyzing Code Graph callers, dependents, and module dependencies.
"""

from typing import Dict, Any, Optional
from agentos_swe.intelligence.models import BlastRadiusLevel


class BlastRadiusAnalyzer:
    """
    Code Graph Blast Radius Analyzer calculating caller fan-in and dependency spread.
    """

    def analyze_blast_radius(
        self,
        finding: Dict[str, Any],
        context: Optional[Any] = None,
    ) -> BlastRadiusLevel:
        """
        Calculates BlastRadiusLevel from finding metadata and Code Graph context.
        """
        file_path = (finding.get("affected_file") or finding.get("file") or "").lower()
        fn_name = finding.get("affected_function")

        # Test files have LOCAL blast radius
        if "test" in file_path or "conftest" in file_path or "fixture" in file_path:
            return BlastRadiusLevel.LOCAL

        # Query Code Graph for callers if context graph_provider exists
        callers_count = 0
        if context and hasattr(context, "get_callers") and fn_name:
            try:
                callers = context.get_callers(fn_name)
                callers_count = len(callers) if callers else 0
            except Exception:
                callers_count = 0

        # Core utility or base module files have BROAD or SYSTEM_WIDE blast radius
        if "utils" in file_path or "core" in file_path or "base" in file_path or "common" in file_path:
            if callers_count >= 10:
                return BlastRadiusLevel.SYSTEM_WIDE
            return BlastRadiusLevel.BROAD

        if callers_count >= 10:
            return BlastRadiusLevel.SYSTEM_WIDE
        elif callers_count >= 3:
            return BlastRadiusLevel.BROAD
        elif callers_count >= 1:
            return BlastRadiusLevel.LIMITED

        return BlastRadiusLevel.LOCAL
