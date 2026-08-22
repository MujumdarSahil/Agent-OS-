"""
M15 Historical Recurrence Analyzer.

Integrates M14 historical scan store data to classify finding recurrence states
(REOPENED, RECURRING, REGRESSION, LONG_STANDING, FIRST_SEEN, UNCHANGED).
"""

from typing import Dict, Any, Optional, List
from agentos_swe.intelligence.models import RecurrenceLevel


class HistoricalRecurrenceAnalyzer:
    """
    Historical Recurrence Analyzer integrating M14 scan history records.
    """

    def analyze_recurrence(
        self,
        finding: Dict[str, Any],
        historical_comparison: Optional[Any] = None,
    ) -> RecurrenceLevel:
        """
        Calculates RecurrenceLevel from finding metadata and historical comparison.
        """
        state_str = str(finding.get("lifecycle_state") or "").upper()

        if state_str == "REOPENED":
            return RecurrenceLevel.REOPENED

        if historical_comparison:
            reopened_fps = {f.get("fingerprint") for f in getattr(historical_comparison, "reopened_findings", [])}
            current_fp = finding.get("fingerprint")
            if current_fp and current_fp in reopened_fps:
                return RecurrenceLevel.REOPENED

            fixed_fps = {f.get("fingerprint") for f in getattr(historical_comparison, "fixed_findings", [])}
            if current_fp and current_fp in fixed_fps:
                return RecurrenceLevel.UNCHANGED

        if state_str == "UNCHANGED":
            return RecurrenceLevel.UNCHANGED

        if state_str == "NEW":
            return RecurrenceLevel.FIRST_SEEN

        return RecurrenceLevel.FIRST_SEEN
