"""
M18 Security Trend Analyzer.

Evaluates security posture trends across historical scan records over time.
"""

from typing import List, Dict, Any
from agentos_swe.monitoring.models import TrendDirection


class TrendAnalyzer:
    """
    Evaluates security posture trajectory over commit history.
    """

    def analyze_trend(
        self,
        historical_snapshots: List[Dict[str, Any]],
        current_score: int,
        score_delta: int,
    ) -> TrendDirection:
        """
        Calculates overall trend direction from historical scan scores.
        """
        if not historical_snapshots:
            if score_delta > 0:
                return TrendDirection.IMPROVING
            elif score_delta < 0:
                return TrendDirection.DEGRADING
            return TrendDirection.STABLE

        scores = [snap.get("security_score", 100) for snap in historical_snapshots]
        scores.append(current_score)

        if len(scores) < 2:
            if score_delta > 0:
                return TrendDirection.IMPROVING
            elif score_delta < 0:
                return TrendDirection.DEGRADING
            return TrendDirection.STABLE

        deltas = [scores[i] - scores[i-1] for i in range(1, len(scores))]

        positive_count = sum(1 for d in deltas if d > 0)
        negative_count = sum(1 for d in deltas if d < 0)

        if negative_count > 0 and positive_count > 0:
            return TrendDirection.VOLATILE
        elif negative_count > 0 or score_delta < 0:
            return TrendDirection.DEGRADING
        elif positive_count > 0 or score_delta > 0:
            return TrendDirection.IMPROVING
        else:
            return TrendDirection.STABLE
