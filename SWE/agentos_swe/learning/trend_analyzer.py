"""
M25 Security Posture Trend Analyzer.

Computes deterministic, mathematical repository security posture trends over scan history.
Tracks score deltas, score statistics, volatility (stddev), and metric directionality.
"""

import math
from typing import List, Dict, Any, Optional

from agentos_swe.learning.models import SecurityTrend, TrendDirection
from agentos_swe.history.models import ScanRecord


class SecurityTrendAnalyzer:
    """
    Analyzes repository security score history and vulnerability counts deterministically.
    """

    def analyze_trends(
        self,
        historical_scans: List[ScanRecord],
        current_score: int = 100,
        current_findings: Optional[List[Dict[str, Any]]] = None,
    ) -> SecurityTrend:
        """
        Calculates repository trend analysis metrics over historical scans and current scan.
        """
        if not historical_scans:
            return SecurityTrend(
                current_score=current_score,
                previous_score=None,
                score_delta=0,
                average_score=float(current_score),
                minimum_score=current_score,
                maximum_score=current_score,
                trend=TrendDirection.INSUFFICIENT_DATA,
                volatility=0.0,
                critical_count_trend="STABLE",
                high_count_trend="STABLE",
                reopened_trend="STABLE",
                recurrence_trend="STABLE",
            )

        # Scans from store are ordered descending (most recent first)
        all_scores = [current_score] + [s.security_score for s in historical_scans if hasattr(s, "security_score")]
        previous_score = historical_scans[0].security_score if historical_scans else current_score
        score_delta = current_score - previous_score

        avg_score = round(sum(all_scores) / len(all_scores), 2)
        min_score = min(all_scores)
        max_score = max(all_scores)

        # Calculate score volatility (sample standard deviation)
        if len(all_scores) > 1:
            variance = sum((x - avg_score) ** 2 for x in all_scores) / len(all_scores)
            volatility = round(math.sqrt(variance), 2)
        else:
            volatility = 0.0

        # Determine trend direction
        if len(all_scores) < 2:
            trend_dir = TrendDirection.INSUFFICIENT_DATA
        elif score_delta >= 15:
            trend_dir = TrendDirection.RAPIDLY_IMPROVING
        elif score_delta > 0:
            trend_dir = TrendDirection.IMPROVING
        elif score_delta == 0:
            trend_dir = TrendDirection.STABLE
        elif score_delta <= -15:
            trend_dir = TrendDirection.RAPIDLY_DEGRADING
        else:
            trend_dir = TrendDirection.DEGRADING

        # Vulnerability count trends (comparing current vs baseline scan)
        curr_crit = sum(1 for f in (current_findings or []) if (f.get("severity") or "").upper() == "CRITICAL")
        curr_high = sum(1 for f in (current_findings or []) if (f.get("severity") or "").upper() == "HIGH")

        prev_scan_findings = getattr(historical_scans[0], "findings", []) or getattr(historical_scans[0], "prioritized_findings", []) or []
        prev_crit = sum(1 for f in prev_scan_findings if (f.get("severity") or "").upper() == "CRITICAL")
        prev_high = sum(1 for f in prev_scan_findings if (f.get("severity") or "").upper() == "HIGH")

        crit_trend = "INCREASING" if curr_crit > prev_crit else ("DECREASING" if curr_crit < prev_crit else "STABLE")
        high_trend = "INCREASING" if curr_high > prev_high else ("DECREASING" if curr_high < prev_high else "STABLE")

        return SecurityTrend(
            current_score=current_score,
            previous_score=previous_score,
            score_delta=score_delta,
            average_score=avg_score,
            minimum_score=min_score,
            maximum_score=max_score,
            trend=trend_dir,
            volatility=volatility,
            critical_count_trend=crit_trend,
            high_count_trend=high_trend,
            reopened_trend="STABLE",
            recurrence_trend="STABLE",
        )
