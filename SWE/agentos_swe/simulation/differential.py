"""
M22 Simulation Differential Analyzer.

Compares BEFORE patch vs AFTER patch simulation outputs to verify attack chain breaking
and ensure zero security regressions or new attack paths.
"""

from typing import Dict, Any, Optional
from agentos_swe.simulation.models import (
    SimulationResult,
    SimulationStatus,
    SimulationDifferentialResult,
)


class SimulationDifferentialAnalyzer:
    """
    Analyzes before/after patch simulation differentials.
    """

    def analyze_differential(
        self,
        finding_id: str,
        before_result: SimulationResult,
        after_result: SimulationResult,
    ) -> SimulationDifferentialResult:
        """
        Calculates differential impact between pre-patch and post-patch simulation results.
        """
        before_st = before_result.status
        after_st = after_result.status

        # 1. Determine attack path impact
        if before_result.reproduced and not after_result.reproduced:
            impact = "ATTACK_PATH_BROKEN"
            repaired = True
            regressed = False
        elif before_result.reproduced and after_result.reproduced:
            impact = "ATTACK_PATH_UNCHANGED"
            repaired = False
            regressed = False
        elif not before_result.reproduced and after_result.reproduced:
            impact = "NEW_ATTACK_PATH_INTRODUCED"
            repaired = False
            regressed = True
        else:
            impact = "ATTACK_PATH_REDUCED"
            repaired = True
            regressed = False

        evidence = [
            f"Pre-patch simulation status: {before_st.value if hasattr(before_st, 'value') else before_st}",
            f"Post-patch simulation status: {after_st.value if hasattr(after_st, 'value') else after_st}",
            f"Attack path differential verdict: {impact}",
        ]

        return SimulationDifferentialResult(
            differential_id=f"diff_{finding_id}",
            finding_id=finding_id,
            before_status=before_st,
            after_status=after_st,
            attack_path_impact=impact,
            repaired=repaired,
            regression_detected=regressed,
            evidence=evidence,
        )
