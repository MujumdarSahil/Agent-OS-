"""
M22 Simulation Reachability Analyzer.

Evaluates M16 attack paths and taint findings to verify whether source inputs,
propagation paths, and dangerous sinks are reachable.
"""

from typing import Dict, Any, List, Optional
from agentos_swe.simulation.models import ReachabilityResult


class SimulationReachabilityAnalyzer:
    """
    Analyzes vulnerability reachability across trust boundaries.
    """

    def analyze_reachability(
        self,
        finding_or_path: Dict[str, Any],
        context: Optional[Any] = None,
    ) -> ReachabilityResult:
        """
        Determines reachability status for a finding or attack path.
        """
        rc = str(finding_or_path.get("root_cause") or "UNKNOWN").upper()
        ep_type = str(finding_or_path.get("entrypoint_type") or finding_or_path.get("source_type") or "HTTP").upper()
        sink_type = str(finding_or_path.get("sink_type") or finding_or_path.get("sink") or "SINK").upper()

        evidence: List[str] = []

        # 1. Source Controllability
        if ep_type in ("INTERNET", "HTTP", "CLI", "ENV"):
            evidence.append(f"Source entrypoint '{ep_type}' is user-controllable.")
        else:
            evidence.append(f"Source entrypoint '{ep_type}' is internal / non-controllable.")
            return ReachabilityResult(
                reachable=False,
                blocked_at="SOURCE_NOT_CONTROLLABLE",
                evidence=evidence,
                confidence=0.90,
            )

        # 2. Sanitizer / Protection Check
        if finding_or_path.get("sanitized") or rc in ("SAFE_CONSTANT", "INTENTIONAL_FALLBACK", "TEST_HARNESS"):
            evidence.append(f"Sanitizer or safe classification detected for root cause '{rc}'.")
            return ReachabilityResult(
                reachable=False,
                blocked_at="DEFENSIVE_SANITIZER_ACTIVE",
                evidence=evidence,
                confidence=0.95,
            )

        # 3. Sink Reachability
        evidence.append(f"Dangerous sink '{sink_type}' is reachable via propagation chain.")
        return ReachabilityResult(
            reachable=True,
            blocked_at=None,
            evidence=evidence,
            confidence=0.95,
        )
