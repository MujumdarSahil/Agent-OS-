"""
M22 Simulation Evidence Builder.

Assembles detailed execution traces and structured evidence records for simulation runs.
"""

from typing import List, Dict, Any
from agentos_swe.simulation.models import SimulationResult, ExecutionTrace


class SimulationEvidenceBuilder:
    """
    Constructs structured evidence packages from simulation results.
    """

    def build_evidence_package(
        self,
        result: SimulationResult,
    ) -> Dict[str, Any]:
        """
        Formats simulation evidence into a clean dictionary payload.
        """
        return {
            "scenario_id": result.scenario_id,
            "status": result.status.value if hasattr(result.status, "value") else str(result.status),
            "reproduced": result.reproduced,
            "blocked": result.blocked,
            "execution_time_sec": result.execution_time,
            "sandbox_id": result.sandbox_id,
            "security_impact": result.security_impact,
            "trace_events": [t.to_dict() for t in result.traces],
            "evidence_items": result.evidence,
        }
