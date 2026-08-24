"""
SecuritySimulationEngine facade coordinating safety gate, reachability, scenario generation,
executor, and differential repair analysis.
"""

from typing import List, Dict, Any, Optional
from agentos_swe.remediation.simulation.models import (
    SimulationStatus,
    SimulationScenario,
    ExecutionTrace,
    SimulationResult,
    ReachabilityResult,
    SimulationDifferentialResult,
)
from agentos_swe.remediation.simulation.safety import SimulationSafetyGate
from agentos_swe.remediation.simulation.reachability import SimulationReachabilityAnalyzer
from agentos_swe.remediation.simulation.scenarios import SecurityScenarioGenerator
from agentos_swe.remediation.simulation.executor import SecuritySimulationExecutor
from agentos_swe.remediation.simulation.evidence import SimulationEvidenceBuilder
from agentos_swe.remediation.simulation.differential import SimulationDifferentialAnalyzer


class SecuritySimulationEngine:
    """
    Main Security Simulation Facade coordinating safety, reachability, scenario generation,
    executor, and differential repair analysis.
    """

    def __init__(self):
        self.safety_gate = SimulationSafetyGate()
        self.reachability_analyzer = SimulationReachabilityAnalyzer()
        self.scenario_generator = SecurityScenarioGenerator()
        self.executor = SecuritySimulationExecutor()
        self.evidence_builder = SimulationEvidenceBuilder()
        self.differential_analyzer = SimulationDifferentialAnalyzer()

    def run_simulation_pipeline(
        self,
        verified_findings: Optional[List[Any]] = None,
        prioritized_findings: Optional[List[Any]] = None,
        attack_paths: Optional[List[Any]] = None,
        repair_validations: Optional[List[Any]] = None,
        repository_name: str = "Unknown Repo",
    ) -> Dict[str, Any]:
        """
        Executes safe simulation pipeline for findings and attack paths.
        """
        findings = [f.to_dict() if hasattr(f, "to_dict") else f for f in (prioritized_findings or verified_findings or [])]
        paths = [ap.to_dict() if hasattr(ap, "to_dict") else ap for ap in (attack_paths or [])]
        validations = [rv.to_dict() if hasattr(rv, "to_dict") else rv for rv in (repair_validations or [])]

        results: List[SimulationResult] = []
        scenarios: List[SimulationScenario] = []
        differentials: List[SimulationDifferentialResult] = []
        reachability_results: List[ReachabilityResult] = []

        # Process top findings
        for f in findings[:5]:
            # 1. Reachability Check
            reach = self.reachability_analyzer.analyze_reachability(f)
            reachability_results.append(reach)

            if not reach.reachable:
                # Construct non-reproduced result
                res = SimulationResult(
                    scenario_id=f"scen_{f.get('finding_id', '1')}",
                    status=SimulationStatus.NOT_REPRODUCED,
                    reproduced=False,
                    blocked=True,
                    security_impact="NONE",
                    traces=[ExecutionTrace(event="SIMULATION_BLOCKED", details=f"Vulnerability not reachable: {reach.blocked_at}")],
                )
                results.append(res)
                continue

            # 2. Scenario Generation
            match_path = next((ap for ap in paths if ap.get("root_cause") == f.get("root_cause")), None)
            scen = self.scenario_generator.generate_scenario(f, match_path)
            scenarios.append(scen)

            # 3. Sandbox Execution
            sim_res = self.executor.execute_simulation(scen)
            results.append(sim_res)

            # 4. Repair Differential Check (if validations exist)
            match_val = next((val for val in validations if val.get("finding_id") == f.get("finding_id")), None)
            if match_val:
                after_res = SimulationResult(
                    scenario_id=scen.scenario_id,
                    status=SimulationStatus.NOT_REPRODUCED if match_val.get("final_verdict") == "REPAIRED" else SimulationStatus.REPRODUCED,
                    reproduced=match_val.get("final_verdict") != "REPAIRED",
                    blocked=match_val.get("final_verdict") == "REPAIRED",
                    security_impact="NONE" if match_val.get("final_verdict") == "REPAIRED" else "HIGH",
                )
                diff = self.differential_analyzer.analyze_differential(f.get("finding_id", "1"), sim_res, after_res)
                differentials.append(diff)

        # Overall Status
        reproduced_count = sum(1 for r in results if r.reproduced)
        overall_status = "REPRODUCED" if reproduced_count > 0 else "NOT_REPRODUCED"

        return {
            "overall_status": overall_status,
            "reproduced_count": reproduced_count,
            "results": [r.to_dict() for r in results],
            "scenarios": [s.to_dict() for s in scenarios],
            "differentials": [d.to_dict() for d in differentials],
            "reachability_results": [r.to_dict() for r in reachability_results],
        }
