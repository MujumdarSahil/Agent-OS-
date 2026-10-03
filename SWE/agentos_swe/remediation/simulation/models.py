"""
M22 Safe Security Simulation Models.

Defines domain models, enums, dataclasses, and data structures for simulation scenarios,
results, execution traces, reachability analysis, and before/after repair differentials.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Dict, Any, Optional
from datetime import datetime


class SimulationStatus(str, Enum):
    """Execution status for security reproduction scenarios."""
    REPRODUCED = "REPRODUCED"
    NOT_REPRODUCED = "NOT_REPRODUCED"
    BLOCKED = "BLOCKED"
    PARTIAL = "PARTIAL"
    UNSUPPORTED = "UNSUPPORTED"
    FAILED = "FAILED"


@dataclass
class SimulationScenario:
    """Dataclass defining a safe synthetic reproduction scenario."""
    scenario_id: str
    vulnerability_id: str
    root_cause: str
    source: str
    sink: str
    attack_path: Optional[Dict[str, Any]] = None
    preconditions: List[str] = field(default_factory=list)
    expected_behavior: str = ""
    safety_constraints: List[str] = field(default_factory=list)
    severity: str = "HIGH"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ExecutionTrace:
    """Chronological event trace captured during sandboxed simulation."""
    event: str  # SOURCE_REACHED, VARIABLE_PROPAGATED, SINK_REACHED, SIMULATION_BLOCKED
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    location: str = "N/A"
    details: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SimulationResult:
    """Execution outcome for a security simulation scenario."""
    scenario_id: str
    status: SimulationStatus
    reproduced: bool
    blocked: bool
    partially_reproduced: bool = False
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    execution_time: float = 0.0
    sandbox_id: str = "N/A"
    security_impact: str = "NONE"
    error: Optional[str] = None
    traces: List[ExecutionTrace] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value if isinstance(self.status, Enum) else self.status
        d["traces"] = [t.to_dict() for t in self.traces]
        return d


@dataclass
class ReachabilityResult:
    """Reachability analysis outcome for an attack path."""
    reachable: bool
    blocked_at: Optional[str] = None
    evidence: List[str] = field(default_factory=list)
    confidence: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SimulationDifferentialResult:
    """Before vs After repair simulation differential analysis."""
    differential_id: str
    finding_id: str
    before_status: SimulationStatus
    after_status: SimulationStatus
    attack_path_impact: str  # ATTACK_PATH_BROKEN, ATTACK_PATH_REDUCED, ATTACK_PATH_UNCHANGED, NEW_ATTACK_PATH_INTRODUCED
    repaired: bool
    regression_detected: bool = False
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["before_status"] = self.before_status.value if isinstance(self.before_status, Enum) else self.before_status
        d["after_status"] = self.after_status.value if isinstance(self.after_status, Enum) else self.after_status
        return d
