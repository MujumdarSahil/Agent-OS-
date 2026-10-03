"""
Domain models for M7 Observability & Evaluation.
Includes TraceEvent, AgentMetrics, FindingMetrics, RepairMetrics, and RunReport.
"""

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
from datetime import datetime


@dataclass
class TraceEvent:
    """Single structured telemetry event in an execution trace."""
    event_id: str
    timestamp: str
    mission_id: str
    stage: str
    agent_name: Optional[str] = None
    provider: Optional[str] = None
    model: Optional[str] = None
    tokens: int = 0
    latency_sec: float = 0.0
    fallback_triggered: bool = False
    fallback_from: Optional[str] = None
    fallback_to: Optional[str] = None
    checkpoint_action: Optional[str] = None
    finding_id: Optional[str] = None
    status: Optional[str] = None
    cost_est: float = 0.0
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AgentMetrics:
    """Execution metrics per agent."""
    agent_name: str
    execution_count: int = 0
    success_count: int = 0
    failure_count: int = 0
    total_duration_sec: float = 0.0
    total_tokens: int = 0
    fallback_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FindingMetrics:
    """Finding lifecycle metrics."""
    total_discovered: int = 0
    confirmed: int = 0
    rejected: int = 0
    inconclusive: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RepairMetrics:
    """Repair pipeline execution metrics."""
    confirmed_findings: int = 0
    patches_generated: int = 0
    reproduction_pass: int = 0
    regression_pass: int = 0
    independent_review_pass: int = 0
    validated_patches: int = 0
    repair_rejected: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RunReport:
    """Summary report for an AgentOS-SWE execution run."""
    repository_name: str
    commit_ref: Optional[str]
    start_time: str
    end_time: str
    total_duration_sec: float
    finding_metrics: FindingMetrics
    repair_metrics: RepairMetrics
    agent_metrics: Dict[str, AgentMetrics]
    fallback_count: int
    checkpoint_recoveries: int
    total_tokens: int
    total_cost_est: float
    trace_events_count: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "repository_name": self.repository_name,
            "commit_ref": self.commit_ref,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "total_duration_sec": self.total_duration_sec,
            "finding_metrics": self.finding_metrics.to_dict(),
            "repair_metrics": self.repair_metrics.to_dict(),
            "agent_metrics": {k: v.to_dict() for k, v in self.agent_metrics.items()},
            "fallback_count": self.fallback_count,
            "checkpoint_recoveries": self.checkpoint_recoveries,
            "total_tokens": self.total_tokens,
            "total_cost_est": self.total_cost_est,
            "trace_events_count": self.trace_events_count,
        }
