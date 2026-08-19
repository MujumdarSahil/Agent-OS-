"""
Resource limits and execution metrics for M6 Production Hardening.
"""

from dataclasses import dataclass, field, asdict
from typing import Dict, Any, Optional


@dataclass
class ResourceLimits:
    """Configurable resource boundaries for sandbox execution."""
    max_execution_time_sec: float = 15.0
    max_memory_mb: float = 512.0
    max_output_size_bytes: int = 1024 * 1024  # 1 MB
    max_repository_size_mb: float = 500.0
    max_patch_size_bytes: int = 100 * 1024    # 100 KB
    max_repair_attempts: int = 2
    network_allowed: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ExecutionMetrics:
    """Structured execution telemetry metrics for M7 observability."""
    execution_time_sec: float = 0.0
    output_size_bytes: int = 0
    resource_limits_exceeded: bool = False
    network_accessed: bool = False
    commands_executed: int = 0
    exit_code: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
