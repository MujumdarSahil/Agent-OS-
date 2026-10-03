"""
M28 Monitoring Job Result Model.

Encapsulates execution outcomes of continuous security monitoring jobs.
"""

from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field, asdict
from datetime import datetime


@dataclass
class MonitoringJobResult:
    """Result of a continuous security monitoring execution job."""
    repository_name: str
    status: str  # NO_CHANGE, SCAN_SUCCESS, SCAN_FAILED
    current_commit: str
    previous_commit: Optional[str] = None
    change_detected: bool = False
    security_score: int = 100
    health_score: float = 100.0
    risk_score: float = 0.0
    drift_score: float = 0.0
    governance_status: str = "ALLOW"
    recommended_action: str = "RELEASE_ALLOWED"
    events_generated: List[Dict[str, Any]] = field(default_factory=list)
    error: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
