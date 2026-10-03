"""
M28 Persistent Operations & Monitoring Models.

Strongly typed dataclasses and enums for M28 operational state persistence,
repository registry tracking, security posture snapshots, and monitoring telemetry.
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class MonitoringScheduleInterval(str, Enum):
    MANUAL = "MANUAL"
    HOURLY = "HOURLY"
    EVERY_6_HOURS = "EVERY_6_HOURS"
    DAILY = "DAILY"
    WEEKLY = "WEEKLY"


class RepositoryMonitoringStatus(str, Enum):
    ACTIVE = "ACTIVE"
    PAUSED = "PAUSED"
    STALE = "STALE"
    FAILED = "FAILED"
    UNREGISTERED = "UNREGISTERED"


@dataclass
class RepositoryRegistration:
    """Represents a repository registered for continuous monitoring."""
    repository_name: str
    repository_path_or_url: str
    branch: str = "main"
    monitoring_enabled: bool = True
    scan_interval: str = MonitoringScheduleInterval.DAILY.value
    last_successful_scan: Optional[str] = None
    last_failed_scan: Optional[str] = None
    next_due_timestamp: Optional[str] = None
    current_status: str = RepositoryMonitoringStatus.ACTIVE.value
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "repository_name": self.repository_name,
            "repository_path_or_url": self.repository_path_or_url,
            "branch": self.branch,
            "monitoring_enabled": self.monitoring_enabled,
            "scan_interval": self.scan_interval,
            "last_successful_scan": self.last_successful_scan,
            "last_failed_scan": self.last_failed_scan,
            "next_due_timestamp": self.next_due_timestamp,
            "current_status": self.current_status,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RepositoryRegistration":
        return cls(
            repository_name=data.get("repository_name", "UNKNOWN"),
            repository_path_or_url=data.get("repository_path_or_url", ""),
            branch=data.get("branch", "main"),
            monitoring_enabled=bool(data.get("monitoring_enabled", True)),
            scan_interval=data.get("scan_interval", MonitoringScheduleInterval.DAILY.value),
            last_successful_scan=data.get("last_successful_scan"),
            last_failed_scan=data.get("last_failed_scan"),
            next_due_timestamp=data.get("next_due_timestamp"),
            current_status=data.get("current_status", RepositoryMonitoringStatus.ACTIVE.value),
            created_at=data.get("created_at", datetime.now().isoformat()),
            updated_at=data.get("updated_at", datetime.now().isoformat()),
        )


@dataclass
class SecurityPostureSnapshotRecord:
    """Historical security posture snapshot for differential comparisons across commits."""
    snapshot_id: str
    repository_name: str
    commit_sha: str
    timestamp: str
    security_score: int = 100
    health_score: float = 100.0
    risk_score: float = 0.0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    active_attack_paths: int = 0
    drift_score: float = 0.0
    drift_severity: str = "NONE"
    governance_status: str = "ALLOW"
    recommended_action: str = "RELEASE_ALLOWED"
    raw_data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "snapshot_id": self.snapshot_id,
            "repository_name": self.repository_name,
            "commit_sha": self.commit_sha,
            "timestamp": self.timestamp,
            "security_score": self.security_score,
            "health_score": self.health_score,
            "risk_score": self.risk_score,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "active_attack_paths": self.active_attack_paths,
            "drift_score": self.drift_score,
            "drift_severity": self.drift_severity,
            "governance_status": self.governance_status,
            "recommended_action": self.recommended_action,
            "raw_data": self.raw_data,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SecurityPostureSnapshotRecord":
        return cls(
            snapshot_id=data.get("snapshot_id", "snap_unknown"),
            repository_name=data.get("repository_name", "UNKNOWN"),
            commit_sha=data.get("commit_sha", "HEAD"),
            timestamp=data.get("timestamp", datetime.now().isoformat()),
            security_score=int(data.get("security_score", 100)),
            health_score=float(data.get("health_score", 100.0)),
            risk_score=float(data.get("risk_score", 0.0)),
            critical_count=int(data.get("critical_count", 0)),
            high_count=int(data.get("high_count", 0)),
            medium_count=int(data.get("medium_count", 0)),
            low_count=int(data.get("low_count", 0)),
            active_attack_paths=int(data.get("active_attack_paths", 0)),
            drift_score=float(data.get("drift_score", 0.0)),
            drift_severity=data.get("drift_severity", "NONE"),
            governance_status=data.get("governance_status", "ALLOW"),
            recommended_action=data.get("recommended_action", "RELEASE_ALLOWED"),
            raw_data=data.get("raw_data", {}),
        )
