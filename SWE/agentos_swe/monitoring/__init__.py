"""
M18 Continuous Security Monitoring Package.

Provides continuous security monitoring, security regression detection, attack-path changes tracking,
remediation plan validity checking, alert generation, timeline building, and cross-repository posture tracking.
"""

from agentos_swe.monitoring.models import (
    RegressionSeverity,
    AlertSeverity,
    AlertCategory,
    AttackPathChangeType,
    RemediationPlanStatus,
    TrendDirection,
    SecurityAlert,
    AttackPathChange,
    RemediationImpact,
    SecurityChangeImpact,
    SecurityTimelineEntry,
    SecurityMonitoringResult,
    CrossRepositoryMonitoringResult,
)
from agentos_swe.monitoring.snapshot_manager import SnapshotManager
from agentos_swe.monitoring.change_detector import ChangeDetector
from agentos_swe.monitoring.regression_detector import RegressionDetector
from agentos_swe.monitoring.trend_analyzer import TrendAnalyzer
from agentos_swe.monitoring.alert_engine import AlertEngine
from agentos_swe.monitoring.monitor import SecurityMonitor

__all__ = [
    "RegressionSeverity",
    "AlertSeverity",
    "AlertCategory",
    "AttackPathChangeType",
    "RemediationPlanStatus",
    "TrendDirection",
    "SecurityAlert",
    "AttackPathChange",
    "RemediationImpact",
    "SecurityChangeImpact",
    "SecurityTimelineEntry",
    "SecurityMonitoringResult",
    "CrossRepositoryMonitoringResult",
    "SnapshotManager",
    "ChangeDetector",
    "RegressionDetector",
    "TrendAnalyzer",
    "AlertEngine",
    "SecurityMonitor",
]
