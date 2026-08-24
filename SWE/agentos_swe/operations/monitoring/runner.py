"""
M28 Security Monitoring Runner.

Executes safe, read-only continuous security monitoring scans.
Supports change-aware commit optimization (NO_CHANGE) and resilient failure fallback
preserving last known good security posture state.
"""

import os
import time
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime

from agentos_swe.persistence.operational_store import PersistentOperationalStateStore
from agentos_swe.persistence.repository_registry import RepositoryRegistry
from agentos_swe.persistence.models import SecurityPostureSnapshotRecord
from agentos_swe.operations.controlplane import SecurityOperationsControlPlane
from agentos_swe.operations.monitoring.models import MonitoringEventType, MonitoringEvent, MonitoringHealthStatus
from agentos_swe.operations.monitoring.result import MonitoringJobResult

logger = logging.getLogger(__name__)


class SecurityMonitoringRunner:
    """
    Runner for executing safe read-only continuous monitoring scans.
    Enforces change-aware commit optimization and secret protection.
    """

    def __init__(self, store: Optional[PersistentOperationalStateStore] = None, registry: Optional[RepositoryRegistry] = None):
        self.store = store or PersistentOperationalStateStore()
        self.registry = registry or RepositoryRegistry()
        self.control_plane = SecurityOperationsControlPlane()

    def run_monitoring_scan(
        self,
        repository_name: str,
        repository_path: str,
        commit_sha: str = "HEAD",
        verified_findings: Optional[List[Any]] = None,
        prioritized_findings: Optional[List[Any]] = None,
        attack_paths: Optional[List[Any]] = None,
        decision_result: Optional[Any] = None,
        learning_result: Optional[Any] = None,
        drift_result: Optional[Any] = None,
        force_rescan: bool = False,
    ) -> MonitoringJobResult:
        """
        Executes a continuous monitoring scan on a target repository.
        """
        last_state = self.store.load_operational_state(repository_name)
        prev_commit = last_state.get("commit_sha") if last_state else None

        # 1. Change-Aware Optimization
        if not force_rescan and prev_commit and prev_commit == commit_sha and commit_sha != "HEAD":
            logger.info(f"Monitoring scan for '{repository_name}': NO_CHANGE detected at commit {commit_sha}.")
            no_change_event = MonitoringEvent(
                event_id=f"ev_nc_{int(time.time())}",
                repository_name=repository_name,
                timestamp=datetime.now().isoformat(),
                event_type=MonitoringEventType.NO_CHANGE,
                severity="INFO",
                previous_commit=prev_commit,
                current_commit=commit_sha,
                reason=f"Commit SHA unchanged ({commit_sha}); re-analysis bypassed.",
            )
            return MonitoringJobResult(
                repository_name=repository_name,
                status="NO_CHANGE",
                current_commit=commit_sha,
                previous_commit=prev_commit,
                change_detected=False,
                security_score=last_state.get("summary", {}).get("security_score", 100),
                health_score=last_state.get("health", {}).get("health_score", 100.0),
                risk_score=last_state.get("summary", {}).get("risk_score", 0.0),
                drift_score=last_state.get("summary", {}).get("drift_score", 0.0),
                governance_status=last_state.get("summary", {}).get("governance_status", "ALLOW"),
                recommended_action=last_state.get("recommended_action", {}).get("action", "RELEASE_ALLOWED"),
                events_generated=[no_change_event.to_dict()],
            )

        # 2. Process operations through M27 Control Plane
        try:
            cp_result = self.control_plane.process_repository_operations(
                repository_name=repository_name,
                commit_sha=commit_sha,
                verified_findings=verified_findings,
                prioritized_findings=prioritized_findings,
                attack_paths=attack_paths,
                decision_result=decision_result,
                learning_result=learning_result,
                drift_result=drift_result,
            )

            res_dict = cp_result.to_dict() if hasattr(cp_result, "to_dict") else cp_result
            res_dict["repository_path_or_url"] = repository_path

            # 3. Save operational state & posture snapshot
            self.store.save_operational_state(repository_name, res_dict)

            snapshot = SecurityPostureSnapshotRecord(
                snapshot_id=f"snap_{repository_name}_{int(time.time())}",
                repository_name=repository_name,
                commit_sha=commit_sha,
                timestamp=datetime.now().isoformat(),
                security_score=res_dict.get("summary", {}).get("security_score", 100),
                health_score=res_dict.get("health", {}).get("health_score", 100.0),
                risk_score=res_dict.get("summary", {}).get("risk_score", 0.0),
                critical_count=res_dict.get("summary", {}).get("critical_findings", 0),
                high_count=res_dict.get("summary", {}).get("high_findings", 0),
                medium_count=res_dict.get("summary", {}).get("medium_findings", 0),
                low_count=res_dict.get("summary", {}).get("low_findings", 0),
                active_attack_paths=res_dict.get("summary", {}).get("active_attack_paths", 0),
                drift_score=res_dict.get("summary", {}).get("drift_score", 0.0),
                drift_severity=res_dict.get("summary", {}).get("drift_severity", "NONE"),
                governance_status=res_dict.get("summary", {}).get("governance_status", "ALLOW"),
                recommended_action=res_dict.get("recommended_action", {}).get("action", "RELEASE_ALLOWED"),
                raw_data=res_dict,
            )
            self.store.save_snapshot(repository_name, snapshot)

            # 4. Update repository registry successful scan time
            reg = self.registry.get_repository(repository_name)
            if reg:
                reg.last_successful_scan = datetime.now().isoformat()
                reg.current_status = MonitoringHealthStatus.HEALTHY.value
                self.registry.register_repository(
                    repository_name=reg.repository_name,
                    repository_path_or_url=reg.repository_path_or_url,
                    branch=reg.branch,
                    scan_interval=reg.scan_interval,
                    monitoring_enabled=reg.monitoring_enabled,
                )

            # 5. Generate events
            events = [
                MonitoringEvent(
                    event_id=f"ev_scan_{int(time.time())}",
                    repository_name=repository_name,
                    timestamp=datetime.now().isoformat(),
                    event_type=MonitoringEventType.SCAN_COMPLETED,
                    severity="INFO",
                    previous_commit=prev_commit,
                    current_commit=commit_sha,
                    reason=f"Monitoring scan completed successfully at commit {commit_sha}.",
                ).to_dict()
            ]

            return MonitoringJobResult(
                repository_name=repository_name,
                status="SCAN_SUCCESS",
                current_commit=commit_sha,
                previous_commit=prev_commit,
                change_detected=True if prev_commit and prev_commit != commit_sha else False,
                security_score=res_dict.get("summary", {}).get("security_score", 100),
                health_score=res_dict.get("health", {}).get("health_score", 100.0),
                risk_score=res_dict.get("summary", {}).get("risk_score", 0.0),
                drift_score=res_dict.get("summary", {}).get("drift_score", 0.0),
                governance_status=res_dict.get("summary", {}).get("governance_status", "ALLOW"),
                recommended_action=res_dict.get("recommended_action", {}).get("action", "RELEASE_ALLOWED"),
                events_generated=events,
            )

        except Exception as e:
            logger.error(f"Monitoring scan failed for '{repository_name}': {e}")

            # Resilient Failure Handling: Preserve last known good state
            reg = self.registry.get_repository(repository_name)
            if reg:
                reg.last_failed_scan = datetime.now().isoformat()
                reg.current_status = MonitoringHealthStatus.FAILED.value
                self.registry.register_repository(
                    repository_name=reg.repository_name,
                    repository_path_or_url=reg.repository_path_or_url,
                    branch=reg.branch,
                    scan_interval=reg.scan_interval,
                    monitoring_enabled=reg.monitoring_enabled,
                )

            fail_event = MonitoringEvent(
                event_id=f"ev_fail_{int(time.time())}",
                repository_name=repository_name,
                timestamp=datetime.now().isoformat(),
                event_type=MonitoringEventType.SCAN_FAILED,
                severity="HIGH",
                previous_commit=prev_commit,
                current_commit=commit_sha,
                reason=f"Monitoring scan failed: {str(e)}",
            )

            return MonitoringJobResult(
                repository_name=repository_name,
                status="SCAN_FAILED",
                current_commit=commit_sha,
                previous_commit=prev_commit,
                change_detected=False,
                security_score=last_state.get("summary", {}).get("security_score", 100) if last_state else 100,
                health_score=last_state.get("health", {}).get("health_score", 100.0) if last_state else 100.0,
                error=str(e),
                events_generated=[fail_event.to_dict()],
            )
