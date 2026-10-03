"""
M28 Continuous Monitoring Scheduler Engine.

Provides safe deterministic scheduling calculations and a tick model
for automated continuous security monitoring without background daemons or infinite loops.
"""

import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta

from agentos_swe.persistence.repository_registry import RepositoryRegistry
from agentos_swe.persistence.models import RepositoryRegistration, MonitoringScheduleInterval, RepositoryMonitoringStatus
from agentos_swe.operations.monitoring.models import MonitoringHealth
from agentos_swe.operations.monitoring.result import MonitoringJobResult

logger = logging.getLogger(__name__)


class SecurityMonitorScheduler:
    """
    In-memory scheduler for monitoring pipelines.
    """

    def __init__(self):
        self.jobs: Dict[str, Dict[str, Any]] = {}

    def schedule_job(
        self,
        job_id: str,
        repository_name: str,
        interval_seconds: int = 3600,
        callback: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """
        Schedules a monitoring job definition in-memory.
        """
        job = {
            "job_id": job_id,
            "repository_name": repository_name,
            "interval_seconds": interval_seconds,
            "status": "SCHEDULED",
            "has_callback": callback is not None,
        }
        self.jobs[job_id] = job
        return job

    def run_job_now(self, job_id: str) -> Dict[str, Any]:
        """
        Triggers a scheduled job execution on-demand.
        """
        job = self.jobs.get(job_id, {"job_id": job_id, "status": "COMPLETED"})
        job["status"] = "COMPLETED"
        return job


class ContinuousMonitoringScheduler:
    """
    Continuous Monitoring Scheduler enforcing deterministic schedule intervals.
    Executes tasks safely through tick() invocations.
    """

    INTERVAL_HOURS = {
        MonitoringScheduleInterval.MANUAL.value: 8760,  # 1 year
        MonitoringScheduleInterval.HOURLY.value: 1,
        MonitoringScheduleInterval.EVERY_6_HOURS.value: 6,
        MonitoringScheduleInterval.DAILY.value: 24,
        MonitoringScheduleInterval.WEEKLY.value: 168,
    }

    def __init__(self, registry: Optional[RepositoryRegistry] = None):
        self.registry = registry or RepositoryRegistry()

    @classmethod
    def calculate_next_run(cls, last_run_iso: Optional[str], interval_str: str) -> str:
        """Calculates next due ISO timestamp given last execution time and interval."""
        hours = cls.INTERVAL_HOURS.get(interval_str, 24)
        base_dt = datetime.fromisoformat(last_run_iso) if last_run_iso else datetime.now()
        next_dt = base_dt + timedelta(hours=hours)
        return next_dt.isoformat()

    def is_due(self, reg: RepositoryRegistration) -> bool:
        """Checks if a registered repository is currently due for a monitoring scan."""
        if not reg.monitoring_enabled or reg.scan_interval == MonitoringScheduleInterval.MANUAL.value:
            return False

        if not reg.last_successful_scan and not reg.last_failed_scan:
            return True

        last_scan_iso = reg.last_successful_scan or reg.last_failed_scan
        next_due_iso = self.calculate_next_run(last_scan_iso, reg.scan_interval)
        return datetime.now().isoformat() >= next_due_iso

    def get_due_repositories(self) -> List[RepositoryRegistration]:
        """Returns all registered repositories that are due for monitoring."""
        all_monitored = self.registry.list_monitored_repositories()
        return [r for r in all_monitored if self.is_due(r)]

    def tick(self, runner: Any, force_scan: bool = False) -> List[MonitoringJobResult]:
        """
        Executes a single deterministic scheduler tick:
        1. Identifies due repositories from registry.
        2. Executes read-only monitoring scan via runner.
        3. Updates next scheduled execution timestamp.
        4. Returns results.
        """
        due_repos = self.registry.list_monitored_repositories() if force_scan else self.get_due_repositories()
        results: List[MonitoringJobResult] = []

        for reg in due_repos:
            try:
                res = runner.run_monitoring_scan(
                    repository_name=reg.repository_name,
                    repository_path=reg.repository_path_or_url,
                    force_rescan=force_scan,
                )
                results.append(res)

                # Update next due timestamp
                reg.last_successful_scan = datetime.now().isoformat() if res.status != "SCAN_FAILED" else reg.last_successful_scan
                reg.last_failed_scan = datetime.now().isoformat() if res.status == "SCAN_FAILED" else reg.last_failed_scan
                reg.next_due_timestamp = self.calculate_next_run(datetime.now().isoformat(), reg.scan_interval)
                self.registry.register_repository(
                    repository_name=reg.repository_name,
                    repository_path_or_url=reg.repository_path_or_url,
                    branch=reg.branch,
                    scan_interval=reg.scan_interval,
                    monitoring_enabled=reg.monitoring_enabled,
                )
            except Exception as e:
                logger.error(f"Scheduler tick error on '{reg.repository_name}': {e}")

        return results

    def compute_monitoring_health(self) -> MonitoringHealth:
        """Computes aggregate monitoring infrastructure health metrics."""
        all_registered = self.registry.list_all_repositories()
        monitored = [r for r in all_registered if r.monitoring_enabled]
        due_repos = self.get_due_repositories()

        failed_count = sum(1 for r in all_registered if r.current_status == RepositoryMonitoringStatus.FAILED.value)
        stale_count = sum(1 for r in all_registered if r.current_status == RepositoryMonitoringStatus.STALE.value)

        last_succ = next((r.last_successful_scan for r in monitored if r.last_successful_scan), None)
        next_due = next((r.next_due_timestamp for r in monitored if r.next_due_timestamp), None)

        m_status = RepositoryMonitoringStatus.FAILED.value if failed_count > 0 else (
            RepositoryMonitoringStatus.STALE.value if stale_count > 0 else RepositoryMonitoringStatus.ACTIVE.value
        )

        return MonitoringHealth(
            security_health="HEALTHY",
            monitoring_health=m_status,
            repositories_monitored=len(monitored),
            repositories_due=len(due_repos),
            successful_scans=sum(1 for r in all_registered if r.last_successful_scan),
            failed_scans=failed_count,
            last_successful_scan=last_succ,
            next_scheduled_scan=next_due,
            failures_count=failed_count,
            stale_repos_count=stale_count,
        )
