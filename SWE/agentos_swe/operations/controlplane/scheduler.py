"""
M27 Security Monitoring Scheduler Abstraction.

Implements safe, local, deterministic scheduling state without background daemons or automated remote writes.
"""

from typing import Dict, Any, Optional
from datetime import datetime, timedelta


class SecurityMonitoringScheduler:
    """
    Deterministic local monitoring scheduler abstraction.
    """

    INTERVAL_MAP = {
        "MANUAL": timedelta(days=365),
        "HOURLY": timedelta(hours=1),
        "DAILY": timedelta(days=1),
        "WEEKLY": timedelta(weeks=1),
    }

    def compute_schedule_state(
        self,
        repository_name: str,
        last_scan_timestamp: Optional[str] = None,
        schedule_mode: str = "DAILY",
        monitoring_enabled: bool = True,
        trigger_reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Calculates deterministic monitoring schedule state safely.
        """
        now = datetime.now()
        last_dt = datetime.fromisoformat(last_scan_timestamp) if last_scan_timestamp else now

        mode = schedule_mode.upper() if schedule_mode.upper() in self.INTERVAL_MAP else "DAILY"
        delta = self.INTERVAL_MAP[mode]

        next_dt = last_dt + delta
        recommended_scan = next_dt.isoformat()[:19].replace("T", " ")

        reason = trigger_reason or (
            f"Scheduled {mode} security monitoring scan." if monitoring_enabled
            else "Monitoring disabled; manual scan required."
        )

        return {
            "repository": repository_name,
            "schedule_mode": mode,
            "monitoring_enabled": monitoring_enabled,
            "last_scan": last_dt.isoformat()[:19].replace("T", " "),
            "next_recommended_scan": recommended_scan,
            "scan_interval": str(delta),
            "reason_for_next_scan": reason,
        }
