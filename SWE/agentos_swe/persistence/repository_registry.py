"""
M28 Repository Registry Store.

Tracks repositories registered for continuous security monitoring,
storing schedule intervals, monitoring status, and execution timestamps in SQLite.
"""

import os
import sqlite3
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime

from agentos_swe.persistence.models import RepositoryRegistration, MonitoringScheduleInterval, RepositoryMonitoringStatus
from agentos_swe.persistence.serialization import PersistenceSerializer

logger = logging.getLogger(__name__)

DEFAULT_DB_FILENAME = "agentos_swe_history.db"


class RepositoryRegistry:
    """
    Registry for tracking and configuring repositories enabled for continuous monitoring.
    Never silently enables monitoring for an unknown repository.
    """

    def __init__(self, db_path: Optional[str] = None):
        if not db_path:
            base_dir = os.environ.get("AGENTOS_DATA_DIR") or os.path.expanduser("~/.gemini/antigravity")
            os.makedirs(base_dir, exist_ok=True)
            db_path = os.path.join(base_dir, DEFAULT_DB_FILENAME)

        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Creates repository_registry table if it does not exist."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS repository_registry (
                        repository_name TEXT PRIMARY KEY,
                        repository_path_or_url TEXT NOT NULL,
                        branch TEXT DEFAULT 'main',
                        monitoring_enabled INTEGER DEFAULT 1,
                        scan_interval TEXT DEFAULT 'DAILY',
                        last_successful_scan TEXT,
                        last_failed_scan TEXT,
                        next_due_timestamp TEXT,
                        current_status TEXT DEFAULT 'ACTIVE',
                        registry_json TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    )
                """)
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to initialize repository_registry SQLite schema: {e}")

    def register_repository(
        self,
        repository_name: str,
        repository_path_or_url: str,
        branch: str = "main",
        scan_interval: str = MonitoringScheduleInterval.DAILY.value,
        monitoring_enabled: bool = True,
    ) -> RepositoryRegistration:
        """Registers a repository for continuous monitoring."""
        reg = RepositoryRegistration(
            repository_name=repository_name,
            repository_path_or_url=repository_path_or_url,
            branch=branch,
            monitoring_enabled=monitoring_enabled,
            scan_interval=scan_interval,
            current_status=RepositoryMonitoringStatus.ACTIVE.value if monitoring_enabled else RepositoryMonitoringStatus.PAUSED.value,
        )

        try:
            json_payload = PersistenceSerializer.serialize(reg.to_dict())
            updated_at = datetime.now().isoformat()

            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO repository_registry (
                        repository_name, repository_path_or_url, branch,
                        monitoring_enabled, scan_interval, last_successful_scan,
                        last_failed_scan, next_due_timestamp, current_status,
                        registry_json, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(repository_name) DO UPDATE SET
                        repository_path_or_url=excluded.repository_path_or_url,
                        branch=excluded.branch,
                        monitoring_enabled=excluded.monitoring_enabled,
                        scan_interval=excluded.scan_interval,
                        current_status=excluded.current_status,
                        registry_json=excluded.registry_json,
                        updated_at=excluded.updated_at
                """, (
                    reg.repository_name, reg.repository_path_or_url, reg.branch,
                    1 if reg.monitoring_enabled else 0, reg.scan_interval,
                    reg.last_successful_scan, reg.last_failed_scan,
                    reg.next_due_timestamp, reg.current_status,
                    json_payload, updated_at
                ))
                conn.commit()
        except Exception as e:
            logger.error(f"Error registering repository '{repository_name}': {e}")

        return reg

    def unregister_repository(self, repository_name: str) -> bool:
        """Unregisters a repository from continuous monitoring."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM repository_registry WHERE repository_name = ?", (repository_name,))
                conn.commit()
            return True
        except Exception as e:
            logger.error(f"Error unregistering repository '{repository_name}': {e}")
            return False

    def enable_monitoring(self, repository_name: str) -> bool:
        """Enables monitoring for a registered repository."""
        reg = self.get_repository(repository_name)
        if not reg:
            logger.warning(f"Cannot enable monitoring for unregistered repo '{repository_name}'")
            return False

        reg.monitoring_enabled = True
        reg.current_status = RepositoryMonitoringStatus.ACTIVE.value
        reg.updated_at = datetime.now().isoformat()
        self.register_repository(
            repository_name=reg.repository_name,
            repository_path_or_url=reg.repository_path_or_url,
            branch=reg.branch,
            scan_interval=reg.scan_interval,
            monitoring_enabled=True,
        )
        return True

    def disable_monitoring(self, repository_name: str) -> bool:
        """Disables monitoring for a registered repository."""
        reg = self.get_repository(repository_name)
        if not reg:
            return False

        reg.monitoring_enabled = False
        reg.current_status = RepositoryMonitoringStatus.PAUSED.value
        reg.updated_at = datetime.now().isoformat()
        self.register_repository(
            repository_name=reg.repository_name,
            repository_path_or_url=reg.repository_path_or_url,
            branch=reg.branch,
            scan_interval=reg.scan_interval,
            monitoring_enabled=False,
        )
        return True

    def update_schedule(self, repository_name: str, scan_interval: str) -> bool:
        """Updates monitoring schedule interval for a registered repository."""
        reg = self.get_repository(repository_name)
        if not reg:
            return False

        reg.scan_interval = scan_interval
        reg.updated_at = datetime.now().isoformat()
        self.register_repository(
            repository_name=reg.repository_name,
            repository_path_or_url=reg.repository_path_or_url,
            branch=reg.branch,
            scan_interval=scan_interval,
            monitoring_enabled=reg.monitoring_enabled,
        )
        return True

    def get_repository(self, repository_name: str) -> Optional[RepositoryRegistration]:
        """Retrieves registration record for a repository."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT registry_json FROM repository_registry WHERE repository_name = ?", (repository_name,))
                row = cursor.fetchone()
                if row and row[0]:
                    d = PersistenceSerializer.deserialize(row[0])
                    return RepositoryRegistration.from_dict(d)
        except Exception as e:
            logger.error(f"Error fetching repository registration '{repository_name}': {e}")
        return None

    def list_all_repositories(self) -> List[RepositoryRegistration]:
        """Lists all registered repositories."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT registry_json FROM repository_registry ORDER BY updated_at DESC")
                rows = cursor.fetchall()
                results = []
                for row in rows:
                    if row[0]:
                        d = PersistenceSerializer.deserialize(row[0])
                        results.append(RepositoryRegistration.from_dict(d))
                return results
        except Exception as e:
            logger.error(f"Error listing registered repositories: {e}")
            return []

    def list_monitored_repositories(self) -> List[RepositoryRegistration]:
        """Lists repositories with monitoring enabled."""
        all_repos = self.list_all_repositories()
        return [r for r in all_repos if r.monitoring_enabled]
