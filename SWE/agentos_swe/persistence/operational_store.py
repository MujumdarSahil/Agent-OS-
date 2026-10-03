"""
M28 Persistent Operational State Store.

Interacts with local SQLite DB (extending M14 agentos_swe_history.db)
to persist M27 control plane operational states, security snapshots, and audit records.
"""

import os
import sqlite3
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime

from agentos_swe.persistence.models import SecurityPostureSnapshotRecord
from agentos_swe.persistence.serialization import PersistenceSerializer

logger = logging.getLogger(__name__)

DEFAULT_DB_FILENAME = "agentos_swe_history.db"


class PersistentOperationalStateStore:
    """
    Persistent store for M27/M28 operational states and security posture snapshots.
    Reuses existing M14 SQLite infrastructure without redundant database initialization.
    """

    def __init__(self, db_path: Optional[str] = None):
        if not db_path:
            base_dir = os.environ.get("AGENTOS_DATA_DIR") or os.path.expanduser("~/.gemini/antigravity")
            os.makedirs(base_dir, exist_ok=True)
            db_path = os.path.join(base_dir, DEFAULT_DB_FILENAME)

        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Initializes operational_states and security_snapshots tables in SQLite."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS operational_states (
                        repository_name TEXT PRIMARY KEY,
                        repository_path_or_url TEXT,
                        branch TEXT,
                        commit_sha TEXT,
                        last_scan_timestamp TEXT,
                        next_scheduled_scan TEXT,
                        lifecycle_stage TEXT,
                        operational_status TEXT,
                        operational_mode TEXT,
                        health_score REAL,
                        security_score INTEGER,
                        risk_score REAL,
                        state_json TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    )
                """)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS security_snapshots (
                        snapshot_id TEXT PRIMARY KEY,
                        repository_name TEXT NOT NULL,
                        commit_sha TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        snapshot_json TEXT NOT NULL
                    )
                """)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS security_incidents (
                        incident_id TEXT PRIMARY KEY,
                        repository_name TEXT NOT NULL,
                        commit_sha TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        status TEXT NOT NULL,
                        incident_json TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    )
                """)
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to initialize operational state SQLite schema: {e}")

    def save_operational_state(self, repository_name: str, state_data: Dict[str, Any]) -> bool:
        """Saves or updates operational state for a repository."""
        if not repository_name:
            return False

        try:
            json_payload = PersistenceSerializer.serialize(state_data)
            updated_at = datetime.now().isoformat()

            repo_path = state_data.get("repository_path_or_url") or state_data.get("repo_path") or ""
            branch = state_data.get("branch") or "main"
            commit_sha = state_data.get("commit_sha") or state_data.get("commit") or "HEAD"
            last_scan = state_data.get("last_scan_timestamp") or updated_at
            next_scan = state_data.get("next_scheduled_scan")
            lifecycle = state_data.get("lifecycle_stage") or "COMPLETE"
            op_status = state_data.get("operational_status") or "HEALTHY"
            op_mode = state_data.get("operational_mode") or "IDLE"
            health_score = float(state_data.get("health_score", 100.0))
            security_score = int(state_data.get("security_score", 100))
            risk_score = float(state_data.get("risk_score", 0.0))

            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO operational_states (
                        repository_name, repository_path_or_url, branch, commit_sha,
                        last_scan_timestamp, next_scheduled_scan, lifecycle_stage,
                        operational_status, operational_mode, health_score,
                        security_score, risk_score, state_json, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(repository_name) DO UPDATE SET
                        repository_path_or_url=excluded.repository_path_or_url,
                        branch=excluded.branch,
                        commit_sha=excluded.commit_sha,
                        last_scan_timestamp=excluded.last_scan_timestamp,
                        next_scheduled_scan=excluded.next_scheduled_scan,
                        lifecycle_stage=excluded.lifecycle_stage,
                        operational_status=excluded.operational_status,
                        operational_mode=excluded.operational_mode,
                        health_score=excluded.health_score,
                        security_score=excluded.security_score,
                        risk_score=excluded.risk_score,
                        state_json=excluded.state_json,
                        updated_at=excluded.updated_at
                """, (
                    repository_name, repo_path, branch, commit_sha,
                    last_scan, next_scan, lifecycle, op_status,
                    op_mode, health_score, security_score, risk_score,
                    json_payload, updated_at
                ))
                conn.commit()
            return True
        except Exception as e:
            logger.error(f"Error saving operational state for '{repository_name}': {e}")
            return False

    def load_operational_state(self, repository_name: str) -> Optional[Dict[str, Any]]:
        """Loads persistent operational state for a repository."""
        if not repository_name:
            return None

        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT state_json FROM operational_states WHERE repository_name = ?", (repository_name,))
                row = cursor.fetchone()
                if row and row[0]:
                    return PersistenceSerializer.deserialize(row[0])
        except Exception as e:
            logger.error(f"Error loading operational state for '{repository_name}': {e}")
        return None

    def update_operational_state(self, repository_name: str, patch_data: Dict[str, Any]) -> bool:
        """Applies patch updates to an existing stored operational state."""
        existing = self.load_operational_state(repository_name) or {}
        existing.update(patch_data)
        return self.save_operational_state(repository_name, existing)

    def delete_operational_state(self, repository_name: str) -> bool:
        """Deletes persistent operational state for a repository."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM operational_states WHERE repository_name = ?", (repository_name,))
                conn.commit()
            return True
        except Exception as e:
            logger.error(f"Error deleting operational state for '{repository_name}': {e}")
            return False

    def list_repositories(self) -> List[str]:
        """Returns list of repository names stored in operational_states."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT repository_name FROM operational_states ORDER BY updated_at DESC")
                rows = cursor.fetchall()
                return [r[0] for r in rows if r[0]]
        except Exception as e:
            logger.error(f"Error listing operational repositories: {e}")
            return []

    def get_latest_state(self, repository_name: str) -> Optional[Dict[str, Any]]:
        """Alias for load_operational_state."""
        return self.load_operational_state(repository_name)

    def clear_repository_state(self, repository_name: str) -> bool:
        """Alias for delete_operational_state."""
        return self.delete_operational_state(repository_name)

    def save_snapshot(self, repository_name: str, snapshot: SecurityPostureSnapshotRecord) -> bool:
        """Saves a security posture snapshot record."""
        try:
            json_payload = PersistenceSerializer.serialize(snapshot.to_dict())
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO security_snapshots (snapshot_id, repository_name, commit_sha, timestamp, snapshot_json)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(snapshot_id) DO UPDATE SET snapshot_json=excluded.snapshot_json
                """, (snapshot.snapshot_id, repository_name, snapshot.commit_sha, snapshot.timestamp, json_payload))
                conn.commit()
            return True
        except Exception as e:
            logger.error(f"Error saving snapshot '{snapshot.snapshot_id}': {e}")
            return False

    def list_snapshots(self, repository_name: str) -> List[SecurityPostureSnapshotRecord]:
        """Lists snapshots for a repository ordered by timestamp descending."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT snapshot_json FROM security_snapshots WHERE repository_name = ? ORDER BY timestamp DESC",
                    (repository_name,)
                )
                rows = cursor.fetchall()
                records = []
                for row in rows:
                    if row[0]:
                        d = PersistenceSerializer.deserialize(row[0])
                        records.append(SecurityPostureSnapshotRecord.from_dict(d))
                return records
        except Exception as e:
            logger.error(f"Error listing snapshots for '{repository_name}': {e}")
            return []

    def get_latest_snapshot(self, repository_name: str) -> Optional[SecurityPostureSnapshotRecord]:
        """Retrieves latest snapshot record for a repository."""
        snaps = self.list_snapshots(repository_name)
        return snaps[0] if snaps else None

    def get_previous_snapshot(self, repository_name: str) -> Optional[SecurityPostureSnapshotRecord]:
        """Retrieves second latest snapshot record for a repository."""
        snaps = self.list_snapshots(repository_name)
        return snaps[1] if len(snaps) > 1 else None

    def compare_snapshots(self, repository_name: str) -> Dict[str, Any]:
        """Compares latest and previous snapshot records to produce delta report."""
        latest = self.get_latest_snapshot(repository_name)
        prev = self.get_previous_snapshot(repository_name)

        if not latest:
            return {"status": "NO_SNAPSHOTS", "repository_name": repository_name}

        if not prev:
            return {
                "status": "INITIAL_SNAPSHOT",
                "repository_name": repository_name,
                "latest_commit": latest.commit_sha,
                "latest_score": latest.security_score,
            }

        score_delta = latest.security_score - prev.security_score
        health_delta = round(latest.health_score - prev.health_score, 2)
        risk_delta = round(latest.risk_score - prev.risk_score, 2)

        return {
            "status": "COMPARED",
            "repository_name": repository_name,
            "previous_commit": prev.commit_sha,
            "latest_commit": latest.commit_sha,
            "previous_score": prev.security_score,
            "latest_score": latest.security_score,
            "score_delta": score_delta,
            "health_delta": health_delta,
            "risk_delta": risk_delta,
            "direction": "IMPROVEMENT" if score_delta > 0 else ("DEGRADATION" if score_delta < 0 else "STABLE"),
        }

    def save_incident(self, repository_name: str, incident_data: Dict[str, Any]) -> bool:
        """Saves a security incident record to SQLite."""
        inc_id = incident_data.get("incident_id")
        if not inc_id or not repository_name:
            return False

        try:
            json_payload = PersistenceSerializer.serialize(incident_data)
            updated_at = datetime.now().isoformat()
            commit_sha = incident_data.get("commit_sha", "HEAD")
            severity = str(incident_data.get("severity", "MEDIUM"))
            status = str(incident_data.get("status", "DETECTED"))

            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO security_incidents (
                        incident_id, repository_name, commit_sha, severity, status, incident_json, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(incident_id) DO UPDATE SET
                        repository_name=excluded.repository_name,
                        commit_sha=excluded.commit_sha,
                        severity=excluded.severity,
                        status=excluded.status,
                        incident_json=excluded.incident_json,
                        updated_at=excluded.updated_at
                """, (inc_id, repository_name, commit_sha, severity, status, json_payload, updated_at))
                conn.commit()
            return True
        except Exception as e:
            logger.error(f"Error saving incident '{inc_id}': {e}")
            return False

    def load_incident(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Loads a security incident record by ID."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT incident_json FROM security_incidents WHERE incident_id = ?", (incident_id,))
                row = cursor.fetchone()
                if row and row[0]:
                    return PersistenceSerializer.deserialize(row[0])
        except Exception as e:
            logger.error(f"Error loading incident '{incident_id}': {e}")
        return None

    def list_incidents(self, repository_name: Optional[str] = None) -> List[Dict[str, Any]]:
        """Lists incidents for a repository or across all repositories."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                if repository_name:
                    cursor.execute("SELECT incident_json FROM security_incidents WHERE repository_name = ? ORDER BY updated_at DESC", (repository_name,))
                else:
                    cursor.execute("SELECT incident_json FROM security_incidents ORDER BY updated_at DESC")
                rows = cursor.fetchall()
                return [PersistenceSerializer.deserialize(r[0]) for r in rows if r[0]]
        except Exception as e:
            logger.error(f"Error listing incidents: {e}")
            return []

    def update_incident_status(self, incident_id: str, new_status: str) -> bool:
        """Updates the status of an existing stored incident."""
        inc = self.load_incident(incident_id)
        if not inc:
            return False
        inc["status"] = new_status
        repo = inc.get("repository_name", "UNKNOWN")
        return self.save_incident(repo, inc)
