"""
M14 Local SQLite Persistent Scan Store.

Manages persistent ScanRecord snapshots and finding history across commits.
Operates completely locally with zero external network or database server requirements.
"""

import os
import sqlite3
import json
import logging
from typing import List, Dict, Any, Optional
from agentos_swe.history.models import ScanRecord
from agentos_swe.security.secret_protection import SecretProtection

logger = logging.getLogger(__name__)

DEFAULT_DB_FILENAME = "agentos_swe_history.db"


class HistoricalScanStore:
    """
    Local SQLite Persistent Store for historical repository security intelligence.
    Enforces multi-repository isolation, secret redaction, and full CRUD scan history.
    """

    def __init__(self, db_path: Optional[str] = None):
        if not db_path:
            # Default to local application directory
            base_dir = os.environ.get("AGENTOS_DATA_DIR") or os.path.expanduser("~/.gemini/antigravity")
            os.makedirs(base_dir, exist_ok=True)
            db_path = os.path.join(base_dir, DEFAULT_DB_FILENAME)

        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Creates SQLite tables for scans and finding histories if not exists."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS scans (
                        scan_id TEXT PRIMARY KEY,
                        repository TEXT NOT NULL,
                        repository_url TEXT,
                        owner TEXT,
                        branch TEXT,
                        commit_sha TEXT,
                        parent_commit_sha TEXT,
                        timestamp TEXT NOT NULL,
                        scan_mode TEXT,
                        files_analyzed INTEGER,
                        graph_nodes INTEGER,
                        graph_edges INTEGER,
                        security_score INTEGER,
                        final_verdict TEXT,
                        runtime REAL,
                        data_json TEXT NOT NULL
                    )
                """)
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_repo_timestamp ON scans(repository, timestamp DESC)
                """)
                conn.commit()
        except Exception as ex:
            logger.error(f"[HistoricalScanStore] DB Initialization Error: {ex}")

    def save_scan(self, scan: ScanRecord) -> bool:
        """Saves or updates a ScanRecord in the SQLite database after redacting secrets."""
        try:
            scan_dict = scan.to_dict()
            json_blob = SecretProtection.sanitize_text(json.dumps(scan_dict))

            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT OR REPLACE INTO scans (
                        scan_id, repository, repository_url, owner, branch, commit_sha,
                        parent_commit_sha, timestamp, scan_mode, files_analyzed, graph_nodes,
                        graph_edges, security_score, final_verdict, runtime, data_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        scan.scan_id,
                        scan.repository,
                        scan.repository_url,
                        scan.owner,
                        scan.branch,
                        scan.commit_sha,
                        scan.parent_commit_sha,
                        scan.timestamp,
                        scan.scan_mode,
                        scan.files_analyzed,
                        scan.graph_nodes,
                        scan.graph_edges,
                        scan.security_score,
                        scan.final_verdict,
                        scan.runtime,
                        json_blob,
                    ),
                )
                conn.commit()
            return True
        except Exception as ex:
            logger.error(f"[HistoricalScanStore] Save scan error: {ex}")
            return False

    def get_scan(self, scan_id: str) -> Optional[ScanRecord]:
        """Retrieves a ScanRecord by ID."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT data_json FROM scans WHERE scan_id = ?", (scan_id,))
                row = cursor.fetchone()
                if row and row[0]:
                    data = json.loads(row[0])
                    return ScanRecord(**data)
        except Exception as ex:
            logger.error(f"[HistoricalScanStore] Get scan error: {ex}")
        return None

    def list_scans(self, repository: Optional[str] = None) -> List[ScanRecord]:
        """Lists historical ScanRecords, optionally filtered by repository name/URL."""
        scans = []
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                if repository:
                    cursor.execute("SELECT data_json FROM scans WHERE repository = ? ORDER BY timestamp DESC", (repository,))
                else:
                    cursor.execute("SELECT data_json FROM scans ORDER BY timestamp DESC")
                rows = cursor.fetchall()
                for r in rows:
                    if r and r[0]:
                        scans.append(ScanRecord(**json.loads(r[0])))
        except Exception as ex:
            logger.error(f"[HistoricalScanStore] List scans error: {ex}")
        return scans

    def get_latest_scan(self, repository: str) -> Optional[ScanRecord]:
        """Gets the most recent scan for a repository."""
        scans = self.list_scans(repository)
        return scans[0] if scans else None

    def get_previous_scan(self, repository: str, current_scan_id: Optional[str] = None) -> Optional[ScanRecord]:
        """Gets the scan immediately preceding current_scan_id for a repository."""
        scans = self.list_scans(repository)
        if not scans:
            return None
        if not current_scan_id:
            return scans[1] if len(scans) > 1 else None

        for idx, s in enumerate(scans):
            if s.scan_id == current_scan_id:
                if idx + 1 < len(scans):
                    return scans[idx + 1]
                break
        return scans[1] if len(scans) > 1 else None

    def delete_scan(self, scan_id: str) -> bool:
        """Deletes a specific scan by ID."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
                conn.commit()
            return True
        except Exception as ex:
            logger.error(f"[HistoricalScanStore] Delete scan error: {ex}")
            return False

    def delete_repository_history(self, repository: str) -> bool:
        """Deletes all scan records for a specific repository."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM scans WHERE repository = ?", (repository,))
                conn.commit()
            return True
        except Exception as ex:
            logger.error(f"[HistoricalScanStore] Delete repo history error: {ex}")
            return False

    def clear_all_history(self) -> bool:
        """Clears all historical scans from the store."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM scans")
                conn.commit()
            return True
        except Exception as ex:
            logger.error(f"[HistoricalScanStore] Clear history error: {ex}")
            return False
