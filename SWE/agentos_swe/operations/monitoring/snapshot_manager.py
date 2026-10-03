"""
M18 Snapshot Manager for Continuous Security Monitoring.

Provides persistent in-memory and filesystem snapshot management for tracking security state snapshots across commits.
"""

from typing import Dict, Any, List, Optional
import os
import json
import logging

logger = logging.getLogger(__name__)


class SnapshotManager:
    """
    Manages historical scan snapshot persistence for repository monitoring.
    """

    _memory_snapshots: Dict[str, List[Dict[str, Any]]] = {}

    def __init__(self, storage_dir: Optional[str] = None):
        self.storage_dir = storage_dir or os.path.join(os.path.expanduser("~"), ".agentos_swe", "snapshots")
        try:
            os.makedirs(self.storage_dir, exist_ok=True)
        except Exception:
            pass

    def save_snapshot(self, repository: str, snapshot: Dict[str, Any]) -> str:
        """
        Saves a scan snapshot for a repository.
        """
        repo_key = repository.lower().replace("/", "_").replace("\\", "_")
        if repo_key not in SnapshotManager._memory_snapshots:
            SnapshotManager._memory_snapshots[repo_key] = []

        SnapshotManager._memory_snapshots[repo_key].append(snapshot)

        # File persistence attempt
        try:
            file_path = os.path.join(self.storage_dir, f"{repo_key}_snapshots.json")
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(SnapshotManager._memory_snapshots[repo_key], f, indent=2)
        except Exception as ex:
            logger.debug(f"[SnapshotManager] Local file write warning: {ex}")

        return snapshot.get("scan_id") or "snap_latest"

    def get_latest_snapshots(self, repository: str, limit: int = 5) -> List[Dict[str, Any]]:
        """
        Retrieves the N most recent scan snapshots for a repository.
        """
        repo_key = repository.lower().replace("/", "_").replace("\\", "_")
        snapshots = SnapshotManager._memory_snapshots.get(repo_key, [])

        if not snapshots and self.storage_dir:
            file_path = os.path.join(self.storage_dir, f"{repo_key}_snapshots.json")
            if os.path.exists(file_path):
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        snapshots = json.load(f)
                        SnapshotManager._memory_snapshots[repo_key] = snapshots
                except Exception as ex:
                    logger.debug(f"[SnapshotManager] Local file read warning: {ex}")

        return snapshots[-limit:]

    def get_previous_snapshot(self, repository: str) -> Optional[Dict[str, Any]]:
        """
        Returns the snapshot immediately prior to the current scan if available.
        """
        snapshots = self.get_latest_snapshots(repository, limit=2)
        if len(snapshots) >= 2:
            return snapshots[-2]
        elif len(snapshots) == 1:
            return snapshots[0]
        return None
