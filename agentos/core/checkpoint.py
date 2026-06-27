"""
Checkpoint Store - Persisted state interface and SQLite implementation
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
import sqlite3
import json
import os
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class CheckpointStore(ABC):
    """
    Abstract Base Class for mission run checkpoint persistence.
    """
    
    @abstractmethod
    def save_checkpoint(self, mission_id: str, task_index: int, state: Dict[str, Any]) -> None:
        """Save a task execution state checkpoint for a mission."""
        pass

    @abstractmethod
    def load_latest_checkpoint(self, mission_id: str) -> Optional[Dict[str, Any]]:
        """Load the most recent checkpoint state for a given mission."""
        pass

    @abstractmethod
    def list_runs(self, mission_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """List checkpoint run history."""
        pass

    @abstractmethod
    def mark_complete(self, mission_id: str) -> None:
        """Mark a mission execution as completely successful."""
        pass


class SQLiteCheckpointStore(CheckpointStore):
    """
    SQLite implementation of CheckpointStore storing state in a local file.
    """
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_db()

    def _init_db(self) -> None:
        """Initialize the database tables."""
        os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS checkpoints (
                    mission_id TEXT NOT NULL,
                    task_index INTEGER NOT NULL,
                    state TEXT NOT NULL,
                    status TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    PRIMARY KEY (mission_id, task_index)
                )
            """)
            conn.commit()

    def save_checkpoint(self, mission_id: str, task_index: int, state: Dict[str, Any]) -> None:
        status = state.get("status", "in_progress")
        timestamp = state.get("timestamp") or datetime.now().isoformat()
        state["timestamp"] = timestamp
        state_str = json.dumps(state)
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO checkpoints (mission_id, task_index, state, status, timestamp)
                VALUES (?, ?, ?, ?, ?)
            """, (mission_id, task_index, state_str, status, timestamp))
            conn.commit()
        logger.debug(f"Saved checkpoint for mission {mission_id}, task {task_index} (status: {status})")

    def load_latest_checkpoint(self, mission_id: str) -> Optional[Dict[str, Any]]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT state FROM checkpoints
                WHERE mission_id = ?
                ORDER BY task_index DESC LIMIT 1
            """, (mission_id,))
            row = cursor.fetchone()
            if row:
                return json.loads(row[0])
        return None

    def list_runs(self, mission_id: Optional[str] = None) -> List[Dict[str, Any]]:
        query = "SELECT mission_id, task_index, status, timestamp FROM checkpoints"
        params = ()
        if mission_id:
            query += " WHERE mission_id = ?"
            params = (mission_id,)
        query += " ORDER BY timestamp DESC"
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            return [
                {
                    "mission_id": r[0],
                    "task_index": r[1],
                    "status": r[2],
                    "timestamp": r[3]
                }
                for r in cursor.fetchall()
            ]

    def mark_complete(self, mission_id: str) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                UPDATE checkpoints SET status = 'completed' WHERE mission_id = ?
            """, (mission_id,))
            conn.commit()
        logger.debug(f"Marked mission {mission_id} as complete.")
