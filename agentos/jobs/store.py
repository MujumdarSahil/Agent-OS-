"""
SQLite3-only persistence store for Job Application Agent with WAL mode and schema versioning.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from agentos.jobs.models import (
    Job,
    JobStatus,
    ScoreComponent,
    validate_status_transition,
)


MIGRATIONS = [
    (
        1,
        "Initial schema: jobs, runs, source_health, audit_log tables and indexes",
        """
        CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL,
            description TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS jobs (
            id TEXT PRIMARY KEY,
            source TEXT NOT NULL,
            source_job_id TEXT NOT NULL,
            company TEXT NOT NULL,
            title TEXT NOT NULL,
            location TEXT NOT NULL,
            url TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            posted_at TEXT,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            dedupe_key TEXT NOT NULL,
            status TEXT NOT NULL,
            score REAL NOT NULL DEFAULT 0.0,
            score_breakdown TEXT NOT NULL DEFAULT '[]',
            UNIQUE(source, source_job_id)
        );

        CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
        CREATE INDEX IF NOT EXISTS idx_jobs_dedupe_key ON jobs(dedupe_key);
        CREATE INDEX IF NOT EXISTS idx_jobs_source_source_id ON jobs(source, source_job_id);

        CREATE TABLE IF NOT EXISTS runs (
            id TEXT PRIMARY KEY,
            started_at TEXT NOT NULL,
            finished_at TEXT,
            status TEXT NOT NULL,
            jobs_discovered INTEGER NOT NULL DEFAULT 0,
            jobs_saved INTEGER NOT NULL DEFAULT 0,
            error_message TEXT,
            metadata TEXT NOT NULL DEFAULT '{}'
        );

        CREATE TABLE IF NOT EXISTS source_health (
            source TEXT PRIMARY KEY,
            last_success_at TEXT,
            last_error_at TEXT,
            consecutive_failures INTEGER NOT NULL DEFAULT 0,
            last_error_message TEXT
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            job_id TEXT NOT NULL,
            from_status TEXT NOT NULL,
            to_status TEXT NOT NULL,
            reason TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_audit_log_job_id ON audit_log(job_id);
        """,
    )
]


def apply_migrations(conn: sqlite3.Connection) -> int:
    """
    Applies any unapplied migrations in sequential order.
    Returns the count of migrations applied in this run.
    """
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL,
            description TEXT NOT NULL
        );
        """
    )
    cursor = conn.cursor()
    cursor.execute("SELECT version FROM schema_version ORDER BY version ASC")
    applied_versions = {row[0] for row in cursor.fetchall()}

    applied_count = 0
    for version, description, script in MIGRATIONS:
        if version not in applied_versions:
            conn.executescript(script)
            now_str = datetime.now(timezone.utc).isoformat()
            conn.execute(
                "INSERT INTO schema_version (version, applied_at, description) VALUES (?, ?, ?)",
                (version, now_str, description),
            )
            applied_count += 1
    conn.commit()
    return applied_count


class JobStore:
    """
    SQLite3-backed persistence store for jobs, runs, source health, and transition audit logs.
    """

    def __init__(self, db_path: str | Path):
        self.db_path = str(Path(db_path).expanduser().resolve())
        # Ensure parent directory exists
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        # Apply migrations
        with self._connect() as conn:
            apply_migrations(conn)

    def _connect(self) -> sqlite3.Connection:
        """Opens a connection configured with WAL mode, busy timeout, and foreign keys."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA busy_timeout=5000;")
        conn.execute("PRAGMA foreign_keys=ON;")
        return conn

    def get_schema_version(self) -> int:
        """Returns the highest applied schema version, or 0 if none."""
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT MAX(version) FROM schema_version")
            row = cursor.fetchone()
            if row and row[0] is not None:
                return int(row[0])
            return 0

    def _row_to_job(self, row: sqlite3.Row) -> Job:
        breakdown_raw = json.loads(row["score_breakdown"]) if row["score_breakdown"] else []
        breakdown = [ScoreComponent(**item) for item in breakdown_raw]
        return Job(
            id=row["id"],
            source=row["source"],
            source_job_id=row["source_job_id"],
            company=row["company"],
            title=row["title"],
            location=row["location"],
            url=row["url"],
            description=row["description"] or "",
            posted_at=row["posted_at"],
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            dedupe_key=row["dedupe_key"],
            status=JobStatus(row["status"]),
            score=float(row["score"]),
            score_breakdown=breakdown,
        )

    def upsert_job(self, job: Job) -> Job:
        """
        Inserts a new job or updates an existing job by (source, source_job_id).
        If existing: updates metadata and last_seen while preserving existing status and first_seen.
        If new: inserts new job and writes an initial audit_log row.
        """
        now_str = datetime.now(timezone.utc).isoformat()
        breakdown_json = json.dumps([c.model_dump() for c in job.score_breakdown])

        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM jobs WHERE source = ? AND source_job_id = ?",
                (job.source, job.source_job_id),
            )
            existing = cursor.fetchone()

            if existing:
                job_id = existing["id"]
                conn.execute(
                    """
                    UPDATE jobs SET
                        company = ?,
                        title = ?,
                        location = ?,
                        url = ?,
                        description = ?,
                        posted_at = ?,
                        last_seen = ?,
                        dedupe_key = ?,
                        score = ?,
                        score_breakdown = ?
                    WHERE id = ?
                    """,
                    (
                        job.company,
                        job.title,
                        job.location,
                        job.url,
                        job.description,
                        job.posted_at,
                        now_str,
                        job.dedupe_key,
                        job.score,
                        breakdown_json,
                        job_id,
                    ),
                )
                conn.commit()
                # Return refreshed Job
                cursor.execute("SELECT * FROM jobs WHERE id = ?", (job_id,))
                return self._row_to_job(cursor.fetchone())
            else:
                conn.execute(
                    """
                    INSERT INTO jobs (
                        id, source, source_job_id, company, title, location, url,
                        description, posted_at, first_seen, last_seen, dedupe_key,
                        status, score, score_breakdown
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        job.id,
                        job.source,
                        job.source_job_id,
                        job.company,
                        job.title,
                        job.location,
                        job.url,
                        job.description,
                        job.posted_at,
                        job.first_seen or now_str,
                        now_str,
                        job.dedupe_key,
                        job.status.value,
                        job.score,
                        breakdown_json,
                    ),
                )
                # Initial discovery audit log
                conn.execute(
                    """
                    INSERT INTO audit_log (job_id, from_status, to_status, reason, created_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (job.id, "", job.status.value, "initial_discovery", now_str),
                )
                conn.commit()
                cursor.execute("SELECT * FROM jobs WHERE id = ?", (job.id,))
                return self._row_to_job(cursor.fetchone())

    def update_job_status(self, job_id: str, new_status: JobStatus, reason: str = "") -> Job:
        """
        Updates the status of an existing job, validating the transition invariants.
        Records an audit_log entry for the change.
        """
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM jobs WHERE id = ?", (job_id,))
            row = cursor.fetchone()
            if not row:
                raise KeyError(f"Job not found with id: {job_id}")

            current_status = JobStatus(row["status"])
            validate_status_transition(current_status, new_status)

            if current_status == new_status:
                return self._row_to_job(row)

            now_str = datetime.now(timezone.utc).isoformat()
            conn.execute(
                "UPDATE jobs SET status = ?, last_seen = ? WHERE id = ?",
                (new_status.value, now_str, job_id),
            )
            conn.execute(
                """
                INSERT INTO audit_log (job_id, from_status, to_status, reason, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (job_id, current_status.value, new_status.value, reason, now_str),
            )
            conn.commit()
            cursor.execute("SELECT * FROM jobs WHERE id = ?", (job_id,))
            return self._row_to_job(cursor.fetchone())

    def get_job(self, job_id: str) -> Optional[Job]:
        """Retrieves a single job by id."""
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM jobs WHERE id = ?", (job_id,))
            row = cursor.fetchone()
            return self._row_to_job(row) if row else None

    def get_job_by_source_id(self, source: str, source_job_id: str) -> Optional[Job]:
        """Retrieves a single job by source and source_job_id."""
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM jobs WHERE source = ? AND source_job_id = ?",
                (source, source_job_id),
            )
            row = cursor.fetchone()
            return self._row_to_job(row) if row else None

    def list_jobs(self, status: Optional[JobStatus] = None, limit: int = 100) -> List[Job]:
        """Lists jobs with optional status filter and limit."""
        with self._connect() as conn:
            cursor = conn.cursor()
            if status is not None:
                cursor.execute(
                    "SELECT * FROM jobs WHERE status = ? ORDER BY last_seen DESC LIMIT ?",
                    (status.value, limit),
                )
            else:
                cursor.execute(
                    "SELECT * FROM jobs ORDER BY last_seen DESC LIMIT ?",
                    (limit,),
                )
            return [self._row_to_job(row) for row in cursor.fetchall()]

    def get_audit_log(self, job_id: str) -> List[Dict[str, Any]]:
        """Returns the audit log history for a specific job."""
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, job_id, from_status, to_status, reason, created_at FROM audit_log WHERE job_id = ? ORDER BY id ASC",
                (job_id,),
            )
            return [dict(row) for row in cursor.fetchall()]

    def record_run_start(self, run_id: str, started_at: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None) -> None:
        """Records the start of a job run."""
        started = started_at or datetime.now(timezone.utc).isoformat()
        meta_json = json.dumps(metadata or {})
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO runs (id, started_at, status, metadata) VALUES (?, ?, ?, ?)",
                (run_id, started, "RUNNING", meta_json),
            )
            conn.commit()

    def record_run_finish(
        self,
        run_id: str,
        status: str,
        jobs_discovered: int = 0,
        jobs_saved: int = 0,
        error_message: Optional[str] = None,
    ) -> None:
        """Records completion or failure of a job run."""
        now_str = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE runs SET
                    finished_at = ?,
                    status = ?,
                    jobs_discovered = ?,
                    jobs_saved = ?,
                    error_message = ?
                WHERE id = ?
                """,
                (now_str, status, jobs_discovered, jobs_saved, error_message, run_id),
            )
            conn.commit()

    def record_source_health(
        self,
        source: str,
        success: bool,
        error_message: Optional[str] = None,
    ) -> None:
        """Records execution health metrics for a source adapter."""
        now_str = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM source_health WHERE source = ?", (source,))
            row = cursor.fetchone()

            if success:
                if row:
                    conn.execute(
                        "UPDATE source_health SET last_success_at = ?, consecutive_failures = 0, last_error_message = NULL WHERE source = ?",
                        (now_str, source),
                    )
                else:
                    conn.execute(
                        "INSERT INTO source_health (source, last_success_at, consecutive_failures) VALUES (?, ?, 0)",
                        (source, now_str),
                    )
            else:
                consecutive = (row["consecutive_failures"] + 1) if row else 1
                if row:
                    conn.execute(
                        "UPDATE source_health SET last_error_at = ?, consecutive_failures = ?, last_error_message = ? WHERE source = ?",
                        (now_str, consecutive, error_message, source),
                    )
                else:
                    conn.execute(
                        "INSERT INTO source_health (source, last_error_at, consecutive_failures, last_error_message) VALUES (?, ?, ?, ?)",
                        (source, now_str, consecutive, error_message),
                    )
            conn.commit()
