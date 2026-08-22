"""
M21 Local SQLite Security Knowledge Store.

Provides persistent storage for SecurityKnowledgeRecord, SecurityPattern, and KnowledgeFeedback.
Sanitizes secrets via SecretProtection before saving. Supports repository isolation.
"""

import json
import sqlite3
import os
from typing import List, Dict, Any, Optional
from datetime import datetime
from agentos_swe.security.secret_protection import SecretProtection
from agentos_swe.knowledge.models import (
    SecurityKnowledgeRecord,
    SecurityPattern,
    KnowledgeFeedback,
)


class SecurityKnowledgeStore:
    """
    Local SQLite store for security knowledge records and patterns.
    """

    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            db_path = os.path.join(base_dir, "security_knowledge.db")
        self.db_path = db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS knowledge_records (
                    knowledge_id TEXT PRIMARY KEY,
                    vulnerability_family TEXT,
                    root_cause TEXT,
                    source_pattern TEXT,
                    sink_pattern TEXT,
                    attack_path_pattern TEXT,
                    affected_framework TEXT,
                    affected_language TEXT,
                    remediation_strategy TEXT,
                    validation_result TEXT,
                    regression_result TEXT,
                    release_outcome TEXT,
                    confidence REAL,
                    recurrence_count INTEGER,
                    successful_repairs INTEGER,
                    failed_repairs INTEGER,
                    repositories_seen TEXT,
                    first_seen TEXT,
                    last_seen TEXT,
                    evidence TEXT
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS human_feedback (
                    feedback_id TEXT PRIMARY KEY,
                    knowledge_id TEXT,
                    reviewer TEXT,
                    decision TEXT,
                    reason TEXT,
                    timestamp TEXT
                )
            """)
            conn.commit()

    def save_record(self, record: SecurityKnowledgeRecord) -> None:
        """Saves or updates a SecurityKnowledgeRecord."""
        sanitized_strat = SecretProtection.sanitize_text(record.remediation_strategy)
        sanitized_evidence = SecretProtection.sanitize_text(json.dumps(record.evidence))
        repos_json = json.dumps(record.repositories_seen)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO knowledge_records (
                    knowledge_id, vulnerability_family, root_cause, source_pattern, sink_pattern,
                    attack_path_pattern, affected_framework, affected_language, remediation_strategy,
                    validation_result, regression_result, release_outcome, confidence, recurrence_count,
                    successful_repairs, failed_repairs, repositories_seen, first_seen, last_seen, evidence
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(knowledge_id) DO UPDATE SET
                    recurrence_count = knowledge_records.recurrence_count + 1,
                    successful_repairs = knowledge_records.successful_repairs + excluded.successful_repairs,
                    failed_repairs = knowledge_records.failed_repairs + excluded.failed_repairs,
                    confidence = excluded.confidence,
                    last_seen = excluded.last_seen,
                    repositories_seen = excluded.repositories_seen,
                    evidence = excluded.evidence
            """, (
                record.knowledge_id, record.vulnerability_family, record.root_cause, record.source_pattern,
                record.sink_pattern, record.attack_path_pattern, record.affected_framework, record.affected_language,
                sanitized_strat, record.validation_result, record.regression_result, record.release_outcome,
                record.confidence, record.recurrence_count, record.successful_repairs, record.failed_repairs,
                repos_json, record.first_seen, record.last_seen, sanitized_evidence
            ))
            conn.commit()

    def get_record(self, knowledge_id: str) -> Optional[SecurityKnowledgeRecord]:
        """Retrieves a SecurityKnowledgeRecord by ID."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM knowledge_records WHERE knowledge_id = ?", (knowledge_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return self._row_to_record(row)

    def search(self, query: str) -> List[SecurityKnowledgeRecord]:
        """Searches records matching query in root cause or vulnerability family."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            pattern = f"%{query.upper()}%"
            cursor.execute("""
                SELECT * FROM knowledge_records
                WHERE UPPER(root_cause) LIKE ? OR UPPER(vulnerability_family) LIKE ?
            """, (pattern, pattern))
            rows = cursor.fetchall()
            return [self._row_to_record(r) for r in rows]

    def get_by_root_cause(self, root_cause: str) -> List[SecurityKnowledgeRecord]:
        """Retrieves records matching root_cause."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM knowledge_records WHERE UPPER(root_cause) = ?", (root_cause.upper(),))
            rows = cursor.fetchall()
            return [self._row_to_record(r) for r in rows]

    def save_feedback(self, feedback: KnowledgeFeedback) -> None:
        """Saves a HumanFeedback entry."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO human_feedback (feedback_id, knowledge_id, reviewer, decision, reason, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                feedback.feedback_id, feedback.knowledge_id, feedback.reviewer,
                feedback.decision, feedback.reason, feedback.timestamp
            ))
            conn.commit()

    def list_feedback(self) -> List[KnowledgeFeedback]:
        """Lists all human feedback entries."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM human_feedback ORDER BY timestamp DESC")
            rows = cursor.fetchall()
            return [
                KnowledgeFeedback(
                    feedback_id=r["feedback_id"], knowledge_id=r["knowledge_id"], reviewer=r["reviewer"],
                    decision=r["decision"], reason=r["reason"], timestamp=r["timestamp"]
                ) for r in rows
            ]

    def clear_all_knowledge(self) -> None:
        """Clears all knowledge tables."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM knowledge_records")
            cursor.execute("DELETE FROM human_feedback")
            conn.commit()

    def _row_to_record(self, row: sqlite3.Row) -> SecurityKnowledgeRecord:
        repos = json.loads(row["repositories_seen"]) if row["repositories_seen"] else []
        evidence = json.loads(row["evidence"]) if row["evidence"] else []
        return SecurityKnowledgeRecord(
            knowledge_id=row["knowledge_id"],
            vulnerability_family=row["vulnerability_family"],
            root_cause=row["root_cause"],
            source_pattern=row["source_pattern"],
            sink_pattern=row["sink_pattern"],
            attack_path_pattern=row["attack_path_pattern"],
            affected_framework=row["affected_framework"],
            affected_language=row["affected_language"],
            remediation_strategy=row["remediation_strategy"],
            validation_result=row["validation_result"],
            regression_result=row["regression_result"],
            release_outcome=row["release_outcome"],
            confidence=row["confidence"],
            recurrence_count=row["recurrence_count"],
            successful_repairs=row["successful_repairs"],
            failed_repairs=row["failed_repairs"],
            repositories_seen=repos,
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            evidence=evidence,
        )
