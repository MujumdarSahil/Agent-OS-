"""
Real-world integration test suite for M25 Continuous Security Learning Engine.

Simulates a multi-commit repository lifecycle:
- Commit 1: Initial scan with vulnerabilities
- Commit 2: Partial repair attempt and new emerging vulnerability
- Commit 3: Vulnerability reopening and failed repair regression
- Commit 4: Successful remediation and security score recovery
"""

import pytest
import os
import tempfile

from agentos_swe.learning import (
    SecurityMemory,
    ContinuousSecurityLearningEngine,
    SecurityPatternType,
    TrendDirection,
    RecurrenceClassification,
    RemediationStatus,
)
from agentos_swe.history.store import HistoricalScanStore


@pytest.fixture
def clean_learning_engine():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        db_path = tf.name
    store = HistoricalScanStore(db_path=db_path)
    memory = SecurityMemory(store=store)
    engine = ContinuousSecurityLearningEngine(memory_store=memory)
    yield engine
    if os.path.exists(db_path):
        try:
            os.remove(db_path)
        except OSError:
            pass


def test_real_world_multi_commit_security_learning_lifecycle(clean_learning_engine):
    engine = clean_learning_engine
    repo = "real_world_app"

    # =========================================================================
    # Commit 1: Initial Scan (Score: 70)
    # =========================================================================
    c1_findings = [
        {
            "finding_id": "f_sql_1",
            "fingerprint": "fp_sql_auth",
            "root_cause": "SQL_INJECTION",
            "severity": "CRITICAL",
            "file": "auth/login.py",
            "line": 35,
            "risk_score": 9.0,
        },
        {
            "finding_id": "f_xss_1",
            "fingerprint": "fp_xss_profile",
            "root_cause": "XSS",
            "severity": "MEDIUM",
            "file": "views/profile.py",
            "line": 80,
            "risk_score": 5.0,
        },
    ]

    res1 = engine.run_learning_pipeline(
        repository_name=repo,
        commit_sha="c1111111",
        current_findings=c1_findings,
        current_security_score=70,
    )

    assert res1.scan_count == 1
    assert res1.trend.trend == TrendDirection.INSUFFICIENT_DATA
    assert len(res1.adaptive_signals) == 2

    # =========================================================================
    # Commit 2: Fix SQL, XSS remains, New Command Injection emerges (Score: 60)
    # =========================================================================
    c2_findings = [
        {
            "finding_id": "f_xss_1",
            "fingerprint": "fp_xss_profile",
            "root_cause": "XSS",
            "severity": "MEDIUM",
            "file": "views/profile.py",
            "line": 80,
            "risk_score": 5.0,
        },
        {
            "finding_id": "f_cmd_1",
            "fingerprint": "fp_cmd_export",
            "root_cause": "COMMAND_INJECTION",
            "severity": "HIGH",
            "file": "utils/export.py",
            "line": 12,
            "risk_score": 8.0,
        },
    ]

    c2_validations = [
        {
            "fingerprint": "fp_sql_auth",
            "root_cause": "SQL_INJECTION",
            "strategy": "PARAMETERIZED_QUERY",
            "verdict": "PASS",
        }
    ]

    c2_repairs = [
        {
            "root_cause": "SQL_INJECTION",
            "strategy": "PARAMETERIZED_QUERY",
        }
    ]

    res2 = engine.run_learning_pipeline(
        repository_name=repo,
        commit_sha="c2222222",
        parent_commit_sha="c1111111",
        current_findings=c2_findings,
        repair_validations=c2_validations,
        repair_results=c2_repairs,
        current_security_score=60,
    )

    assert res2.scan_count == 2
    assert res2.trend.score_delta == -10
    assert res2.trend.trend in [TrendDirection.DEGRADING, TrendDirection.RAPIDLY_DEGRADING]

    detected_types_2 = {p.pattern_type for p in res2.detected_patterns}
    assert SecurityPatternType.NEW_EMERGING_PATTERN in detected_types_2
    assert SecurityPatternType.SUCCESSFUL_REMEDIATION in detected_types_2

    # Check that XSS is classified as OCCASIONAL (recurrence count 2)
    xss_rec = next(r for r in res2.recurrence_analysis if r.fingerprint == "fp_xss_profile")
    assert xss_rec.classification == RecurrenceClassification.OCCASIONAL

    # =========================================================================
    # Commit 3: SQL Reopens, Command Injection Failed Repair (Score: 40)
    # =========================================================================
    c3_findings = [
        {
            "finding_id": "f_sql_1_reopen",
            "fingerprint": "fp_sql_auth",
            "root_cause": "SQL_INJECTION",
            "severity": "CRITICAL",
            "file": "auth/login.py",
            "line": 35,
            "risk_score": 9.0,
        },
        {
            "finding_id": "f_cmd_1",
            "fingerprint": "fp_cmd_export",
            "root_cause": "COMMAND_INJECTION",
            "severity": "HIGH",
            "file": "utils/export.py",
            "line": 12,
            "risk_score": 8.0,
        },
    ]

    c3_validations = [
        {
            "fingerprint": "fp_cmd_export",
            "root_cause": "COMMAND_INJECTION",
            "strategy": "STRING_SANITIZATION",
            "verdict": "FAIL",
        }
    ]

    c3_repairs = [
        {
            "root_cause": "COMMAND_INJECTION",
            "strategy": "STRING_SANITIZATION",
        }
    ]

    res3 = engine.run_learning_pipeline(
        repository_name=repo,
        commit_sha="c3333333",
        parent_commit_sha="c2222222",
        current_findings=c3_findings,
        repair_validations=c3_validations,
        repair_results=c3_repairs,
        current_security_score=40,
    )

    assert res3.scan_count == 3
    assert res3.trend.trend == TrendDirection.RAPIDLY_DEGRADING

    detected_types_3 = {p.pattern_type for p in res3.detected_patterns}
    assert SecurityPatternType.REOPENED_VULNERABILITY in detected_types_3
    assert SecurityPatternType.FAILED_REMEDIATION in detected_types_3

    # Check adaptive risk multiplier for reopened SQL finding
    sql_signal = next(s for s in res3.adaptive_signals if s.fingerprint == "fp_sql_auth")
    assert sql_signal.risk_multiplier >= 1.30
    assert sql_signal.priority_boost is True

    # =========================================================================
    # Commit 4: Successful full remediation of all findings (Score: 100)
    # =========================================================================
    c4_validations = [
        {
            "fingerprint": "fp_sql_auth",
            "root_cause": "SQL_INJECTION",
            "strategy": "PARAMETERIZED_QUERY",
            "verdict": "PASS",
        },
        {
            "fingerprint": "fp_cmd_export",
            "root_cause": "COMMAND_INJECTION",
            "strategy": "REPLACE_SHELL_TRUE_WITH_ARG_ARRAY",
            "verdict": "PASS",
        },
    ]

    res4 = engine.run_learning_pipeline(
        repository_name=repo,
        commit_sha="c4444444",
        parent_commit_sha="c3333333",
        current_findings=[],
        repair_validations=c4_validations,
        current_security_score=100,
    )

    assert res4.scan_count == 4
    assert res4.trend.score_delta == +60
    assert res4.trend.trend == TrendDirection.RAPIDLY_IMPROVING
    assert res4.explainability is not None
