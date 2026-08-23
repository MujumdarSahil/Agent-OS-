"""
Unit test suite for M25 — Continuous Security Learning, Trend Intelligence & Adaptive Risk Engine.
"""

import pytest
import os
import tempfile
from datetime import datetime

from agentos_swe.learning import (
    SecurityMemory,
    SecurityPatternDetector,
    SecurityTrendAnalyzer,
    RecurrenceAnalyzer,
    RemediationLearningEngine,
    AdaptiveRiskEngine,
    LearningExplainabilityEngine,
    ContinuousSecurityLearningEngine,
    SecurityPatternType,
    TrendDirection,
    RecurrenceClassification,
    RemediationStatus,
    SecurityPattern,
    SecurityTrend,
)
from agentos_swe.history.store import HistoricalScanStore
from agentos_swe.history.models import ScanRecord


@pytest.fixture
def temp_db_store():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        db_path = tf.name
    store = HistoricalScanStore(db_path=db_path)
    memory = SecurityMemory(store=store)
    yield memory, store
    if os.path.exists(db_path):
        try:
            os.remove(db_path)
        except OSError:
            pass


def test_security_memory_persistence(temp_db_store):
    memory, store = temp_db_store

    scan1 = ScanRecord(
        scan_id="scan_001",
        repository="test_repo",
        commit_sha="c11111",
        timestamp=datetime.now().isoformat(),
        security_score=85,
        findings=[
            {
                "fingerprint": "fp_sql_01",
                "root_cause": "SQL_INJECTION",
                "severity": "HIGH",
                "file": "db/query.py",
                "line": 42,
            }
        ],
    )
    assert memory.record_scan_snapshot(scan1) is True

    scans = memory.get_repository_scans("test_repo")
    assert len(scans) == 1
    assert scans[0].commit_sha == "c11111"

    mems = memory.extract_finding_memories("test_repo")
    assert len(mems) == 1
    assert mems[0]["fingerprint"] == "fp_sql_01"
    assert mems[0]["root_cause"] == "SQL_INJECTION"
    assert mems[0]["recurrence_count"] == 1


def test_security_pattern_detector_all_10_patterns():
    detector = SecurityPatternDetector()

    memories = [
        # Recurring and Chronic
        {
            "fingerprint": "fp_cmd_01",
            "root_cause": "COMMAND_INJECTION",
            "file": "app/exec.py",
            "recurrence_count": 3,
            "reopened_count": 1,
            "scan_occurrences": ["s1", "s2", "s3"],
            "repair_validation_result": "FAIL",
            "active": True,
        },
        # Repeated root cause & hotspot file
        {
            "fingerprint": "fp_cmd_02",
            "root_cause": "COMMAND_INJECTION",
            "file": "app/exec.py",
            "recurrence_count": 1,
            "reopened_count": 0,
            "scan_occurrences": ["s3"],
            "active": True,
        },
        {
            "fingerprint": "fp_cmd_03",
            "root_cause": "COMMAND_INJECTION",
            "file": "app/exec.py",
            "recurrence_count": 1,
            "reopened_count": 0,
            "scan_occurrences": ["s3"],
            "active": True,
        },
        # Successful remediation
        {
            "fingerprint": "fp_xss_01",
            "root_cause": "XSS",
            "file": "views/render.py",
            "recurrence_count": 1,
            "reopened_count": 0,
            "repair_validation_result": "PASS",
            "active": False,
        },
    ]

    scans = [
        ScanRecord(scan_id="s3", repository="r1", security_score=70),
        ScanRecord(scan_id="s2", repository="r1", security_score=80),
        ScanRecord(scan_id="s1", repository="r1", security_score=90),
    ]

    current_findings = [
        {"root_cause": "PATH_TRAVERSAL", "file": "utils/fs.py", "line": 10}
    ]

    patterns = detector.detect_patterns(
        finding_memories=memories,
        historical_scans=scans,
        current_findings=current_findings,
        drift_result={"drift": {"category": "NEGATIVE_DRIFT"}},
    )

    detected_types = {p.pattern_type for p in patterns}

    assert SecurityPatternType.RECURRING_VULNERABILITY in detected_types
    assert SecurityPatternType.REOPENED_VULNERABILITY in detected_types
    assert SecurityPatternType.REPEATED_ROOT_CAUSE in detected_types
    assert SecurityPatternType.REPEATED_FILE_PATTERN in detected_types
    assert SecurityPatternType.REPEATED_SECURITY_DRIFT in detected_types
    assert SecurityPatternType.FAILED_REMEDIATION in detected_types
    assert SecurityPatternType.SUCCESSFUL_REMEDIATION in detected_types
    assert SecurityPatternType.PERSISTENT_VULNERABILITY in detected_types
    assert SecurityPatternType.NEW_EMERGING_PATTERN in detected_types


def test_trend_analyzer():
    analyzer = SecurityTrendAnalyzer()

    # 1. Improving trend
    scans_improving = [
        ScanRecord(scan_id="s2", repository="r1", security_score=70),
        ScanRecord(scan_id="s1", repository="r1", security_score=60),
    ]
    trend_imp = analyzer.analyze_trends(scans_improving, current_score=90)
    assert trend_imp.trend == TrendDirection.RAPIDLY_IMPROVING
    assert trend_imp.score_delta == 20

    # 2. Degrading trend
    scans_degrading = [
        ScanRecord(scan_id="s2", repository="r1", security_score=90),
        ScanRecord(scan_id="s1", repository="r1", security_score=95),
    ]
    trend_deg = analyzer.analyze_trends(scans_degrading, current_score=70)
    assert trend_deg.trend == TrendDirection.RAPIDLY_DEGRADING
    assert trend_deg.score_delta == -20

    # 3. Insufficient data
    trend_empty = analyzer.analyze_trends([], current_score=85)
    assert trend_empty.trend == TrendDirection.INSUFFICIENT_DATA


def test_recurrence_analyzer():
    analyzer = RecurrenceAnalyzer()

    memories = [
        {
            "fingerprint": "fp_1",
            "root_cause": "SQL_INJECTION",
            "file": "db.py",
            "recurrence_count": 1,
            "reopened_count": 0,
        },
        {
            "fingerprint": "fp_2",
            "root_cause": "XSS",
            "file": "ui.py",
            "recurrence_count": 2,
            "reopened_count": 0,
        },
        {
            "fingerprint": "fp_3",
            "root_cause": "COMMAND_INJECTION",
            "file": "cmd.py",
            "recurrence_count": 4,
            "reopened_count": 0,
        },
        {
            "fingerprint": "fp_4",
            "root_cause": "PATH_TRAVERSAL",
            "file": "fs.py",
            "recurrence_count": 6,
            "reopened_count": 0,
        },
        {
            "fingerprint": "fp_5",
            "root_cause": "INSECURE_DESERIALIZATION",
            "file": "ser.py",
            "recurrence_count": 3,
            "reopened_count": 2,
            "repair_validation_result": "FAIL",
        },
    ]

    recs = analyzer.analyze_recurrence(memories)
    class_map = {r.fingerprint: r.classification for r in recs}

    assert class_map["fp_1"] == RecurrenceClassification.FIRST_SEEN
    assert class_map["fp_2"] == RecurrenceClassification.OCCASIONAL
    assert class_map["fp_3"] == RecurrenceClassification.RECURRING
    assert class_map["fp_4"] == RecurrenceClassification.PERSISTENT
    assert class_map["fp_5"] == RecurrenceClassification.CHRONIC


def test_remediation_learning_engine():
    engine = RemediationLearningEngine()

    scans = [
        ScanRecord(
            scan_id="s1",
            repository="r1",
            repair_results=[{"root_cause": "SQL_INJECTION", "strategy": "PARAMETERIZED_QUERY"}],
            repair_validations=[{"root_cause": "SQL_INJECTION", "strategy": "PARAMETERIZED_QUERY", "verdict": "PASS"}],
        ),
        ScanRecord(
            scan_id="s2",
            repository="r1",
            repair_results=[{"root_cause": "SQL_INJECTION", "strategy": "PARAMETERIZED_QUERY"}],
            repair_validations=[{"root_cause": "SQL_INJECTION", "strategy": "PARAMETERIZED_QUERY", "verdict": "PASS"}],
        ),
    ]

    records = engine.analyze_remediation_efficacy(scans, [])
    assert len(records) >= 1
    sql_rec = next(r for r in records if r.root_cause == "SQL_INJECTION")
    assert sql_rec.status == RemediationStatus.SUCCESSFUL
    assert sql_rec.successful_repairs == 2
    assert sql_rec.success_rate == 1.0


def test_adaptive_risk_engine():
    adapter = AdaptiveRiskEngine()

    current_findings = [
        {"finding_id": "f1", "fingerprint": "fp_chronic", "root_cause": "COMMAND_INJECTION", "risk_score": 7.0}
    ]

    recurrence_insights = [
        RecurrenceAnalyzer().analyze_recurrence([
            {
                "fingerprint": "fp_chronic",
                "root_cause": "COMMAND_INJECTION",
                "file": "cmd.py",
                "recurrence_count": 4,
                "reopened_count": 2,
            }
        ])[0]
    ]

    patterns = [
        SecurityPattern(
            pattern_type=SecurityPatternType.RECURRING_VULNERABILITY,
            title="Recurring",
            description="Recurring test",
        )
    ]

    signals = adapter.compute_adaptive_signals(current_findings, recurrence_insights, patterns)
    assert len(signals) == 1
    sig = signals[0]

    assert sig.risk_multiplier > 1.5
    assert sig.priority_boost is True
    assert sig.adapted_risk_score > sig.base_risk_score


def test_explainability_engine():
    engine = LearningExplainabilityEngine()

    patterns = [
        SecurityPattern(
            pattern_type=SecurityPatternType.RECURRING_VULNERABILITY,
            title="Recurring Vulnerability",
            description="Finding recurred across scans.",
        )
    ]
    trend = SecurityTrend(current_score=90, score_delta=10, trend=TrendDirection.IMPROVING)

    report = engine.generate_explainability_report(
        repository_name="test_repo",
        detected_patterns=patterns,
        trend=trend,
        recurrence_insights=[],
        remediation_lessons=[],
        adaptive_signals=[],
    )

    assert "test_repo" in report.summary
    assert len(report.explanation_details) >= 2


def test_continuous_security_learning_engine_end_to_end(temp_db_store):
    memory, store = temp_db_store
    engine = ContinuousSecurityLearningEngine(memory_store=memory)

    findings = [
        {
            "finding_id": "f_eval_1",
            "fingerprint": "fp_eval_1",
            "root_cause": "CODE_INJECTION",
            "severity": "CRITICAL",
            "file": "eval_service.py",
            "line": 15,
            "risk_score": 8.5,
        }
    ]

    result = engine.run_learning_pipeline(
        repository_name="learning_repo",
        commit_sha="c_test_001",
        current_findings=findings,
        current_security_score=80,
    )

    assert result.repository_name == "learning_repo"
    assert result.commit_sha == "c_test_001"
    assert result.scan_count == 1
    assert result.trend is not None
    assert result.explainability is not None
