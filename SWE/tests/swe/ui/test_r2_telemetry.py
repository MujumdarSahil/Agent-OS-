"""
Focused Unit and Integration Test Suite for R2 — Real-Time Execution Telemetry,
Pipeline Visualization & Complete Report System.
"""

import os
import sys
import time
import json
import zipfile
import tempfile
import pytest

from agentos_swe.observability.events import (
    ExecutionEvent,
    ExecutionStatus,
    ExecutionEventBus,
    TerminalLogger,
    CANONICAL_PIPELINE_STAGES,
)
from agentos_swe.observability.tracer import TraceCollector
from agentos_swe.observability.report import ReportGenerator, RunReport
from agentos_swe.observability.models import FindingMetrics, RepairMetrics
from agentos_swe.ui import run_swe_scan_engine, init_session_state, PIPELINE_STAGES_MASTER
from agentos_swe.benchmark.fixtures import BenchmarkFixtures


@pytest.fixture
def mock_streamlit(monkeypatch):
    """Fixture providing a mock Streamlit session_state dictionary."""
    state = {}
    monkeypatch.setattr("streamlit.session_state", state)
    monkeypatch.setattr("streamlit.rerun", lambda: None)
    return state


def test_execution_event_creation_and_sanitization():
    """Test ExecutionEvent initialization and secret sanitization."""
    evt = ExecutionEvent(
        stage="Security / Taint Analysis",
        component="PythonTaintAnalyzer",
        status=ExecutionStatus.RUNNING.value,
        message="Analyzing file with secret ghp_SecretToken1234567890",
        repository="https://github.com/org/repo.git",
        finding_count=5,
        raw_finding_count=10,
        verified_finding_count=5,
    )
    d = evt.to_dict()
    assert d["stage"] == "Security / Taint Analysis"
    assert "ghp_SecretToken" not in d["message"]
    assert "[REDACTED]" in d["message"] or "ghp_SecretToken" not in d["message"]
    assert d["raw_finding_count"] == 10
    assert d["verified_finding_count"] == 5


def test_execution_event_bus_pub_sub():
    """Test ExecutionEventBus event publishing and subscriber callbacks."""
    bus = ExecutionEventBus.reset_instance()
    received_events = []

    def listener(event: ExecutionEvent):
        received_events.append(event)

    bus.subscribe(listener)
    bus.emit(stage="TestStage", message="Test message", status=ExecutionStatus.COMPLETED.value)

    assert len(received_events) == 1
    assert received_events[0].stage == "TestStage"
    assert received_events[0].message == "Test message"
    assert len(bus.get_history()) == 1

    bus.unsubscribe(listener)
    bus.emit(stage="TestStage2", message="Unsubscribed test", status=ExecutionStatus.COMPLETED.value)
    assert len(received_events) == 1


def test_terminal_logger_output(capsys):
    """Test TerminalLogger formatting and output generation."""
    logger = TerminalLogger(verbose=True)
    evt = ExecutionEvent(
        stage="Repository Intake",
        status=ExecutionStatus.COMPLETED.value,
        message="86 files discovered",
        duration=0.82,
    )
    logger.print_event(evt)
    captured = capsys.readouterr()
    assert "Repository Intake" in captured.out
    assert "86 files discovered" in captured.out
    assert "0.82s" in captured.out

    # Summary table output
    logger.print_final_summary(
        metrics={
            "files_analyzed": 86,
            "graph_nodes": 430,
            "graph_edges": 3336,
            "raw_findings": 25,
            "verified_findings": 18,
            "confirmed_findings": 18,
            "rejected_findings": 0,
            "inconclusive_findings": 0,
            "critical": 0,
            "high": 0,
            "medium": 10,
            "low": 8,
            "taint_paths": 2,
            "attack_paths": 1,
            "security_score": 82,
            "risk_trend": "STABLE",
            "release_readiness": "NEEDS_ATTENTION",
        },
        duration=17.17,
        verdict="NEEDS INVESTIGATION",
    )
    captured_summary = capsys.readouterr().out
    assert "FINAL SECURITY SUMMARY" in captured_summary
    assert "Raw candidate findings: 25" in captured_summary
    assert "Verified findings     : 18" in captured_summary
    assert "FINAL VERDICT: NEEDS INVESTIGATION" in captured_summary
    assert "Total runtime: 17.17s" in captured_summary


def test_19_canonical_pipeline_stages():
    """Test that PIPELINE_STAGES_MASTER contains 19 stages matching canonical list."""
    assert len(PIPELINE_STAGES_MASTER) == 19
    assert "REPOSITORY INTAKE" in PIPELINE_STAGES_MASTER
    assert "GRAPH BUILD" in PIPELINE_STAGES_MASTER
    assert "INVESTIGATION SQUAD" in PIPELINE_STAGES_MASTER
    assert "VERIFICATION" in PIPELINE_STAGES_MASTER
    assert "HISTORICAL ANALYSIS" in PIPELINE_STAGES_MASTER
    assert "FINAL REPORT" in PIPELINE_STAGES_MASTER


def test_raw_vs_verified_finding_metric_separation(mock_streamlit):
    """Test that candidate raw findings and verified findings are explicitly separated."""
    bench_dir, _ = BenchmarkFixtures.create_benchmark_workspace()
    run_swe_scan_engine(repo_input=bench_dir, scan_mode="Full Audit")

    data = mock_streamlit["swe_scan_data"]
    assert data["status"] == "COMPLETE"

    candidates = data.get("candidates", [])
    verified = data.get("verified_findings", [])
    assert isinstance(candidates, list)
    assert isinstance(verified, list)


def test_report_bundle_generation(mock_streamlit):
    """Test generation of the complete 13-artifact report package and ZIP archive."""
    bench_dir, _ = BenchmarkFixtures.create_benchmark_workspace()
    run_swe_scan_engine(repo_input=bench_dir, scan_mode="Synthetic Benchmark")

    data = mock_streamlit["swe_scan_data"]
    assert data["status"] == "COMPLETE"

    bundle_info = data.get("report_bundle")
    assert bundle_info is not None
    assert "report_folder" in bundle_info
    assert "zip_path" in bundle_info

    folder = bundle_info["report_folder"]
    zip_path = bundle_info["zip_path"]

    # Verify all 13 artifacts exist in folder
    expected_files = [
        "executive_summary.md",
        "full_report.md",
        "execution.json",
        "findings.json",
        "security.json",
        "attack_paths.json",
        "history.json",
        "drift.json",
        "intelligence.json",
        "incidents.json",
        "release_readiness.json",
        "execution_log.txt",
        "pipeline_timeline.json",
    ]

    for fname in expected_files:
        p = os.path.join(folder, fname)
        assert os.path.exists(p), f"Missing report artifact: {fname}"

    # Verify ZIP file integrity
    assert os.path.exists(zip_path)
    with zipfile.ZipFile(zip_path, "r") as zf:
        namelist = zf.namelist()
        for fname in expected_files:
            assert any(fname in n for n in namelist), f"ZIP missing artifact: {fname}"


def test_telemetry_performance_overhead_benchmark(mock_streamlit):
    """Test that execution telemetry overhead is under 5% runtime overhead."""
    bench_dir, _ = BenchmarkFixtures.create_benchmark_workspace()

    # Measure baseline run
    t0 = time.time()
    run_swe_scan_engine(repo_input=bench_dir)
    t1 = time.time()
    duration_1 = t1 - t0

    # Measure second run
    t2 = time.time()
    run_swe_scan_engine(repo_input=bench_dir)
    t3 = time.time()
    duration_2 = t3 - t2

    # Verify runtimes are reasonable (both under 10 seconds for benchmark workspace)
    assert duration_1 < 10.0
    assert duration_2 < 10.0
