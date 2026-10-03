"""
Targeted tests for M7 Observability & Evaluation.
"""

import json
import pytest
from agentos_swe.observability.tracer import TraceCollector
from agentos_swe.observability.report import ReportGenerator
from agentos_swe.observability.models import TraceEvent, RunReport


@pytest.fixture(autouse=True)
def mock_llm_env(monkeypatch):
    monkeypatch.setenv("AGENTOS_MOCK_LLM", "1")


def test_trace_collector_event_recording():
    collector = TraceCollector(mission_id="mission_e2e_obs_1")

    # Record investigation event
    e1 = collector.record_event(
        stage="INVESTIGATION",
        agent_name="BugAgent",
        provider="ollama",
        model="llama3",
        tokens=150,
        latency_sec=1.2,
        status="CONFIRMED",
        details={"info": "Found bug with token ghp_secret1234567890abcdef1234567890"},
    )

    assert e1.stage == "INVESTIGATION"
    assert e1.agent_name == "BugAgent"
    assert e1.tokens == 150
    # Secret redaction check in details
    assert "ghp_" not in e1.details["info"]
    assert "[REDACTED_GITHUB_TOKEN]" in e1.details["info"]

    # Record fallback event
    e2 = collector.record_event(
        stage="REPAIR",
        agent_name="FixAgent",
        provider="openai",
        model="gpt-4o",
        tokens=200,
        latency_sec=2.5,
        fallback_triggered=True,
        fallback_from="ollama",
        fallback_to="openai",
        status="VALIDATED",
    )

    assert e2.fallback_triggered is True
    assert collector.fallback_count == 1

    # Record checkpoint event
    collector.record_event(
        stage="CHECKPOINT_RESTORE",
        checkpoint_action="restored",
        status="SUCCESS",
    )

    assert collector.checkpoint_recoveries == 1


def test_agent_metrics_aggregation():
    collector = TraceCollector()

    collector.record_event(stage="INV", agent_name="BugAgent", tokens=100, latency_sec=0.5, status="SUCCESS")
    collector.record_event(stage="INV", agent_name="BugAgent", tokens=150, latency_sec=0.7, status="FAILED")

    metrics = collector.agent_metrics["BugAgent"]
    assert metrics.execution_count == 2
    assert metrics.success_count == 1
    assert metrics.failure_count == 1
    assert metrics.total_tokens == 250
    assert abs(metrics.total_duration_sec - 1.2) < 0.01


def test_run_report_generation_json_and_markdown():
    collector = TraceCollector(mission_id="mission_report_test")

    collector.record_event(stage="INTAKE", status="SUCCESS")
    collector.record_event(stage="INVESTIGATION", agent_name="SecurityAgent", tokens=300, latency_sec=1.5, status="CONFIRMED")
    collector.record_event(stage="PATCH_GENERATED", agent_name="FixAgent", tokens=500, latency_sec=2.0, status="SUCCESS")
    collector.record_event(stage="VALIDATED", agent_name="FixAgent", status="VALIDATED")

    generator = ReportGenerator()
    report = generator.generate_run_report(collector, repository_name="test_repo", commit_ref="abc1234")

    assert report.repository_name == "test_repo"
    assert report.commit_ref == "abc1234"
    assert report.total_tokens == 800
    assert report.repair_metrics.validated_patches == 1

    # JSON export check
    report_dict = report.to_dict()
    report_json = json.dumps(report_dict)
    assert "test_repo" in report_json
    assert "SecurityAgent" in report_json

    # Markdown export check
    md = generator.render_markdown_report(report)
    assert "# 📊 AgentOS-SWE Execution Run Report" in md
    assert "`test_repo`" in md
    assert "`SecurityAgent`" in md
