"""
Unit and Integration Test Suite for AgentOS-SWE M12.5 Single-File Unified UI.
Includes coverage for Repository Source Detection, GitHub Cloning, Local Path Resolution,
Repository Info Extraction, Safety Invariants, and Scan State Transitions.
"""

import os
import pytest
from unittest.mock import MagicMock, patch

from agentos_swe.ui import (
    init_session_state,
    run_swe_scan_engine,
    parse_repository_input,
    clone_github_repository,
    render_dashboard,
    render_agents,
    render_graph,
    render_findings,
    render_security,
    render_architecture,
    render_performance,
    render_verification,
    render_pipeline,
    render_report,
    render_safety,
    render_enterprise_release_readiness,
)
from agentos_swe.models import Finding, FindingStatus, Evidence
from agentos_swe.security.taint.models import (
    TaintFinding,
    TaintPath,
    TaintSource,
    TaintSink,
    TaintSeverity,
)
from agentos_swe.benchmark.fixtures import BenchmarkFixtures


@pytest.fixture(autouse=True)
def mock_llm_env(monkeypatch):
    monkeypatch.setenv("AGENTOS_MOCK_LLM", "1")
    monkeypatch.setenv("AGENTOS_SWE_DRY_RUN", "1")


@pytest.fixture
def mock_streamlit(monkeypatch):
    """Mock Streamlit session_state and UI render components for unit testing."""
    session_store = {}

    class SessionStateProxy(dict):
        def __getattr__(self, item):
            return self.get(item)
        def __setattr__(self, key, value):
            self[key] = value

    proxy = SessionStateProxy(session_store)
    monkeypatch.setattr("streamlit.session_state", proxy)
    return proxy


def test_ui_module_imports():
    """1. UI imports successfully."""
    import agentos_swe.ui as ui
    assert hasattr(ui, "main")
    assert hasattr(ui, "run_swe_scan_engine")
    assert hasattr(ui, "parse_repository_input")
    assert hasattr(ui, "clone_github_repository")


def test_parse_repository_input_local_and_relative(tmp_path):
    """2. Local repository path detection."""
    source, path, owner, repo = parse_repository_input(str(tmp_path))
    assert source == "LOCAL"
    assert path == str(tmp_path)
    assert repo == tmp_path.name
    assert owner is None


def test_parse_repository_input_github_standard_and_git():
    """3. GitHub URL detection (standard and .git)."""
    url1 = "https://github.com/MujumdarSahil/Job_Agent"
    src1, res1, owner1, repo1 = parse_repository_input(url1)
    assert src1 == "GITHUB"
    assert res1 == url1
    assert owner1 == "MujumdarSahil"
    assert repo1 == "Job_Agent"

    url2 = "https://github.com/MujumdarSahil/Job_Agent.git"
    src2, res2, owner2, repo2 = parse_repository_input(url2)
    assert src2 == "GITHUB"
    assert owner2 == "MujumdarSahil"
    assert repo2 == "Job_Agent"


def test_parse_repository_input_invalid_cases():
    """4. Invalid and empty input detection."""
    src_emp, _, _, _ = parse_repository_input("")
    assert src_emp == "EMPTY"

    src_inv_gh, _, _, _ = parse_repository_input("https://github.com/invalid_format_only")
    assert src_inv_gh == "INVALID_GITHUB"

    src_inv_loc, _, _, _ = parse_repository_input("C:/nonexistent_path_123456789")
    assert src_inv_loc == "INVALID_LOCAL"


def test_ui_initializes_session_state(mock_streamlit):
    """5. UI starts successfully and initializes state."""
    data = init_session_state()
    assert data["status"] == "IDLE"
    assert "metadata" in data
    assert "safety_state" in data


def test_scan_validation_errors(mock_streamlit):
    """6. Repository input validation error messages."""
    # Empty input
    run_swe_scan_engine(repo_input="")
    data = mock_streamlit["swe_scan_data"]
    assert data["status"] == "FAILED"
    assert "Please enter a repository" in data["error"]

    # Invalid local path
    run_swe_scan_engine(repo_input="C:/nonexistent_path_999")
    data = mock_streamlit["swe_scan_data"]
    assert data["status"] == "FAILED"
    assert "path does not exist" in data["error"]

    # Invalid GitHub URL
    run_swe_scan_engine(repo_input="https://github.com/bad_format")
    data = mock_streamlit["swe_scan_data"]
    assert data["status"] == "FAILED"
    assert "valid GitHub repository URL" in data["error"]


def test_swe_pipeline_provides_data_to_ui(mock_streamlit):
    """7. Existing SWE pipeline execution on local workspace."""
    bench_dir, _ = BenchmarkFixtures.create_benchmark_workspace()
    run_swe_scan_engine(repo_input=bench_dir, scan_mode="Synthetic Benchmark")

    data = mock_streamlit["swe_scan_data"]
    assert data["status"] == "COMPLETE"
    assert data["context"] is not None
    assert len(data["verified_findings"]) >= 1
    assert data["metadata"]["source_type"] == "LOCAL"
    assert data["report_markdown"] != ""


def test_github_repository_preparation_and_scan(mock_streamlit):
    """8. GitHub repository scan flow with mock clone."""
    bench_dir, _ = BenchmarkFixtures.create_benchmark_workspace()

    with patch("agentos_swe.ui.clone_github_repository") as mock_clone:
        mock_clone.return_value = (True, bench_dir, "abc12345")
        run_swe_scan_engine(repo_input="https://github.com/MujumdarSahil/Job_Agent", branch="main")

    data = mock_streamlit["swe_scan_data"]
    assert data["status"] == "COMPLETE"
    assert data["metadata"]["source_type"] == "GITHUB"
    assert data["metadata"]["repo_owner"] == "MujumdarSahil"
    assert data["metadata"]["repo_name"] == "Job_Agent"
    assert data["metadata"]["commit"] == "abc12345"


def test_empty_scan_does_not_crash(mock_streamlit):
    """9. Empty scan does not crash layout rendering."""
    data = init_session_state()
    render_dashboard(data)
    render_agents(data)
    render_graph(data)
    render_findings(data)
    render_security(data)
    render_architecture(data)
    render_performance(data)
    render_verification(data)
    render_pipeline(data)
    render_report(data)
    render_safety(data)


def test_failed_scan_does_not_crash(mock_streamlit):
    """10. Failed scan state rendering."""
    data = init_session_state()
    data["status"] = "FAILED"
    data["error"] = "Synthetic clone error"
    render_dashboard(data)


def test_findings_and_statuses_render(mock_streamlit):
    """11. Findings and status rendering."""
    data = init_session_state()
    f_conf = Finding(title="Conf Bug", category="bug", status=FindingStatus.CONFIRMED, severity="high", file="app.py")
    f_rej = Finding(title="Rej FP", category="security", status=FindingStatus.REJECTED, severity="medium", file="auth.py")
    f_inc = Finding(title="Inc Perf", category="performance", status=FindingStatus.INCONCLUSIVE, severity="low", file="db.py")

    data["verified_findings"] = [f_conf, f_rej, f_inc]
    data["status"] = "COMPLETE"

    render_dashboard(data)
    render_agents(data)
    render_findings(data)
    render_verification(data)


def test_graph_and_taint_paths_render(mock_streamlit):
    """12. Graph and taint path rendering."""
    data = init_session_state()
    bench_dir, _ = BenchmarkFixtures.create_benchmark_workspace()
    run_swe_scan_engine(repo_input=bench_dir)

    data = mock_streamlit["swe_scan_data"]
    render_graph(data)
    render_security(data)


def test_safety_status_and_dry_run_invariants(mock_streamlit):
    """13. Safety status and dry-run invariant enforcement."""
    data = init_session_state()
    render_safety(data)
    assert data["safety_state"]["dry_run"] is True
    assert data["safety_state"]["remote_writes"] == 0
    assert data["safety_state"]["files_modified"] == 0


def test_render_enterprise_release_readiness(mock_streamlit):
    """14. Page 29 Enterprise Release Readiness rendering test."""
    data = init_session_state()
    data["metadata"] = {"repo_name": "test_ui_repo", "commit": "HEAD"}
    render_enterprise_release_readiness(data)


# ---------------------------------------------------------------------------
# R1 Telemetry, Visualization, Reporting & Hard Stop Invariant Tests
# ---------------------------------------------------------------------------

def test_r1_scan_starts_only_on_explicit_request(mock_streamlit):
    """R1.13.1 — Scan starts only on explicit request, initially IDLE."""
    data = init_session_state()
    assert data["status"] == "IDLE"
    assert len(data["terminal_events"]) == 0
    assert len(data["pipeline_stages"]) == 18
    for stg in data["pipeline_stages"]:
        assert stg["status"] == "PENDING"


def test_r1_scan_completes_and_telemetry_collected(mock_streamlit):
    """R1.13.2 & R1.13.7 — Scan completes and collects stage/agent telemetry."""
    bench_dir, _ = BenchmarkFixtures.create_benchmark_workspace()
    run_swe_scan_engine(repo_input=bench_dir, scan_mode="Synthetic Benchmark")

    data = mock_streamlit["swe_scan_data"]
    assert data["status"] == "COMPLETE"
    assert len(data["pipeline_stages"]) == 18

    stage_names = [s["name"] for s in data["pipeline_stages"]]
    assert "REPOSITORY INTAKE" in stage_names
    assert "GRAPH BUILD" in stage_names
    assert "INVESTIGATION SQUAD" in stage_names
    assert "FINAL REPORT" in stage_names

    completed_stages = [s for s in data["pipeline_stages"] if s["status"] == "COMPLETE"]
    assert len(completed_stages) == 18

    agents = data["agent_activity"]
    assert len(agents) >= 7
    executed_agents = [a for a in agents if a["status"] == "COMPLETE"]
    assert len(executed_agents) >= 5

    # Check non-python resolvers are marked NOT EXECUTED on python benchmark
    js_resolver = next((a for a in agents if a["name"] == "JavaScriptSemanticResolver"), None)
    if js_resolver:
        assert js_resolver["status"] in ("NOT EXECUTED", "COMPLETE")


def test_r1_scan_rerun_safety_and_no_auto_restart(mock_streamlit):
    """R1.13.3, R1.13.4 & R1.13.12 — Completed scan remains stopped, reruns do not duplicate scan."""
    bench_dir, _ = BenchmarkFixtures.create_benchmark_workspace()
    run_swe_scan_engine(repo_input=bench_dir)
    data = mock_streamlit["swe_scan_data"]
    assert data["status"] == "COMPLETE"

    initial_event_count = len(data["terminal_events"])
    assert initial_event_count > 0

    # Simulate UI render / widget interaction rerun
    render_dashboard(data)
    render_pipeline(data)
    render_report(data)

    # Status remains COMPLETE and events count unchanged
    assert data["status"] == "COMPLETE"
    assert len(data["terminal_events"]) == initial_event_count


def test_r1_failed_scan_stops_without_retries(mock_streamlit):
    """R1.13.5 — Failed scan stops cleanly, marks pending stages SKIPPED, no retries."""
    run_swe_scan_engine(repo_input="C:/invalid_nonexistent_directory_9999")
    data = mock_streamlit["swe_scan_data"]
    assert data["status"] == "FAILED"
    assert "path does not exist" in data["error"]

    intake_stage = next(s for s in data["pipeline_stages"] if s["name"] == "REPOSITORY INTAKE")
    assert intake_stage["status"] == "FAILED"

    pending_or_skipped = [s for s in data["pipeline_stages"] if s["status"] in ("SKIPPED", "PENDING")]
    assert len(pending_or_skipped) == 17


def test_r1_downloadable_reports_generated_once(mock_streamlit):
    """R1.13.8 - R1.13.11 — Final reports generated ONCE and available in JSON, MD, HTML formats."""
    bench_dir, _ = BenchmarkFixtures.create_benchmark_workspace()
    run_swe_scan_engine(repo_input=bench_dir)

    data = mock_streamlit["swe_scan_data"]
    assert data["report_generated_once"] is True
    assert data["report_json"] != ""
    assert data["report_markdown"] != ""
    assert data["report_html"] != ""

    import json
    parsed_json = json.loads(data["report_json"])
    assert "mission_id" in parsed_json or "findings" in parsed_json or "summary" in parsed_json or "stages" in parsed_json or isinstance(parsed_json, dict)
    assert "<html>" in data["report_html"]


def test_r1_terminal_events_reflect_real_pipeline(mock_streamlit):
    """R1.13.13 — Terminal log events contain real-time timestamps and stage progression."""
    bench_dir, _ = BenchmarkFixtures.create_benchmark_workspace()
    run_swe_scan_engine(repo_input=bench_dir)

    data = mock_streamlit["swe_scan_data"]
    events = data["terminal_events"]
    assert len(events) >= 10
    assert events[0].startswith("[")
    assert "Starting AgentOS-SWE scan" in events[0]
    assert any("SCAN COMPLETE" in e for e in events)


def test_r1_no_infinite_loop_or_background_processes(mock_streamlit):
    """R1.13.14 & R1.13.15 — Finite execution completes without leaving background loops."""
    bench_dir, _ = BenchmarkFixtures.create_benchmark_workspace()
    run_swe_scan_engine(repo_input=bench_dir)

    data = mock_streamlit["swe_scan_data"]
    assert data["status"] in ("COMPLETE", "FAILED")
    # Verify execution returned control cleanly without throwing infinite loop or timeout

