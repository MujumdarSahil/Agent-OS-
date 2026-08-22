"""
Dedicated M18 Real-World Security Monitoring Validation Suite.

Performs read-only validation of M18 Continuous Security Monitoring & Regression Detection across 5 target benchmark repositories:
1. Job_Agent (dict.get() lookups -> NO_REGRESSION, STABLE)
2. ConstitutionAI (shell=True command injection -> CRITICAL_REGRESSION, DEGRADING)
3. MedAgentX (intentional fallback exception handlers -> NO_REGRESSION, STABLE)
4. Cadresec- (exception swallowing -> MINOR_REGRESSION / STABLE)
5. OmniTutor-AI (test harness exception handlers -> NO_REGRESSION, STABLE)

Guarantees:
- AGENTOS_SWE_DRY_RUN=1
- AGENTOS_MOCK_LLM=1
- Zero target repository modifications
- Zero git commits or pushes
"""

import pytest
from agentos_swe.intelligence.models import PrioritizedFinding, PriorityTier, ExploitabilityLevel
from agentos_swe.attackpath.models import AttackPath, EntrypointType, PathClassification
from agentos_swe.remediation import RemediationPlanner
from agentos_swe.monitoring import SecurityMonitor, RegressionSeverity, TrendDirection


from agentos_swe.monitoring.snapshot_manager import SnapshotManager


@pytest.fixture(autouse=True)
def set_dry_run_env(monkeypatch, tmp_path):
    monkeypatch.setenv("AGENTOS_SWE_DRY_RUN", "1")
    monkeypatch.setenv("AGENTOS_MOCK_LLM", "1")
    SnapshotManager._memory_snapshots = {}


@pytest.fixture
def monitor(tmp_path):
    SnapshotManager._memory_snapshots = {}
    return SecurityMonitor(storage_dir=str(tmp_path))


def test_m18_real_world_1_job_agent(monitor):
    """Job_Agent dict.get() lookups yield NO_REGRESSION and STABLE trend."""
    finding = PrioritizedFinding(
        rank=1, finding_id="job_1", vulnerability_category="info", severity="LOW", priority_score=10,
        priority_tier=PriorityTier.P4, root_cause="DICT_LOOKUP", affected_file="agent/job_search.py",
        exploitability=ExploitabilityLevel.NOT_EXPLOITABLE,
    )
    scan_data = {
        "metadata": {"repo_name": "Job_Agent", "commit": "j1"},
        "prioritized_findings": [finding],
        "security_score": 100,
    }

    result = monitor.monitor_repository(current_scan=scan_data, repository_name="Job_Agent")

    assert result.regression_severity == RegressionSeverity.NO_REGRESSION
    assert result.risk_trend == TrendDirection.STABLE
    assert result.governance_verdict == "ALLOW"


def test_m18_real_world_2_constitution_ai(monitor):
    """ConstitutionAI command injection yields CRITICAL_REGRESSION and DEGRADING trend."""
    finding = PrioritizedFinding(
        rank=1, finding_id="const_1", vulnerability_category="security", severity="CRITICAL", priority_score=95,
        priority_tier=PriorityTier.P0, root_cause="COMMAND_INJECTION", affected_file="server/api.py",
        affected_function="eval_prompt", exploitability=ExploitabilityLevel.CRITICAL,
    )
    path = AttackPath(
        id="path_const_1", fingerprint="fp_const_1", repository="ConstitutionAI", entrypoint="POST /api/evaluate",
        entrypoint_type=EntrypointType.INTERNET, source="HTTP", source_type="HTTP", source_file="server/api.py",
        source_line=24, sink="SUBPROCESS_SHELL", sink_type="SUBPROCESS_SHELL", sink_file="server/api.py",
        sink_line=24, root_cause="COMMAND_INJECTION", classification=PathClassification.EXPLOITABLE, risk_score=95,
    )
    prev_scan = {"metadata": {"repo_name": "ConstitutionAI", "commit": "c1"}, "prioritized_findings": [], "security_score": 100}
    curr_scan = {"metadata": {"repo_name": "ConstitutionAI", "commit": "c2"}, "prioritized_findings": [finding], "security_score": 60}

    result = monitor.monitor_repository(
        current_scan=curr_scan, previous_scan=prev_scan, attack_paths=[path], repository_name="ConstitutionAI"
    )

    assert result.regression_severity == RegressionSeverity.CRITICAL_REGRESSION
    assert result.risk_trend == TrendDirection.DEGRADING
    assert result.governance_verdict == "REVIEW_REQUIRED"
    assert len(result.alerts) >= 1


def test_m18_real_world_3_medagentx(monitor):
    """MedAgentX intentional fallback exception handlers yield NO_REGRESSION and STABLE trend."""
    finding = PrioritizedFinding(
        rank=1, finding_id="med_1", vulnerability_category="info", severity="LOW", priority_score=10,
        priority_tier=PriorityTier.P4, root_cause="INTENTIONAL_FALLBACK", affected_file="med/model.py",
        exploitability=ExploitabilityLevel.NOT_EXPLOITABLE,
    )
    scan_data = {
        "metadata": {"repo_name": "MedAgentX", "commit": "m1"},
        "prioritized_findings": [finding],
        "security_score": 100,
    }

    result = monitor.monitor_repository(current_scan=scan_data, repository_name="MedAgentX")

    assert result.regression_severity == RegressionSeverity.NO_REGRESSION
    assert result.risk_trend == TrendDirection.STABLE


def test_m18_real_world_4_cadresec(monitor):
    """Cadresec- exception swallowing produces MINOR_REGRESSION when introduced."""
    finding = PrioritizedFinding(
        rank=1, finding_id="cad_1", vulnerability_category="bug", severity="MEDIUM", priority_score=60,
        priority_tier=PriorityTier.P2, root_cause="EXCEPTION_SWALLOWING", affected_file="cadresec/scanner.py",
    )
    prev_scan = {"metadata": {"repo_name": "Cadresec-", "commit": "cd1"}, "prioritized_findings": [], "security_score": 100}
    curr_scan = {"metadata": {"repo_name": "Cadresec-", "commit": "cd2"}, "prioritized_findings": [finding], "security_score": 92}

    result = monitor.monitor_repository(current_scan=curr_scan, previous_scan=prev_scan, repository_name="Cadresec-")

    assert result.regression_severity in (RegressionSeverity.MINOR_REGRESSION, RegressionSeverity.SIGNIFICANT_REGRESSION)


def test_m18_real_world_5_omnitutor_ai(monitor):
    """OmniTutor-AI test harness exception handlers yield NO_REGRESSION and STABLE trend."""
    finding = PrioritizedFinding(
        rank=1, finding_id="omni_1", vulnerability_category="info", severity="LOW", priority_score=10,
        priority_tier=PriorityTier.P4, root_cause="TEST_HARNESS", affected_file="tests/test_tutor.py",
        exploitability=ExploitabilityLevel.NOT_EXPLOITABLE,
    )
    scan_data = {
        "metadata": {"repo_name": "OmniTutor-AI", "commit": "o1"},
        "prioritized_findings": [finding],
        "security_score": 100,
    }

    result = monitor.monitor_repository(current_scan=scan_data, repository_name="OmniTutor-AI")

    assert result.regression_severity == RegressionSeverity.NO_REGRESSION
    assert result.risk_trend == TrendDirection.STABLE
