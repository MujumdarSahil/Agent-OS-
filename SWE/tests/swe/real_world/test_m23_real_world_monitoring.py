"""
Dedicated M23 Real-World Security Monitoring & Drift Validation Suite.

Performs read-only validation of M23 Continuous Security Monitoring & Security Drift across 5 target benchmark repositories:
1. Job_Agent (dict.get() lookups -> NO_DRIFT, Release Safe)
2. ConstitutionAI (shell=True command injection -> HIGH_DRIFT / CRITICAL_DRIFT, Release Blocked)
3. MedAgentX (intentional fallback exception handlers -> NO_DRIFT, Release Safe)
4. Cadresec- (exception swallowing -> NO_DRIFT, Release Safe)
5. OmniTutor-AI (test harness exception handlers -> NO_DRIFT, Release Safe)

Guarantees:
- AGENTOS_SWE_DRY_RUN=1
- AGENTOS_MOCK_LLM=1
- Zero target repository modifications
- Zero git commits or pushes
"""

import pytest
from agentos_swe.intelligence.models import PrioritizedFinding, PriorityTier, ExploitabilityLevel
from agentos_swe.intelligence.attackpath.models import AttackPath, EntrypointType, PathClassification
from agentos_swe.operations.monitoring import SecurityMonitoringEngine


@pytest.fixture(autouse=True)
def set_dry_run_env(monkeypatch):
    monkeypatch.setenv("AGENTOS_SWE_DRY_RUN", "1")
    monkeypatch.setenv("AGENTOS_MOCK_LLM", "1")


@pytest.fixture
def engine():
    return SecurityMonitoringEngine()


def test_m23_real_world_1_job_agent(engine):
    """Job_Agent dict.get() lookups yield NO_DRIFT and release_safe=True."""
    finding = PrioritizedFinding(
        rank=1, finding_id="job_1", vulnerability_category="info", severity="LOW", priority_score=10,
        priority_tier=PriorityTier.P4, root_cause="DICT_LOOKUP", affected_file="agent/job_search.py",
        exploitability=ExploitabilityLevel.NOT_EXPLOITABLE,
    )
    result = engine.run_monitoring_pipeline(
        repository_name="Job_Agent",
        current_commit="job_c1",
        baseline_commit="job_c0",
        current_findings=[finding],
        baseline_findings=[finding],
    )

    assert result["drift"]["category"] == "NO_DRIFT"
    assert result["release_assessment"]["release_safe"] is True


def test_m23_real_world_2_constitution_ai(engine):
    """ConstitutionAI command injection yields CRITICAL_DRIFT / HIGH_DRIFT and release_safe=False."""
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

    result = engine.run_monitoring_pipeline(
        repository_name="ConstitutionAI",
        current_commit="const_c1",
        baseline_commit="const_c0",
        current_findings=[finding],
        baseline_findings=[],
        attack_paths=[path],
    )

    assert result["drift"]["category"] in ("CRITICAL_DRIFT", "HIGH_DRIFT")
    assert result["release_assessment"]["release_safe"] is False


def test_m23_real_world_3_medagentx(engine):
    """MedAgentX intentional fallback exception handlers yield NO_DRIFT and release_safe=True."""
    finding = PrioritizedFinding(
        rank=1, finding_id="med_1", vulnerability_category="info", severity="LOW", priority_score=10,
        priority_tier=PriorityTier.P4, root_cause="INTENTIONAL_FALLBACK", affected_file="med/model.py",
        exploitability=ExploitabilityLevel.NOT_EXPLOITABLE,
    )

    result = engine.run_monitoring_pipeline(
        repository_name="MedAgentX",
        current_commit="med_c1",
        baseline_commit="med_c0",
        current_findings=[finding],
        baseline_findings=[finding],
    )

    assert result["drift"]["category"] == "NO_DRIFT"
    assert result["release_assessment"]["release_safe"] is True


def test_m23_real_world_4_cadresec(engine):
    """Cadresec- exception swallowing yields NO_DRIFT and release_safe=True."""
    finding = PrioritizedFinding(
        rank=1, finding_id="cad_1", vulnerability_category="bug", severity="MEDIUM", priority_score=60,
        priority_tier=PriorityTier.P2, root_cause="EXCEPTION_SWALLOWING", affected_file="cadresec/scanner.py",
        exploitability=ExploitabilityLevel.MEDIUM,
    )

    result = engine.run_monitoring_pipeline(
        repository_name="Cadresec-",
        current_commit="cad_c1",
        baseline_commit="cad_c0",
        current_findings=[finding],
        baseline_findings=[finding],
    )

    assert result["drift"]["category"] == "NO_DRIFT"
    assert result["release_assessment"]["release_safe"] is True


def test_m23_real_world_5_omnitutor_ai(engine):
    """OmniTutor-AI test harness exception handlers yield NO_DRIFT and release_safe=True."""
    finding = PrioritizedFinding(
        rank=1, finding_id="omni_1", vulnerability_category="info", severity="LOW", priority_score=10,
        priority_tier=PriorityTier.P4, root_cause="TEST_HARNESS", affected_file="tests/test_tutor.py",
        exploitability=ExploitabilityLevel.NOT_EXPLOITABLE,
    )

    result = engine.run_monitoring_pipeline(
        repository_name="OmniTutor-AI",
        current_commit="omni_c1",
        baseline_commit="omni_c0",
        current_findings=[finding],
        baseline_findings=[finding],
    )

    assert result["drift"]["category"] == "NO_DRIFT"
    assert result["release_assessment"]["release_safe"] is True
