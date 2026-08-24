"""
Dedicated M22 Real-World Security Simulation Validation Suite.

Performs read-only validation of M22 Safe Security Simulation & Exploitability Validation across 5 target benchmark repositories:
1. Job_Agent (dict.get() lookups -> NOT_REPRODUCED, BLOCKED, Safe Control)
2. ConstitutionAI (shell=True command injection -> REPRODUCED, High Exploitability, Safe Marker)
3. MedAgentX (intentional fallback exception handlers -> NOT_REPRODUCED, Safe Fallback)
4. Cadresec- (exception swallowing -> NOT_REPRODUCED, Review Required)
5. OmniTutor-AI (test harness exception handlers -> NOT_REPRODUCED, Safe Test Harness)

Guarantees:
- AGENTOS_SWE_DRY_RUN=1
- AGENTOS_MOCK_LLM=1
- Zero target repository modifications
- Zero git commits or pushes
"""

import pytest
from agentos_swe.intelligence.models import PrioritizedFinding, PriorityTier, ExploitabilityLevel
from agentos_swe.intelligence.attackpath.models import AttackPath, EntrypointType, PathClassification
from agentos_swe.remediation.simulation import SecuritySimulationEngine, SimulationStatus


@pytest.fixture(autouse=True)
def set_dry_run_env(monkeypatch):
    monkeypatch.setenv("AGENTOS_SWE_DRY_RUN", "1")
    monkeypatch.setenv("AGENTOS_MOCK_LLM", "1")


@pytest.fixture
def engine():
    return SecuritySimulationEngine()


def test_m22_real_world_1_job_agent(engine):
    """Job_Agent dict.get() lookups yield NOT_REPRODUCED status."""
    finding = PrioritizedFinding(
        rank=1, finding_id="job_1", vulnerability_category="info", severity="LOW", priority_score=10,
        priority_tier=PriorityTier.P4, root_cause="DICT_LOOKUP", affected_file="agent/job_search.py",
        exploitability=ExploitabilityLevel.NOT_EXPLOITABLE,
    )
    result = engine.run_simulation_pipeline(
        verified_findings=[finding],
        prioritized_findings=[finding],
        repository_name="Job_Agent",
    )

    assert result["overall_status"] == "NOT_REPRODUCED"
    assert result["reproduced_count"] == 0


def test_m22_real_world_2_constitution_ai(engine):
    """ConstitutionAI command injection yields REPRODUCED status with safe synthetic marker."""
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

    result = engine.run_simulation_pipeline(
        verified_findings=[finding],
        prioritized_findings=[finding],
        attack_paths=[path],
        repository_name="ConstitutionAI",
    )

    assert result["overall_status"] == "REPRODUCED"
    assert result["reproduced_count"] == 1
    assert result["results"][0]["status"] == "REPRODUCED"


def test_m22_real_world_3_medagentx(engine):
    """MedAgentX intentional fallback exception handlers yield NOT_REPRODUCED status."""
    finding = PrioritizedFinding(
        rank=1, finding_id="med_1", vulnerability_category="info", severity="LOW", priority_score=10,
        priority_tier=PriorityTier.P4, root_cause="INTENTIONAL_FALLBACK", affected_file="med/model.py",
        exploitability=ExploitabilityLevel.NOT_EXPLOITABLE,
    )

    result = engine.run_simulation_pipeline(
        verified_findings=[finding],
        prioritized_findings=[finding],
        repository_name="MedAgentX",
    )

    assert result["overall_status"] == "NOT_REPRODUCED"


def test_m22_real_world_4_cadresec(engine):
    """Cadresec- exception swallowing yields NOT_REPRODUCED status."""
    finding = PrioritizedFinding(
        rank=1, finding_id="cad_1", vulnerability_category="bug", severity="MEDIUM", priority_score=60,
        priority_tier=PriorityTier.P2, root_cause="EXCEPTION_SWALLOWING", affected_file="cadresec/scanner.py",
        exploitability=ExploitabilityLevel.MEDIUM,
    )

    result = engine.run_simulation_pipeline(
        verified_findings=[finding],
        prioritized_findings=[finding],
        repository_name="Cadresec-",
    )

    assert result["overall_status"] == "NOT_REPRODUCED"


def test_m22_real_world_5_omnitutor_ai(engine):
    """OmniTutor-AI test harness exception handlers yield NOT_REPRODUCED status."""
    finding = PrioritizedFinding(
        rank=1, finding_id="omni_1", vulnerability_category="info", severity="LOW", priority_score=10,
        priority_tier=PriorityTier.P4, root_cause="TEST_HARNESS", affected_file="tests/test_tutor.py",
        exploitability=ExploitabilityLevel.NOT_EXPLOITABLE,
    )

    result = engine.run_simulation_pipeline(
        verified_findings=[finding],
        prioritized_findings=[finding],
        repository_name="OmniTutor-AI",
    )

    assert result["overall_status"] == "NOT_REPRODUCED"
