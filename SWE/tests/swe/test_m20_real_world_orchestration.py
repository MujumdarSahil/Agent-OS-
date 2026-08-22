"""
Dedicated M20 Real-World Security Engineering Orchestration Validation Suite.

Performs read-only validation of M20 Security Engineering Orchestration across 5 target benchmark repositories:
1. Job_Agent (dict.get() lookups -> NO_ACTION_REQUIRED, COMPLETED, GO)
2. ConstitutionAI (shell=True command injection -> BLOCK_RELEASE, BLOCKED, DENY)
3. MedAgentX (intentional fallback exception handlers -> NO_ACTION_REQUIRED, COMPLETED, GO)
4. Cadresec- (exception swallowing -> REQUIRE_HUMAN_REVIEW / INVESTIGATE_FINDING)
5. OmniTutor-AI (test harness exception handlers -> NO_ACTION_REQUIRED, COMPLETED, GO)

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
from agentos_swe.monitoring import SecurityMonitor
from agentos_swe.release import SecurityReleaseReadinessEngine
from agentos_swe.orchestration import (
    SecurityEngineeringOrchestrator,
    WorkflowState,
    NextActionDecision,
    SecurityCaseStatus,
)


@pytest.fixture(autouse=True)
def set_dry_run_env(monkeypatch):
    monkeypatch.setenv("AGENTOS_SWE_DRY_RUN", "1")
    monkeypatch.setenv("AGENTOS_MOCK_LLM", "1")


def test_m20_real_world_1_job_agent():
    """Job_Agent dict.get() lookups yield NO_ACTION_REQUIRED and COMPLETED workflow."""
    orchestrator = SecurityEngineeringOrchestrator()
    finding = PrioritizedFinding(
        rank=1, finding_id="job_1", vulnerability_category="info", severity="LOW", priority_score=10,
        priority_tier=PriorityTier.P4, root_cause="DICT_LOOKUP", affected_file="agent/job_search.py",
        exploitability=ExploitabilityLevel.NOT_EXPLOITABLE,
    )
    rel_dec = {"decision": "GO", "release_status": "ALLOW_RELEASE"}

    result = orchestrator.orchestrate_repository(
        verified_findings=[finding],
        prioritized_findings=[finding],
        release_decision=rel_dec,
        repository_name="Job_Agent",
    )

    assert result.current_state == WorkflowState.COMPLETED
    assert result.next_action == NextActionDecision.NO_ACTION_REQUIRED
    assert result.human_review is None


def test_m20_real_world_2_constitution_ai():
    """ConstitutionAI command injection yields BLOCK_RELEASE and BLOCKED state."""
    orchestrator = SecurityEngineeringOrchestrator()
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
    rel_dec = {"decision": "BLOCKED", "release_status": "DENY_RELEASE"}

    result = orchestrator.orchestrate_repository(
        verified_findings=[finding],
        prioritized_findings=[finding],
        attack_paths=[path],
        release_decision=rel_dec,
        repository_name="ConstitutionAI",
    )

    assert result.current_state == WorkflowState.BLOCKED
    assert result.next_action == NextActionDecision.BLOCK_RELEASE
    assert len(result.cases) == 1
    assert result.cases[0].current_status == SecurityCaseStatus.BLOCKED


def test_m20_real_world_3_medagentx():
    """MedAgentX intentional fallback exception handlers yield NO_ACTION_REQUIRED."""
    orchestrator = SecurityEngineeringOrchestrator()
    finding = PrioritizedFinding(
        rank=1, finding_id="med_1", vulnerability_category="info", severity="LOW", priority_score=10,
        priority_tier=PriorityTier.P4, root_cause="INTENTIONAL_FALLBACK", affected_file="med/model.py",
        exploitability=ExploitabilityLevel.NOT_EXPLOITABLE,
    )
    rel_dec = {"decision": "GO", "release_status": "ALLOW_RELEASE"}

    result = orchestrator.orchestrate_repository(
        verified_findings=[finding],
        prioritized_findings=[finding],
        release_decision=rel_dec,
        repository_name="MedAgentX",
    )

    assert result.current_state == WorkflowState.COMPLETED
    assert result.next_action == NextActionDecision.NO_ACTION_REQUIRED


def test_m20_real_world_4_cadresec():
    """Cadresec- exception swallowing yields REQUIRE_HUMAN_REVIEW decision."""
    orchestrator = SecurityEngineeringOrchestrator()
    finding = PrioritizedFinding(
        rank=1, finding_id="cad_1", vulnerability_category="bug", severity="MEDIUM", priority_score=60,
        priority_tier=PriorityTier.P2, root_cause="EXCEPTION_SWALLOWING", affected_file="cadresec/scanner.py",
        exploitability=ExploitabilityLevel.MEDIUM,
    )
    rel_dec = {"decision": "REVIEW_REQUIRED", "release_status": "REQUIRE_REVIEW"}

    result = orchestrator.orchestrate_repository(
        verified_findings=[finding],
        prioritized_findings=[finding],
        release_decision=rel_dec,
        repository_name="Cadresec-",
    )

    assert result.next_action == NextActionDecision.REQUIRE_HUMAN_REVIEW


def test_m20_real_world_5_omnitutor_ai():
    """OmniTutor-AI test harness exception handlers yield NO_ACTION_REQUIRED."""
    orchestrator = SecurityEngineeringOrchestrator()
    finding = PrioritizedFinding(
        rank=1, finding_id="omni_1", vulnerability_category="info", severity="LOW", priority_score=10,
        priority_tier=PriorityTier.P4, root_cause="TEST_HARNESS", affected_file="tests/test_tutor.py",
        exploitability=ExploitabilityLevel.NOT_EXPLOITABLE,
    )
    rel_dec = {"decision": "GO", "release_status": "ALLOW_RELEASE"}

    result = orchestrator.orchestrate_repository(
        verified_findings=[finding],
        prioritized_findings=[finding],
        release_decision=rel_dec,
        repository_name="OmniTutor-AI",
    )

    assert result.current_state == WorkflowState.COMPLETED
    assert result.next_action == NextActionDecision.NO_ACTION_REQUIRED
