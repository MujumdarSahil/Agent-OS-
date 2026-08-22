"""
Dedicated M19 Real-World Security Release Readiness Validation Suite.

Performs read-only validation of M19 Security Release Readiness & Executive Gate decisions across 5 target benchmark repositories:
1. Job_Agent (dict.get() lookups -> GO)
2. ConstitutionAI (shell=True command injection + INTERNET attack path -> BLOCKED)
3. MedAgentX (intentional fallback exception handlers -> GO)
4. Cadresec- (exception swallowing -> REVIEW_REQUIRED)
5. OmniTutor-AI (test harness exception handlers -> GO)

Guarantees:
- AGENTOS_SWE_DRY_RUN=1
- AGENTOS_MOCK_LLM=1
- Zero target repository modifications
- Zero git commits or pushes
"""

import pytest
from agentos_swe.intelligence.models import PrioritizedFinding, PriorityTier, ExploitabilityLevel
from agentos_swe.attackpath.models import AttackPath, EntrypointType, PathClassification, AuthStatus
from agentos_swe.remediation import RemediationPlanner
from agentos_swe.monitoring import SecurityMonitor
from agentos_swe.release import SecurityReleaseReadinessEngine, ReleaseDecisionState, SecurityGateVerdict
from agentos_swe.monitoring.snapshot_manager import SnapshotManager


@pytest.fixture(autouse=True)
def set_dry_run_env(monkeypatch):
    monkeypatch.setenv("AGENTOS_SWE_DRY_RUN", "1")
    monkeypatch.setenv("AGENTOS_MOCK_LLM", "1")
    SnapshotManager._memory_snapshots = {}


def test_m19_real_world_1_job_agent():
    """Job_Agent dict.get() lookups yield GO decision."""
    engine = SecurityReleaseReadinessEngine()
    finding = PrioritizedFinding(
        rank=1, finding_id="job_1", vulnerability_category="info", severity="LOW", priority_score=10,
        priority_tier=PriorityTier.P4, root_cause="DICT_LOOKUP", affected_file="agent/job_search.py",
        exploitability=ExploitabilityLevel.NOT_EXPLOITABLE,
    )

    decision = engine.evaluate_release_readiness(
        prioritized_findings=[finding], repository_name="Job_Agent"
    )

    assert decision.decision == ReleaseDecisionState.GO
    assert decision.release_status == SecurityGateVerdict.ALLOW_RELEASE.value
    assert len(decision.blockers) == 0


def test_m19_real_world_2_constitution_ai():
    """ConstitutionAI command injection yields BLOCKED decision."""
    engine = SecurityReleaseReadinessEngine()
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
        auth_status=AuthStatus.UNAUTHENTICATED
    )

    decision = engine.evaluate_release_readiness(
        prioritized_findings=[finding], attack_paths=[path], repository_name="ConstitutionAI"
    )

    assert decision.decision == ReleaseDecisionState.BLOCKED
    assert decision.release_status == SecurityGateVerdict.DENY_RELEASE.value
    assert len(decision.blockers) >= 1
    assert "path_const_1" in decision.blocking_attack_paths


def test_m19_real_world_3_medagentx():
    """MedAgentX intentional fallback exception handlers yield GO decision."""
    engine = SecurityReleaseReadinessEngine()
    finding = PrioritizedFinding(
        rank=1, finding_id="med_1", vulnerability_category="info", severity="LOW", priority_score=10,
        priority_tier=PriorityTier.P4, root_cause="INTENTIONAL_FALLBACK", affected_file="med/model.py",
        exploitability=ExploitabilityLevel.NOT_EXPLOITABLE,
    )

    decision = engine.evaluate_release_readiness(
        prioritized_findings=[finding], repository_name="MedAgentX"
    )

    assert decision.decision == ReleaseDecisionState.GO
    assert decision.release_status == SecurityGateVerdict.ALLOW_RELEASE.value


def test_m19_real_world_4_cadresec():
    """Cadresec- exception swallowing yields REVIEW_REQUIRED decision."""
    engine = SecurityReleaseReadinessEngine()
    finding = PrioritizedFinding(
        rank=1, finding_id="cad_1", vulnerability_category="bug", severity="MEDIUM", priority_score=60,
        priority_tier=PriorityTier.P2, root_cause="EXCEPTION_SWALLOWING", affected_file="cadresec/scanner.py",
        exploitability=ExploitabilityLevel.MEDIUM,
    )

    decision = engine.evaluate_release_readiness(
        prioritized_findings=[finding], repository_name="Cadresec-"
    )

    assert decision.decision == ReleaseDecisionState.REVIEW_REQUIRED
    assert decision.release_status == SecurityGateVerdict.REQUIRE_REVIEW.value


def test_m19_real_world_5_omnitutor_ai():
    """OmniTutor-AI test harness exception handlers yield GO decision."""
    engine = SecurityReleaseReadinessEngine()
    finding = PrioritizedFinding(
        rank=1, finding_id="omni_1", vulnerability_category="info", severity="LOW", priority_score=10,
        priority_tier=PriorityTier.P4, root_cause="TEST_HARNESS", affected_file="tests/test_tutor.py",
        exploitability=ExploitabilityLevel.NOT_EXPLOITABLE,
    )

    decision = engine.evaluate_release_readiness(
        prioritized_findings=[finding], repository_name="OmniTutor-AI"
    )

    assert decision.decision == ReleaseDecisionState.GO
    assert decision.release_status == SecurityGateVerdict.ALLOW_RELEASE.value
