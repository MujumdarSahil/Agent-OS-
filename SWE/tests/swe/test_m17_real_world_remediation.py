"""
Dedicated M17 Real-World Remediation Validation Suite.

Performs read-only validation of M17 Intelligent Security Remediation Orchestration across 5 target benchmark repositories:
1. Job_Agent (dict.get() lookups -> 0 remediation items required)
2. ConstitutionAI (shell=True command injection -> 1 P0 remediation item replacing shell=True with argument array)
3. MedAgentX (intentional fallback exception handlers -> 0 remediation items required)
4. Cadresec- (exception swallowing -> 1 P2 remediation item narrowing exception and adding logging)
5. OmniTutor-AI (test harness exception handlers -> 0 remediation items required)

Guarantees:
- AGENTOS_SWE_DRY_RUN=1
- AGENTOS_MOCK_LLM=1
- Zero target repository modifications
- Zero git commits or pushes
"""

import pytest
from agentos_swe.intelligence.models import PrioritizedFinding, PriorityTier, ExploitabilityLevel
from agentos_swe.attackpath.models import AttackPath, EntrypointType, PathClassification
from agentos_swe.remediation import RemediationPlanner, RemediationStatus, EffortCategory


@pytest.fixture(autouse=True)
def set_dry_run_env(monkeypatch):
    monkeypatch.setenv("AGENTOS_SWE_DRY_RUN", "1")
    monkeypatch.setenv("AGENTOS_MOCK_LLM", "1")


def test_m17_real_world_1_job_agent():
    """Job_Agent dict.get() lookups produce 0 remediation items required."""
    planner = RemediationPlanner()
    finding = PrioritizedFinding(
        rank=1,
        finding_id="job_1",
        vulnerability_category="info",
        severity="LOW",
        priority_score=10,
        priority_tier=PriorityTier.P4,
        root_cause="DICT_LOOKUP",
        affected_file="agent/job_search.py",
        exploitability=ExploitabilityLevel.NOT_EXPLOITABLE,
    )

    plan = planner.generate_remediation_plan(
        prioritized_findings=[finding],
        repository_name="Job_Agent",
    )

    assert len(plan.remediation_items) == 0
    assert plan.current_security_score == 100
    assert plan.projected_security_score == 100
    assert plan.total_risk_reduction == 0
    assert plan.final_recommendation.startswith("NO_REPAIR_REQUIRED")


def test_m17_real_world_2_constitution_ai():
    """ConstitutionAI shell=True produces 1 P0 remediation item replacing shell=True."""
    planner = RemediationPlanner()
    finding = PrioritizedFinding(
        rank=1,
        finding_id="const_1",
        vulnerability_category="security",
        severity="CRITICAL",
        priority_score=95,
        priority_tier=PriorityTier.P0,
        root_cause="COMMAND_INJECTION",
        affected_file="server/api.py",
        affected_function="eval_prompt",
        exploitability=ExploitabilityLevel.CRITICAL,
        recommended_action="Replace shell=True with argument array",
    )
    path = AttackPath(
        id="path_const_1",
        fingerprint="fp_const_1",
        repository="ConstitutionAI",
        entrypoint="POST /api/evaluate",
        entrypoint_type=EntrypointType.INTERNET,
        source="HTTP",
        source_type="HTTP",
        source_file="server/api.py",
        source_line=24,
        sink="SUBPROCESS_SHELL",
        sink_type="SUBPROCESS_SHELL",
        sink_file="server/api.py",
        sink_line=24,
        root_cause="COMMAND_INJECTION",
        classification=PathClassification.EXPLOITABLE,
        risk_score=95,
        severity="CRITICAL",
    )

    plan = planner.generate_remediation_plan(
        prioritized_findings=[finding],
        attack_paths=[path],
        repository_name="ConstitutionAI",
    )

    assert len(plan.remediation_items) == 1
    item = plan.remediation_items[0]
    assert item.priority_tier == "P0"
    assert item.repair_strategy == "REPLACE_SHELL_TRUE_WITH_ARG_ARRAY"
    assert item.projected_risk_reduction >= 20
    assert plan.projected_security_score > plan.current_security_score
    assert plan.graph is not None
    assert len(plan.graph.nodes) >= 5


def test_m17_real_world_3_medagentx():
    """MedAgentX intentional fallback exception handlers produce 0 remediation items."""
    planner = RemediationPlanner()
    finding = PrioritizedFinding(
        rank=1,
        finding_id="med_1",
        vulnerability_category="info",
        severity="LOW",
        priority_score=10,
        priority_tier=PriorityTier.P4,
        root_cause="INTENTIONAL_FALLBACK",
        affected_file="med/model.py",
        exploitability=ExploitabilityLevel.NOT_EXPLOITABLE,
    )

    plan = planner.generate_remediation_plan(
        prioritized_findings=[finding],
        repository_name="MedAgentX",
    )

    assert len(plan.remediation_items) == 0
    assert plan.total_risk_reduction == 0


def test_m17_real_world_4_cadresec():
    """Cadresec- bare except produces 1 P2 remediation item narrowing exception and adding logging."""
    planner = RemediationPlanner()
    finding = PrioritizedFinding(
        rank=1,
        finding_id="cad_1",
        vulnerability_category="bug",
        severity="MEDIUM",
        priority_score=60,
        priority_tier=PriorityTier.P2,
        root_cause="EXCEPTION_SWALLOWING",
        affected_file="cadresec/scanner.py",
        affected_function="run_scan",
        exploitability=ExploitabilityLevel.MEDIUM,
        recommended_action="Narrow exception and add logging",
    )

    plan = planner.generate_remediation_plan(
        prioritized_findings=[finding],
        repository_name="Cadresec-",
    )

    assert len(plan.remediation_items) == 1
    item = plan.remediation_items[0]
    assert item.priority_tier == "P2"
    assert item.repair_strategy == "NARROW_EXCEPTION_AND_LOG"
    assert "Exception Block" in item.earliest_break_point


def test_m17_real_world_5_omnitutor_ai():
    """OmniTutor-AI test harness exception handlers produce 0 remediation items."""
    planner = RemediationPlanner()
    finding = PrioritizedFinding(
        rank=1,
        finding_id="omni_1",
        vulnerability_category="info",
        severity="LOW",
        priority_score=10,
        priority_tier=PriorityTier.P4,
        root_cause="TEST_HARNESS",
        affected_file="tests/test_tutor.py",
        exploitability=ExploitabilityLevel.NOT_EXPLOITABLE,
    )

    plan = planner.generate_remediation_plan(
        prioritized_findings=[finding],
        repository_name="OmniTutor-AI",
    )

    assert len(plan.remediation_items) == 0
    assert plan.final_recommendation.startswith("NO_REPAIR_REQUIRED")
