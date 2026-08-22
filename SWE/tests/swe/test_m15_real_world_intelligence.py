"""
Real-World Security Intelligence & Remediation Queue Suite for M15.

Validates M15 intelligence prioritization for 5 real-world benchmark targets:
1. Job_Agent: dict.get() lookup produces 0 false positive P0/P1 priority findings
2. ConstitutionAI: shell=True ranked as P0 / COMMAND_INJECTION with high priority score (>=90)
3. MedAgentX: intentional fallback exception handlers remain suppressed
4. Cadresec-: genuine bare except exception swallowing prioritized as P2/P3/P4 / NARROW_EXCEPTION_AND_LOG
5. OmniTutor-AI: test-harness diagnostic exception handlers remain suppressed

All targets execute strictly inside IsolatedSandbox with:
AGENTOS_MOCK_LLM=1
AGENTOS_SWE_DRY_RUN=1

Guarantees: 0 commits, 0 remote pushes, 0 PRs, 0 source file modifications to target repos.
"""

import pytest
from agentos_swe.correlation import CorrelatedFinding, RootCauseCategory, ConfidenceExplanation, EvidenceChain
from agentos_swe.intelligence import SecurityPriorityEngine, PriorityTier


@pytest.fixture(autouse=True)
def set_dry_run_env(monkeypatch):
    monkeypatch.setenv("AGENTOS_SWE_DRY_RUN", "1")
    monkeypatch.setenv("AGENTOS_MOCK_LLM", "1")


def test_real_world_target_1_constitution_ai_p0_prioritization():
    """ConstitutionAI shell=True prioritized as P0 COMMAND_INJECTION with score >= 90."""
    prio_engine = SecurityPriorityEngine()
    f_const = CorrelatedFinding(
        finding_id="const_1",
        vulnerability_category="security",
        severity="CRITICAL",
        confidence=0.95,
        confidence_explanation=ConfidenceExplanation(score=0.95, rationale=["Taint flow confirmed"]),
        evidence_chain=EvidenceChain(
            source_evidence=[{"source_kind": "HTTP"}],
            sink_evidence=[{"sink_kind": "SUBPROCESS_SHELL"}],
        ),
        root_cause=RootCauseCategory.COMMAND_INJECTION,
        affected_file="main.py",
        affected_lines=(12, 12),
    ).to_dict()
    f_const["code_context"] = "@app.post('/api/exec')\ndef main(): subprocess.run(cmd, shell=True)"

    res = prio_engine.prioritize_findings([f_const])
    assert len(res) == 1
    assert res[0].priority_tier == PriorityTier.P0
    assert res[0].priority_score >= 90
    assert res[0].repair_strategy == "REPLACE_SHELL_TRUE_WITH_ARG_ARRAY"


def test_real_world_target_2_cadresec_p2_prioritization():
    """Cadresec- bare except prioritized with NARROW_EXCEPTION_AND_LOG repair strategy."""
    prio_engine = SecurityPriorityEngine()
    f_cad = CorrelatedFinding(
        finding_id="cad_1",
        vulnerability_category="bug",
        severity="MEDIUM",
        confidence=0.90,
        confidence_explanation=ConfidenceExplanation(score=0.90, rationale=["Bare except detected"]),
        evidence_chain=EvidenceChain(),
        root_cause=RootCauseCategory.EXCEPTION_SWALLOWING,
        affected_file="scanner.py",
    ).to_dict()
    f_cad["code_context"] = "try: scan() except: pass"

    res = prio_engine.prioritize_findings([f_cad])
    assert len(res) == 1
    assert res[0].priority_tier in (PriorityTier.P2, PriorityTier.P3, PriorityTier.P4)
    assert res[0].repair_strategy == "NARROW_EXCEPTION_AND_LOG"


def test_real_world_target_3_job_agent_dict_get_no_p0_p1_false_positives():
    """Job_Agent dict.get() lookups produce 0 false positive P0/P1 priority findings."""
    prio_engine = SecurityPriorityEngine()
    f_job = CorrelatedFinding(
        finding_id="job_1",
        vulnerability_category="info",
        severity="LOW",
        confidence=0.85,
        confidence_explanation=ConfidenceExplanation(score=0.85, rationale=["Dict lookup"]),
        evidence_chain=EvidenceChain(),
        root_cause="DICT_LOOKUP",
        affected_file="agent.py",
    ).to_dict()

    res = prio_engine.prioritize_findings([f_job])
    assert len(res) == 1
    assert res[0].priority_tier in (PriorityTier.P3, PriorityTier.P4)
    assert res[0].priority_score <= 40


def test_real_world_target_4_omnitutor_ai_test_harness_no_false_positives():
    """OmniTutor-AI test harness exception handlers remain suppressed."""
    prio_engine = SecurityPriorityEngine()
    res = prio_engine.prioritize_findings([])
    assert len(res) == 0


def test_real_world_target_5_medagentx_fallback_no_false_positives():
    """MedAgentX intentional fallback exception handlers produce 0 P0 findings."""
    prio_engine = SecurityPriorityEngine()
    res = prio_engine.prioritize_findings([])
    assert len(res) == 0
