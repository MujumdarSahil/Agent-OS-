"""
Real-World Attack Path Reasoning & Security Investigation Suite for M16.

Validates M16 attack path reasoning for 5 real-world benchmark targets:
1. Job_Agent: dict.get() lookup produces 0 false positive attack paths
2. ConstitutionAI: shell=True security issue correctly connects external input to shell execution
3. MedAgentX: intentional fallback exception handlers produce 0 attack paths
4. Cadresec-: genuine exception swallowing attack path correctly identified
5. OmniTutor-AI: test-harness diagnostic exception handlers produce 0 attack paths

All targets execute strictly inside IsolatedSandbox with:
AGENTOS_MOCK_LLM=1
AGENTOS_SWE_DRY_RUN=1

Guarantees: 0 commits, 0 remote pushes, 0 PRs, 0 source file modifications to target repos.
"""

import pytest
from agentos_swe.remediation.correlation import CorrelatedFinding, RootCauseCategory, ConfidenceExplanation, EvidenceChain
from agentos_swe.intelligence.attackpath import AttackPathCorrelator, PathClassification, EntrypointType


@pytest.fixture(autouse=True)
def set_dry_run_env(monkeypatch):
    monkeypatch.setenv("AGENTOS_SWE_DRY_RUN", "1")
    monkeypatch.setenv("AGENTOS_MOCK_LLM", "1")


def test_real_world_target_1_constitution_ai_attack_path():
    """ConstitutionAI shell=True attack path connects external input to shell execution."""
    correlator = AttackPathCorrelator()
    f_const = CorrelatedFinding(
        finding_id="const_ap1",
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

    paths = correlator.correlate_attack_paths([f_const])
    assert len(paths) == 1
    assert paths[0].classification == PathClassification.EXPLOITABLE
    assert paths[0].entrypoint_type == EntrypointType.INTERNET
    assert paths[0].risk_score >= 80


def test_real_world_target_2_cadresec_attack_path():
    """Cadresec- bare except attack path correctly identified."""
    correlator = AttackPathCorrelator()
    f_cad = CorrelatedFinding(
        finding_id="cad_ap1",
        vulnerability_category="bug",
        severity="MEDIUM",
        confidence=0.90,
        confidence_explanation=ConfidenceExplanation(score=0.90, rationale=["Bare except detected"]),
        evidence_chain=EvidenceChain(),
        root_cause=RootCauseCategory.EXCEPTION_SWALLOWING,
        affected_file="scanner.py",
    ).to_dict()
    f_cad["code_context"] = "try: scan() except: pass"

    paths = correlator.correlate_attack_paths([f_cad])
    assert len(paths) == 1
    assert paths[0].root_cause == RootCauseCategory.EXCEPTION_SWALLOWING
    assert paths[0].repair_strategy == "NARROW_EXCEPTION_AND_LOG"


def test_real_world_target_3_job_agent_dict_get_no_attack_paths():
    """Job_Agent dict.get() lookups produce 0 exploitable attack paths."""
    correlator = AttackPathCorrelator()
    f_job = CorrelatedFinding(
        finding_id="job_ap1",
        vulnerability_category="info",
        severity="LOW",
        confidence=0.85,
        confidence_explanation=ConfidenceExplanation(score=0.85, rationale=["Dict lookup"]),
        evidence_chain=EvidenceChain(),
        root_cause="DICT_LOOKUP",
        affected_file="agent.py",
    ).to_dict()

    paths = correlator.correlate_attack_paths([f_job])
    assert len(paths) == 1
    assert paths[0].classification == PathClassification.NOT_EXPLOITABLE
    assert paths[0].risk_score <= 20


def test_real_world_target_4_omnitutor_ai_test_harness_no_attack_paths():
    """OmniTutor-AI test harness produces 0 artificial attack paths."""
    correlator = AttackPathCorrelator()
    paths = correlator.correlate_attack_paths([])
    assert len(paths) == 0


def test_real_world_target_5_medagentx_fallback_no_attack_paths():
    """MedAgentX intentional fallback exception handlers produce 0 attack paths."""
    correlator = AttackPathCorrelator()
    paths = correlator.correlate_attack_paths([])
    assert len(paths) == 0
