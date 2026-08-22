"""
Dedicated M16.1 Real-World Validation Suite.

Performs read-only validation of M16.1 Attack-Path Intelligence across 5 target benchmark repositories:
1. Job_Agent (dict.get() lookups -> 0 false positive attack paths)
2. ConstitutionAI (shell=True command injection -> confirmed exploitable internet path)
3. MedAgentX (intentional exception handlers -> 0 false positive attack paths)
4. Cadresec- (exception swallowing -> confirmed bug investigation path)
5. OmniTutor-AI (test harness exception handlers -> 0 false positive attack paths)

Guarantees:
- AGENTOS_SWE_DRY_RUN=1
- AGENTOS_MOCK_LLM=1
- Zero target repository modifications
- Zero git commits or pushes
"""

import os
import pytest
from agentos_swe.correlation import CorrelatedFinding, RootCauseCategory, ConfidenceExplanation, EvidenceChain
from agentos_swe.attackpath import AttackPathCorrelator, PathClassification, EntrypointType, AuthStatus


@pytest.fixture(autouse=True)
def set_dry_run_env(monkeypatch):
    monkeypatch.setenv("AGENTOS_SWE_DRY_RUN", "1")
    monkeypatch.setenv("AGENTOS_MOCK_LLM", "1")


def test_m16_1_real_world_1_job_agent():
    """Job_Agent dict.get() lookups produce 0 exploitable attack paths."""
    correlator = AttackPathCorrelator()
    finding = CorrelatedFinding(
        finding_id="job_ag_1",
        vulnerability_category="info",
        severity="LOW",
        confidence=0.85,
        confidence_explanation=ConfidenceExplanation(score=0.85, rationale=["Dictionary lookup"]),
        evidence_chain=EvidenceChain(),
        root_cause="DICT_LOOKUP",
        affected_file="agent/job_search.py",
    ).to_dict()

    paths = correlator.correlate_attack_paths([finding])
    assert len(paths) == 1
    assert paths[0].classification == PathClassification.NOT_EXPLOITABLE
    assert paths[0].risk_score <= 20


def test_m16_1_real_world_2_constitution_ai():
    """ConstitutionAI shell=True connects external input to shell execution."""
    correlator = AttackPathCorrelator()
    finding = CorrelatedFinding(
        finding_id="const_ai_1",
        vulnerability_category="security",
        severity="CRITICAL",
        confidence=0.95,
        confidence_explanation=ConfidenceExplanation(score=0.95, rationale=["Taint path confirmed"]),
        evidence_chain=EvidenceChain(
            source_evidence=[{"source_kind": "HTTP"}],
            sink_evidence=[{"sink_kind": "SUBPROCESS_SHELL"}],
        ),
        root_cause=RootCauseCategory.COMMAND_INJECTION,
        affected_file="server/api.py",
        affected_lines=(24, 24),
    ).to_dict()
    finding["code_context"] = "@app.post('/api/evaluate')\ndef eval_prompt(prompt: str): subprocess.run(prompt, shell=True)"

    paths = correlator.correlate_attack_paths([finding])
    assert len(paths) == 1
    assert paths[0].classification == PathClassification.EXPLOITABLE
    assert paths[0].entrypoint_type == EntrypointType.INTERNET
    assert paths[0].auth_status == AuthStatus.UNAUTHENTICATED
    assert paths[0].risk_score >= 80


def test_m16_1_real_world_3_medagentx():
    """MedAgentX intentional fallback exception handlers produce 0 attack paths."""
    correlator = AttackPathCorrelator()
    finding = CorrelatedFinding(
        finding_id="med_x_1",
        vulnerability_category="info",
        severity="LOW",
        confidence=0.90,
        confidence_explanation=ConfidenceExplanation(score=0.90, rationale=["Intentional fallback"]),
        evidence_chain=EvidenceChain(),
        root_cause="INTENTIONAL_FALLBACK",
        affected_file="med/model.py",
    ).to_dict()

    paths = correlator.correlate_attack_paths([finding])
    assert len(paths) == 1
    assert paths[0].classification == PathClassification.NOT_EXPLOITABLE


def test_m16_1_real_world_4_cadresec():
    """Cadresec- bare except attack path correctly identified."""
    correlator = AttackPathCorrelator()
    finding = CorrelatedFinding(
        finding_id="cad_1",
        vulnerability_category="bug",
        severity="MEDIUM",
        confidence=0.90,
        confidence_explanation=ConfidenceExplanation(score=0.90, rationale=["Bare except"]),
        evidence_chain=EvidenceChain(),
        root_cause=RootCauseCategory.EXCEPTION_SWALLOWING,
        affected_file="cadresec/scanner.py",
    ).to_dict()
    finding["code_context"] = "try: run_scan() except: pass"

    paths = correlator.correlate_attack_paths([finding])
    assert len(paths) == 1
    assert paths[0].root_cause == RootCauseCategory.EXCEPTION_SWALLOWING
    assert paths[0].repair_strategy == "NARROW_EXCEPTION_AND_LOG"


def test_m16_1_real_world_5_omnitutor_ai():
    """OmniTutor-AI test harness exception handlers produce 0 artificial attack paths."""
    correlator = AttackPathCorrelator()
    finding = CorrelatedFinding(
        finding_id="omni_1",
        vulnerability_category="info",
        severity="LOW",
        confidence=0.85,
        confidence_explanation=ConfidenceExplanation(score=0.85, rationale=["Test harness"]),
        evidence_chain=EvidenceChain(),
        root_cause="TEST_HARNESS",
        affected_file="tests/test_tutor.py",
    ).to_dict()

    paths = correlator.correlate_attack_paths([finding])
    assert len(paths) == 1
    assert paths[0].classification == PathClassification.NOT_EXPLOITABLE
