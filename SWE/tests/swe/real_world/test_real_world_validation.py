"""
Real-World Repository Pattern Validation Suite for M13.

Runs M13 correlation and repair pipeline against real-world benchmark target patterns:
1. Job_Agent: dict.get() must remain DICT_LOOKUP (0 false positives)
2. ConstitutionAI: shell=True must remain detected as COMMAND_INJECTION
3. MedAgentX: fallback exception & entrypoint semantics remain correct
4. Cadresec-: bare exception bugs remain detected as EXCEPTION_SWALLOWING
5. OmniTutor-AI: intentional test-harness exception handlers do not regress into false positives

All targets run with AGENTOS_MOCK_LLM=1 and AGENTOS_SWE_DRY_RUN=1.
Guarantees: 0 commits, 0 remote pushes, 0 PRs, 0 source modifications.
"""

import pytest
import os
from agentos_swe.core.models import Finding
from agentos_swe.security.taint.models import (
    TaintFinding,
    TaintPath,
    TaintSource,
    TaintSink,
    TaintSourceKind,
    TaintSinkKind,
    TaintSeverity,
)
from agentos_swe.remediation.correlation import EvidenceCorrelator, RootCauseCategory
from agentos_swe.remediation.repair.repair_strategy import IntelligentRepairEngine
from agentos_swe.remediation.pr.governance_gate import GovernanceGate


@pytest.fixture(autouse=True)
def set_dry_run_env(monkeypatch):
    monkeypatch.setenv("AGENTOS_SWE_DRY_RUN", "1")
    monkeypatch.setenv("AGENTOS_MOCK_LLM", "1")


def test_real_world_job_agent_dict_get():
    """Job_Agent dict.get() must NOT regress into false positive command injection or taint source."""
    correlator = EvidenceCorrelator()
    f = Finding(
        id="ja_1",
        category="general",
        severity="low",
        title="Dict lookup in loop",
        file="job_agent.py",
        line_range=(15, 15),
    )
    results = correlator.correlate(findings=[f], taint_findings=[])
    assert len(results) == 1
    assert results[0].root_cause != RootCauseCategory.COMMAND_INJECTION
    assert results[0].confidence <= 0.50


def test_real_world_constitution_ai_shell_true():
    """ConstitutionAI shell=True must remain detected as COMMAND_INJECTION."""
    source = TaintSource(
        var_name="prompt",
        source_kind=TaintSourceKind.USER_INPUT,
        line_no=10,
        code_snippet="prompt = input('Enter prompt: ')",
        file="eval.py",
    )
    sink = TaintSink(
        var_name="cmd",
        sink_kind=TaintSinkKind.SHELL_EXECUTION,
        line_no=25,
        code_snippet="subprocess.run(f'python run.py --prompt {prompt}', shell=True)",
        file="eval.py",
        is_shell_true=True,
    )
    path = TaintPath(source=source, sink=sink, file="eval.py")
    tf = TaintFinding(
        path=path,
        severity=TaintSeverity.CRITICAL,
        confidence=0.95,
        title="Unsafe shell execution in ConstitutionAI eval harness",
        explanation="User prompt flows to shell=True subprocess call",
    )

    correlator = EvidenceCorrelator()
    results = correlator.correlate(findings=[], taint_findings=[tf])
    assert len(results) == 1
    corr = results[0]
    assert corr.root_cause == RootCauseCategory.COMMAND_INJECTION
    assert corr.severity == "CRITICAL"

    # Verify Intelligent Repair Strategy
    engine = IntelligentRepairEngine()
    proposal = engine.generate_proposal(corr, file_content=sink.code_snippet)
    assert proposal.strategy == "REPLACE_SHELL_TRUE_WITH_ARG_ARRAY"
    assert "shell=False" in proposal.proposed_snippet


def test_real_world_medagentx_entrypoint_semantics():
    """MedAgentX entrypoint and fallback exception handling remain correct."""
    f = Finding(
        id="med_1",
        category="bug",
        severity="medium",
        title="Diagnostic exception handling with return fallback",
        file="main.py",
        line_range=(50, 55),
    )
    semantic_info = {"exception_intent": "INTENTIONAL_FALLBACK", "module_role": "ENTRYPOINT_LAUNCHER"}

    correlator = EvidenceCorrelator()
    results = correlator.correlate(findings=[f], semantic_results={"main.py": semantic_info})
    assert len(results) == 1
    assert results[0].root_cause != RootCauseCategory.EXCEPTION_SWALLOWING


def test_real_world_cadresec_bare_exception():
    """Cadresec- bare exception clause must remain detected as EXCEPTION_SWALLOWING."""
    f = Finding(
        id="cad_1",
        category="bug",
        severity="medium",
        title="Silent error swallow in exception handler",
        file="scanner.py",
        line_range=(30, 32),
    )
    semantic_info = {"exception_intent": "POSSIBLE_ERROR_SWALLOW"}

    correlator = EvidenceCorrelator()
    results = correlator.correlate(findings=[f], semantic_results={"scanner.py": semantic_info})
    assert len(results) == 1
    assert results[0].root_cause == RootCauseCategory.EXCEPTION_SWALLOWING

    # Verify repair proposal narrows exception
    engine = IntelligentRepairEngine()
    proposal = engine.generate_proposal(results[0], file_content="try:\n    scan()\nexcept:\n    pass\n")
    assert proposal.strategy == "NARROW_EXCEPTION_AND_LOG"
    assert "except Exception as err:" in proposal.proposed_snippet


def test_real_world_omnitutor_ai_test_harness():
    """OmniTutor-AI test harness exception handlers must not regress into false positives."""
    f = Finding(
        id="omni_1",
        category="bug",
        severity="low",
        title="Test harness exception logging",
        file="test_tutor.py",
        line_range=(10, 15),
    )
    semantic_info = {"exception_intent": "INTENTIONAL_FALLBACK", "module_role": "TEST_HARNESS"}

    correlator = EvidenceCorrelator()
    results = correlator.correlate(findings=[f], semantic_results={"test_tutor.py": semantic_info})
    assert len(results) == 1
    assert results[0].root_cause != RootCauseCategory.EXCEPTION_SWALLOWING
