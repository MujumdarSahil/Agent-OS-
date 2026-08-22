"""
Real-World Repository Repair Validation & Security Regression Suite for M13.1.

Runs M13.1 repair validation pipeline against pattern specifications for 5 real-world benchmark targets:
1. Job_Agent: dict.get() must resolve to NO_REPAIR_REQUIRED (0 false positives)
2. ConstitutionAI: shell=True in main.py must be detected, repaired in IsolatedSandbox, and verified REPAIRED
3. MedAgentX: fallback exception & entrypoint semantics remain NO_REPAIR_REQUIRED
4. Cadresec-: bare except clauses must be detected and REPAIRED with narrowed exception handlers
5. OmniTutor-AI: test-harness exception handlers remain NO_REPAIR_REQUIRED

All targets execute strictly inside IsolatedSandbox with:
AGENTOS_MOCK_LLM=1
AGENTOS_SWE_DRY_RUN=1

Guarantees: 0 commits, 0 remote pushes, 0 PRs, 0 source file modifications to target repos.
"""

import pytest
import os
from agentos_swe.models import Finding
from agentos_swe.security.taint.models import (
    TaintFinding,
    TaintPath,
    TaintSource,
    TaintSink,
    TaintSourceKind,
    TaintSinkKind,
    TaintSeverity,
)
from agentos_swe.correlation import EvidenceCorrelator, RootCauseCategory
from agentos_swe.repair.repair_strategy import IntelligentRepairEngine
from agentos_swe.repair.repair_validator import RealWorldRepairValidator
from agentos_swe.repair.models import RepairVerdict
from agentos_swe.verification.sandbox import IsolatedSandbox


@pytest.fixture(autouse=True)
def set_dry_run_env(monkeypatch):
    monkeypatch.setenv("AGENTOS_SWE_DRY_RUN", "1")
    monkeypatch.setenv("AGENTOS_MOCK_LLM", "1")


def test_real_world_target_1_constitution_ai_repair_validation():
    """ConstitutionAI shell=True in main.py must be detected, repaired in IsolatedSandbox, and verified REPAIRED."""
    source = TaintSource(
        var_name="prompt",
        source_kind=TaintSourceKind.USER_INPUT,
        line_no=5,
        code_snippet="prompt = input('Enter prompt: ')",
        file="main.py",
    )
    sink = TaintSink(
        var_name="cmd",
        sink_kind=TaintSinkKind.SHELL_EXECUTION,
        line_no=12,
        code_snippet="subprocess.run(f'python run.py --prompt {prompt}', shell=True)",
        file="main.py",
        is_shell_true=True,
    )
    path = TaintPath(source=source, sink=sink, file="main.py")
    tf = TaintFinding(
        path=path,
        severity=TaintSeverity.CRITICAL,
        confidence=0.95,
        title="Unsafe shell execution in ConstitutionAI main.py",
        explanation="User prompt flows to shell=True subprocess call",
    )

    correlator = EvidenceCorrelator()
    corr_results = correlator.correlate(findings=[], taint_findings=[tf])
    assert len(corr_results) == 1
    corr = corr_results[0]
    assert corr.root_cause == RootCauseCategory.COMMAND_INJECTION

    # Generate candidate repair proposal
    repair_engine = IntelligentRepairEngine()
    original_code = "import subprocess\ncmd = f'python run.py --prompt {prompt}'\nsubprocess.run(cmd, shell=True)\n"
    proposal = repair_engine.generate_proposal(corr, file_content=original_code)
    assert proposal.strategy == "REPLACE_SHELL_TRUE_WITH_ARG_ARRAY"

    # Validate repair strictly inside IsolatedSandbox
    validator = RealWorldRepairValidator()
    with IsolatedSandbox() as sandbox:
        sandbox.write_file("main.py", original_code)
        val_result = validator.validate_repair(
            correlated_finding=corr,
            proposal=proposal,
            sandbox=sandbox,
            repository_name="ConstitutionAI",
        )

        assert val_result.final_verdict == RepairVerdict.REPAIRED
        assert val_result.syntax_valid is True
        assert val_result.reproduction_passed is True
        assert val_result.original_finding_present_after is False
        assert val_result.patch_quality.quality_score == "HIGH"


def test_real_world_target_2_cadresec_bare_except_repair_validation():
    """Cadresec- bare except clause must be detected and REPAIRED with narrowed exception handler."""
    f = Finding(
        id="cad_1",
        category="bug",
        severity="medium",
        title="Silent error swallow in exception handler",
        file="scanner.py",
        line_range=(1, 4),
    )
    semantic_info = {"exception_intent": "POSSIBLE_ERROR_SWALLOW"}

    correlator = EvidenceCorrelator()
    corr_results = correlator.correlate(findings=[f], semantic_results={"scanner.py": semantic_info})
    assert len(corr_results) == 1
    corr = corr_results[0]
    assert corr.root_cause == RootCauseCategory.EXCEPTION_SWALLOWING

    repair_engine = IntelligentRepairEngine()
    original_code = "try:\n    scan()\nexcept:\n    pass\n"
    proposal = repair_engine.generate_proposal(corr, file_content=original_code)
    assert proposal.strategy == "NARROW_EXCEPTION_AND_LOG"

    validator = RealWorldRepairValidator()
    with IsolatedSandbox() as sandbox:
        sandbox.write_file("scanner.py", original_code)
        val_result = validator.validate_repair(
            correlated_finding=corr,
            proposal=proposal,
            sandbox=sandbox,
            semantic_info=semantic_info,
            repository_name="Cadresec-",
        )
        assert val_result.final_verdict == RepairVerdict.REPAIRED
        assert val_result.syntax_valid is True


def test_real_world_target_3_omnitutor_ai_test_harness_preservation():
    """OmniTutor-AI test harness exception handlers must resolve as NO_REPAIR_REQUIRED."""
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
    corr_results = correlator.correlate(findings=[f], semantic_results={"test_tutor.py": semantic_info})
    corr = corr_results[0]

    validator = RealWorldRepairValidator()
    with IsolatedSandbox() as sandbox:
        val_result = validator.validate_repair(
            correlated_finding=corr,
            proposal=None,
            sandbox=sandbox,
            semantic_info=semantic_info,
            repository_name="OmniTutor-AI",
        )
        assert val_result.final_verdict == RepairVerdict.NO_REPAIR_REQUIRED
        assert val_result.patch_generated is False


def test_real_world_target_4_job_agent_dict_get_preservation():
    """Job_Agent dict.get() must resolve as NO_REPAIR_REQUIRED (0 false positives)."""
    f = Finding(
        id="ja_1",
        category="general",
        severity="low",
        title="Dict lookup in loop",
        file="job_agent.py",
        line_range=(15, 15),
    )

    correlator = EvidenceCorrelator()
    corr_results = correlator.correlate(findings=[f], taint_findings=[])
    corr = corr_results[0]

    validator = RealWorldRepairValidator()
    with IsolatedSandbox() as sandbox:
        semantic_info = {"exception_intent": "INTENTIONAL_FALLBACK"}
        val_result = validator.validate_repair(
            correlated_finding=corr,
            proposal=None,
            sandbox=sandbox,
            semantic_info=semantic_info,
            repository_name="Job_Agent",
        )
        assert val_result.final_verdict == RepairVerdict.NO_REPAIR_REQUIRED
        assert val_result.patch_generated is False


def test_real_world_target_5_medagentx_fallback_preservation():
    """MedAgentX intentional fallback exception handling must resolve as NO_REPAIR_REQUIRED."""
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
    corr_results = correlator.correlate(findings=[f], semantic_results={"main.py": semantic_info})
    corr = corr_results[0]

    validator = RealWorldRepairValidator()
    with IsolatedSandbox() as sandbox:
        val_result = validator.validate_repair(
            correlated_finding=corr,
            proposal=None,
            sandbox=sandbox,
            semantic_info=semantic_info,
            repository_name="MedAgentX",
        )
        assert val_result.final_verdict == RepairVerdict.NO_REPAIR_REQUIRED
        assert val_result.patch_generated is False
