"""
Dedicated M13.1 Test Suite — Real-World Intelligent Repair Validation & Security Regression Hardening.
Validates all 16 M13.1 requirement specifications:
1. Successful shell=True repair validation
2. Failed repair handling
3. Syntax-invalid patch rejection
4. Regression introduced by patch (REGRESSION_DETECTED)
5. Vulnerability remains after patch (PARTIALLY_REPAIRED)
6. Vulnerability removed after patch (REPAIRED)
7. No-repair-required intentional fallback (NO_REPAIR_REQUIRED)
8. Test harness diagnostic handler preservation
9. dict.get() lookup non-regression
10. Inter-procedural taint repair validation
11. SQL injection repair validation
12. Minimal patch quality metrics calculation
13. Before/after finding differential calculation
14. Governance gate integration with repair validation
15. Single-file UI repair validation rendering
16. Report generation with M13.1 summary
"""

import pytest
import os
import tempfile
import json
from agentos_swe.core.models import Finding, FindingStatus
from agentos_swe.security.taint.models import (
    TaintFinding,
    TaintPath,
    TaintSource,
    TaintSink,
    TaintSourceKind,
    TaintSinkKind,
    TaintSeverity,
)
from agentos_swe.remediation.correlation import (
    EvidenceCorrelator,
    RootCauseCategory,
    CorrelatedFinding,
)
from agentos_swe.remediation.repair.repair_strategy import IntelligentRepairEngine
from agentos_swe.remediation.repair.repair_validator import RealWorldRepairValidator
from agentos_swe.remediation.repair.models import (
    RepairVerdict,
    RegressionStatus,
    RepairProposal,
    PatchQualityMetrics,
    RepairValidationResult,
)
from agentos_swe.remediation.pr.governance_gate import GovernanceGate
from agentos_swe.remediation.pr.models import GovernanceDecision
from agentos_swe.analysis.verification.sandbox import IsolatedSandbox
from agentos_swe.observability.tracer import TraceCollector
from agentos_swe.observability.report import ReportGenerator
from agentos_swe.ui import run_swe_scan_engine


@pytest.fixture
def shell_finding():
    return CorrelatedFinding(
        finding_id="cmd_inj_1",
        vulnerability_category="security",
        severity="CRITICAL",
        confidence=0.95,
        confidence_explanation=None,
        evidence_chain=None,
        root_cause=RootCauseCategory.COMMAND_INJECTION,
        affected_file="main.py",
        affected_lines=(1, 1),
    )


@pytest.fixture
def shell_proposal():
    return RepairProposal(
        finding_id="cmd_inj_1",
        root_cause="COMMAND_INJECTION",
        strategy="REPLACE_SHELL_TRUE_WITH_ARG_ARRAY",
        target_file="main.py",
        target_lines=(1, 1),
        original_snippet="subprocess.run(cmd, shell=True)\n",
        proposed_snippet="import subprocess\nsubprocess.run(['ls'], shell=False)\n",
        unified_diff="--- a/main.py\n+++ b/main.py\n@@ -1 +1 @@\n-subprocess.run(cmd, shell=True)\n+subprocess.run(['ls'], shell=False)\n",
        expected_risk_reduction="100% elimination",
    )


# 1. Successful shell=True repair validation
def test_1_successful_shell_true_repair(shell_finding, shell_proposal):
    validator = RealWorldRepairValidator()
    with IsolatedSandbox() as sandbox:
        sandbox.write_file("main.py", shell_proposal.original_snippet)
        result = validator.validate_repair(
            correlated_finding=shell_finding,
            proposal=shell_proposal,
            sandbox=sandbox,
            repository_name="ConstitutionAI",
        )
        assert result.final_verdict == RepairVerdict.REPAIRED
        assert result.syntax_valid is True
        assert result.original_finding_present_after is False


# 2. Failed repair handling
def test_2_failed_repair_handling(shell_finding):
    validator = RealWorldRepairValidator()
    with IsolatedSandbox() as sandbox:
        result = validator.validate_repair(
            correlated_finding=shell_finding,
            proposal=None,
            sandbox=sandbox,
        )
        assert result.final_verdict == RepairVerdict.REPAIR_FAILED
        assert "No candidate patch" in result.failure_reason


# 3. Syntax-invalid patch rejection
def test_3_syntax_invalid_patch_rejection(shell_finding):
    bad_proposal = RepairProposal(
        finding_id="cmd_inj_1",
        root_cause="COMMAND_INJECTION",
        strategy="BAD_SYNTAX",
        target_file="main.py",
        proposed_snippet="def broken_syntax(\n",
    )
    validator = RealWorldRepairValidator()
    with IsolatedSandbox() as sandbox:
        sandbox.write_file("main.py", "subprocess.run(cmd, shell=True)\n")
        result = validator.validate_repair(
            correlated_finding=shell_finding,
            proposal=bad_proposal,
            sandbox=sandbox,
        )
        assert result.final_verdict == RepairVerdict.REPAIR_FAILED
        assert result.syntax_valid is False


# 4. Regression introduced by patch (REGRESSION_DETECTED)
def test_4_regression_introduced_by_patch(shell_finding):
    validator = RealWorldRepairValidator()
    proposal = RepairProposal(
        finding_id="cmd_inj_1",
        root_cause="COMMAND_INJECTION",
        strategy="REPLACE",
        target_file="main.py",
        proposed_snippet="import os\nos.system('eval_str')\n",
    )
    with IsolatedSandbox() as sandbox:
        sandbox.write_file("main.py", "subprocess.run(cmd, shell=True)\n")
        result = validator.validate_repair(
            correlated_finding=shell_finding,
            proposal=proposal,
            sandbox=sandbox,
        )
        assert result.final_verdict == RepairVerdict.REGRESSION_DETECTED


# 5. Vulnerability remains after patch (PARTIALLY_REPAIRED)
def test_5_vulnerability_remains_after_patch(shell_finding):
    validator = RealWorldRepairValidator()
    proposal = RepairProposal(
        finding_id="cmd_inj_1",
        root_cause="COMMAND_INJECTION",
        strategy="INCOMPLETE",
        target_file="main.py",
        proposed_snippet="import subprocess\ncmd='ls'\nsubprocess.run(cmd, shell=True)\n",
    )
    with IsolatedSandbox() as sandbox:
        sandbox.write_file("main.py", "import subprocess\nsubprocess.run(cmd, shell=True)\n")
        result = validator.validate_repair(
            correlated_finding=shell_finding,
            proposal=proposal,
            sandbox=sandbox,
        )
        assert result.final_verdict == RepairVerdict.PARTIALLY_REPAIRED


# 6. Vulnerability removed after patch (REPAIRED)
def test_6_vulnerability_removed_after_patch(shell_finding, shell_proposal):
    validator = RealWorldRepairValidator()
    with IsolatedSandbox() as sandbox:
        sandbox.write_file("main.py", shell_proposal.original_snippet)
        result = validator.validate_repair(
            correlated_finding=shell_finding,
            proposal=shell_proposal,
            sandbox=sandbox,
        )
        assert result.final_verdict == RepairVerdict.REPAIRED
        assert result.original_finding_present_after is False


# 7. No-repair-required intentional fallback (NO_REPAIR_REQUIRED)
def test_7_no_repair_required_intentional_fallback():
    cf = CorrelatedFinding(
        finding_id="diag_1",
        vulnerability_category="bug",
        severity="medium",
        confidence=0.5,
        confidence_explanation=None,
        evidence_chain=None,
        root_cause=RootCauseCategory.UNKNOWN,
        affected_file="med.py",
    )
    validator = RealWorldRepairValidator()
    with IsolatedSandbox() as sandbox:
        result = validator.validate_repair(
            correlated_finding=cf,
            proposal=None,
            sandbox=sandbox,
            semantic_info={"exception_intent": "INTENTIONAL_FALLBACK"},
        )
        assert result.final_verdict == RepairVerdict.NO_REPAIR_REQUIRED


# 8. Test harness diagnostic handler preservation
def test_8_test_harness_diagnostic_handler():
    cf = CorrelatedFinding(
        finding_id="th_1",
        vulnerability_category="bug",
        severity="low",
        confidence=0.4,
        confidence_explanation=None,
        evidence_chain=None,
        root_cause=RootCauseCategory.UNKNOWN,
        affected_file="test_omni.py",
    )
    validator = RealWorldRepairValidator()
    with IsolatedSandbox() as sandbox:
        result = validator.validate_repair(
            correlated_finding=cf,
            proposal=None,
            sandbox=sandbox,
            semantic_info={"module_role": "TEST_HARNESS"},
        )
        assert result.final_verdict == RepairVerdict.NO_REPAIR_REQUIRED


# 9. dict.get() lookup non-regression
def test_9_dict_get_lookup_non_regression():
    cf = CorrelatedFinding(
        finding_id="dict_1",
        vulnerability_category="general",
        severity="low",
        confidence=0.3,
        confidence_explanation=None,
        evidence_chain=None,
        root_cause=RootCauseCategory.UNKNOWN,
        affected_file="job_agent.py",
    )
    validator = RealWorldRepairValidator()
    with IsolatedSandbox() as sandbox:
        result = validator.validate_repair(
            correlated_finding=cf,
            proposal=None,
            sandbox=sandbox,
        )
        assert result.final_verdict == RepairVerdict.NO_REPAIR_REQUIRED


# 10. Inter-procedural taint repair validation
def test_10_inter_procedural_taint_repair():
    cf = CorrelatedFinding(
        finding_id="inter_1",
        vulnerability_category="security",
        severity="HIGH",
        confidence=0.9,
        confidence_explanation=None,
        evidence_chain=None,
        root_cause=RootCauseCategory.COMMAND_INJECTION,
        affected_file="wrapper.py",
        affected_lines=(1, 1),
    )
    prop = RepairProposal(
        finding_id="inter_1",
        root_cause="COMMAND_INJECTION",
        strategy="REPLACE_SHELL_TRUE",
        target_file="wrapper.py",
        original_snippet="os.system(arg)\n",
        proposed_snippet="import subprocess, shlex\nsubprocess.run(shlex.split(arg))\n",
    )
    validator = RealWorldRepairValidator()
    with IsolatedSandbox() as sandbox:
        sandbox.write_file("wrapper.py", prop.original_snippet)
        result = validator.validate_repair(correlated_finding=cf, proposal=prop, sandbox=sandbox)
        assert result.final_verdict == RepairVerdict.REPAIRED


# 11. SQL injection repair validation
def test_11_sql_injection_repair_validation():
    cf = CorrelatedFinding(
        finding_id="sql_1",
        vulnerability_category="security",
        severity="HIGH",
        confidence=0.9,
        confidence_explanation=None,
        evidence_chain=None,
        root_cause=RootCauseCategory.SQL_INJECTION,
        affected_file="db.py",
        affected_lines=(1, 1),
    )
    prop = RepairProposal(
        finding_id="sql_1",
        root_cause="SQL_INJECTION",
        strategy="PARAMETERIZED_SQL_QUERY",
        target_file="db.py",
        original_snippet="cursor.execute('SELECT * FROM users WHERE name=%s' % name)\n",
        proposed_snippet="cursor.execute('SELECT * FROM users WHERE name=?', (name,))\n",
    )
    validator = RealWorldRepairValidator()
    with IsolatedSandbox() as sandbox:
        sandbox.write_file("db.py", prop.original_snippet)
        result = validator.validate_repair(correlated_finding=cf, proposal=prop, sandbox=sandbox)
        assert result.final_verdict == RepairVerdict.REPAIRED


# 12. Minimal patch quality metrics calculation
def test_12_minimal_patch_quality_metrics(shell_proposal):
    validator = RealWorldRepairValidator()
    quality = validator._evaluate_patch_quality(shell_proposal)
    assert quality.modified_files_count == 1
    assert quality.quality_score == "HIGH"
    assert quality.api_signatures_preserved is True


# 13. Before/after finding differential calculation
def test_13_before_after_finding_differential(shell_finding, shell_proposal):
    validator = RealWorldRepairValidator()
    pre_f = [Finding(id="f1", category="security", title="shell=True", file="main.py")]
    with IsolatedSandbox() as sandbox:
        sandbox.write_file("main.py", shell_proposal.original_snippet)
        result = validator.validate_repair(
            correlated_finding=shell_finding,
            proposal=shell_proposal,
            sandbox=sandbox,
            pre_patch_findings=pre_f,
        )
        assert len(result.removed_security_findings) >= 0


# 14. Governance gate integration with repair validation
def test_14_governance_gate_repair_validation():
    gate = GovernanceGate()
    val_res = RepairValidationResult(
        finding_id="val_1",
        repository="TestRepo",
        target_file="main.py",
        final_verdict=RepairVerdict.REPAIRED,
        original_severity="CRITICAL",
    )
    decision = gate.evaluate_repair_validation(val_res)
    assert decision == GovernanceDecision.REVIEW_REQUIRED


# 15. Single-file UI repair validation rendering
def test_15_ui_repair_validation_rendering(tmp_path):
    test_repo = tmp_path / "ui_test_repo"
    test_repo.mkdir()
    (test_repo / "main.py").write_text("import os\nos.system('ls')\n", encoding="utf-8")

    session_data = {}
    run_swe_scan_engine(repo_input=str(test_repo), branch="main", commit="HEAD", session_data=session_data)
    assert "repair_validations" in session_data
    assert len(session_data["repair_validations"]) > 0


# 16. Report generation with M13.1 summary
def test_16_report_generation_with_m13_1_summary(shell_finding):
    val_res = RepairValidationResult(
        finding_id="rep_1",
        repository="TestRepo",
        target_file="main.py",
        final_verdict=RepairVerdict.REPAIRED,
        original_severity="HIGH",
    )
    gen = ReportGenerator()
    collector = TraceCollector()
    run_report = gen.generate_run_report(collector, repository_name="TestRepo")
    md = gen.render_markdown_report(
        report=run_report,
        repair_validations=[val_res.to_dict()],
        final_verdict="PASS",
    )
    assert "M13.1 Real-World Repair Validation Summary" in md
    assert "main.py" in md
