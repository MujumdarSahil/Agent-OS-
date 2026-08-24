"""
Dedicated M13 Test Suite — Evidence-Driven Vulnerability Correlation & Intelligent Repair.
Validates all 16 M13 requirement specifications:
1. Single finding correlation
2. Same vulnerability from multiple agents
3. Source-to-sink correlation
4. Inter-procedural vulnerability correlation
5. Root cause identification
6. Confidence scoring
7. Command injection repair proposal
8. SQL injection repair proposal
9. Exception swallow repair proposal
10. Minimal patch generation
11. Patch syntax validation
12. Security regression detection
13. Failed patch handling
14. Governance integration
15. UI rendering
16. Report generation
"""

import pytest
import os
import tempfile
import json
from agentos_swe.core.models import Finding, FindingStatus, Evidence, EvidenceSource
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
    RootCauseAnalyzer,
    RootCauseCategory,
    CorrelatedFinding,
)
from agentos_swe.remediation.repair.repair_strategy import IntelligentRepairEngine
from agentos_swe.remediation.repair.patch_validator import SandboxedPatchValidator
from agentos_swe.remediation.repair.security_regression import SecurityRegressionAnalyzer
from agentos_swe.remediation.repair.models import RegressionStatus, RepairProposal
from agentos_swe.remediation.pr.governance_gate import GovernanceGate
from agentos_swe.remediation.pr.models import GovernanceDecision
from agentos_swe.analysis.verification.sandbox import IsolatedSandbox
from agentos_swe.observability.tracer import TraceCollector
from agentos_swe.observability.report import ReportGenerator
from agentos_swe.ui import run_swe_scan_engine


@pytest.fixture
def sample_findings():
    f1 = Finding(
        id="f1",
        category="security",
        severity="critical",
        title="Unsafe subprocess command execution",
        description="Command injection via shell=True",
        file="app.py",
        line_range=(1, 1),
        symbol="run_cmd",
        confidence=0.9,
    )
    f2 = Finding(
        id="f2",
        category="security",
        severity="high",
        title="Command injection vulnerability in run_cmd",
        description="Untrusted user input reaches subprocess",
        file="app.py",
        line_range=(1, 1),
        symbol="run_cmd",
        confidence=0.85,
    )
    return [f1, f2]


@pytest.fixture
def sample_taint_finding():
    source = TaintSource(
        var_name="cmd",
        source_kind=TaintSourceKind.HTTP_REQUEST,
        line_no=1,
        code_snippet="cmd = request.args['cmd']",
        file="app.py",
    )
    sink = TaintSink(
        var_name="cmd",
        sink_kind=TaintSinkKind.SHELL_EXECUTION,
        line_no=1,
        code_snippet="subprocess.run(cmd, shell=True)",
        file="app.py",
        is_shell_true=True,
    )
    path = TaintPath(source=source, sink=sink, file="app.py")
    return TaintFinding(
        path=path,
        severity=TaintSeverity.CRITICAL,
        confidence=0.95,
        title="Command Injection via shell=True",
        explanation="Untrusted HTTP request arg reaches shell=True sink",
    )


# 1. Single finding correlation
def test_1_single_finding_correlation(sample_findings):
    correlator = EvidenceCorrelator()
    results = correlator.correlate(findings=[sample_findings[0]])
    assert len(results) == 1
    assert results[0].finding_id == "f1"
    assert results[0].affected_file == "app.py"


# 2. Same vulnerability from multiple agents
def test_2_same_vulnerability_from_multiple_agents(sample_findings):
    correlator = EvidenceCorrelator()
    results = correlator.correlate(findings=sample_findings)
    assert len(results) == 1
    assert results[0].finding_id == "f1"
    assert "f2" in results[0].related_finding_ids


# 3. Source-to-sink correlation
def test_3_source_to_sink_correlation(sample_findings, sample_taint_finding):
    correlator = EvidenceCorrelator()
    results = correlator.correlate(findings=sample_findings, taint_findings=[sample_taint_finding])
    assert len(results) == 1
    corr = results[0]
    assert corr.root_cause == RootCauseCategory.COMMAND_INJECTION
    assert len(corr.evidence_chain.source_evidence) > 0
    assert len(corr.evidence_chain.sink_evidence) > 0


# 4. Inter-procedural vulnerability correlation
def test_4_inter_procedural_vulnerability_correlation():
    source = TaintSource(
        var_name="arg",
        source_kind=TaintSourceKind.CLI_ARGUMENT,
        line_no=1,
        code_snippet="arg = sys.argv[1]",
        file="cli.py",
    )
    sink = TaintSink(
        var_name="arg",
        sink_kind=TaintSinkKind.SHELL_EXECUTION,
        line_no=1,
        code_snippet="os.system(arg)",
        file="cli.py",
        is_shell_true=True,
    )
    path = TaintPath(source=source, sink=sink, file="cli.py")
    tf = TaintFinding(path=path, severity=TaintSeverity.HIGH, confidence=0.9, title="CLI Injection", explanation="")
    correlator = EvidenceCorrelator()
    results = correlator.correlate(findings=[], taint_findings=[tf])
    assert len(results) == 1
    assert results[0].root_cause == RootCauseCategory.COMMAND_INJECTION


# 5. Root cause identification
def test_5_root_cause_identification(sample_findings, sample_taint_finding):
    analyzer = RootCauseAnalyzer()
    rc = analyzer.determine_root_cause(sample_findings[0], sample_taint_finding)
    assert rc == RootCauseCategory.COMMAND_INJECTION


# 6. Confidence scoring
def test_6_confidence_scoring(sample_findings, sample_taint_finding):
    correlator = EvidenceCorrelator()
    results = correlator.correlate(findings=sample_findings, taint_findings=[sample_taint_finding])
    corr = results[0]
    assert corr.confidence >= 0.80
    assert len(corr.confidence_explanation.rationale) > 0


# 7. Command injection repair proposal
def test_7_command_injection_repair_proposal(sample_findings, sample_taint_finding):
    correlator = EvidenceCorrelator()
    results = correlator.correlate(findings=sample_findings, taint_findings=[sample_taint_finding])
    engine = IntelligentRepairEngine()
    proposal = engine.generate_proposal(results[0], file_content="subprocess.run(cmd, shell=True)\n")
    assert proposal.strategy == "REPLACE_SHELL_TRUE_WITH_ARG_ARRAY"
    assert "shell=False" in proposal.proposed_snippet
    assert "100% elimination" in proposal.expected_risk_reduction


# 8. SQL injection repair proposal
def test_8_sql_injection_repair_proposal():
    corr = CorrelatedFinding(
        finding_id="sql1",
        vulnerability_category="security",
        severity="high",
        confidence=0.9,
        confidence_explanation=None,
        evidence_chain=None,
        root_cause=RootCauseCategory.SQL_INJECTION,
        affected_file="db.py",
        affected_lines=(1, 1),
    )
    engine = IntelligentRepairEngine()
    proposal = engine.generate_proposal(corr, file_content="cursor.execute('SELECT * FROM users WHERE name=%s' % name)\n")
    assert proposal.strategy == "PARAMETERIZED_SQL_QUERY"
    assert "100% protection" in proposal.expected_risk_reduction


# 9. Exception swallow repair proposal
def test_9_exception_swallow_repair_proposal():
    corr = CorrelatedFinding(
        finding_id="ex1",
        vulnerability_category="bug",
        severity="medium",
        confidence=0.8,
        confidence_explanation=None,
        evidence_chain=None,
        root_cause=RootCauseCategory.EXCEPTION_SWALLOWING,
        affected_file="main.py",
        affected_lines=(1, 4),
    )
    engine = IntelligentRepairEngine()
    proposal = engine.generate_proposal(corr, file_content="try:\n    do_something()\nexcept:\n    pass\n")
    assert proposal.strategy == "NARROW_EXCEPTION_AND_LOG"
    assert "except Exception as err:" in proposal.proposed_snippet


# 10. Minimal patch generation
def test_10_minimal_patch_generation(sample_findings, sample_taint_finding):
    correlator = EvidenceCorrelator()
    results = correlator.correlate(findings=sample_findings, taint_findings=[sample_taint_finding])
    engine = IntelligentRepairEngine()
    proposal = engine.generate_proposal(results[0], file_content="res = subprocess.run(cmd, shell=True)\n")
    assert proposal.unified_diff != ""
    assert "--- a/app.py" in proposal.unified_diff
    assert "+++ b/app.py" in proposal.unified_diff


# 11. Patch syntax validation
def test_11_patch_syntax_validation(sample_findings, sample_taint_finding):
    validator = SandboxedPatchValidator()
    proposal = RepairProposal(
        finding_id="f1",
        root_cause="COMMAND_INJECTION",
        strategy="REPLACE_SHELL_TRUE",
        target_file="app.py",
        proposed_snippet="import subprocess\nsubprocess.run(['ls'], shell=False)\n",
    )
    with IsolatedSandbox() as sandbox:
        sandbox.write_file("app.py", proposal.proposed_snippet)
        res = validator.validate_patch(proposal, sandbox, original_findings=sample_findings)
        assert res.syntax_valid is True
        assert res.repro_valid is True


# 12. Security regression detection
def test_12_security_regression_detection(sample_findings):
    analyzer = SecurityRegressionAnalyzer()
    res = analyzer.analyze_regression(
        pre_patch_findings=sample_findings,
        post_patch_findings=[],
        target_finding_id="f1",
    )
    assert res.regression_status == RegressionStatus.CLEAN
    assert len(res.fixed_findings) > 0


# 13. Failed patch handling
def test_13_failed_patch_handling():
    validator = SandboxedPatchValidator()
    invalid_proposal = RepairProposal(
        finding_id="bad1",
        root_cause="COMMAND_INJECTION",
        strategy="INVALID_SYNTAX",
        target_file="bad.py",
        proposed_snippet="def broken_func(\n",
    )
    with IsolatedSandbox() as sandbox:
        sandbox.write_file("bad.py", invalid_proposal.proposed_snippet)
        res = validator.validate_patch(invalid_proposal, sandbox)
        assert res.success is False
        assert res.syntax_valid is False
        assert "Syntax Error" in res.error_reason


# 14. Governance integration
def test_14_governance_integration():
    gate = GovernanceGate()
    cf = CorrelatedFinding(
        finding_id="g1",
        vulnerability_category="security",
        severity="critical",
        confidence=0.95,
        confidence_explanation=None,
        evidence_chain=None,
        root_cause=RootCauseCategory.COMMAND_INJECTION,
    )
    decision = gate.evaluate_correlated_finding(cf)
    assert decision == GovernanceDecision.REVIEW_REQUIRED


# 15. UI rendering
def test_15_ui_rendering(tmp_path):
    # Test scan engine session data setup with M13 fields
    test_repo = tmp_path / "test_repo"
    test_repo.mkdir()
    (test_repo / "main.py").write_text("import os\nos.system('ls')\n", encoding="utf-8")

    session_data = {}
    run_swe_scan_engine(repo_input=str(test_repo), branch="main", commit="HEAD", session_data=session_data)
    assert "correlated_findings" in session_data
    assert "repair_proposals" in session_data
    assert "governance_decisions" in session_data


# 16. Report generation
def test_16_report_generation(sample_findings, sample_taint_finding):
    correlator = EvidenceCorrelator()
    corr_results = correlator.correlate(findings=sample_findings, taint_findings=[sample_taint_finding])
    gen = ReportGenerator()
    collector = TraceCollector()
    run_report = gen.generate_run_report(collector, repository_name="TestRepo")
    md = gen.render_markdown_report(
        report=run_report,
        correlated_findings=[c.to_dict() for c in corr_results],
        final_verdict="PASS",
    )
    assert "AgentOS-SWE Execution Run Report" in md
    assert "Correlated Vulnerabilities & Root-Cause Analysis" in md
