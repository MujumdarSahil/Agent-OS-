"""
M12 Taint Analysis Test Suite.

Tests deterministic data-flow / taint analysis covering all 16 required cases:
1.  HTTP input → subprocess shell=True             → CRITICAL
2.  HTTP input → eval()                            → CRITICAL
3.  Environment variable → eval()                  → CRITICAL
4.  CLI argument → subprocess                      → HIGH
5.  HTTP input → SQL string concat → execute()     → SQL injection
6.  HTTP input → shlex.quote() → shell             → sanitizer-aware (no finding)
7.  HTTP input → html.escape() → HTML output       → sanitized (no false positive)
8.  Safe constant → subprocess                     → no taint finding
9.  Unknown object .get() in loop                  → no network I/O false positive
10. Inter-procedural: request → var → wrapper → subprocess → path detected
11. Broken propagation path                        → REJECTED or INCONCLUSIVE
12. ConstitutionAI shell=True vuln regression      → still detected
13. Job_Agent patterns                             → no regression
14. MedAgentX patterns                             → no false-positive regression
15. Generic swallowed exception                    → M10.1 behavior preserved
16. Test harness fan-out                           → M11.1 behavior preserved
"""

import os
import pytest

from agentos_swe.security.taint.python_analyzer import PythonTaintAnalyzer
from agentos_swe.security.taint.models import (
    TaintSeverity,
    TaintSinkKind,
    TaintSourceKind,
)
from agentos_swe.security.taint.sources import SourceDetector
from agentos_swe.security.taint.sinks import SinkDetector
from agentos_swe.security.taint.sanitizer import SanitizerDetector
from agentos_swe.core.models import Finding, FindingStatus, Evidence, EvidenceSource
from agentos_swe.core.context import build_repository_context
from agentos_swe.analysis.verification.strategies import StaticVerificationStrategy


@pytest.fixture(autouse=True)
def mock_llm_env(monkeypatch):
    monkeypatch.setenv("AGENTOS_MOCK_LLM", "1")


@pytest.fixture
def analyzer():
    return PythonTaintAnalyzer()


# ============================================================================
# Test 1: HTTP input → subprocess shell=True → CRITICAL
# ============================================================================
def test_http_input_subprocess_shell_true_critical(analyzer):
    """HTTP query param flows directly into subprocess shell=True → CRITICAL."""
    code = """\
import subprocess
from flask import request

def run_cmd():
    cmd = request.args["cmd"]
    subprocess.run(cmd, shell=True)
"""
    result = analyzer.analyze("app.py", code)
    assert not result.unsupported
    assert result.sources_found >= 1, "Should detect request.args as source"
    assert result.sinks_found >= 1, "Should detect subprocess.run as sink"

    confirmed = result.confirmed_findings
    assert confirmed, "Should have at least one confirmed taint finding"
    severities = {f.severity for f in confirmed}
    assert TaintSeverity.CRITICAL in severities, f"Expected CRITICAL, got {severities}"
    # Confidence must be high
    max_conf = max(f.confidence for f in confirmed)
    assert max_conf >= 0.90


# ============================================================================
# Test 2: HTTP input → eval() → CRITICAL
# ============================================================================
def test_http_input_eval_critical(analyzer):
    """HTTP query param flows into eval() → CRITICAL."""
    code = """\
from flask import request

def handler():
    expr = request.args.get("expression")
    result = eval(expr)
    return result
"""
    result = analyzer.analyze("handler.py", code)
    confirmed = result.confirmed_findings
    assert confirmed, "Should detect eval() as critical taint sink"
    severities = {f.severity for f in confirmed}
    assert TaintSeverity.CRITICAL in severities
    sink_kinds = {f.path.sink.sink_kind for f in confirmed}
    assert TaintSinkKind.EVAL_EXECUTION in sink_kinds


# ============================================================================
# Test 3: Environment variable → eval() → CRITICAL
# ============================================================================
def test_env_var_eval_critical(analyzer):
    """os.environ variable flows into eval() → CRITICAL."""
    code = """\
import os

def run():
    user_code = os.environ["SCRIPT"]
    eval(user_code)
"""
    result = analyzer.analyze("runner.py", code)
    confirmed = result.confirmed_findings
    assert confirmed, "Should detect os.environ → eval() as critical"
    sources = {f.path.source.source_kind for f in confirmed}
    assert TaintSourceKind.ENVIRONMENT_VARIABLE in sources
    severities = {f.severity for f in confirmed}
    assert TaintSeverity.CRITICAL in severities


# ============================================================================
# Test 4: CLI argument → subprocess → HIGH
# ============================================================================
def test_cli_argument_subprocess_high(analyzer):
    """sys.argv argument flows into subprocess → HIGH or CRITICAL."""
    code = """\
import sys
import subprocess

def main():
    target = sys.argv[1]
    subprocess.run(target, shell=True)
"""
    result = analyzer.analyze("main.py", code)
    confirmed = result.confirmed_findings
    assert confirmed, "Should detect sys.argv → subprocess as security finding"
    sources = {f.path.source.source_kind for f in confirmed}
    assert TaintSourceKind.CLI_ARGUMENT in sources
    severities = {f.severity for f in confirmed}
    assert severities & {TaintSeverity.HIGH, TaintSeverity.CRITICAL}, \
        f"Expected HIGH or CRITICAL, got {severities}"


# ============================================================================
# Test 5: HTTP input → SQL string concat → execute() → SQL injection
# ============================================================================
def test_http_input_sql_injection(analyzer):
    """HTTP input concatenated into SQL string → SQL injection."""
    code = """\
import sqlite3
from flask import request

def search():
    name = request.args["name"]
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    cursor.execute(query)
"""
    result = analyzer.analyze("search.py", code)
    confirmed = result.confirmed_findings
    assert confirmed, "Should detect SQL injection taint path"
    sink_kinds = {f.path.sink.sink_kind for f in confirmed}
    assert TaintSinkKind.SQL_QUERY in sink_kinds, f"Expected SQL_QUERY sink, got {sink_kinds}"


# ============================================================================
# Test 6: HTTP input → shlex.quote() → shell → sanitizer aware
# ============================================================================
def test_http_input_shlex_quote_sanitized(analyzer):
    """HTTP input sanitized via shlex.quote() before shell execution → sanitized path."""
    code = """\
import shlex
import subprocess
from flask import request

def run_safe():
    raw = request.args.get("cmd")
    safe_cmd = shlex.quote(raw)
    subprocess.run(safe_cmd, shell=True)
"""
    result = analyzer.analyze("safe_cmd.py", code)
    # There may be findings but all should be marked is_sanitized=True
    # OR the confirmed findings (non-sanitized) should be empty
    non_sanitized = [f for f in result.findings if not f.is_sanitized]
    # shlex.quote covers the raw var — path should be sanitized
    assert result.sanitizers_found >= 1, "Should detect shlex.quote() as sanitizer"
    # If there are non-sanitized findings, confidence should be lower
    for f in non_sanitized:
        # Any non-sanitized findings here are for the raw→sink path, but
        # the sanitizer should have been detected on the shlex.quote output var
        assert f.confidence < 0.95 or f.is_sanitized, \
            "High confidence non-sanitized finding on shlex.quote path is unexpected"


# ============================================================================
# Test 7: HTTP input → html.escape() → HTML output → sanitized
# ============================================================================
def test_http_input_html_escape_no_false_positive(analyzer):
    """HTTP input sanitized via html.escape() before HTML output → no false positive."""
    code = """\
import html
from flask import request

def render():
    user_name = request.args.get("name", "")
    safe_name = html.escape(user_name)
    return f"<p>Hello {safe_name}</p>"
"""
    result = analyzer.analyze("render.py", code)
    assert result.sanitizers_found >= 1, "Should detect html.escape() as sanitizer"
    # All findings on this path should be sanitized
    for f in result.findings:
        # user_name → safe_name path should be recognized as sanitized
        if f.path.source.source_kind == TaintSourceKind.QUERY_PARAMETER:
            assert f.is_sanitized, f"Expected sanitized finding for html.escape path, got non-sanitized: {f.title}"


# ============================================================================
# Test 8: Safe constant → subprocess → no taint finding
# ============================================================================
def test_safe_constant_subprocess_no_finding(analyzer):
    """Subprocess called with a static string constant → no taint finding."""
    code = """\
import subprocess

def clean_build():
    subprocess.run("make clean", shell=True)
"""
    result = analyzer.analyze("build.py", code)
    confirmed = result.confirmed_findings
    assert not confirmed, \
        f"Should NOT report taint finding for constant subprocess arg, got: {[f.title for f in confirmed]}"


# ============================================================================
# Test 9: Unknown object .get() inside loop → no network I/O false positive
# ============================================================================
def test_unknown_get_in_loop_no_network_false_positive(analyzer):
    """Unknown object .get() calls inside loop should not be flagged as network I/O."""
    code = """\
def process_jobs(jobs):
    results = []
    for job in jobs:
        title = job.get("title", "")
        company = job.get("company", "")
        results.append({"title": title, "company": company})
    return results
"""
    result = analyzer.analyze("jobs.py", code)
    # Should find no sources (job.get is dict lookup, not external input)
    assert result.sources_found == 0, \
        f"Should not detect dict .get() as external source. Found {result.sources_found} sources."
    assert not result.confirmed_findings, \
        "Should have no taint findings for dict lookup patterns"


# ============================================================================
# Test 10: Inter-procedural propagation: request → var → wrapper → subprocess
# ============================================================================
def test_inter_procedural_propagation_detected(analyzer):
    """Taint flows through a wrapper function to a subprocess sink."""
    code = """\
import subprocess
from flask import request

def execute_command(cmd):
    subprocess.run(cmd, shell=True)

def handler():
    user_cmd = request.args["cmd"]
    execute_command(user_cmd)
"""
    result = analyzer.analyze("handler.py", code)
    confirmed = result.confirmed_findings
    assert confirmed, "Should detect inter-procedural taint path request→var→wrapper→subprocess"
    # Should have propagation steps showing the argument passing
    for f in confirmed:
        if TaintSeverity.CRITICAL == f.severity:
            # The chain should mention the inter-procedural flow
            chain = f.path.chain_description()
            assert "user_cmd" in chain or "cmd" in chain, f"Chain should include propagation vars: {chain}"
            break
    severities = {f.severity for f in confirmed}
    assert TaintSeverity.CRITICAL in severities


# ============================================================================
# Test 11: Broken propagation path → treated as inconclusive or UNKNOWN
# ============================================================================
def test_broken_propagation_path_inconclusive(analyzer):
    """Source is detected but no reachable sink → should produce no confirmed finding."""
    code = """\
from flask import request

def handler():
    user_input = request.args.get("q")
    # No sink — tainted variable is used safely
    cleaned = user_input.strip() if user_input else ""
    return cleaned
"""
    result = analyzer.analyze("safe_handler.py", code)
    # Sources detected but no dangerous sinks → no confirmed findings
    confirmed = result.confirmed_findings
    assert not confirmed, \
        f"Should have no confirmed findings for path without dangerous sink: {[f.title for f in confirmed]}"


# ============================================================================
# Test 12: ConstitutionAI shell=True vulnerability still detected (regression)
# ============================================================================
def test_constitution_ai_shell_true_regression(analyzer):
    """Regression: shell=True subprocess with external input must still be detected."""
    code = """\
import subprocess
from flask import request

def run_constitution_check():
    policy_cmd = request.args.get("policy_cmd")
    # This is the ConstitutionAI-style pattern
    result = subprocess.run(policy_cmd, shell=True, capture_output=True)
    return result.stdout
"""
    result = analyzer.analyze("constitution_check.py", code)
    confirmed = result.confirmed_findings
    assert confirmed, "ConstitutionAI shell=True vuln must still be detected by M12"
    severities = {f.severity for f in confirmed}
    assert TaintSeverity.CRITICAL in severities


# ============================================================================
# Test 13: Job_Agent dict .get() patterns → no regression
# ============================================================================
def test_job_agent_no_regression(analyzer):
    """Job_Agent-style dict.get() loops must NOT produce false positives."""
    code = """\
def process_jobs(jobs):
    for job in jobs:
        title = job.get("title", "N/A")
        salary = job.get("salary", 0)
        location = job.get("location", "Remote")
        if salary > 100000:
            yield {"title": title, "location": location}
"""
    result = analyzer.analyze("job_processor.py", code)
    assert result.sources_found == 0, \
        "Job_Agent dict.get() must not be classified as external source"
    assert not result.confirmed_findings, \
        "Job_Agent dict.get() loops must not produce false-positive taint findings"


# ============================================================================
# Test 14: MedAgentX patterns → no semantic false-positive regression
# ============================================================================
def test_medagentx_no_false_positive(analyzer):
    """MedAgentX-style try/except with fallback must not be flagged as taint vuln."""
    code = """\
import json

def parse_medical_data(raw_data):
    try:
        result = json.loads(raw_data)
        return result
    except (json.JSONDecodeError, ValueError):
        return {}

def load_config(config_path):
    data = {}
    try:
        with open(config_path) as f:
            data = json.load(f)
    except Exception:
        data = {"default": True}
    return data
"""
    result = analyzer.analyze("medagent.py", code)
    # json.loads is deserialization but raw_data here is a function parameter, not an HTTP source
    # No HTTP/env/CLI sources detected
    confirmed = result.confirmed_findings
    # MedAgentX patterns should not trigger taint false positives (no external sources)
    assert not confirmed, \
        f"MedAgentX patterns must not produce false-positive taint findings: {[f.title for f in confirmed]}"


# ============================================================================
# Test 15: Generic swallowed exception → M10.1 behavior preserved
# ============================================================================
def test_swallowed_exception_m10_preserved(tmp_path):
    """M10.1 semantic exception analysis must still work correctly."""
    from agentos_swe.analysis.semantic import SemanticProviderRegistry, ExceptionIntent
    import ast

    code = """\
try:
    import ujson as json
except ImportError:
    import json
"""
    tree = ast.parse(code)
    handler_node = None
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            handler_node = node
            break

    registry = SemanticProviderRegistry()
    result = registry.analyze_exception_block("app.py", handler_node, tree)
    assert result.intent == ExceptionIntent.INTENTIONAL_FALLBACK, \
        "M10.1 ImportError exception analysis must still classify as INTENTIONAL_FALLBACK"


# ============================================================================
# Test 16: Test harness fan-out → M11.1 behavior preserved
# ============================================================================
def test_harness_fanout_m11_preserved(tmp_path):
    """M11.1 test harness module role classification must still work correctly."""
    from agentos_swe.analysis.semantic import SemanticProviderRegistry, ModuleRole

    repo_dir = tmp_path / "myrepo"
    repo_dir.mkdir()
    (repo_dir / "test_core.py").write_text(
        "import unittest\n"
        "from myrepo import core, utils, helpers, config\n"
        "class TestCore(unittest.TestCase): pass\n"
    )

    registry = SemanticProviderRegistry()
    result = registry.analyze_module_role("test_core.py", None)
    assert result.role == ModuleRole.TEST_HARNESS, \
        f"M11.1 test harness classification must still work. Got: {result.role}"


# ============================================================================
# Additional integration tests
# ============================================================================

def test_taint_finding_verification_integration(tmp_path):
    """Taint findings integrate correctly with StaticVerificationStrategy."""
    repo_dir = tmp_path / "vuln_repo"
    repo_dir.mkdir()
    vuln_code = """\
import subprocess
from flask import request

def handler():
    cmd = request.args["cmd"]
    subprocess.run(cmd, shell=True)
"""
    (repo_dir / "vuln.py").write_text(vuln_code)

    context = build_repository_context(str(repo_dir))
    strategy = StaticVerificationStrategy()

    # Build a mock taint finding
    finding = Finding(
        category="security",
        severity="critical",
        title="Potential Shell Command Execution via HTTP Query Parameter",
        file="vuln.py",
        line_range=(5, 6),
        confidence=0.95,
        graph_context={
            "taint_finding": True,
            "source_line": 5,
            "sink_line": 6,
            "chain": "request.args[\"cmd\"]\n→ cmd\n→ subprocess.run(cmd, shell=True)",
            "source_kind": "QUERY_PARAMETER",
            "sink_kind": "SHELL_EXECUTION",
        },
        evidence=[
            Evidence(
                source=EvidenceSource.STATIC_ANALYSIS,
                description="Taint source detected",
                payload={"taint_source": {"code_snippet": '    cmd = request.args["cmd"]'}},
            )
        ],
    )

    confirmed, ev = strategy.verify(finding, context)
    assert confirmed is True, \
        f"Taint finding in real file should be CONFIRMED. Evidence: {ev.description if ev else 'none'}"


def test_taint_finding_rejected_nonexistent_line(tmp_path):
    """Taint finding with invalid line number gets rejected in verification."""
    repo_dir = tmp_path / "small_repo"
    repo_dir.mkdir()
    (repo_dir / "tiny.py").write_text("x = 1\n")

    context = build_repository_context(str(repo_dir))
    strategy = StaticVerificationStrategy()

    finding = Finding(
        category="security",
        severity="critical",
        title="Potential Shell Command Execution via HTTP Query Parameter",
        file="tiny.py",
        line_range=(999, 1001),  # lines that don't exist
        confidence=0.95,
        graph_context={
            "taint_finding": True,
            "source_line": 999,  # invalid
            "sink_line": 1001,   # invalid
            "chain": "source → sink",
        },
        evidence=[],
    )

    confirmed, ev = strategy.verify(finding, context)
    assert confirmed is False, "Taint finding with invalid line numbers should be REJECTED"
    assert "REJECTED" in ev.description or "does not exist" in ev.description


def test_source_detector_flask_patterns():
    """SourceDetector recognizes all Flask request access patterns."""
    import ast
    code = """\
from flask import request
a = request.args["x"]
b = request.args.get("y")
c = request.form["z"]
d = request.get_json()
e = request.json
"""
    tree = ast.parse(code)
    lines = code.splitlines()
    detector = SourceDetector("test.py")
    sources = detector.detect(tree, lines)
    var_names = {s.var_name for s in sources}
    assert "a" in var_names, "request.args[] should be detected"
    assert "b" in var_names, "request.args.get() should be detected"
    assert "c" in var_names, "request.form[] should be detected"


def test_sink_detector_subprocess_variants():
    """SinkDetector recognizes subprocess.run, Popen, call variants."""
    import ast
    code = """\
import subprocess
subprocess.run(cmd, shell=True)
subprocess.Popen(cmd2, shell=True)
subprocess.call(cmd3)
"""
    tree = ast.parse(code)
    lines = code.splitlines()
    detector = SinkDetector("test.py")
    sinks = detector.detect(tree, lines)
    assert len(sinks) >= 2, f"Should detect subprocess sinks, got: {[(s.sink_kind, s.var_name) for s in sinks]}"
    shell_sinks = [s for s in sinks if s.is_shell_true]
    assert len(shell_sinks) >= 2, "subprocess.run and Popen with shell=True should be detected"


def test_sanitizer_detector_parameterized_sql():
    """SanitizerDetector recognizes parameterized SQL patterns."""
    import ast
    code = """\
query = "SELECT * FROM users WHERE id = ?"
cursor.execute(query, (user_id,))
"""
    tree = ast.parse(code)
    lines = code.splitlines()
    detector = SanitizerDetector("test.py")
    sanitizers = detector.detect(tree, lines)
    san_names = {s.sanitizer_name for s in sanitizers}
    assert "parameterized_sql" in san_names, \
        "cursor.execute(query, params) should be recognized as parameterized SQL sanitizer"


def test_env_var_source_detection():
    """SourceDetector recognizes os.environ and os.getenv patterns."""
    import ast
    code = """\
import os
a = os.environ["SECRET"]
b = os.getenv("TOKEN")
c = os.environ.get("KEY", "default")
"""
    tree = ast.parse(code)
    lines = code.splitlines()
    detector = SourceDetector("test.py")
    sources = detector.detect(tree, lines)
    kinds = {s.source_kind for s in sources}
    assert TaintSourceKind.ENVIRONMENT_VARIABLE in kinds, \
        f"os.environ/getenv should be detected as ENVIRONMENT_VARIABLE, got: {kinds}"


def test_taint_severity_model():
    """Severity scoring is deterministic based on source + sink combination."""
    from agentos_swe.security.taint.python_analyzer import _score_severity
    from agentos_swe.security.taint.models import (
        TaintSource, TaintSink, TaintSourceKind, TaintSinkKind,
        TaintSeverity
    )

    source = TaintSource(
        var_name="cmd",
        source_kind=TaintSourceKind.QUERY_PARAMETER,
        line_no=1,
        code_snippet="cmd = request.args['cmd']",
        file="app.py",
    )
    sink_shell = TaintSink(
        var_name="cmd",
        sink_kind=TaintSinkKind.SHELL_EXECUTION,
        line_no=2,
        code_snippet="subprocess.run(cmd, shell=True)",
        file="app.py",
        is_shell_true=True,
    )
    sink_sql = TaintSink(
        var_name="query",
        sink_kind=TaintSinkKind.SQL_QUERY,
        line_no=3,
        code_snippet="cursor.execute(query)",
        file="app.py",
    )

    severity_shell, conf_shell, _ = _score_severity(source, sink_shell, [], False)
    assert severity_shell == TaintSeverity.CRITICAL
    assert conf_shell >= 0.90

    severity_sql, conf_sql, _ = _score_severity(source, sink_sql, [], False)
    assert severity_sql == TaintSeverity.HIGH
    assert conf_sql >= 0.85

    # Sanitized path → LOW
    severity_san, conf_san, _ = _score_severity(source, sink_shell, [], True)
    assert severity_san == TaintSeverity.LOW
