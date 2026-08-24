"""
Dedicated M16.1 Test Suite — Attack-Path Real-World Validation & False-Positive Hardening.

Validates synthetic test scenarios A through L and false-positive hardening invariants:
TEST A — Genuine unauthenticated command injection
TEST B — Authenticated command injection
TEST C — SQL injection
TEST D — Safe parameterized SQL
TEST E — Constant command
TEST F — Sanitized shell input
TEST G — Dictionary lookup negative control
TEST H — Test harness negative control
TEST I — Silent exception
TEST J — Inter-procedural attack path
TEST K — Trust boundary transition
TEST L — Internal-only API
Plus verification rejection, evidence confidence, and UI data consistency.
"""

import pytest
from agentos_swe.intelligence.attackpath.models import (
    AttackPath,
    EntrypointType,
    TrustBoundary,
    AuthStatus,
    PathClassification,
)
from agentos_swe.intelligence.attackpath.entrypoints import EntrypointDetector
from agentos_swe.intelligence.attackpath.trust_boundaries import TrustBoundaryAnalyzer
from agentos_swe.intelligence.attackpath.auth_analyzer import AuthenticationAnalyzer
from agentos_swe.intelligence.attackpath.path_builder import AttackPathBuilder, MAX_ATTACK_PATH_DEPTH
from agentos_swe.intelligence.attackpath.attack_graph import AttackGraphBuilder
from agentos_swe.intelligence.attackpath.attack_scorer import AttackPathScorer
from agentos_swe.intelligence.attackpath.attack_correlator import AttackPathCorrelator
from agentos_swe.intelligence.attackpath.investigation import AutonomousSecurityInvestigator


# TEST A — Genuine unauthenticated command injection
def test_m16_1_test_a_unauthenticated_command_injection():
    builder = AttackPathBuilder()
    scorer = AttackPathScorer()
    finding = {
        "finding_id": "test_a_1",
        "severity": "CRITICAL",
        "root_cause": "COMMAND_INJECTION",
        "affected_file": "app/routes.py",
        "affected_function": "execute_user_cmd",
        "code_context": "@app.post('/api/v1/run')\ndef run(cmd: str): subprocess.run(cmd, shell=True)",
    }
    taint = {
        "finding_id": "test_a_1",
        "path": {
            "source": {"source_kind": "HTTP"},
            "sink": {"sink_kind": "SUBPROCESS_SHELL"},
        },
    }
    path = builder.build_attack_path(finding, taint)
    scorer.score_attack_path(path)

    assert path.entrypoint_type == EntrypointType.INTERNET
    assert path.auth_status == AuthStatus.UNAUTHENTICATED
    assert path.sink_type == "SUBPROCESS_SHELL"
    assert path.root_cause == "COMMAND_INJECTION"
    assert path.classification == PathClassification.EXPLOITABLE
    assert path.severity in ("CRITICAL", "HIGH")
    assert path.risk_score >= 70
    assert len(path.propagation_steps) >= 2
    assert TrustBoundary.INTERNET in path.trust_boundaries_crossed
    assert TrustBoundary.OPERATING_SYSTEM in path.trust_boundaries_crossed


# TEST B — Authenticated command injection
def test_m16_1_test_b_authenticated_command_injection():
    builder = AttackPathBuilder()
    scorer = AttackPathScorer()
    finding = {
        "finding_id": "test_b_1",
        "severity": "HIGH",
        "root_cause": "COMMAND_INJECTION",
        "affected_file": "app/admin.py",
        "code_context": "@app.post('/admin/exec')\ndef admin_exec(cmd: str, user=Depends(get_current_user)):\n subprocess.run(cmd, shell=True)",
    }
    taint = {
        "finding_id": "test_b_1",
        "path": {
            "source": {"source_kind": "HTTP"},
            "sink": {"sink_kind": "SUBPROCESS_SHELL"},
        },
    }
    path = builder.build_attack_path(finding, taint)
    scorer.score_attack_path(path)

    assert path.entrypoint_type == EntrypointType.INTERNET
    assert path.auth_status == AuthStatus.AUTHENTICATED
    assert path.auth_status != AuthStatus.UNAUTHENTICATED
    assert path.classification == PathClassification.EXPLOITABLE
    # Score should reflect authentication boundary penalty vs unauthenticated
    path_unauth = builder.build_attack_path({**finding, "code_context": "@app.post('/admin/exec')\ndef exec(cmd): subprocess.run(cmd, shell=True)"}, taint)
    scorer.score_attack_path(path_unauth)
    assert path.risk_score < path_unauth.risk_score


# TEST C — SQL injection
def test_m16_1_test_c_sql_injection():
    builder = AttackPathBuilder()
    finding = {
        "finding_id": "test_c_1",
        "severity": "CRITICAL",
        "root_cause": "SQL_INJECTION",
        "affected_file": "app/users.py",
        "code_context": "@app.get('/user')\ndef get_user():\n sql = 'SELECT * FROM users WHERE id = ' + request.args['id']\n cursor.execute(sql)",
    }
    taint = {
        "finding_id": "test_c_1",
        "path": {
            "source": {"source_kind": "HTTP"},
            "sink": {"sink_kind": "SQL_EXECUTE"},
        },
    }
    path = builder.build_attack_path(finding, taint)

    assert path.root_cause == "SQL_INJECTION"
    assert path.sink_type == "SQL_EXECUTE"
    assert path.classification == PathClassification.EXPLOITABLE
    assert TrustBoundary.DATABASE in path.trust_boundaries_crossed


# TEST D — Safe parameterized SQL
def test_m16_1_test_d_safe_parameterized_sql():
    builder = AttackPathBuilder()
    finding = {
        "finding_id": "test_d_1",
        "severity": "LOW",
        "root_cause": "SQL_INJECTION",
        "affected_file": "app/users.py",
        "code_context": "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,)) params=",
    }
    path = builder.build_attack_path(finding)

    assert path.classification == PathClassification.NOT_EXPLOITABLE


# TEST E — Constant command
def test_m16_1_test_e_constant_command():
    builder = AttackPathBuilder()
    finding = {
        "finding_id": "test_e_1",
        "severity": "LOW",
        "root_cause": "COMMAND_INJECTION",
        "affected_file": "app/system.py",
        "code_context": "subprocess.run('echo hello', shell=True)",
    }
    path = builder.build_attack_path(finding)

    assert path.classification == PathClassification.NOT_EXPLOITABLE
    assert path.entrypoint_type != EntrypointType.INTERNET or path.classification != PathClassification.EXPLOITABLE


# TEST F — Sanitized shell input
def test_m16_1_test_f_sanitized_shell_input():
    builder = AttackPathBuilder()
    scorer = AttackPathScorer()
    finding = {
        "finding_id": "test_f_1",
        "severity": "HIGH",
        "root_cause": "COMMAND_INJECTION",
        "affected_file": "app/utils.py",
        "code_context": "@app.post('/api/clean')\nsafe_input = shlex.quote(user_input)\nsubprocess.run(safe_input, shell=True)",
    }
    taint = {
        "finding_id": "test_f_1",
        "path": {
            "source": {"source_kind": "HTTP"},
            "sink": {"sink_kind": "SUBPROCESS_SHELL"},
            "sanitizers": ["shlex.quote"],
        },
    }
    path = builder.build_attack_path(finding, taint)
    scorer.score_attack_path(path)

    assert path.classification == PathClassification.PARTIALLY_MITIGATED
    assert "shlex.quote" in path.sanitizer_steps
    assert path.severity != "CRITICAL"


# TEST G — Dictionary lookup negative control
def test_m16_1_test_g_dict_lookup_negative_control():
    builder = AttackPathBuilder()
    finding = {
        "finding_id": "test_g_1",
        "severity": "LOW",
        "root_cause": "DICT_LOOKUP",
        "affected_file": "app/data.py",
        "code_context": "job.get('title') or data.get('status')",
    }
    path = builder.build_attack_path(finding)

    assert path.classification == PathClassification.NOT_EXPLOITABLE
    assert path.entrypoint_type != EntrypointType.INTERNET


# TEST H — Test harness negative control
def test_m16_1_test_h_test_harness_negative_control():
    detector = EntrypointDetector()
    builder = AttackPathBuilder()
    ep = detector.detect_entrypoints(
        code_context="try:\n run_test()\nexcept Exception as e:\n print(e)\n return None",
        file_path="tests/test_security.py",
    )
    assert ep[0]["framework"] == "TestHarness"

    path = builder.build_attack_path({
        "finding_id": "test_h_1",
        "root_cause": "EXCEPTION_SWALLOWING",
        "affected_file": "tests/test_security.py",
        "code_context": "try:\n run()\nexcept Exception as e:\n print(e)",
    })
    assert path.classification == PathClassification.NOT_EXPLOITABLE


# TEST I — Silent exception
def test_m16_1_test_i_silent_exception():
    builder = AttackPathBuilder()
    finding = {
        "finding_id": "test_i_1",
        "severity": "MEDIUM",
        "root_cause": "EXCEPTION_SWALLOWING",
        "affected_file": "app/worker.py",
        "code_context": "try:\n dangerous_operation()\nexcept Exception:\n pass",
    }
    path = builder.build_attack_path(finding)

    assert path.classification in (PathClassification.BLOCKED, PathClassification.NOT_EXPLOITABLE)
    assert path.root_cause == "EXCEPTION_SWALLOWING"


# TEST J — Inter-procedural attack path
def test_m16_1_test_j_inter_procedural_attack_path():
    builder = AttackPathBuilder()

    class MockCallContext:
        def get_callers(self, fn):
            return ["wrapper_function", "execute_command"]

    finding = {
        "finding_id": "test_j_1",
        "severity": "HIGH",
        "root_cause": "COMMAND_INJECTION",
        "affected_file": "app/handler.py",
        "affected_function": "execute_command",
        "code_context": "@app.post('/cmd')\ndef handle(input): wrapper_function(input)",
    }
    taint = {
        "finding_id": "test_j_1",
        "path": {"source": {"source_kind": "HTTP"}, "sink": {"sink_kind": "SUBPROCESS_SHELL"}},
    }
    path = builder.build_attack_path(finding, taint_finding=taint, context=MockCallContext())

    assert len(path.propagation_steps) >= 3
    assert len(path.propagation_steps) <= MAX_ATTACK_PATH_DEPTH
    funcs = [s.function_name for s in path.propagation_steps if s.function_name]
    assert "wrapper_function" in funcs or "execute_command" in funcs


# TEST K — Trust boundary transition
def test_m16_1_test_k_trust_boundary_transition():
    analyzer = TrustBoundaryAnalyzer()
    boundaries, count = analyzer.analyze_trust_boundaries(
        entrypoint_type=EntrypointType.INTERNET,
        source_kind="HTTP",
        sink_kind="SUBPROCESS_SHELL",
    )

    assert TrustBoundary.INTERNET in boundaries
    assert TrustBoundary.APPLICATION in boundaries
    assert TrustBoundary.OPERATING_SYSTEM in boundaries
    assert boundaries.index(TrustBoundary.INTERNET) < boundaries.index(TrustBoundary.APPLICATION)
    assert boundaries.index(TrustBoundary.APPLICATION) < boundaries.index(TrustBoundary.OPERATING_SYSTEM)


# TEST L — Internal-only API
def test_m16_1_test_l_internal_only_api():
    builder = AttackPathBuilder()
    finding = {
        "finding_id": "test_l_1",
        "severity": "HIGH",
        "root_cause": "COMMAND_INJECTION",
        "affected_file": "services/internal.py",
        "code_context": "def internal_cron_task(): subprocess.run(['ls', '-la'])",
    }
    path = builder.build_attack_path(finding)

    assert path.entrypoint_type in (EntrypointType.INTERNAL_API, EntrypointType.UNKNOWN)
    assert path.classification != PathClassification.EXPLOITABLE or path.entrypoint_type != EntrypointType.INTERNET


# Additional Tests: Investigation Rationale and UI Data Consistency
def test_m16_1_investigation_rationale():
    investigator = AutonomousSecurityInvestigator()
    builder = AttackPathBuilder()
    path = builder.build_attack_path({
        "finding_id": "inv_test",
        "root_cause": "COMMAND_INJECTION",
        "code_context": "@app.post('/run')\ndef run(): subprocess.run(cmd, shell=True)",
    })
    inv = investigator.investigate_attack_path(path)

    assert inv.why_dangerous_narrative
    assert inv.how_to_break_narrative
    assert inv.root_cause == "COMMAND_INJECTION"
    assert inv.recommendation == "REPLACE_SHELL_TRUE_WITH_ARG_ARRAY"


def test_m16_1_correlator_deduplication():
    correlator = AttackPathCorrelator()
    f1 = {"finding_id": "dedup1", "root_cause": "SQL_INJECTION", "affected_file": "db.py", "code_context": "@app.get('/db')"}
    f2 = {"finding_id": "dedup2", "root_cause": "SQL_INJECTION", "affected_file": "db.py", "code_context": "@app.get('/db')"}
    paths = correlator.correlate_attack_paths([f1, f2])

    assert len(paths) == 1
    assert paths[0].root_cause == "SQL_INJECTION"
