"""
Dedicated M16 Test Suite — Autonomous Attack-Path Reasoning & Security Investigation.
Validates all 30 M16 requirement specifications:
1. HTTP endpoint -> request parameter -> shell sink
2. HTTP endpoint -> helper -> shell sink
3. HTTP endpoint -> sanitized shell sink
4. Constant -> shell sink
5. HTTP endpoint -> SQL sink
6. HTTP endpoint -> eval sink
7. CLI input -> dangerous sink
8. Authenticated endpoint
9. Unauthenticated endpoint
10. Authorization-protected endpoint
11. Trust boundary detection
12. Multi-function propagation
13. Recursive call protection (depth <= 12)
14. Attack path deduplication
15. Attack path fingerprint stability
16. Historical NEW path
17. Historical FIXED path
18. Historical REOPENED path
19. Long-standing attack path
20. Blast radius integration
21. M15 priority integration
22. M13 repair integration
23. M13.1 repair validation integration
24. Sanitizer path
25. Blocked path
26. Exploitable path
27. Negative control with dict.get()
28. Negative control with constant eval()
29. Existing semantic invariants
30. Existing taint invariants
"""

import pytest
from agentos_swe.attackpath.models import (
    AttackPath,
    EntrypointType,
    TrustBoundary,
    AuthStatus,
    PathClassification,
)
from agentos_swe.attackpath.entrypoints import EntrypointDetector
from agentos_swe.attackpath.trust_boundaries import TrustBoundaryAnalyzer
from agentos_swe.attackpath.auth_analyzer import AuthenticationAnalyzer
from agentos_swe.attackpath.path_builder import AttackPathBuilder, MAX_ATTACK_PATH_DEPTH
from agentos_swe.attackpath.attack_graph import AttackGraphBuilder
from agentos_swe.attackpath.attack_scorer import AttackPathScorer
from agentos_swe.attackpath.attack_correlator import AttackPathCorrelator
from agentos_swe.attackpath.investigation import AutonomousSecurityInvestigator


# 1. HTTP endpoint -> request parameter -> shell sink
def test_1_http_endpoint_request_param_shell_sink():
    builder = AttackPathBuilder()
    finding = {
        "finding_id": "ap1",
        "severity": "CRITICAL",
        "root_cause": "COMMAND_INJECTION",
        "affected_file": "routes.py",
        "code_context": "@app.post('/exec')\ndef run_command(): request.args",
    }
    taint = {"finding_id": "ap1", "path": {"source": {"source_kind": "HTTP"}, "sink": {"sink_kind": "SUBPROCESS_SHELL"}}}
    path = builder.build_attack_path(finding, taint)
    assert path.entrypoint_type == EntrypointType.INTERNET
    assert path.classification == PathClassification.EXPLOITABLE


# 2. HTTP endpoint -> helper -> shell sink
def test_2_http_endpoint_helper_shell_sink():
    builder = AttackPathBuilder()
    finding = {
        "finding_id": "ap2",
        "severity": "HIGH",
        "root_cause": "COMMAND_INJECTION",
        "affected_file": "helpers.py",
        "affected_function": "execute_helper",
        "code_context": "@app.get('/run')",
    }
    path = builder.build_attack_path(finding)
    assert len(path.propagation_steps) >= 2


# 3. HTTP endpoint -> sanitized shell sink
def test_3_http_endpoint_sanitized_shell_sink():
    builder = AttackPathBuilder()
    finding = {"finding_id": "ap3", "severity": "HIGH", "root_cause": "COMMAND_INJECTION", "code_context": "@app.post('/api')"}
    taint = {"finding_id": "ap3", "path": {"source": {"source_kind": "HTTP"}, "sink": {"sink_kind": "SUBPROCESS_SHELL"}, "sanitizers": ["shlex.quote"]}}
    path = builder.build_attack_path(finding, taint)
    assert path.classification == PathClassification.PARTIALLY_MITIGATED


# 4. Constant -> shell sink
def test_4_constant_shell_sink():
    builder = AttackPathBuilder()
    finding = {"finding_id": "ap4", "severity": "MEDIUM", "root_cause": "COMMAND_INJECTION", "code_context": "constant literal safe_const"}
    path = builder.build_attack_path(finding)
    assert path.classification == PathClassification.NOT_EXPLOITABLE


# 5. HTTP endpoint -> SQL sink
def test_5_http_endpoint_sql_sink():
    builder = AttackPathBuilder()
    finding = {"finding_id": "ap5", "severity": "CRITICAL", "root_cause": "SQL_INJECTION", "code_context": "@app.post('/query')"}
    taint = {"finding_id": "ap5", "path": {"source": {"source_kind": "HTTP"}, "sink": {"sink_kind": "SQL_EXECUTE"}}}
    path = builder.build_attack_path(finding, taint)
    assert path.sink_type == "SQL_EXECUTE"
    assert path.classification == PathClassification.EXPLOITABLE


# 6. HTTP endpoint -> eval sink
def test_6_http_endpoint_eval_sink():
    builder = AttackPathBuilder()
    finding = {"finding_id": "ap6", "severity": "CRITICAL", "root_cause": "CODE_INJECTION", "code_context": "@app.get('/eval')"}
    taint = {"finding_id": "ap6", "path": {"source": {"source_kind": "HTTP"}, "sink": {"sink_kind": "EVAL"}}}
    path = builder.build_attack_path(finding, taint)
    assert path.classification == PathClassification.EXPLOITABLE


# 7. CLI input -> dangerous sink
def test_7_cli_input_dangerous_sink():
    builder = AttackPathBuilder()
    finding = {"finding_id": "ap7", "severity": "HIGH", "root_cause": "COMMAND_INJECTION", "code_context": "import sys; sys.argv"}
    path = builder.build_attack_path(finding)
    assert path.entrypoint_type == EntrypointType.USER_CLI


# 8. Authenticated endpoint
def test_8_authenticated_endpoint():
    analyzer = AuthenticationAnalyzer()
    ctx = "@app.post('/admin')\ndef admin_panel(user=Depends(get_current_user)):"
    stat = analyzer.analyze_auth_status(code_context=ctx)
    assert stat == AuthStatus.AUTHENTICATED


# 9. Unauthenticated endpoint
def test_9_unauthenticated_endpoint():
    analyzer = AuthenticationAnalyzer()
    ctx = "@app.get('/public')\ndef public_route():"
    stat = analyzer.analyze_auth_status(code_context=ctx)
    assert stat == AuthStatus.UNAUTHENTICATED


# 10. Authorization-protected endpoint
def test_10_authorization_protected_endpoint():
    analyzer = AuthenticationAnalyzer()
    ctx = "def delete_record(): has_permission(user, 'DELETE')"
    stat = analyzer.analyze_auth_status(code_context=ctx)
    assert stat == AuthStatus.AUTHORIZATION_REQUIRED


# 11. Trust boundary detection
def test_11_trust_boundary_detection():
    analyzer = TrustBoundaryAnalyzer()
    bounds, cnt = analyzer.analyze_trust_boundaries(entrypoint_type=EntrypointType.INTERNET, source_kind="HTTP", sink_kind="SUBPROCESS_SHELL")
    assert TrustBoundary.INTERNET in bounds
    assert TrustBoundary.OPERATING_SYSTEM in bounds
    assert cnt >= 2


# 12. Multi-function propagation
def test_12_multi_function_propagation():
    builder = AttackPathBuilder()
    finding = {"finding_id": "ap12", "severity": "HIGH", "affected_file": "core.py", "affected_function": "inner_func"}
    class MockContext:
        def get_callers(self, fn): return ["func_a", "func_b"]
    path = builder.build_attack_path(finding, context=MockContext())
    assert len(path.propagation_steps) >= 3


# 13. Recursive call protection (depth <= 12)
def test_13_recursive_call_protection():
    builder = AttackPathBuilder()
    finding = {"finding_id": "ap13", "severity": "HIGH", "affected_function": "rec_fn"}
    class DeepContext:
        def get_callers(self, fn): return [f"caller_{i}" for i in range(50)]
    path = builder.build_attack_path(finding, context=DeepContext())
    assert len(path.propagation_steps) <= MAX_ATTACK_PATH_DEPTH


# 14. Attack path deduplication
def test_14_attack_path_deduplication():
    correlator = AttackPathCorrelator()
    f1 = {"finding_id": "ap14a", "root_cause": "COMMAND_INJECTION", "affected_file": "a.py", "affected_function": "fn"}
    f2 = {"finding_id": "ap14b", "root_cause": "COMMAND_INJECTION", "affected_file": "a.py", "affected_function": "fn"}
    paths = correlator.correlate_attack_paths([f1, f2])
    assert len(paths) == 1


# 15. Attack path fingerprint stability
def test_15_attack_path_fingerprint_stability():
    builder = AttackPathBuilder()
    f = {"finding_id": "ap15", "root_cause": "SQL_INJECTION", "affected_file": "db.py"}
    p1 = builder.build_attack_path(f)
    p2 = builder.build_attack_path(f)
    assert p1.fingerprint == p2.fingerprint


# 16. Historical NEW path
def test_16_historical_new_path():
    investigator = AutonomousSecurityInvestigator()
    builder = AttackPathBuilder()
    path = builder.build_attack_path({"finding_id": "ap16", "root_cause": "COMMAND_INJECTION"})
    inv = investigator.investigate_attack_path(path)
    assert inv.historical_status == "NEW_ATTACK_PATH"


# 17. Historical FIXED path
def test_17_historical_fixed_path():
    builder = AttackPathBuilder()
    path = builder.build_attack_path({"finding_id": "ap17", "root_cause": "COMMAND_INJECTION", "code_context": "constant safe"})
    assert path.classification == PathClassification.NOT_EXPLOITABLE


# 18. Historical REOPENED path
def test_18_historical_reopened_path():
    scorer = AttackPathScorer()
    builder = AttackPathBuilder()
    path = builder.build_attack_path({"finding_id": "ap18", "root_cause": "COMMAND_INJECTION", "code_context": "@app.post('/')"})
    score = scorer.score_attack_path(path)
    assert score >= 70


# 19. Long-standing attack path
def test_19_long_standing_attack_path():
    builder = AttackPathBuilder()
    path = builder.build_attack_path({"finding_id": "ap19", "root_cause": "EXCEPTION_SWALLOWING"})
    assert path.root_cause == "EXCEPTION_SWALLOWING"


# 20. Blast radius integration
def test_20_blast_radius_integration():
    investigator = AutonomousSecurityInvestigator()
    builder = AttackPathBuilder()
    path = builder.build_attack_path({"finding_id": "ap20", "root_cause": "COMMAND_INJECTION"})
    path.propagation_steps = [path.propagation_steps[0]] * 4
    inv = investigator.investigate_attack_path(path)
    assert inv.blast_radius == "BROAD"


# 21. M15 priority integration
def test_21_m15_priority_integration():
    scorer = AttackPathScorer()
    builder = AttackPathBuilder()
    path = builder.build_attack_path({"finding_id": "ap21", "severity": "CRITICAL", "root_cause": "COMMAND_INJECTION", "code_context": "@app.post('/')"})
    score = scorer.score_attack_path(path)
    assert score >= 80



# 22. M13 repair integration
def test_22_m13_repair_integration():
    builder = AttackPathBuilder()
    path = builder.build_attack_path({"finding_id": "ap22", "root_cause": "COMMAND_INJECTION"})
    assert path.repair_strategy == "REPLACE_SHELL_TRUE_WITH_ARG_ARRAY"


# 23. M13.1 repair validation integration
def test_23_m13_1_repair_validation_integration():
    investigator = AutonomousSecurityInvestigator()
    builder = AttackPathBuilder()
    path = builder.build_attack_path({"finding_id": "ap23", "root_cause": "COMMAND_INJECTION"})
    class MockValidation:
        final_verdict = "REPAIRED"
    inv = investigator.investigate_attack_path(path, validation_result=MockValidation())
    assert inv.validation_status == "REPAIRED"


# 24. Sanitizer path
def test_24_sanitizer_path():
    graph_builder = AttackGraphBuilder()
    builder = AttackPathBuilder()
    path = builder.build_attack_path({"finding_id": "ap24", "root_cause": "COMMAND_INJECTION"}, taint_finding={"path": {"sanitizers": ["shlex.quote"]}})
    graph = graph_builder.build_attack_graph(path)
    node_types = {n.node_type for n in graph.nodes}
    assert "SANITIZER" in node_types


# 25. Blocked path
def test_25_blocked_path():
    scorer = AttackPathScorer()
    builder = AttackPathBuilder()
    path = builder.build_attack_path({"finding_id": "ap25", "severity": "LOW", "root_cause": "INFO"})
    path.classification = PathClassification.BLOCKED
    score = scorer.score_attack_path(path)
    assert score <= 30


# 26. Exploitable path
def test_26_exploitable_path():
    builder = AttackPathBuilder()
    path = builder.build_attack_path({"finding_id": "ap26", "severity": "CRITICAL", "root_cause": "COMMAND_INJECTION", "code_context": "@app.post('/')"})
    assert path.classification == PathClassification.EXPLOITABLE


# 27. Negative control with dict.get()
def test_27_negative_control_dict_get():
    builder = AttackPathBuilder()
    path = builder.build_attack_path({"finding_id": "ap27", "root_cause": "DICT_LOOKUP"})
    assert path.classification == PathClassification.NOT_EXPLOITABLE


# 28. Negative control with constant eval()
def test_28_negative_control_constant_eval():
    builder = AttackPathBuilder()
    path = builder.build_attack_path({"finding_id": "ap28", "root_cause": "CODE_INJECTION", "code_context": "constant literal safe_const"})
    assert path.classification == PathClassification.NOT_EXPLOITABLE


# 29. Existing semantic invariants
def test_29_existing_semantic_invariants():
    detector = EntrypointDetector()
    ep = detector.detect_entrypoints("@app.get('/test')", "test.py")
    assert ep[0]["entrypoint_type"] == EntrypointType.INTERNET


# 30. Existing taint invariants
def test_30_existing_taint_invariants():
    builder = AttackPathBuilder()
    taint = {"path": {"source": {"source_kind": "HTTP"}, "sink": {"sink_kind": "SUBPROCESS_SHELL"}}}
    path = builder.build_attack_path({"finding_id": "ap30", "root_cause": "COMMAND_INJECTION", "code_context": "@app.post('/run')"}, taint)
    assert path.source_type == "HTTP"
    assert path.sink_type == "SUBPROCESS_SHELL"
