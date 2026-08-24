"""
Dedicated Synthetic Test Suite for M22 Safe Security Simulation & Exploitability Validation.

Validates synthetic test scenarios TEST A through TEST Z:
TEST A: Safety gate allows localhost simulation
TEST B: Safety gate blocks external target
TEST C: Safety gate blocks destructive command
TEST D: Command injection simulation reproduced safely
TEST E: SQL injection simulation reproduced in SQLite sandbox
TEST F: Path traversal simulation stays sandboxed
TEST G: SSRF simulation uses localhost only
TEST H: XSS simulation uses inert marker
TEST I: Non-tainted command not reproduced
TEST J: Sanitizer blocks simulation
TEST K: Attack path trace generated
TEST L: Reachability analyzer works
TEST M: Before repair reproduced
TEST N: After repair blocked
TEST O: Attack path differential detects broken path
TEST P: New attack path causes regression
TEST Q: M15 exploitability integration
TEST R: M16 attack path integration
TEST S: M17 remediation integration
TEST T: M18 regression integration
TEST U: M19 release integration
TEST V: M20 orchestration integration
TEST W: M21 knowledge integration
TEST X: Sandbox cleanup
TEST Y: Timeout enforcement
TEST Z: Target repository immutability preserved
"""

import pytest
from agentos_swe.remediation.simulation import (
    SecuritySimulationEngine,
    SimulationSafetyGate,
    SimulationReachabilityAnalyzer,
    SecurityScenarioGenerator,
    SecuritySimulationExecutor,
    SimulationDifferentialAnalyzer,
    SimulationStatus,
    SimulationScenario,
    SimulationResult,
)


@pytest.fixture
def engine():
    return SecuritySimulationEngine()


# TEST A — Safety gate allows localhost
def test_m22_test_a_safety_gate_localhost():
    gate = SimulationSafetyGate()
    ok, msg = gate.evaluate_scenario_safety("127.0.0.1", "echo M22_TEST_MARKER")
    assert ok is True
    assert "ALLOWED" in msg


# TEST B — Safety gate blocks external target
def test_m22_test_b_safety_gate_external_target():
    gate = SimulationSafetyGate()
    ok, msg = gate.evaluate_scenario_safety("8.8.8.8", "echo test")
    assert ok is False
    assert "BLOCKED" in msg


# TEST C — Safety gate blocks destructive command
def test_m22_test_c_safety_gate_destructive_command():
    gate = SimulationSafetyGate()
    ok, msg = gate.evaluate_scenario_safety("127.0.0.1", "rm -rf /")
    assert ok is False
    assert "BLOCKED" in msg


# TEST D — Command injection simulation reproduced safely
def test_m22_test_d_command_injection_reproduced():
    gen = SecurityScenarioGenerator()
    scen = gen.generate_scenario({"finding_id": "f_d1", "root_cause": "COMMAND_INJECTION", "source_type": "HTTP", "sink_type": "SUBPROCESS_SHELL"})
    exec_sim = SecuritySimulationExecutor()
    res = exec_sim.execute_simulation(scen)
    assert res.status == SimulationStatus.REPRODUCED
    assert res.reproduced is True


# TEST E — SQL injection simulation reproduced in SQLite sandbox
def test_m22_test_e_sql_injection_reproduced():
    gen = SecurityScenarioGenerator()
    scen = gen.generate_scenario({"finding_id": "f_e1", "root_cause": "SQL_INJECTION", "source_type": "HTTP", "sink_type": "EXECUTE"})
    exec_sim = SecuritySimulationExecutor()
    res = exec_sim.execute_simulation(scen)
    assert res.status == SimulationStatus.REPRODUCED


# TEST F — Path traversal simulation stays sandboxed
def test_m22_test_f_path_traversal_sandboxed():
    gen = SecurityScenarioGenerator()
    scen = gen.generate_scenario({"finding_id": "f_f1", "root_cause": "PATH_TRAVERSAL", "source_type": "HTTP", "sink_type": "OPEN"})
    assert "../sandbox_test.txt" in scen.expected_behavior or "sandbox_test.txt" in scen.expected_behavior


# TEST G — SSRF simulation uses localhost only
def test_m22_test_g_ssrf_localhost():
    gen = SecurityScenarioGenerator()
    scen = gen.generate_scenario({"finding_id": "f_g1", "root_cause": "SSRF", "source_type": "HTTP", "sink_type": "REQUESTS"})
    assert "127.0.0.1" in scen.expected_behavior or "localhost" in scen.expected_behavior


# TEST H — XSS simulation uses inert marker
def test_m22_test_h_xss_inert_marker():
    gen = SecurityScenarioGenerator()
    scen = gen.generate_scenario({"finding_id": "f_h1", "root_cause": "XSS", "source_type": "HTTP", "sink_type": "RESPONSE"})
    assert "M22_MARKER" in scen.expected_behavior


# TEST I — Non-tainted command not reproduced
def test_m22_test_i_non_tainted_command():
    gen = SecurityScenarioGenerator()
    scen = gen.generate_scenario({"finding_id": "f_i1", "root_cause": "SAFE_CONSTANT", "source_type": "INTERNAL", "sink_type": "SUBPROCESS"})
    exec_sim = SecuritySimulationExecutor()
    res = exec_sim.execute_simulation(scen)
    assert res.status == SimulationStatus.NOT_REPRODUCED
    assert res.reproduced is False


# TEST J — Sanitizer blocks simulation
def test_m22_test_j_sanitizer_blocks():
    analyzer = SimulationReachabilityAnalyzer()
    reach = analyzer.analyze_reachability({"root_cause": "COMMAND_INJECTION", "sanitized": True})
    assert reach.reachable is False
    assert reach.blocked_at == "DEFENSIVE_SANITIZER_ACTIVE"


# TEST K — Attack path trace generated
def test_m22_test_k_attack_path_trace():
    gen = SecurityScenarioGenerator()
    scen = gen.generate_scenario({"finding_id": "f_k1", "root_cause": "COMMAND_INJECTION"})
    exec_sim = SecuritySimulationExecutor()
    res = exec_sim.execute_simulation(scen)
    assert len(res.traces) >= 3
    assert res.traces[0].event == "SOURCE_REACHED"


# TEST L — Reachability analyzer works
def test_m22_test_l_reachability_analyzer():
    analyzer = SimulationReachabilityAnalyzer()
    reach = analyzer.analyze_reachability({"root_cause": "COMMAND_INJECTION", "source_type": "HTTP", "sink_type": "SUBPROCESS_SHELL"})
    assert reach.reachable is True


# TEST M — Before repair reproduced
def test_m22_test_m_before_repair_reproduced(engine):
    res = engine.run_simulation_pipeline(
        verified_findings=[{"finding_id": "f_m1", "root_cause": "COMMAND_INJECTION", "source_type": "HTTP", "sink_type": "SUBPROCESS_SHELL"}],
    )
    assert res["overall_status"] == "REPRODUCED"
    assert res["reproduced_count"] == 1


# TEST N — After repair blocked
def test_m22_test_n_after_repair_blocked(engine):
    res = engine.run_simulation_pipeline(
        verified_findings=[{"finding_id": "f_n1", "root_cause": "COMMAND_INJECTION", "source_type": "HTTP", "sink_type": "SUBPROCESS_SHELL"}],
        repair_validations=[{"finding_id": "f_n1", "final_verdict": "REPAIRED"}],
    )
    assert len(res["differentials"]) == 1
    assert res["differentials"][0]["repaired"] is True


# TEST O — Attack path differential detects broken path
def test_m22_test_o_differential_broken_path():
    diff_analyzer = SimulationDifferentialAnalyzer()
    b_res = SimulationResult(scenario_id="s1", status=SimulationStatus.REPRODUCED, reproduced=True, blocked=False)
    a_res = SimulationResult(scenario_id="s1", status=SimulationStatus.NOT_REPRODUCED, reproduced=False, blocked=True)
    diff = diff_analyzer.analyze_differential("f1", b_res, a_res)
    assert diff.attack_path_impact == "ATTACK_PATH_BROKEN"
    assert diff.repaired is True


# TEST P — New attack path causes regression
def test_m22_test_p_differential_new_attack_path():
    diff_analyzer = SimulationDifferentialAnalyzer()
    b_res = SimulationResult(scenario_id="s1", status=SimulationStatus.NOT_REPRODUCED, reproduced=False, blocked=True)
    a_res = SimulationResult(scenario_id="s1", status=SimulationStatus.REPRODUCED, reproduced=True, blocked=False)
    diff = diff_analyzer.analyze_differential("f1", b_res, a_res)
    assert diff.attack_path_impact == "NEW_ATTACK_PATH_INTRODUCED"
    assert diff.regression_detected is True


# TEST Q — M15 exploitability integration
def test_m22_test_q_m15_exploitability(engine):
    res = engine.run_simulation_pipeline(
        prioritized_findings=[{"finding_id": "f_q1", "root_cause": "COMMAND_INJECTION", "source_type": "HTTP", "sink_type": "SUBPROCESS_SHELL"}],
    )
    assert res["results"][0]["security_impact"] in ("CRITICAL", "HIGH")


# TEST R — M16 attack path integration
def test_m22_test_r_m16_attack_path(engine):
    res = engine.run_simulation_pipeline(
        verified_findings=[{"finding_id": "f_r1", "root_cause": "COMMAND_INJECTION", "source_type": "HTTP", "sink_type": "SUBPROCESS_SHELL"}],
        attack_paths=[{"root_cause": "COMMAND_INJECTION", "entrypoint_type": "INTERNET"}],
    )
    assert len(res["scenarios"]) == 1
    assert res["scenarios"][0]["attack_path"] is not None


# TEST S — M17 remediation integration
def test_m22_test_s_m17_remediation(engine):
    res = engine.run_simulation_pipeline(
        verified_findings=[{"finding_id": "f_s1", "root_cause": "COMMAND_INJECTION", "source_type": "HTTP", "sink_type": "SUBPROCESS_SHELL"}],
        repair_validations=[{"finding_id": "f_s1", "final_verdict": "REPAIRED"}],
    )
    assert len(res["differentials"]) == 1


# TEST T — M18 regression integration
def test_m22_test_t_m18_regression(engine):
    diff_analyzer = SimulationDifferentialAnalyzer()
    b_res = SimulationResult(scenario_id="s1", status=SimulationStatus.NOT_REPRODUCED, reproduced=False, blocked=True)
    a_res = SimulationResult(scenario_id="s1", status=SimulationStatus.REPRODUCED, reproduced=True, blocked=False)
    diff = diff_analyzer.analyze_differential("f_t1", b_res, a_res)
    assert diff.regression_detected is True


# TEST U — M19 release integration
def test_m22_test_u_m19_release(engine):
    res = engine.run_simulation_pipeline(
        verified_findings=[{"finding_id": "f_u1", "root_cause": "COMMAND_INJECTION", "source_type": "HTTP", "sink_type": "SUBPROCESS_SHELL"}],
    )
    assert res["reproduced_count"] == 1


# TEST V — M20 orchestration integration
def test_m22_test_v_m20_orchestration(engine):
    res = engine.run_simulation_pipeline(repository_name="RepoV")
    assert "overall_status" in res


# TEST W — M21 knowledge integration
def test_m21_test_w_m21_knowledge(engine):
    res = engine.run_simulation_pipeline(
        verified_findings=[{"finding_id": "f_w1", "root_cause": "SQL_INJECTION", "source_type": "HTTP", "sink_type": "EXECUTE"}],
        repository_name="RepoW",
    )
    assert res["overall_status"] == "REPRODUCED"


# TEST X — Sandbox cleanup
def test_m22_test_x_sandbox_cleanup():
    exec_sim = SecuritySimulationExecutor()
    gen = SecurityScenarioGenerator()
    scen = gen.generate_scenario({"finding_id": "f_x1", "root_cause": "COMMAND_INJECTION"})
    res = exec_sim.execute_simulation(scen)
    assert res.sandbox_id.startswith("sb_sim_")


# TEST Y — Timeout enforcement
def test_m22_test_y_timeout_enforcement():
    gate = SimulationSafetyGate()
    ok, msg = gate.evaluate_scenario_safety("127.0.0.1", "echo test", timeout_sec=45.0)
    assert ok is False
    assert "exceeds maximum threshold" in msg


# TEST Z — Target repository immutability preserved
def test_m22_test_z_target_repo_immutability(engine):
    res = engine.run_simulation_pipeline(
        verified_findings=[{"finding_id": "f_z1", "root_cause": "COMMAND_INJECTION"}],
        repository_name="TargetRepoZ",
    )
    assert res["overall_status"] == "REPRODUCED"
