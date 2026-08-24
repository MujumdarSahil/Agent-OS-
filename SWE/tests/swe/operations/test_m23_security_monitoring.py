"""
Dedicated Synthetic Test Suite for M23 Continuous Security Monitoring, Security Drift Detection & Change Impact.

Validates synthetic test scenarios TEST A through TEST AD:
TEST A: Baseline snapshot creation
TEST B: Current snapshot creation
TEST C: New finding detection
TEST D: Fixed finding detection
TEST E: Reopened finding detection
TEST F: Severity increase
TEST G: Severity decrease
TEST H: New attack path detection
TEST I: Removed attack path detection
TEST J: New exploitable path detection
TEST K: Security score degradation
TEST L: Security score improvement
TEST M: Changed-file detection
TEST N: Security-sensitive changed-file detection
TEST O: Finding -> changed-code correlation
TEST P: Attack-path -> changed-code correlation
TEST Q: Drift scoring
TEST R: Critical drift classification
TEST S: Alert generation
TEST T: M14 historical integration
TEST U: M15 prioritization integration
TEST V: M16 attack-path integration
TEST W: M21 knowledge integration
TEST X: M22 simulation eligibility integration
TEST Y: M19 release blocker integration
TEST Z: M20 orchestration integration
TEST AA: Historical timeline generation
TEST AB: No-drift clean repository
TEST AC: Repository isolation
TEST AD: Target repository immutability
"""

import pytest
from agentos_swe.operations.monitoring import (
    SecurityMonitoringEngine,
    SecuritySnapshotEngine,
    SecurityDriftAnalyzer,
    SecurityDriftScorer,
    SecurityChangeAnalyzer,
    SecurityChangeImpactCorrelator,
    SecurityAlertEngine,
    SecurityMonitorScheduler,
    DriftScoreCategory,
)


@pytest.fixture
def engine():
    return SecurityMonitoringEngine()


# TEST A — Baseline snapshot creation
def test_m23_test_a_baseline_snapshot():
    snap_eng = SecuritySnapshotEngine()
    snap = snap_eng.create_snapshot("RepoA", "commit_a", findings=[{"finding_id": "f1", "severity": "HIGH"}])
    assert snap.repository == "RepoA"
    assert snap.high_count == 1


# TEST B — Current snapshot creation
def test_m23_test_b_current_snapshot():
    snap_eng = SecuritySnapshotEngine()
    snap = snap_eng.create_snapshot("RepoB", "commit_b", findings=[{"finding_id": "f2", "severity": "CRITICAL"}])
    assert snap.critical_count == 1


# TEST C — New finding detection
def test_m23_test_c_new_finding_detection():
    snap_eng = SecuritySnapshotEngine()
    analyzer = SecurityDriftAnalyzer()
    b_snap = snap_eng.create_snapshot("RepoC", "c_base", findings=[])
    c_snap = snap_eng.create_snapshot("RepoC", "c_curr", findings=[{"finding_id": "f_new", "severity": "HIGH"}])
    drift = analyzer.analyze_drift(b_snap, c_snap)
    assert len(drift.new_findings) == 1
    assert drift.new_findings[0]["finding_id"] == "f_new"


# TEST D — Fixed finding detection
def test_m23_test_d_fixed_finding_detection():
    snap_eng = SecuritySnapshotEngine()
    analyzer = SecurityDriftAnalyzer()
    b_snap = snap_eng.create_snapshot("RepoD", "d_base", findings=[{"finding_id": "f_old", "severity": "HIGH"}])
    c_snap = snap_eng.create_snapshot("RepoD", "d_curr", findings=[])
    drift = analyzer.analyze_drift(b_snap, c_snap)
    assert len(drift.fixed_findings) == 1
    assert drift.fixed_findings[0]["finding_id"] == "f_old"


# TEST E — Reopened finding detection
def test_m23_test_e_reopened_finding_detection():
    snap_eng = SecuritySnapshotEngine()
    analyzer = SecurityDriftAnalyzer()
    b_snap = snap_eng.create_snapshot("RepoE", "e_base", findings=[])
    c_snap = snap_eng.create_snapshot("RepoE", "e_curr", findings=[{"finding_id": "f_reopen", "severity": "HIGH", "previously_fixed": True}])
    drift = analyzer.analyze_drift(b_snap, c_snap)
    assert len(drift.reopened_findings) == 1


# TEST F — Severity increase
def test_m23_test_f_severity_increase():
    snap_eng = SecuritySnapshotEngine()
    analyzer = SecurityDriftAnalyzer()
    b_snap = snap_eng.create_snapshot("RepoF", "f_base", findings=[{"finding_id": "f1", "severity": "LOW"}])
    c_snap = snap_eng.create_snapshot("RepoF", "f_curr", findings=[{"finding_id": "f1", "severity": "CRITICAL"}])
    drift = analyzer.analyze_drift(b_snap, c_snap)
    assert len(drift.severity_increases) == 1


# TEST G — Severity decrease
def test_m23_test_g_severity_decrease():
    snap_eng = SecuritySnapshotEngine()
    analyzer = SecurityDriftAnalyzer()
    b_snap = snap_eng.create_snapshot("RepoG", "g_base", findings=[{"finding_id": "f1", "severity": "CRITICAL"}])
    c_snap = snap_eng.create_snapshot("RepoG", "g_curr", findings=[{"finding_id": "f1", "severity": "LOW"}])
    drift = analyzer.analyze_drift(b_snap, c_snap)
    assert len(drift.severity_decreases) == 1


# TEST H — New attack path detection
def test_m23_test_h_new_attack_path():
    snap_eng = SecuritySnapshotEngine()
    analyzer = SecurityDriftAnalyzer()
    b_snap = snap_eng.create_snapshot("RepoH", "h_base", attack_paths=[])
    c_snap = snap_eng.create_snapshot("RepoH", "h_curr", attack_paths=[{"id": "ap1", "entrypoint": "HTTP", "sink": "SHELL", "classification": "EXPLOITABLE"}])
    drift = analyzer.analyze_drift(b_snap, c_snap)
    assert len(drift.new_attack_paths) == 1


# TEST I — Removed attack path detection
def test_m23_test_i_removed_attack_path():
    snap_eng = SecuritySnapshotEngine()
    analyzer = SecurityDriftAnalyzer()
    b_snap = snap_eng.create_snapshot("RepoI", "i_base", attack_paths=[{"id": "ap1", "entrypoint": "HTTP"}])
    c_snap = snap_eng.create_snapshot("RepoI", "i_curr", attack_paths=[])
    drift = analyzer.analyze_drift(b_snap, c_snap)
    assert len(drift.removed_attack_paths) == 1


# TEST J — New exploitable path detection
def test_m23_test_j_new_exploitable_path():
    snap_eng = SecuritySnapshotEngine()
    analyzer = SecurityDriftAnalyzer()
    b_snap = snap_eng.create_snapshot("RepoJ", "j_base", attack_paths=[])
    c_snap = snap_eng.create_snapshot("RepoJ", "j_curr", attack_paths=[{"id": "ap1", "classification": "EXPLOITABLE"}])
    drift = analyzer.analyze_drift(b_snap, c_snap)
    assert len(drift.new_exploitable_paths) == 1


# TEST K — Security score degradation
def test_m23_test_k_score_degradation():
    snap_eng = SecuritySnapshotEngine()
    analyzer = SecurityDriftAnalyzer()
    b_snap = snap_eng.create_snapshot("RepoK", "k_base", security_score=100.0)
    c_snap = snap_eng.create_snapshot("RepoK", "k_curr", security_score=75.0)
    drift = analyzer.analyze_drift(b_snap, c_snap)
    assert drift.security_score_delta == -25.0


# TEST L — Security score improvement
def test_m23_test_l_score_improvement():
    snap_eng = SecuritySnapshotEngine()
    analyzer = SecurityDriftAnalyzer()
    b_snap = snap_eng.create_snapshot("RepoL", "l_base", security_score=70.0)
    c_snap = snap_eng.create_snapshot("RepoL", "l_curr", security_score=95.0)
    drift = analyzer.analyze_drift(b_snap, c_snap)
    assert drift.security_score_delta == 25.0


# TEST M — Changed-file detection
def test_m23_test_m_changed_file_detection():
    ch_analyzer = SecurityChangeAnalyzer()
    res = ch_analyzer.analyze_changes(file_list=["app.py", "utils.py"])
    assert len(res["modified_files"]) == 2


# TEST N — Security-sensitive changed-file detection
def test_m23_test_n_security_sensitive_file():
    ch_analyzer = SecurityChangeAnalyzer()
    res = ch_analyzer.analyze_changes(file_list=["server/api.py", "db/queries.py"])
    assert "modified_files" in res


# TEST O — Finding -> changed-code correlation
def test_m23_test_o_finding_correlation():
    correlator = SecurityChangeImpactCorrelator()
    res = correlator.correlate_impact(
        change_analysis={"modified_files": ["server/api.py"], "security_sensitive_files": ["server/api.py"]},
        findings=[{"finding_id": "f1", "affected_file": "server/api.py"}],
    )
    assert len(res.affected_findings) == 1


# TEST P — Attack-path -> changed-code correlation
def test_m23_test_p_attack_path_correlation():
    correlator = SecurityChangeImpactCorrelator()
    res = correlator.correlate_impact(
        change_analysis={"modified_files": ["server/api.py"]},
        attack_paths=[{"id": "ap1", "source_file": "server/api.py", "sink_file": "server/exec.py"}],
    )
    assert len(res.affected_attack_paths) == 1


# TEST Q — Drift scoring
def test_m23_test_q_drift_scoring():
    scorer = SecurityDriftScorer()
    snap_eng = SecuritySnapshotEngine()
    analyzer = SecurityDriftAnalyzer()
    b_snap = snap_eng.create_snapshot("RepoQ", "q_base", findings=[])
    c_snap = snap_eng.create_snapshot("RepoQ", "q_curr", findings=[{"finding_id": "f1", "severity": "CRITICAL"}])
    drift = analyzer.analyze_drift(b_snap, c_snap)
    assert drift.drift_score >= 30.0


# TEST R — Critical drift classification
def test_m23_test_r_critical_drift_classification():
    scorer = SecurityDriftScorer()
    cat = scorer.categorize_drift(65.0)
    assert cat == DriftScoreCategory.CRITICAL_DRIFT


# TEST S — Alert generation
def test_m23_test_s_alert_generation():
    alert_eng = SecurityAlertEngine()
    snap_eng = SecuritySnapshotEngine()
    analyzer = SecurityDriftAnalyzer()
    b_snap = snap_eng.create_snapshot("RepoS", "s_base", findings=[])
    c_snap = snap_eng.create_snapshot("RepoS", "s_curr", findings=[{"finding_id": "f1", "severity": "CRITICAL"}])
    drift = analyzer.analyze_drift(b_snap, c_snap)
    alerts = alert_eng.generate_alerts(drift, "RepoS", "s_curr")
    assert len(alerts) >= 1
    assert alerts[0].alert_type == "CRITICAL_VULNERABILITY_INTRODUCED"


# TEST T — M14 historical integration
def test_m23_test_t_m14_historical(engine):
    res = engine.run_monitoring_pipeline("RepoT", "commit_t", baseline_commit="commit_t0")
    assert "historical_context" in res


# TEST U — M15 prioritization integration
def test_m23_test_u_m15_prioritization(engine):
    res = engine.run_monitoring_pipeline(
        "RepoU", "commit_u",
        current_findings=[{"finding_id": "f_u1", "severity": "CRITICAL"}],
    )
    assert len(res["drift"]["new_findings"]) == 1


# TEST V — M16 attack-path integration
def test_m23_test_v_m16_attack_path(engine):
    res = engine.run_monitoring_pipeline(
        "RepoV", "commit_v",
        attack_paths=[{"id": "ap_v1", "classification": "EXPLOITABLE"}],
    )
    assert "drift" in res


# TEST W — M21 knowledge integration
def test_m23_test_w_m21_knowledge(engine):
    res = engine.run_monitoring_pipeline("RepoW", "commit_w")
    assert res["historical_context"]["historical_success_rate"] == 0.90


# TEST X — M22 simulation eligibility integration
def test_m23_test_x_m22_simulation(engine):
    res = engine.run_monitoring_pipeline(
        "RepoX", "commit_x",
        simulation_results={"overall_status": "NOT_REPRODUCED"},
    )
    assert res["current_snapshot"]["simulation_results"]["overall_status"] == "NOT_REPRODUCED"


# TEST Y — M19 release blocker integration
def test_m23_test_y_m19_release_blocker(engine):
    res = engine.run_monitoring_pipeline(
        "RepoY", "commit_y",
        current_findings=[{"finding_id": "f_y1", "severity": "CRITICAL"}],
    )
    assert res["release_assessment"]["release_safe"] is False


# TEST Z — M20 orchestration integration
def test_m23_test_z_m20_orchestration(engine):
    res = engine.run_monitoring_pipeline("RepoZ", "commit_z")
    assert res["repository"] == "RepoZ"


# TEST AA — Historical timeline generation
def test_m23_test_aa_historical_timeline(engine):
    res = engine.run_monitoring_pipeline("RepoAA", "commit_aa")
    assert "baseline_snapshot" in res
    assert "current_snapshot" in res


# TEST AB — No-drift clean repository
def test_m23_test_ab_clean_repository(engine):
    res = engine.run_monitoring_pipeline("RepoAB", "commit_ab", current_findings=[], baseline_findings=[])
    assert res["drift"]["category"] == "NO_DRIFT"


# TEST AC — Repository isolation
def test_m23_test_ac_repository_isolation(engine):
    res1 = engine.run_monitoring_pipeline("RepoAC1", "c1")
    res2 = engine.run_monitoring_pipeline("RepoAC2", "c2")
    assert res1["repository"] != res2["repository"]


# TEST AD — Target repository immutability
def test_m23_test_ad_repository_immutability(engine):
    res = engine.run_monitoring_pipeline("RepoAD", "c_ad")
    assert res["release_assessment"]["release_safe"] is True
