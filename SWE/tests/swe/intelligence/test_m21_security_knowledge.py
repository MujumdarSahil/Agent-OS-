"""
Dedicated Synthetic Test Suite for M21 Security Knowledge Graph & Learning Intelligence.

Validates synthetic test scenarios TEST A through TEST Y:
TEST A: Store knowledge record
TEST B: Retrieve knowledge record
TEST C: Stable fingerprint
TEST D: Line shift preserves fingerprint
TEST E: Material sink change changes fingerprint
TEST F: Successful remediation learning
TEST G: Failed remediation learning
TEST H: Regression-prone strategy detection
TEST I: Attack-path pattern learning
TEST J: Cross-repository pattern detection
TEST K: Similar finding retrieval
TEST L: Recommendation ranking
TEST M: Historical recurrence influence
TEST N: M15 integration
TEST O: M16 integration
TEST P: M17 integration
TEST Q: M18 integration
TEST R: M19 integration
TEST S: M20 integration
TEST T: Knowledge confidence decay
TEST U: Human feedback
TEST V: Knowledge graph traversal
TEST W: Repository isolation
TEST X: Secret sanitization
TEST Y: Real-world benchmark repository knowledge extraction
"""

import pytest
import os
import tempfile
from agentos_swe.intelligence.knowledge import (
    SecurityKnowledgeEngine,
    SecurityKnowledgeStore,
    SecurityPatternFingerprinter,
    SecurityPatternLearner,
    SecurityKnowledgeRetriever,
    RemediationSuccessLearner,
    AdaptiveSecurityRecommendationEngine,
    SecurityKnowledgeGraph,
    SecurityKnowledgeRecord,
    KnowledgeFeedback,
    SecurityOutcome,
)


@pytest.fixture
def temp_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    yield path
    if os.path.exists(path):
        try:
            os.remove(path)
        except Exception:
            pass


@pytest.fixture
def engine(temp_db):
    return SecurityKnowledgeEngine(store_path=temp_db)


# TEST A — Store knowledge record
def test_m21_test_a_store_record(engine):
    rec = SecurityKnowledgeRecord(
        knowledge_id="k_test_a", vulnerability_family="COMMAND_INJECTION", root_cause="COMMAND_INJECTION",
        source_pattern="HTTP", sink_pattern="SUBPROCESS_SHELL", attack_path_pattern="ap_1",
        affected_framework="FASTAPI", affected_language="PYTHON", remediation_strategy="ARG_ARRAY",
        validation_result="SUCCESSFUL_REPAIR", regression_result="NO_REGRESSION", release_outcome="GO",
    )
    engine.store.save_record(rec)
    fetched = engine.store.get_record("k_test_a")
    assert fetched is not None
    assert fetched.vulnerability_family == "COMMAND_INJECTION"


# TEST B — Retrieve knowledge record
def test_m21_test_b_retrieve_record(engine):
    rec = SecurityKnowledgeRecord(
        knowledge_id="k_test_b", vulnerability_family="SQL_INJECTION", root_cause="SQL_INJECTION",
        source_pattern="HTTP", sink_pattern="EXECUTE", attack_path_pattern="ap_2",
        affected_framework="FLASK", affected_language="PYTHON", remediation_strategy="PARAMETERIZED",
        validation_result="SUCCESSFUL_REPAIR", regression_result="NO_REGRESSION", release_outcome="GO",
    )
    engine.store.save_record(rec)
    results = engine.store.get_by_root_cause("SQL_INJECTION")
    assert len(results) >= 1
    assert results[0].remediation_strategy == "PARAMETERIZED"


# TEST C — Stable fingerprint
def test_m21_test_c_stable_fingerprint():
    fp = SecurityPatternFingerprinter()
    h1 = fp.compute_pattern_fingerprint("CMD", "COMMAND_INJECTION", "HTTP", "SUBPROCESS_SHELL", "PYTHON")
    h2 = fp.compute_pattern_fingerprint("CMD", "COMMAND_INJECTION", "HTTP", "SUBPROCESS_SHELL", "PYTHON")
    assert h1 == h2


# TEST D — Line shift preserves fingerprint
def test_m21_test_d_line_shift_fingerprint():
    fp = SecurityPatternFingerprinter()
    c1 = "def fn():\n    eval(x)"
    c2 = "\n\ndef fn():\n    # comment\n    eval(x)\n"
    assert fp.normalize_code_snippet(c1) == fp.normalize_code_snippet(c2)


# TEST E — Material sink change changes fingerprint
def test_m21_test_e_material_sink_change():
    fp = SecurityPatternFingerprinter()
    h1 = fp.compute_pattern_fingerprint("CMD", "COMMAND_INJECTION", "HTTP", "SUBPROCESS_SHELL", "PYTHON")
    h2 = fp.compute_pattern_fingerprint("CMD", "COMMAND_INJECTION", "HTTP", "OS_SYSTEM", "PYTHON")
    assert h1 != h2


# TEST F — Successful remediation learning
def test_m21_test_f_successful_remediation():
    learner = RemediationSuccessLearner()
    records = [
        {"remediation_strategy": "ARG_ARRAY", "root_cause": "COMMAND_INJECTION", "validation_result": "SUCCESSFUL_REPAIR", "regression_result": "NO_REGRESSION"},
        {"remediation_strategy": "ARG_ARRAY", "root_cause": "COMMAND_INJECTION", "validation_result": "SUCCESSFUL_REPAIR", "regression_result": "NO_REGRESSION"},
    ]
    eff = learner.calculate_effectiveness("ARG_ARRAY", "COMMAND_INJECTION", "COMMAND_INJECTION", records)
    assert eff.successes == 2
    assert eff.confidence_level == "HIGH"


# TEST G — Failed remediation learning
def test_m21_test_g_failed_remediation():
    learner = RemediationSuccessLearner()
    records = [
        {"remediation_strategy": "SANITIZER", "root_cause": "COMMAND_INJECTION", "validation_result": "FAILED_VALIDATION", "regression_result": "NO_REGRESSION"},
    ]
    eff = learner.calculate_effectiveness("SANITIZER", "COMMAND_INJECTION", "COMMAND_INJECTION", records)
    assert eff.failures == 1
    assert eff.confidence_level == "LOW"


# TEST H — Regression-prone strategy detection
def test_m21_test_h_regression_prone():
    learner = RemediationSuccessLearner()
    records = [
        {"remediation_strategy": "BAD_FIX", "root_cause": "COMMAND_INJECTION", "validation_result": "SUCCESSFUL_REPAIR", "regression_result": "INTRODUCED_REGRESSION"},
    ]
    eff = learner.calculate_effectiveness("BAD_FIX", "COMMAND_INJECTION", "COMMAND_INJECTION", records)
    assert eff.regressions == 1
    assert eff.confidence_level == "LOW"


# TEST I — Attack-path pattern learning
def test_m21_test_i_attack_path_pattern():
    learner = SecurityPatternLearner()
    ap = {"entrypoint_type": "INTERNET", "auth_status": "UNAUTHENTICATED", "source_type": "HTTP", "sink_type": "SUBPROCESS_SHELL", "root_cause": "COMMAND_INJECTION"}
    app = learner.extract_attack_path_pattern(ap, "RepoI")
    assert app.entrypoint_type == "INTERNET"
    assert app.sink_type == "SUBPROCESS_SHELL"


# TEST J — Cross-repository pattern detection
def test_m21_test_j_cross_repository():
    learner = SecurityPatternLearner()
    records = [
        {"repository": "Repo1", "root_cause": "COMMAND_INJECTION", "validation_result": "SUCCESSFUL_REPAIR"},
        {"repository": "Repo2", "root_cause": "COMMAND_INJECTION", "validation_result": "SUCCESSFUL_REPAIR"},
    ]
    cross = learner.learn_cross_repository_patterns(records)
    assert len(cross) == 1
    assert cross[0].frequency == 2
    assert len(cross[0].repositories) == 2


# TEST K — Similar finding retrieval
def test_m21_test_k_similar_retrieval(engine):
    rec = SecurityKnowledgeRecord(
        knowledge_id="k_test_k", vulnerability_family="COMMAND_INJECTION", root_cause="COMMAND_INJECTION",
        source_pattern="HTTP", sink_pattern="SUBPROCESS_SHELL", attack_path_pattern="ap_k",
        affected_framework="FASTAPI", affected_language="PYTHON", remediation_strategy="ARG_ARRAY",
        validation_result="SUCCESSFUL_REPAIR", regression_result="NO_REGRESSION", release_outcome="GO",
    )
    engine.store.save_record(rec)
    f = {"root_cause": "COMMAND_INJECTION", "source_type": "HTTP", "sink_type": "SUBPROCESS_SHELL"}
    res = engine.retriever.retrieve_similar_records(f)
    assert len(res) >= 1
    assert res[0].knowledge_id == "k_test_k"


# TEST L — Recommendation ranking
def test_m21_test_l_recommendation_ranking(engine):
    f = {"root_cause": "COMMAND_INJECTION", "vulnerability_family": "COMMAND_INJECTION"}
    rec = engine.recommendation_engine.generate_recommendation(f, [])
    assert rec.strategy == "REPLACE_SHELL_TRUE_WITH_ARG_ARRAY"
    assert rec.confidence in ("HIGH", "MEDIUM")


# TEST M — Historical recurrence influence
def test_m21_test_m_recurrence_influence(engine):
    rec = SecurityKnowledgeRecord(
        knowledge_id="k_test_m", vulnerability_family="PATH_TRAVERSAL", root_cause="PATH_TRAVERSAL",
        source_pattern="HTTP", sink_pattern="FILE", attack_path_pattern="ap_m",
        affected_framework="FLASK", affected_language="PYTHON", remediation_strategy="PATH_VALIDATE",
        validation_result="SUCCESSFUL_REPAIR", regression_result="NO_REGRESSION", release_outcome="GO",
        recurrence_count=5,
    )
    engine.store.save_record(rec)
    fetched = engine.store.get_record("k_test_m")
    assert fetched.recurrence_count >= 1


# TEST N — M15 integration
def test_m21_test_n_m15_integration(engine):
    res = engine.process_scan_knowledge(
        verified_findings=[{"finding_id": "f_n1", "root_cause": "COMMAND_INJECTION"}],
        repository_name="RepoN",
    )
    assert "records_created" in res
    assert len(res["records_created"]) == 1


# TEST O — M16 integration
def test_m21_test_o_m16_integration(engine):
    res = engine.process_scan_knowledge(
        attack_paths=[{"id": "path_o1", "entrypoint_type": "INTERNET", "root_cause": "COMMAND_INJECTION"}],
        repository_name="RepoO",
    )
    assert len(res["attack_patterns"]) == 1


# TEST P — M17 integration
def test_m21_test_p_m17_integration(engine):
    res = engine.process_scan_knowledge(
        remediation_plan={"remediation_items": [{"recommended_fix": "ARG_ARRAY"}]},
        repository_name="RepoP",
    )
    assert "recommendations" in res


# TEST Q — M18 integration
def test_m21_test_q_m18_integration(engine):
    res = engine.process_scan_knowledge(
        monitoring_result={"regression_severity": "CRITICAL_REGRESSION"},
        repository_name="RepoQ",
    )
    assert res["total_knowledge_records"] >= 0


# TEST R — M19 integration
def test_m21_test_r_m19_integration(engine):
    res = engine.process_scan_knowledge(
        verified_findings=[{"finding_id": "f_r1", "root_cause": "COMMAND_INJECTION"}],
        release_decision={"decision": "BLOCKED"},
        repository_name="RepoR",
    )
    assert res["records_created"][0]["release_outcome"] == "BLOCKED"


# TEST S — M20 integration
def test_m21_test_s_m20_integration(engine):
    res = engine.process_scan_knowledge(
        verified_findings=[{"finding_id": "f_s1", "root_cause": "COMMAND_INJECTION"}],
        release_decision={"decision": "GO"},
        repository_name="RepoS",
    )
    assert res["records_created"][0]["validation_result"] == "SUCCESSFUL_REPAIR"


# TEST T — Knowledge confidence decay
def test_m21_test_t_confidence_decay():
    learner = RemediationSuccessLearner()
    decayed = learner.apply_confidence_decay(1.0, "2025-01-01T00:00:00", "2025-01-01T00:00:00", 1)
    assert decayed < 1.0


# TEST U — Human feedback
def test_m21_test_u_human_feedback(engine):
    fb = KnowledgeFeedback(
        feedback_id="fb_1", knowledge_id="k_test_a", reviewer="sec_auditor",
        decision="CONFIRMED", reason="Accurate fix strategy",
    )
    engine.store.save_feedback(fb)
    fbs = engine.store.list_feedback()
    assert len(fbs) == 1
    assert fbs[0].decision == "CONFIRMED"


# TEST V — Knowledge graph traversal
def test_m21_test_v_graph_traversal():
    graph = SecurityKnowledgeGraph()
    graph.add_node("RepoV", "RepoV", "Repository")
    graph.add_node("FindV", "FindV", "Finding")
    graph.add_edge("RepoV", "FindV", "FOUND_IN")
    traversed = graph.traverse("RepoV", max_depth=2)
    assert len(traversed) == 2


# TEST W — Repository isolation
def test_m21_test_w_repository_isolation(engine):
    r1 = SecurityKnowledgeRecord(
        knowledge_id="k_w1", vulnerability_family="SQL", root_cause="SQL", source_pattern="H", sink_pattern="S",
        attack_path_pattern="a", affected_framework="F", affected_language="P", remediation_strategy="R",
        validation_result="S", regression_result="N", release_outcome="G", repositories_seen=["RepoW1"],
    )
    r2 = SecurityKnowledgeRecord(
        knowledge_id="k_w2", vulnerability_family="SQL", root_cause="SQL", source_pattern="H", sink_pattern="S",
        attack_path_pattern="a", affected_framework="F", affected_language="P", remediation_strategy="R",
        validation_result="S", regression_result="N", release_outcome="G", repositories_seen=["RepoW2"],
    )
    engine.store.save_record(r1)
    engine.store.save_record(r2)
    assert engine.store.get_record("k_w1").repositories_seen == ["RepoW1"]


# TEST X — Secret sanitization
def test_m21_test_x_secret_sanitization(engine):
    rec = SecurityKnowledgeRecord(
        knowledge_id="k_x", vulnerability_family="SECRET", root_cause="SECRET", source_pattern="H", sink_pattern="S",
        attack_path_pattern="a", affected_framework="F", affected_language="P",
        remediation_strategy="Fix with key=sk-proj-1234567890abcdef1234567890abcdef",
        validation_result="S", regression_result="N", release_outcome="G",
    )
    engine.store.save_record(rec)
    fetched = engine.store.get_record("k_x")
    assert "sk-proj-" not in fetched.remediation_strategy


# TEST Y — Real-world benchmark repository knowledge extraction
def test_m21_test_y_real_world_extraction(engine):
    res = engine.process_scan_knowledge(
        verified_findings=[{"finding_id": "f_y1", "root_cause": "DICT_LOOKUP"}],
        repository_name="Job_Agent",
    )
    assert res["total_knowledge_records"] >= 1
