"""
Dedicated M15 Test Suite — Intelligent Security Prioritization & Cross-Repository Risk Intelligence.
Validates all 20 M15 requirement specifications:
1. Critical external input -> shell sink (P0)
2. Constant -> shell sink (P3/P4)
3. External input -> SQL sink
4. Sanitized external input
5. Internet-exposed FastAPI route
6. Internal-only function
7. High blast-radius shared function
8. Local isolated vulnerability
9. Newly introduced finding
10. Historical unchanged finding
11. Reopened finding
12. Recurring vulnerability
13. Cross-repository same vulnerability family
14. Different root causes remain separate
15. Priority ordering
16. Priority score breakdown explanation
17. Recommendation generation
18. Existing M12 taint invariants preserved
19. Existing M13 repair invariants preserved
20. Existing M14 historical invariants preserved
"""

import pytest
from agentos_swe.intelligence.models import (
    PriorityTier,
    ExploitabilityLevel,
    ExposureLevel,
    BlastRadiusLevel,
    RecurrenceLevel,
)
from agentos_swe.intelligence.prioritizer import SecurityPriorityEngine
from agentos_swe.intelligence.exploitability import ExploitabilityAnalyzer
from agentos_swe.intelligence.exposure import ExposureAnalyzer
from agentos_swe.intelligence.blast_radius import BlastRadiusAnalyzer
from agentos_swe.intelligence.cross_repository import CrossRepositoryIntelligenceEngine
from agentos_swe.intelligence.recommendation import SecurityRecommendationEngine
from agentos_swe.pr.governance_gate import GovernanceGate
from agentos_swe.pr.models import GovernanceDecision
from agentos_swe.observability.tracer import TraceCollector
from agentos_swe.observability.report import ReportGenerator
from agentos_swe.history.store import HistoricalScanStore


# 1. Critical external input -> shell sink (P0)
def test_1_critical_external_input_shell_sink():
    prio_engine = SecurityPriorityEngine()
    finding = {
        "finding_id": "f1",
        "severity": "CRITICAL",
        "root_cause": "COMMAND_INJECTION",
        "affected_file": "api/routes.py",
        "code_context": "@app.post('/run')\ndef run_cmd(): request.args",
        "confidence": 0.95,
    }
    taint = {"finding_id": "f1", "path": {"source": {"source_kind": "HTTP"}, "sink": {"sink_kind": "SUBPROCESS_SHELL"}}}
    res = prio_engine.prioritize_findings(findings=[finding], taint_findings=[taint])
    assert len(res) == 1
    assert res[0].priority_tier == PriorityTier.P0
    assert res[0].priority_score >= 90


# 2. Constant -> shell sink (P3/P4)
def test_2_constant_shell_sink():
    prio_engine = SecurityPriorityEngine()
    finding = {
        "finding_id": "f2",
        "severity": "MEDIUM",
        "root_cause": "COMMAND_INJECTION",
        "affected_file": "main.py",
        "code_context": "subprocess.run('ls -l', shell=True)",
        "confidence": 0.90,
    }
    taint = {"finding_id": "f2", "path": {"source": {"source_kind": "CONSTANT"}, "sink": {"sink_kind": "SUBPROCESS_SHELL"}}}
    res = prio_engine.prioritize_findings(findings=[finding], taint_findings=[taint])
    assert len(res) == 1
    assert res[0].priority_tier in (PriorityTier.P3, PriorityTier.P4)
    assert res[0].priority_score <= 50


# 3. External input -> SQL sink
def test_3_external_input_sql_sink():
    analyzer = ExploitabilityAnalyzer()
    finding = {"root_cause": "SQL_INJECTION", "severity": "CRITICAL"}
    taint = {"path": {"source": {"source_kind": "HTTP"}, "sink": {"sink_kind": "SQL_EXECUTE"}}}
    lvl = analyzer.analyze_exploitability(finding, taint)
    assert lvl == ExploitabilityLevel.CRITICAL


# 4. Sanitized external input
def test_4_sanitized_external_input():
    analyzer = ExploitabilityAnalyzer()
    finding = {"root_cause": "COMMAND_INJECTION", "severity": "HIGH"}
    taint = {"path": {"source": {"source_kind": "HTTP"}, "sink": {"sink_kind": "SUBPROCESS_SHELL"}, "sanitizers": ["shlex.quote"]}}
    lvl = analyzer.analyze_exploitability(finding, taint)
    assert lvl == ExploitabilityLevel.LOW


# 5. Internet-exposed FastAPI route
def test_5_internet_exposed_fastapi_route():
    analyzer = ExposureAnalyzer()
    finding = {"affected_file": "routes.py"}
    ctx = "@app.post('/api/v1/execute')\ndef execute_endpoint():"
    lvl = analyzer.analyze_exposure(finding, ctx)
    assert lvl == ExposureLevel.INTERNET_EXPOSED


# 6. Internal-only function
def test_6_internal_only_function():
    analyzer = ExposureAnalyzer()
    finding = {"affected_file": "internal_helper.py"}
    ctx = "def internal_compute(): return 42"
    lvl = analyzer.analyze_exposure(finding, ctx)
    assert lvl == ExposureLevel.INTERNAL


# 7. High blast-radius shared function
def test_7_high_blast_radius_shared_function():
    analyzer = BlastRadiusAnalyzer()
    finding = {"affected_file": "core/utils.py", "affected_function": "shared_exec"}
    lvl = analyzer.analyze_blast_radius(finding)
    assert lvl in (BlastRadiusLevel.BROAD, BlastRadiusLevel.SYSTEM_WIDE)


# 8. Local isolated vulnerability
def test_8_local_isolated_vulnerability():
    analyzer = BlastRadiusAnalyzer()
    finding = {"affected_file": "tests/test_demo.py"}
    lvl = analyzer.analyze_blast_radius(finding)
    assert lvl == BlastRadiusLevel.LOCAL


# 9. Newly introduced finding
def test_9_newly_introduced_finding():
    prio_engine = SecurityPriorityEngine()
    finding = {"finding_id": "f_new", "severity": "HIGH", "root_cause": "SQL_INJECTION", "lifecycle_state": "NEW"}
    res = prio_engine.prioritize_findings([finding])
    assert len(res) == 1
    assert res[0].recurrence == RecurrenceLevel.FIRST_SEEN


# 10. Historical unchanged finding
def test_10_historical_unchanged_finding():
    prio_engine = SecurityPriorityEngine()
    finding = {"finding_id": "f_unchanged", "severity": "MEDIUM", "root_cause": "EXCEPTION_SWALLOWING", "lifecycle_state": "UNCHANGED"}
    res = prio_engine.prioritize_findings([finding])
    assert len(res) == 1
    assert res[0].recurrence == RecurrenceLevel.UNCHANGED


# 11. Reopened finding
def test_11_reopened_finding():
    prio_engine = SecurityPriorityEngine()
    finding = {"finding_id": "f_reopened", "severity": "HIGH", "root_cause": "COMMAND_INJECTION", "lifecycle_state": "REOPENED"}
    res = prio_engine.prioritize_findings([finding])
    assert len(res) == 1
    assert res[0].recurrence == RecurrenceLevel.REOPENED


# 12. Recurring vulnerability
def test_12_recurring_vulnerability():
    cross_engine = CrossRepositoryIntelligenceEngine()
    patterns = cross_engine.analyze_cross_repository_patterns(current_repository="RepoA", current_findings=[{"root_cause": "COMMAND_INJECTION"}])
    assert isinstance(patterns, list)


# 13. Cross-repository same vulnerability family
def test_13_cross_repository_same_vulnerability_family(tmp_path):
    store = HistoricalScanStore(db_path=str(tmp_path / "cross_test.db"))
    cross_engine = CrossRepositoryIntelligenceEngine()
    patterns = cross_engine.analyze_cross_repository_patterns(
        store=store,
        current_repository="RepoX",
        current_findings=[{"root_cause": "COMMAND_INJECTION", "severity": "CRITICAL"}],
    )
    assert len(patterns) >= 1
    assert patterns[0].vulnerability_family == "COMMAND_INJECTION"


# 14. Different root causes remain separate
def test_14_different_root_causes_remain_separate(tmp_path):
    cross_engine = CrossRepositoryIntelligenceEngine()
    findings = [{"root_cause": "COMMAND_INJECTION"}, {"root_cause": "SQL_INJECTION"}]
    patterns = cross_engine.analyze_cross_repository_patterns(current_repository="RepoY", current_findings=findings)
    fams = {p.vulnerability_family for p in patterns}
    assert "COMMAND_INJECTION" in fams
    assert "SQL_INJECTION" in fams


# 15. Priority ordering
def test_15_priority_ordering():
    prio_engine = SecurityPriorityEngine()
    f_high = {"finding_id": "fh", "severity": "CRITICAL", "root_cause": "COMMAND_INJECTION", "code_context": "@app.get('/')"}
    f_low = {"finding_id": "fl", "severity": "LOW", "root_cause": "EXCEPTION_SWALLOWING"}
    res = prio_engine.prioritize_findings([f_low, f_high])
    assert res[0].finding_id == "fh"
    assert res[0].rank == 1
    assert res[1].finding_id == "fl"
    assert res[1].rank == 2


# 16. Priority score breakdown explanation
def test_16_priority_score_breakdown_explanation():
    prio_engine = SecurityPriorityEngine()
    f = {"finding_id": "f_exp", "severity": "HIGH", "root_cause": "SQL_INJECTION"}
    res = prio_engine.prioritize_findings([f])
    assert "severity_contribution" in res[0].score_breakdown
    assert res[0].why_it_is_prioritized != ""


# 17. Recommendation generation
def test_17_recommendation_generation():
    rec_engine = SecurityRecommendationEngine()
    rec = rec_engine.generate_recommendation(
        finding={"root_cause": "COMMAND_INJECTION", "affected_file": "main.py"},
        priority_tier=PriorityTier.P0,
        priority_score=95,
        exploitability=ExploitabilityLevel.CRITICAL,
        exposure=ExposureLevel.INTERNET_EXPOSED,
        blast_radius=BlastRadiusLevel.BROAD,
    )
    assert "shell=True" in rec["recommended_action"]
    assert rec["repair_strategy"] == "REPLACE_SHELL_TRUE_WITH_ARG_ARRAY"


# 18. Existing M12 taint invariants preserved
def test_18_existing_m12_taint_invariants_preserved():
    analyzer = ExploitabilityAnalyzer()
    f_dict = {"root_cause": "COMMAND_INJECTION", "severity": "CRITICAL"}
    t_dict = {"path": {"source": {"source_kind": "HTTP"}, "sink": {"sink_kind": "SUBPROCESS_SHELL"}}}
    assert analyzer.analyze_exploitability(f_dict, t_dict) == ExploitabilityLevel.CRITICAL


# 19. Existing M13 repair invariants preserved
def test_19_existing_m13_repair_invariants_preserved():
    rec_engine = SecurityRecommendationEngine()
    rec = rec_engine.generate_recommendation(
        finding={"root_cause": "EXCEPTION_SWALLOWING", "affected_file": "scanner.py"},
        priority_tier=PriorityTier.P2,
        priority_score=65,
        exploitability=ExploitabilityLevel.LOW,
        exposure=ExposureLevel.INTERNAL,
        blast_radius=BlastRadiusLevel.LOCAL,
    )
    assert rec["repair_strategy"] == "NARROW_EXCEPTION_AND_LOG"


# 20. Existing M14 historical invariants preserved
def test_20_existing_m14_historical_invariants_preserved():
    prio_engine = SecurityPriorityEngine()
    f = {"finding_id": "f_reop", "severity": "HIGH", "root_cause": "COMMAND_INJECTION", "lifecycle_state": "REOPENED"}
    res = prio_engine.prioritize_findings([f])
    assert res[0].recurrence == RecurrenceLevel.REOPENED
    assert res[0].score_breakdown["recurrence_contribution"] == 10
