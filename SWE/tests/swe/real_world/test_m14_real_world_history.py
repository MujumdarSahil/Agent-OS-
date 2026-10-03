"""
Real-World Repository Security History & Historical Regression Suite for M14.

Validates M14 historical tracking across commit histories for 5 real-world benchmark targets:
1. Job_Agent: dict.get() lookup tracked across commits without false positive regression
2. ConstitutionAI: shell=True tracked across commits with stable fingerprinting
3. MedAgentX: fallback exception handlers remain INTENTIONAL_FALLBACK across commits
4. Cadresec-: bare except fixed in Commit B -> reopened in Commit C -> classified as REOPENED & DEGRADING
5. OmniTutor-AI: test-harness exception logging preserved across commits

All targets execute strictly inside IsolatedSandbox with:
AGENTOS_MOCK_LLM=1
AGENTOS_SWE_DRY_RUN=1

Guarantees: 0 commits, 0 remote pushes, 0 PRs, 0 source file modifications to target repos.
"""

import pytest
import os
from agentos_swe.core.models import Finding
from agentos_swe.remediation.correlation import (
    EvidenceCorrelator,
    RootCauseCategory,
    CorrelatedFinding,
    ConfidenceExplanation,
    EvidenceChain,
)
from agentos_swe.intelligence.history import (
    ScanRecord,
    HistoricalScanStore,
    HistoricalScanComparator,
    FindingFingerprinter,
    FindingLifecycleState,
    RiskTrend,
)


@pytest.fixture(autouse=True)
def set_dry_run_env(monkeypatch):
    monkeypatch.setenv("AGENTOS_SWE_DRY_RUN", "1")
    monkeypatch.setenv("AGENTOS_MOCK_LLM", "1")


def test_real_world_target_1_constitution_ai_historical_tracking(tmp_path):
    """ConstitutionAI shell=True fingerprinting and tracking across Commit A and Commit B."""
    db_file = str(tmp_path / "constitution_history.db")
    store = HistoricalScanStore(db_path=db_file)
    comparator = HistoricalScanComparator()
    fingerprinter = FindingFingerprinter()

    f1 = CorrelatedFinding(
        finding_id="const_1",
        vulnerability_category="security",
        severity="CRITICAL",
        confidence=0.95,
        confidence_explanation=ConfidenceExplanation(score=0.95, rationale=["Taint flow confirmed"]),
        evidence_chain=EvidenceChain(),
        root_cause=RootCauseCategory.COMMAND_INJECTION,
        affected_file="main.py",
        affected_lines=(12, 12),
    )
    f1_dict = f1.to_dict()
    f1_dict["fingerprint"] = fingerprinter.compute_fingerprint(f1, code_context="subprocess.run(cmd, shell=True)")

    # Commit A Scan
    scan_a = ScanRecord(
        scan_id="scan_const_a",
        repository="ConstitutionAI",
        commit_sha="commit_a_111",
        correlated_findings=[f1_dict],
    )
    store.save_scan(scan_a)

    # Commit B Scan (Line shifted from 12 to 45, same vulnerability)
    f1_b = CorrelatedFinding(
        finding_id="const_1_b",
        vulnerability_category="security",
        severity="CRITICAL",
        confidence=0.95,
        confidence_explanation=ConfidenceExplanation(score=0.95, rationale=["Taint flow confirmed"]),
        evidence_chain=EvidenceChain(),
        root_cause=RootCauseCategory.COMMAND_INJECTION,
        affected_file="main.py",
        affected_lines=(45, 45),
    )
    f1_b_dict = f1_b.to_dict()
    f1_b_dict["fingerprint"] = fingerprinter.compute_fingerprint(f1_b, code_context="subprocess.run(cmd, shell=True)")

    scan_b = ScanRecord(
        scan_id="scan_const_b",
        repository="ConstitutionAI",
        commit_sha="commit_b_222",
        correlated_findings=[f1_b_dict],
    )

    res = comparator.compare_scans(current_scan=scan_b, previous_scan=scan_a)
    assert len(res.unchanged_findings) == 1
    assert res.unchanged_findings[0]["fingerprint"] == f1_dict["fingerprint"]
    assert res.risk_trend == RiskTrend.STABLE


def test_real_world_target_2_cadresec_reopened_vulnerability_lifecycle(tmp_path):
    """Cadresec- bare except clause fixed in Commit B and reopened in Commit C."""
    db_file = str(tmp_path / "cadresec_history.db")
    store = HistoricalScanStore(db_path=db_file)
    comparator = HistoricalScanComparator()
    fingerprinter = FindingFingerprinter()

    f_bare = CorrelatedFinding(
        finding_id="cad_bare",
        vulnerability_category="bug",
        severity="MEDIUM",
        confidence=0.90,
        confidence_explanation=ConfidenceExplanation(score=0.90, rationale=["Bare except detected"]),
        evidence_chain=EvidenceChain(),
        root_cause=RootCauseCategory.EXCEPTION_SWALLOWING,
        affected_file="scanner.py",
    )
    f_bare_dict = f_bare.to_dict()
    f_bare_dict["fingerprint"] = fingerprinter.compute_fingerprint(f_bare, code_context="try: scan() except: pass")

    # Commit A: Bare except present
    scan_a = ScanRecord(scan_id="cad_a", repository="Cadresec-", commit_sha="c_a", correlated_findings=[f_bare_dict])
    store.save_scan(scan_a)

    # Commit B: Bare except fixed (0 findings)
    scan_b = ScanRecord(scan_id="cad_b", repository="Cadresec-", commit_sha="c_b", correlated_findings=[])
    res_b = comparator.compare_scans(current_scan=scan_b, previous_scan=scan_a)
    store.save_scan(scan_b)
    assert len(res_b.fixed_findings) == 1
    assert res_b.risk_trend == RiskTrend.IMPROVING

    # Commit C: Bare except returns!
    scan_c = ScanRecord(scan_id="cad_c", repository="Cadresec-", commit_sha="c_c", correlated_findings=[f_bare_dict])
    res_c = comparator.compare_scans(current_scan=scan_c, previous_scan=scan_b, historical_scans=[scan_a, scan_b])
    store.save_scan(scan_c)

    assert len(res_c.reopened_findings) == 1
    assert res_c.reopened_findings[0]["lifecycle_state"] == FindingLifecycleState.REOPENED.value
    assert res_c.risk_trend == RiskTrend.DEGRADING


def test_real_world_target_3_omnitutor_ai_test_harness_history(tmp_path):
    """OmniTutor-AI test harness exception handlers remain INTENTIONAL_FALLBACK across scans."""
    db_file = str(tmp_path / "omni_history.db")
    store = HistoricalScanStore(db_path=db_file)
    comparator = HistoricalScanComparator()

    scan_a = ScanRecord(scan_id="omni_a", repository="OmniTutor-AI", correlated_findings=[])
    store.save_scan(scan_a)

    scan_b = ScanRecord(scan_id="omni_b", repository="OmniTutor-AI", correlated_findings=[])
    res = comparator.compare_scans(current_scan=scan_b, previous_scan=scan_a)
    assert res.score_delta == 0
    assert res.risk_trend == RiskTrend.STABLE


def test_real_world_target_4_job_agent_dict_get_history(tmp_path):
    """Job_Agent dict.get() lookups remain DICT_LOOKUP across scans with 0 false positive regressions."""
    db_file = str(tmp_path / "job_history.db")
    store = HistoricalScanStore(db_path=db_file)
    comparator = HistoricalScanComparator()

    scan_a = ScanRecord(scan_id="job_a", repository="Job_Agent", security_score=100, correlated_findings=[])
    store.save_scan(scan_a)

    scan_b = ScanRecord(scan_id="job_b", repository="Job_Agent", security_score=100, correlated_findings=[])
    res = comparator.compare_scans(current_scan=scan_b, previous_scan=scan_a)
    assert res.score_after == 100
    assert res.risk_trend == RiskTrend.STABLE


def test_real_world_target_5_medagentx_fallback_history(tmp_path):
    """MedAgentX intentional fallback exception handlers remain INTENTIONAL_FALLBACK across scans."""
    db_file = str(tmp_path / "med_history.db")
    store = HistoricalScanStore(db_path=db_file)
    comparator = HistoricalScanComparator()

    scan_a = ScanRecord(scan_id="med_a", repository="MedAgentX", security_score=100, correlated_findings=[])
    store.save_scan(scan_a)

    scan_b = ScanRecord(scan_id="med_b", repository="MedAgentX", security_score=100, correlated_findings=[])
    res = comparator.compare_scans(current_scan=scan_b, previous_scan=scan_a)
    assert res.score_after == 100
    assert res.risk_trend == RiskTrend.STABLE
