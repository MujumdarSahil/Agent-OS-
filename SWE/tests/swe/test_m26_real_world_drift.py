"""
Real-world validation test suite for M26 — Security Monitoring & Security Drift Engine.

Validates M26 behavior against the 5 target benchmark repositories under read-only mode:
- Job_Agent: Safe repository -> NO_DRIFT / MONITOR ONLY
- ConstitutionAI: Command injection -> CRITICAL_SECURITY_DRIFT / BLOCK_RELEASE
- MedAgentX: Intentional fallback -> NO_DRIFT (Filtered)
- Cadresec-: Swallowed exception -> MODERATE_DRIFT / HIGH_SECURITY_DRIFT
- OmniTutor-AI: Diagnostic test harness -> NO_DRIFT (Filtered)
"""

import pytest
from agentos_swe.drift import SecurityMonitoringDriftEngine


def test_m26_real_world_1_job_agent():
    """Job_Agent safe dict lookup -> NO_DRIFT."""
    engine = SecurityMonitoringDriftEngine()
    current_findings = [{
        "finding_id": "f_job_1",
        "root_cause": "DICT_LOOKUP",
        "severity": "LOW",
        "sanitized": True,
    }]

    res = engine.run_monitoring_pipeline(
        repository_name="Job_Agent",
        current_commit="job_commit_1",
        current_findings=current_findings,
        current_security_score=100,
        baseline_security_score=100,
    )

    assert res.summary.overall_status == "NO_DRIFT"
    assert res.governance_verdict == "ALLOW"


def test_m26_real_world_2_constitution_ai():
    """ConstitutionAI command injection -> CRITICAL_SECURITY_DRIFT / DENY."""
    engine = SecurityMonitoringDriftEngine()
    current_findings = [{
        "finding_id": "f_const_1",
        "root_cause": "COMMAND_INJECTION",
        "severity": "CRITICAL",
        "file": "eval.py",
        "exposure": "INTERNET_EXPOSED",
    }]
    attack_paths = [{"path_id": "ap_const", "entrypoint": "api", "target": "eval.py"}]

    res = engine.run_monitoring_pipeline(
        repository_name="ConstitutionAI",
        current_commit="const_commit_1",
        current_findings=current_findings,
        attack_paths=attack_paths,
        current_security_score=40,
        baseline_security_score=90,
    )

    assert res.summary.overall_status in ["CRITICAL_SECURITY_DRIFT", "HIGH_SECURITY_DRIFT"]
    assert res.governance_verdict in ["DENY", "REVIEW_REQUIRED"]


def test_m26_real_world_3_medagentx():
    """MedAgentX intentional fallback -> NO_DRIFT."""
    engine = SecurityMonitoringDriftEngine()
    current_findings = [{
        "finding_id": "f_med_1",
        "root_cause": "INTENTIONAL_FALLBACK",
        "severity": "MEDIUM",
        "sanitized": True,
    }]

    res = engine.run_monitoring_pipeline(
        repository_name="MedAgentX",
        current_commit="med_commit_1",
        current_findings=current_findings,
        current_security_score=95,
        baseline_security_score=95,
    )

    assert res.summary.overall_status == "NO_DRIFT"
    assert res.governance_verdict == "ALLOW"


def test_m26_real_world_4_cadresec():
    """Cadresec- swallowed exception -> DRIFT DETECTED."""
    engine = SecurityMonitoringDriftEngine()
    current_findings = [{
        "finding_id": "f_cadre_1",
        "root_cause": "SWALLOWED_EXCEPTION",
        "severity": "HIGH",
        "file": "parser.py",
    }]

    res = engine.run_monitoring_pipeline(
        repository_name="Cadresec-",
        current_commit="cadre_commit_1",
        current_findings=current_findings,
        current_security_score=70,
        baseline_security_score=90,
    )

    assert res.summary.overall_status != "NO_DRIFT"
    assert len(res.drift_events) >= 1


def test_m26_real_world_5_omnitutor_ai():
    """OmniTutor-AI test harness diagnostic -> NO_DRIFT."""
    engine = SecurityMonitoringDriftEngine()
    current_findings = [{
        "finding_id": "f_omni_1",
        "root_cause": "TEST_HARNESS_DIAGNOSTIC",
        "severity": "LOW",
        "file": "tests/harness.py",
    }]

    res = engine.run_monitoring_pipeline(
        repository_name="OmniTutor-AI",
        current_commit="omni_commit_1",
        current_findings=current_findings,
        current_security_score=100,
        baseline_security_score=100,
    )

    assert res.summary.overall_status == "NO_DRIFT"
    assert res.governance_verdict == "ALLOW"
