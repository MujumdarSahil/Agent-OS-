"""
Real-world validation suite for M30 Enterprise Release Readiness & Final Security Hardening.
Validates release gate evaluations across 5 canonical target repositories:
1. Job_Agent: safe dict.get() -> RELEASE_READY
2. ConstitutionAI: command injection -> BLOCKED
3. MedAgentX: intentional fallback -> RELEASE_READY
4. Cadresec-: swallowed exception -> READY_WITH_WARNINGS / BLOCKED
5. OmniTutor-AI: intentional test-harness diagnostic handler -> RELEASE_READY
"""

import pytest
from agentos_swe.release import ReleaseReadinessEngine, ReadinessLevel


# Real-World Test 1: Job_Agent -> dict.get() safe lookup -> RELEASE_READY
def test_m30_real_world_1_job_agent():
    engine = ReleaseReadinessEngine()
    findings = [
        {"finding_id": "ja_1", "root_cause": "DICT_LOOKUP", "severity": "LOW", "sanitized": True, "file": "job_agent.py"}
    ]
    res = engine.evaluate_release_readiness("Job_Agent", verified_findings=findings)

    assert res.summary.readiness_level == ReadinessLevel.RELEASE_READY
    assert len(res.blockers) == 0


# Real-World Test 2: ConstitutionAI -> command injection -> BLOCKED
def test_m30_real_world_2_constitution_ai():
    engine = ReleaseReadinessEngine()
    findings = [
        {"finding_id": "cai_1", "root_cause": "COMMAND_INJECTION", "severity": "CRITICAL", "sanitized": False, "file": "agent.py"}
    ]
    paths = [
        {"path_id": "ap_cai", "entrypoint": "api/run", "source_type": "HTTP", "sink_type": "SUBPROCESS", "is_internet_exposed": True, "exploitable": True}
    ]
    res = engine.evaluate_release_readiness("ConstitutionAI", verified_findings=findings, attack_paths=paths)

    assert res.summary.readiness_level == ReadinessLevel.BLOCKED
    assert len(res.blockers) >= 1


# Real-World Test 3: MedAgentX -> intentional fallback -> RELEASE_READY
def test_m30_real_world_3_medagentx():
    engine = ReleaseReadinessEngine()
    findings = [
        {"finding_id": "max_1", "root_cause": "INTENTIONAL_FALLBACK", "severity": "MEDIUM", "sanitized": True, "file": "parser.py"}
    ]
    res = engine.evaluate_release_readiness("MedAgentX", verified_findings=findings)

    assert res.summary.readiness_level == ReadinessLevel.RELEASE_READY
    assert len(res.blockers) == 0


# Real-World Test 4: Cadresec- -> swallowed exception -> READY_WITH_WARNINGS / BLOCKED
def test_m30_real_world_4_cadresec():
    engine = ReleaseReadinessEngine()
    findings = [
        {"finding_id": "cad_1", "root_cause": "EXCEPTION_SWALLOWING", "severity": "HIGH", "sanitized": False, "file": "handler.py"}
    ]
    res = engine.evaluate_release_readiness("Cadresec-", verified_findings=findings)

    assert res.summary.readiness_level in [ReadinessLevel.READY_WITH_WARNINGS, ReadinessLevel.BLOCKED]


# Real-World Test 5: OmniTutor-AI -> test-harness diagnostic handler -> RELEASE_READY
def test_m30_real_world_5_omnitutor_ai():
    engine = ReleaseReadinessEngine()
    findings = [
        {"finding_id": "omni_1", "root_cause": "TEST_HARNESS_DIAGNOSTIC", "severity": "LOW", "sanitized": True, "file": "conftest.py"}
    ]
    res = engine.evaluate_release_readiness("OmniTutor-AI", verified_findings=findings)

    assert res.summary.readiness_level == ReadinessLevel.RELEASE_READY
    assert len(res.blockers) == 0
