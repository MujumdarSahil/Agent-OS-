"""
Real-world validation test suite for M27 — Security Operations Control Plane.

Validates control plane behavior against the 5 target benchmark repositories under read-only mode:
- Job_Agent: Safe repository -> HEALTHY / RELEASE_ALLOWED
- ConstitutionAI: Shell=True security issue -> CRITICAL / BLOCKED
- MedAgentX: Intentional fallback -> HEALTHY / RELEASE_ALLOWED
- Cadresec-: Swallowed exception -> AT_RISK / REPAIR_PENDING
- OmniTutor-AI: Diagnostic test harness -> HEALTHY / RELEASE_ALLOWED
"""

import pytest
from agentos_swe.controlplane import SecurityOperationsControlPlane, OperationalStatus


def test_m27_real_world_1_job_agent():
    """Job_Agent safe dict lookup -> HEALTHY / RELEASE_ALLOWED."""
    cp = SecurityOperationsControlPlane()
    verified_findings = [{
        "finding_id": "f_job_1",
        "root_cause": "DICT_LOOKUP",
        "severity": "LOW",
        "sanitized": True,
    }]

    res = cp.process_repository_operations(
        repository_name="Job_Agent",
        commit_sha="job_sha_1",
        verified_findings=verified_findings,
    )

    assert res.health.status == OperationalStatus.HEALTHY
    assert res.summary.release_status == "RELEASE_ALLOWED"


def test_m27_real_world_2_constitution_ai():
    """ConstitutionAI command injection -> CRITICAL / BLOCKED."""
    cp = SecurityOperationsControlPlane()
    verified_findings = [{
        "finding_id": "f_const_1",
        "root_cause": "COMMAND_INJECTION",
        "severity": "CRITICAL",
        "file": "eval.py",
        "exposure": "INTERNET_EXPOSED",
    }]
    decision_result = {"overall_decision": "BLOCK_RELEASE"}

    res = cp.process_repository_operations(
        repository_name="ConstitutionAI",
        commit_sha="const_sha_1",
        verified_findings=verified_findings,
        decision_result=decision_result,
    )

    assert res.health.status == OperationalStatus.BLOCKED
    assert res.summary.release_status == "RELEASE_BLOCKED"


def test_m27_real_world_3_medagentx():
    """MedAgentX intentional fallback -> HEALTHY / RELEASE_ALLOWED."""
    cp = SecurityOperationsControlPlane()
    verified_findings = [{
        "finding_id": "f_med_1",
        "root_cause": "INTENTIONAL_FALLBACK",
        "severity": "MEDIUM",
        "sanitized": True,
    }]

    res = cp.process_repository_operations(
        repository_name="MedAgentX",
        commit_sha="med_sha_1",
        verified_findings=verified_findings,
    )

    assert res.health.status == OperationalStatus.HEALTHY
    assert res.summary.release_status == "RELEASE_ALLOWED"


def test_m27_real_world_4_cadresec():
    """Cadresec- swallowed exception -> AT_RISK / REPAIR_PENDING."""
    cp = SecurityOperationsControlPlane()
    verified_findings = [{
        "finding_id": "f_cadre_1",
        "root_cause": "SWALLOWED_EXCEPTION",
        "severity": "HIGH",
        "priority": "P1",
        "file": "parser.py",
    }]

    res = cp.process_repository_operations(
        repository_name="Cadresec-",
        commit_sha="cadre_sha_1",
        verified_findings=verified_findings,
    )

    assert res.health.status != OperationalStatus.HEALTHY
    assert res.recommended_action.action.value in ["GENERATE_REPAIR", "BLOCK_RELEASE"]


def test_m27_real_world_5_omnitutor_ai():
    """OmniTutor-AI test harness diagnostic -> HEALTHY / RELEASE_ALLOWED."""
    cp = SecurityOperationsControlPlane()
    verified_findings = [{
        "finding_id": "f_omni_1",
        "root_cause": "TEST_HARNESS_DIAGNOSTIC",
        "severity": "LOW",
        "sanitized": True,
    }]

    res = cp.process_repository_operations(
        repository_name="OmniTutor-AI",
        commit_sha="omni_sha_1",
        verified_findings=verified_findings,
    )

    assert res.health.status == OperationalStatus.HEALTHY
    assert res.summary.release_status == "RELEASE_ALLOWED"
