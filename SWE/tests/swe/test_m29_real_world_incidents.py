"""
Real-world validation suite for M29 Security Incident Response & Investigation.
Validates semantic protections and incident detection across 5 canonical target repositories:
1. Job_Agent: dict.get() safe lookup -> Zero false incidents
2. ConstitutionAI: shell=True command injection -> Valid CRITICAL security incident
3. MedAgentX: intentional fallback -> Zero false incidents
4. Cadresec-: swallowed exception -> Valid HIGH security incident
5. OmniTutor-AI: intentional test-harness diagnostic handler -> Zero false incidents
"""

import pytest
from agentos_swe.incident import SecurityIncidentResponseEngine, IncidentSeverity


# Real-World Test 1: Job_Agent -> dict.get() safe lookup -> Zero false incidents
def test_m29_real_world_1_job_agent():
    inc_engine = SecurityIncidentResponseEngine()
    findings = [
        {"finding_id": "ja_1", "root_cause": "DICT_LOOKUP", "severity": "LOW", "sanitized": True, "file": "job_agent.py"}
    ]
    res = inc_engine.process_security_incidents("Job_Agent", verified_findings=findings)

    assert res.active_incident_count == 0
    assert len(res.incidents) == 0


# Real-World Test 2: ConstitutionAI -> shell=True command injection -> Valid security incident
def test_m29_real_world_2_constitution_ai():
    inc_engine = SecurityIncidentResponseEngine()
    findings = [
        {"finding_id": "cai_1", "root_cause": "COMMAND_INJECTION", "severity": "CRITICAL", "sanitized": False, "file": "agent.py"}
    ]
    paths = [
        {"path_id": "ap_cai", "entrypoint": "api/run", "source_type": "HTTP", "sink_type": "SUBPROCESS", "is_internet_exposed": True}
    ]
    res = inc_engine.process_security_incidents("ConstitutionAI", verified_findings=findings, attack_paths=paths)

    assert res.active_incident_count >= 1
    crit_incidents = [inc for inc in res.incidents if inc.severity == IncidentSeverity.CRITICAL]
    assert len(crit_incidents) >= 1


# Real-World Test 3: MedAgentX -> intentional fallback -> Zero false incidents
def test_m29_real_world_3_medagentx():
    inc_engine = SecurityIncidentResponseEngine()
    findings = [
        {"finding_id": "max_1", "root_cause": "INTENTIONAL_FALLBACK", "severity": "MEDIUM", "sanitized": True, "file": "parser.py"}
    ]
    res = inc_engine.process_security_incidents("MedAgentX", verified_findings=findings)

    assert res.active_incident_count == 0


# Real-World Test 4: Cadresec- -> swallowed exception -> Valid security incident
def test_m29_real_world_4_cadresec():
    inc_engine = SecurityIncidentResponseEngine()
    findings = [
        {"finding_id": "cad_1", "root_cause": "EXCEPTION_SWALLOWING", "severity": "HIGH", "sanitized": False, "file": "handler.py"}
    ]
    res = inc_engine.process_security_incidents("Cadresec-", verified_findings=findings)

    assert res.active_incident_count >= 1


# Real-World Test 5: OmniTutor-AI -> test-harness diagnostic handler -> Zero false incidents
def test_m29_real_world_5_omnitutor_ai():
    inc_engine = SecurityIncidentResponseEngine()
    findings = [
        {"finding_id": "omni_1", "root_cause": "TEST_HARNESS_DIAGNOSTIC", "severity": "LOW", "sanitized": True, "file": "conftest.py"}
    ]
    res = inc_engine.process_security_incidents("OmniTutor-AI", verified_findings=findings)

    assert res.active_incident_count == 0
