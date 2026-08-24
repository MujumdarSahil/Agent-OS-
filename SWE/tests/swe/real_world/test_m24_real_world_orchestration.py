"""
M24 Autonomous Security Decision Orchestration Real-World Validation Suite.

Validates decision orchestration on the 5 target benchmark repositories under read-only mode:
- Job_Agent: Safe repository -> NO ACTION REQUIRED / MONITOR ONLY
- ConstitutionAI: Command injection -> BLOCK RELEASE (Repair recommended, human approval required)
- MedAgentX: Intentional fallback -> IGNORE / MONITOR (No repair generated)
- Cadresec-: Bare exception -> GENERATE REPAIR / INVESTIGATE / HUMAN REVIEW
- OmniTutor-AI: Diagnostic test harness -> IGNORE
"""

import pytest
from agentos_swe.operations.orchestration import SecurityDecisionOrchestrator, DecisionAction


def test_m24_real_world_1_job_agent():
    """Job_Agent safe dictionary lookup -> MONITOR or NO ACTION REQUIRED."""
    orchestrator = SecurityDecisionOrchestrator()
    verified_findings = [{
        "finding_id": "f_job_1",
        "root_cause": "DICT_LOOKUP",
        "severity": "LOW",
        "sanitized": True,
        "verified": True,
    }]

    res = orchestrator.orchestrate_decisions(
        repository_name="Job_Agent",
        commit_sha="job_111111",
        verified_findings=verified_findings,
    )

    assert res.global_decision in (DecisionAction.MONITOR, DecisionAction.IGNORE)
    assert res.governance_outcome == "ALLOW"
    assert len(res.approval_requests) == 0


def test_m24_real_world_2_constitution_ai():
    """ConstitutionAI command injection -> BLOCK_RELEASE or GENERATE_REPAIR + human approval required."""
    orchestrator = SecurityDecisionOrchestrator()
    verified_findings = [{
        "finding_id": "f_const_1",
        "root_cause": "COMMAND_INJECTION",
        "severity": "CRITICAL",
        "exploitability": "HIGH",
        "sanitized": False,
        "verified": True,
    }]
    attack_paths = [{"root_cause": "COMMAND_INJECTION", "risk_score": 90}]

    res = orchestrator.orchestrate_decisions(
        repository_name="ConstitutionAI",
        commit_sha="const_222222",
        verified_findings=verified_findings,
        attack_paths=attack_paths,
    )

    assert res.global_decision in (DecisionAction.BLOCK_RELEASE, DecisionAction.GENERATE_REPAIR, DecisionAction.HUMAN_REVIEW)
    assert len(res.approval_requests) >= 1
    assert res.approval_requests[0].proposed_action in (DecisionAction.BLOCK_RELEASE, DecisionAction.GENERATE_REPAIR)


def test_m24_real_world_3_medagentx():
    """MedAgentX intentional fallback -> IGNORE / MONITOR (No repair generated)."""
    orchestrator = SecurityDecisionOrchestrator()
    verified_findings = [{
        "finding_id": "f_med_1",
        "root_cause": "INTENTIONAL_FALLBACK",
        "severity": "MEDIUM",
        "sanitized": True,
        "verified": True,
    }]

    res = orchestrator.orchestrate_decisions(
        repository_name="MedAgentX",
        commit_sha="med_333333",
        verified_findings=verified_findings,
    )

    assert res.global_decision in (DecisionAction.IGNORE, DecisionAction.MONITOR)
    assert res.governance_outcome == "ALLOW"
    assert len([q for q in res.remediation_queue if q.recommended_action == DecisionAction.GENERATE_REPAIR]) == 0


def test_m24_real_world_4_cadresec():
    """Cadresec- bare exception swallowing -> GENERATE_REPAIR / INVESTIGATE / HUMAN_REVIEW."""
    orchestrator = SecurityDecisionOrchestrator()
    verified_findings = [{
        "finding_id": "f_cadre_1",
        "root_cause": "SWALLOWED_EXCEPTION",
        "severity": "HIGH",
        "sanitized": False,
        "verified": True,
    }]

    res = orchestrator.orchestrate_decisions(
        repository_name="Cadresec-",
        commit_sha="cadre_444444",
        verified_findings=verified_findings,
    )

    assert res.global_decision in (DecisionAction.GENERATE_REPAIR, DecisionAction.INVESTIGATE, DecisionAction.HUMAN_REVIEW)
    assert len(res.remediation_queue) >= 1
    assert res.remediation_queue[0].recommended_action in (DecisionAction.GENERATE_REPAIR, DecisionAction.INVESTIGATE)


def test_m24_real_world_5_omnitutor_ai():
    """OmniTutor-AI diagnostic test harness -> IGNORE (No false-positive repair)."""
    orchestrator = SecurityDecisionOrchestrator()
    verified_findings = [{
        "finding_id": "f_omni_1",
        "root_cause": "TEST_HARNESS",
        "severity": "MEDIUM",
        "sanitized": True,
        "verified": True,
    }]

    res = orchestrator.orchestrate_decisions(
        repository_name="OmniTutor-AI",
        commit_sha="omni_555555",
        verified_findings=verified_findings,
    )

    assert res.global_decision == DecisionAction.IGNORE
    assert res.governance_outcome == "ALLOW"
    assert len(res.remediation_queue) == 0
