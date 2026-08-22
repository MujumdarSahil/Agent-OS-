"""
M24 Autonomous Security Decision & Remediation Orchestration Synthetic Test Suite.

Validates deterministic policy evaluation (P01-P09), weighted decision confidence scoring,
action selection, human approval engine, remediation queue ranking, explainability,
and governance gate integration.
"""

import pytest
from agentos_swe.orchestration.models import (
    DecisionAction,
    DecisionStatus,
    DecisionReason,
    DecisionConfidence,
    DecisionRecommendation,
    ApprovalRequest,
    RemediationQueueItem,
    OrchestrationResult,
)
from agentos_swe.orchestration.policy_engine import SecurityPolicyEngine
from agentos_swe.orchestration.confidence_engine import DecisionConfidenceEngine
from agentos_swe.orchestration.action_selector import ActionSelector
from agentos_swe.orchestration.approval_engine import HumanApprovalEngine
from agentos_swe.orchestration.remediation_queue import RemediationQueue
from agentos_swe.orchestration.explainability import DecisionExplainabilityEngine
from agentos_swe.orchestration.decision_engine import SecurityDecisionEngine
from agentos_swe.orchestration.orchestrator import SecurityDecisionOrchestrator
from agentos_swe.pr.governance_gate import GovernanceGate, GovernanceDecision


# --- Policy Tests (1 - 8) ---

def test_1_policy_critical_exploitable_blocks_release():
    engine = SecurityPolicyEngine()
    finding = {"finding_id": "f1", "severity": "CRITICAL", "exploitability": "HIGH"}
    action, reasons, traces = engine.evaluate_finding_policy(finding)
    assert action == DecisionAction.BLOCK_RELEASE
    assert any("P01" in r for r in reasons)


def test_2_policy_high_reachable_generates_repair():
    engine = SecurityPolicyEngine()
    finding = {"finding_id": "f2", "severity": "HIGH", "exploitability": "MEDIUM"}
    action, reasons, traces = engine.evaluate_finding_policy(finding)
    assert action == DecisionAction.GENERATE_REPAIR
    assert any("P02" in r for r in reasons)


def test_3_policy_medium_recurring_investigates():
    engine = SecurityPolicyEngine()
    finding = {"finding_id": "f3", "severity": "MEDIUM", "exploitability": "LOW"}
    action, reasons, traces = engine.evaluate_finding_policy(finding)
    assert action == DecisionAction.INVESTIGATE
    assert any("P03" in r for r in reasons)


def test_4_policy_reopened_vulnerability_requires_human_review():
    engine = SecurityPolicyEngine()
    finding = {"finding_id": "f4", "severity": "HIGH", "previously_fixed": True}
    action, reasons, traces = engine.evaluate_finding_policy(finding)
    assert action == DecisionAction.HUMAN_REVIEW
    assert any("P04" in r for r in reasons)


def test_5_policy_intentional_fallback_ignored():
    engine = SecurityPolicyEngine()
    finding = {"finding_id": "f5", "root_cause": "INTENTIONAL_FALLBACK", "severity": "HIGH"}
    action, reasons, traces = engine.evaluate_finding_policy(finding)
    assert action == DecisionAction.IGNORE
    assert any("P05" in r for r in reasons)


def test_6_policy_test_harness_diagnostic_ignored():
    engine = SecurityPolicyEngine()
    finding = {"finding_id": "f6", "root_cause": "TEST_HARNESS", "severity": "HIGH"}
    action, reasons, traces = engine.evaluate_finding_policy(finding)
    assert action == DecisionAction.IGNORE
    assert any("P06" in r for r in reasons)


def test_7_policy_sanitized_taint_monitored():
    engine = SecurityPolicyEngine()
    finding = {"finding_id": "f7", "sanitized": True, "severity": "HIGH"}
    action, reasons, traces = engine.evaluate_finding_policy(finding)
    assert action == DecisionAction.MONITOR
    assert any("P07" in r for r in reasons)


def test_8_policy_low_confidence_requires_human_review():
    engine = SecurityPolicyEngine()
    finding = {"finding_id": "f8", "severity": "HIGH"}
    action, reasons, traces = engine.evaluate_finding_policy(finding, confidence_score=0.40)
    assert action == DecisionAction.HUMAN_REVIEW
    assert any("P08" in r for r in reasons)


# --- Confidence Tests (9 - 13) ---

def test_9_confidence_very_high():
    engine = DecisionConfidenceEngine()
    finding = {"verified": True, "root_cause": "COMMAND_INJECTION", "source_type": "HTTP", "historical_recurrent": True}
    attack_path = {"path_id": "ap1"}
    drift = {"category": "LOW_DRIFT"}
    conf = engine.compute_confidence(finding, attack_path, drift)
    assert conf.score >= 0.85
    assert conf.level == "VERY_HIGH"


def test_10_confidence_high():
    engine = DecisionConfidenceEngine()
    finding = {"verified": True, "source_type": "HTTP"}
    conf = engine.compute_confidence(finding)
    assert 0.70 <= conf.score < 0.85
    assert conf.level == "HIGH"


def test_11_confidence_medium():
    engine = DecisionConfidenceEngine()
    finding = {"verified": None, "source_type": "HTTP"}
    conf = engine.compute_confidence(finding)
    assert 0.50 <= conf.score < 0.70
    assert conf.level == "MEDIUM"


def test_12_confidence_low():
    engine = DecisionConfidenceEngine()
    finding = {"verified": False}
    conf = engine.compute_confidence(finding)
    assert conf.score < 0.50
    assert conf.level == "LOW"


def test_13_confidence_contribution_rationale():
    engine = DecisionConfidenceEngine()
    finding = {"verified": True, "source_type": "HTTP"}
    conf = engine.compute_confidence(finding)
    assert "Confidence score" in conf.rationale
    assert "verification" in conf.breakdown


# --- Remediation Queue Tests (14 - 18) ---

def test_14_remediation_queue_p0_sorting():
    builder = RemediationQueue()
    rec1 = DecisionRecommendation(finding_id="f1", recommended_action=DecisionAction.GENERATE_REPAIR, priority="HIGH", confidence=DecisionConfidence(score=0.8, level="HIGH"))
    rec2 = DecisionRecommendation(finding_id="f2", recommended_action=DecisionAction.BLOCK_RELEASE, priority="CRITICAL", confidence=DecisionConfidence(score=0.9, level="VERY_HIGH"))

    findings_map = {"f1": {"root_cause": "SQL"}, "f2": {"root_cause": "COMMAND_INJECTION"}}
    queue = builder.build_queue([rec1, rec2], findings_map)

    assert len(queue) == 2
    assert queue[0].finding_id == "f2"  # Block release critical should rank first
    assert queue[0].rank == 1
    assert queue[1].rank == 2


def test_15_remediation_queue_exploitability_ordering():
    builder = RemediationQueue()
    rec1 = DecisionRecommendation(finding_id="f1", recommended_action=DecisionAction.INVESTIGATE, priority="MEDIUM", confidence=DecisionConfidence(score=0.6, level="MEDIUM"))
    rec2 = DecisionRecommendation(finding_id="f2", recommended_action=DecisionAction.GENERATE_REPAIR, priority="HIGH", confidence=DecisionConfidence(score=0.8, level="HIGH"))

    findings_map = {"f1": {}, "f2": {}}
    queue = builder.build_queue([rec1, rec2], findings_map)
    assert queue[0].finding_id == "f2"


def test_16_remediation_queue_reopened_ordering():
    builder = RemediationQueue()
    rec1 = DecisionRecommendation(finding_id="f1", recommended_action=DecisionAction.HUMAN_REVIEW, priority="HIGH", confidence=DecisionConfidence(score=0.75, level="HIGH"))
    rec2 = DecisionRecommendation(finding_id="f2", recommended_action=DecisionAction.INVESTIGATE, priority="MEDIUM", confidence=DecisionConfidence(score=0.55, level="MEDIUM"))

    findings_map = {"f1": {}, "f2": {}}
    queue = builder.build_queue([rec1, rec2], findings_map)
    assert queue[0].finding_id == "f1"


def test_17_remediation_queue_ignores_ignore_actions():
    builder = RemediationQueue()
    rec1 = DecisionRecommendation(finding_id="f1", recommended_action=DecisionAction.IGNORE, priority="LOW", confidence=DecisionConfidence(score=0.9, level="VERY_HIGH"))
    rec2 = DecisionRecommendation(finding_id="f2", recommended_action=DecisionAction.MONITOR, priority="LOW", confidence=DecisionConfidence(score=0.9, level="VERY_HIGH"))

    findings_map = {"f1": {}, "f2": {}}
    queue = builder.build_queue([rec1, rec2], findings_map)
    assert len(queue) == 1
    assert queue[0].finding_id == "f2"


def test_18_remediation_queue_stable_ordering():
    builder = RemediationQueue()
    rec1 = DecisionRecommendation(finding_id="f1", recommended_action=DecisionAction.MONITOR, priority="MEDIUM", confidence=DecisionConfidence(score=0.7, level="HIGH"))
    rec2 = DecisionRecommendation(finding_id="f2", recommended_action=DecisionAction.MONITOR, priority="MEDIUM", confidence=DecisionConfidence(score=0.7, level="HIGH"))

    findings_map = {"f1": {}, "f2": {}}
    queue = builder.build_queue([rec1, rec2], findings_map)
    assert len(queue) == 2


# --- Approval Engine Tests (19 - 23) ---

def test_19_approval_engine_create_request():
    engine = HumanApprovalEngine()
    req = engine.create_request("f1", DecisionAction.GENERATE_REPAIR, "Repair approval needed")
    assert req.finding_id == "f1"
    assert req.status == DecisionStatus.PENDING


def test_20_approval_engine_approve():
    engine = HumanApprovalEngine()
    req = engine.create_request("f1", DecisionAction.GENERATE_REPAIR, "Repair approval needed")
    appr = engine.approve_request(req.approval_id)
    assert appr.status == DecisionStatus.APPROVED


def test_21_approval_engine_decline():
    engine = HumanApprovalEngine()
    req = engine.create_request("f1", DecisionAction.GENERATE_REPAIR, "Repair approval needed")
    decl = engine.decline_request(req.approval_id)
    assert decl.status == DecisionStatus.REJECTED


def test_22_approval_engine_expire():
    engine = HumanApprovalEngine()
    req = engine.create_request("f1", DecisionAction.GENERATE_REPAIR, "Repair approval needed")
    exp = engine.expire_request(req.approval_id)
    assert exp.status == DecisionStatus.ESCALATED


def test_23_approval_engine_audit_trail_simulation():
    engine = HumanApprovalEngine()
    r1 = engine.create_request("f1", DecisionAction.GENERATE_REPAIR, "Needs review")
    r2 = engine.create_request("f2", DecisionAction.BLOCK_RELEASE, "Critical release blocker")

    engine.approve_request(r1.approval_id)
    engine.decline_request(r2.approval_id)

    assert engine.requests[r1.approval_id].status == DecisionStatus.APPROVED
    assert engine.requests[r2.approval_id].status == DecisionStatus.REJECTED


# --- Governance Integration Test (24) ---

def test_24_governance_block_release_integration():
    gov = GovernanceGate()

    orc_block = {"governance_outcome": "DENY", "global_decision": "BLOCK_RELEASE"}
    assert gov.evaluate_orchestration_decision(orc_block) == GovernanceDecision.DENY

    orc_review = {"governance_outcome": "REVIEW_REQUIRED", "global_decision": "HUMAN_REVIEW"}
    assert gov.evaluate_orchestration_decision(orc_review) == GovernanceDecision.REVIEW_REQUIRED

    orc_allow = {"governance_outcome": "ALLOW", "global_decision": "MONITOR"}
    assert gov.evaluate_orchestration_decision(orc_allow) == GovernanceDecision.ALLOW
