"""
M24 Security Decision Orchestrator.

Master entrypoint for Autonomous Security Decision & Remediation Orchestration.
Coordinates data intake from M0-M23, executes decision engine, builds remediation queue,
manages approval requests, and determines global repository decision.
"""

from typing import Dict, Any, List, Optional
from agentos_swe.orchestration.models import (
    DecisionAction,
    DecisionConfidence,
    DecisionRecommendation,
    ApprovalRequest,
    OrchestrationResult,
)
from agentos_swe.orchestration.decision_engine import SecurityDecisionEngine
from agentos_swe.orchestration.approval_engine import HumanApprovalEngine
from agentos_swe.orchestration.remediation_queue import RemediationQueue


class SecurityDecisionOrchestrator:
    """
    Master orchestrator for Security Decision & Remediation Orchestration.
    """

    def __init__(self):
        self.decision_engine = SecurityDecisionEngine()
        self.approval_engine = HumanApprovalEngine()
        self.queue_builder = RemediationQueue()

    def orchestrate_decisions(
        self,
        repository_name: str,
        commit_sha: str,
        verified_findings: Optional[List[Any]] = None,
        prioritized_findings: Optional[List[Any]] = None,
        attack_paths: Optional[List[Any]] = None,
        drift_result: Optional[Dict[str, Any]] = None,
        simulation_result: Optional[Dict[str, Any]] = None,
    ) -> OrchestrationResult:
        """
        Executes end-to-end autonomous decision orchestration.
        """
        findings = [f.to_dict() if hasattr(f, "to_dict") else f for f in (prioritized_findings or verified_findings or [])]
        paths = [ap.to_dict() if hasattr(ap, "to_dict") else ap for ap in (attack_paths or [])]
        findings_map = {str(f.get("finding_id") or f.get("id") or "f1"): f for f in findings}

        recommendations: List[DecisionRecommendation] = []
        policy_trace: List[Dict[str, Any]] = []
        approval_requests: List[ApprovalRequest] = []

        for f in findings:
            fid = str(f.get("finding_id") or f.get("id") or "f1")
            match_path = next((ap for ap in paths if ap.get("root_cause") == f.get("root_cause")), None)

            rec, traces = self.decision_engine.evaluate_finding(f, match_path, drift_result)
            recommendations.append(rec)
            policy_trace.extend(traces)

            if rec.required_human_approval:
                explanation = f"Action '{rec.recommended_action.value if hasattr(rec.recommended_action, 'value') else rec.recommended_action}' requires human review for finding {fid}."
                req = self.approval_engine.create_request(fid, rec.recommended_action, explanation, rec.priority)
                approval_requests.append(req)

        # Build Remediation Queue
        rem_queue = self.queue_builder.build_queue(recommendations, findings_map)

        # Determine Global Security Decision
        actions = [r.recommended_action for r in recommendations]
        if DecisionAction.BLOCK_RELEASE in actions:
            global_dec = DecisionAction.BLOCK_RELEASE
            gov_outcome = "DENY"
            summary = "BLOCK RELEASE: Critical exploitable security vulnerabilities or severe drift detected."
        elif DecisionAction.HUMAN_REVIEW in actions or any(r.required_human_approval for r in recommendations):
            global_dec = DecisionAction.HUMAN_REVIEW
            gov_outcome = "REVIEW_REQUIRED"
            summary = "HUMAN REVIEW REQUIRED: Findings require human approval before remediation execution."
        elif DecisionAction.GENERATE_REPAIR in actions:
            global_dec = DecisionAction.GENERATE_REPAIR
            gov_outcome = "ALLOW"
            summary = "REPAIR RECOMMENDED: Automated repair proposals ready for validation."
        elif DecisionAction.INVESTIGATE in actions:
            global_dec = DecisionAction.INVESTIGATE
            gov_outcome = "ALLOW"
            summary = "INVESTIGATION RECOMMENDED: Medium priority findings queued for investigation."
        elif DecisionAction.MONITOR in actions:
            global_dec = DecisionAction.MONITOR
            gov_outcome = "ALLOW"
            summary = "MONITOR ONLY: Sanitized or low-risk findings actively monitored."
        else:
            global_dec = DecisionAction.IGNORE
            gov_outcome = "ALLOW"
            summary = "NO ACTION REQUIRED: Clean repository pass or safe non-exploitable controls."

        # Compute Global Decision Confidence
        avg_score = round(sum(r.confidence.score for r in recommendations) / len(recommendations), 2) if recommendations else 1.0
        global_conf = DecisionConfidence(
            score=avg_score,
            level="VERY_HIGH" if avg_score >= 0.85 else ("HIGH" if avg_score >= 0.70 else ("MEDIUM" if avg_score >= 0.50 else "LOW")),
            rationale=f"Global decision confidence {int(avg_score * 100)}% across {len(recommendations)} evaluated findings.",
            breakdown={"verification": 0.25, "taint": 0.25, "attack_path": 0.15, "drift": 0.15, "history": 0.10, "semantic": 0.10},
        )

        return OrchestrationResult(
            repository=repository_name,
            commit_sha=commit_sha,
            global_decision=global_dec,
            confidence=global_conf,
            recommendations=recommendations,
            remediation_queue=rem_queue,
            approval_requests=approval_requests,
            policy_trace=policy_trace,
            governance_outcome=gov_outcome,
            summary=summary,
        )
