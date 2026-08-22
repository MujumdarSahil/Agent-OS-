"""
M19 Main SecurityReleaseReadinessEngine and SecurityReleaseGate.

Orchestrates release decision making, gate verdict calculation, scorecard computation,
release diff analysis, blocker extraction, evidence chain building, and executive recommendations.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime
from agentos_swe.release.models import (
    ReleaseDecisionState,
    SecurityGateVerdict,
    ReleaseDeltaState,
    ExecutiveScorecard,
    ReleaseDiff,
    SecurityReleaseDecision,
    CrossRepositoryReleasePosture,
)
from agentos_swe.release.policy import RiskPolicyEngine
from agentos_swe.release.blockers import BlockerEngine
from agentos_swe.release.evidence import EvidenceChainBuilder


class SecurityReleaseGate:
    """
    Deterministic security gate mapping decision state to gate verdict.
    """

    def evaluate_gate(self, decision: ReleaseDecisionState) -> SecurityGateVerdict:
        if decision == ReleaseDecisionState.GO:
            return SecurityGateVerdict.ALLOW_RELEASE
        elif decision == ReleaseDecisionState.GO_WITH_WARNINGS:
            return SecurityGateVerdict.ALLOW_WITH_WARNINGS
        elif decision == ReleaseDecisionState.REVIEW_REQUIRED:
            return SecurityGateVerdict.REQUIRE_REVIEW
        else:
            return SecurityGateVerdict.DENY_RELEASE


class SecurityReleaseReadinessEngine:
    """
    Main Security Release Readiness Engine Facade.
    """

    def __init__(self):
        self.policy_engine = RiskPolicyEngine()
        self.blocker_engine = BlockerEngine()
        self.evidence_builder = EvidenceChainBuilder()
        self.gate = SecurityReleaseGate()

    def evaluate_release_readiness(
        self,
        verified_findings: Optional[List[Any]] = None,
        prioritized_findings: Optional[List[Any]] = None,
        attack_paths: Optional[List[Any]] = None,
        remediation_plan: Optional[Any] = None,
        monitoring_result: Optional[Any] = None,
        previous_decision: Optional[ReleaseDecisionState] = None,
        repository_name: str = "Unknown Repo",
        commit_sha: str = "HEAD",
        governance_status: str = "ALLOW",
    ) -> SecurityReleaseDecision:
        """
        Executes a deterministic release readiness assessment for a repository.
        """
        verified_findings = verified_findings or []
        prioritized_findings = prioritized_findings or []
        attack_paths = attack_paths or []

        findings_dict = [f.to_dict() if hasattr(f, "to_dict") else f for f in (prioritized_findings or verified_findings)]
        paths_dict = [ap.to_dict() if hasattr(ap, "to_dict") else ap for ap in attack_paths]
        rem_dict = remediation_plan.to_dict() if hasattr(remediation_plan, "to_dict") else (remediation_plan or {})
        mon_dict = monitoring_result.to_dict() if hasattr(monitoring_result, "to_dict") else (monitoring_result or {})

        # 1. Security Score Determination
        sec_score = rem_dict.get("current_security_score", 100)
        if sec_score == 100 and mon_dict:
            sec_score = mon_dict.get("security_score_after", 100)
        risk_score = max(0, 100 - sec_score)

        # 2. Policy Evaluation
        decision_state, policy_triggers = self.policy_engine.evaluate_policy(
            findings=findings_dict,
            prioritized_findings=findings_dict,
            attack_paths=paths_dict,
            remediation_plan=rem_dict,
            monitoring_result=mon_dict,
            security_score=sec_score,
            governance_status=governance_status,
        )

        # 3. Blocker Extraction
        blockers = self.blocker_engine.identify_blockers(
            prioritized_findings=findings_dict,
            attack_paths=paths_dict,
            remediation_plan=rem_dict,
            monitoring_result=mon_dict,
        )

        # 4. Evidence Chain Building
        evidence_chain = self.evidence_builder.build_evidence_chain(
            decision_state=decision_state,
            policy_triggers=policy_triggers,
            findings=findings_dict,
            attack_paths=paths_dict,
            remediation_plan=rem_dict,
            monitoring_result=mon_dict,
        )

        # 5. Executive Scorecard Computation
        crit_cnt = sum(1 for f in findings_dict if str(f.get("severity") or "").upper() == "CRITICAL")
        high_cnt = sum(1 for f in findings_dict if str(f.get("severity") or "").upper() == "HIGH")
        med_cnt = sum(1 for f in findings_dict if str(f.get("severity") or "").upper() == "MEDIUM")
        low_cnt = sum(1 for f in findings_dict if str(f.get("severity") or "").upper() == "LOW")

        p0_cnt = sum(1 for it in rem_dict.get("remediation_items", []) if str(it.get("priority_tier") or "") == "P0")
        p1_cnt = sum(1 for it in rem_dict.get("remediation_items", []) if str(it.get("priority_tier") or "") == "P1")

        has_internet = any(str(ap.get("entrypoint_type") or "").upper() == "INTERNET" for ap in paths_dict)
        has_critical_exp = any(str(f.get("exploitability") or "").upper() == "CRITICAL" for f in findings_dict)

        scorecard = ExecutiveScorecard(
            security_score=sec_score,
            risk_score=risk_score,
            exploitability="CRITICAL" if has_critical_exp else ("HIGH" if high_cnt > 0 else "LOW"),
            internet_exposure="INTERNET_EXPOSED" if has_internet else "INTERNAL_ONLY",
            critical_findings=crit_cnt,
            high_findings=high_cnt,
            medium_findings=med_cnt,
            low_findings=low_cnt,
            attack_paths=len(paths_dict),
            regressions=1 if mon_dict and "CRITICAL" in str(mon_dict.get("regression_severity", "")).upper() else 0,
            p0_remediations=p0_cnt,
            p1_remediations=p1_cnt,
            governance_status=governance_status,
            release_decision=decision_state,
        )

        # 6. Release Gate Verdict
        gate_verdict = self.gate.evaluate_gate(decision_state)

        # 7. Release Diff Analysis
        release_diff = None
        if previous_decision:
            delta_state = ReleaseDeltaState.UNCHANGED
            if previous_decision in (ReleaseDecisionState.BLOCKED, ReleaseDecisionState.NO_GO) and decision_state in (ReleaseDecisionState.GO, ReleaseDecisionState.GO_WITH_WARNINGS):
                delta_state = ReleaseDeltaState.RECOVERED
            elif previous_decision in (ReleaseDecisionState.GO, ReleaseDecisionState.GO_WITH_WARNINGS) and decision_state in (ReleaseDecisionState.BLOCKED, ReleaseDecisionState.NO_GO):
                delta_state = ReleaseDeltaState.DEGRADED
            elif decision_state.value != previous_decision.value:
                delta_state = ReleaseDeltaState.IMPROVED if sec_score >= 80 else ReleaseDeltaState.DEGRADED

            release_diff = ReleaseDiff(
                previous_decision=previous_decision,
                current_decision=decision_state,
                release_delta_state=delta_state,
                explanation=f"Release posture changed from {previous_decision.value} to {decision_state.value} ({delta_state.value}).",
            )

        # 8. Deterministic Recommendations Generation
        recommendations = []
        if decision_state == ReleaseDecisionState.BLOCKED:
            recommendations.append("Release is BLOCKED by critical security vulnerabilities or exploitable attack paths.")
            if p0_cnt > 0:
                recommendations.append(f"Resolve {p0_cnt} P0 remediation item(s) before release.")
        elif decision_state == ReleaseDecisionState.NO_GO:
            recommendations.append("Release is NO_GO due to HIGH severity vulnerabilities or unresolved P1 items.")
        elif decision_state == ReleaseDecisionState.REVIEW_REQUIRED:
            recommendations.append("Human security review required before proceeding with release.")
        elif decision_state == ReleaseDecisionState.GO_WITH_WARNINGS:
            recommendations.append("Repository is release-ready with non-blocking low/medium risk warnings.")
        else:
            recommendations.append("Repository is fully release-ready. No blocking security risks detected.")

        return SecurityReleaseDecision(
            repository=repository_name,
            commit=commit_sha[:7],
            decision=decision_state,
            release_status=gate_verdict.value,
            security_score=sec_score,
            risk_score=risk_score,
            scorecard=scorecard,
            blockers=blockers,
            blocking_findings=[b.finding_id for b in blockers if b.finding_id],
            blocking_attack_paths=[b.attack_path_id for b in blockers if b.attack_path_id],
            blocking_remediations=[b.remediation_id for b in blockers if b.remediation_id],
            regressions=[str(mon_dict.get("regression_severity", ""))] if mon_dict and mon_dict.get("regression_severity") != "NO_REGRESSION" else [],
            governance_status=governance_status,
            evidence_chain=evidence_chain,
            recommendations=recommendations,
            release_diff=release_diff,
            generated_at=datetime.now().isoformat(),
        )

    def evaluate_cross_repository_release_posture(
        self,
        repositories_scans: Dict[str, Dict[str, Any]],
    ) -> CrossRepositoryReleasePosture:
        """
        Executes a batch cross-repository release posture evaluation.
        """
        repo_decisions: Dict[str, SecurityReleaseDecision] = {}
        go_cnt = 0
        blocked_cnt = 0
        no_go_cnt = 0
        review_cnt = 0

        for repo_name, scan_data in repositories_scans.items():
            dec = self.evaluate_release_readiness(
                prioritized_findings=scan_data.get("prioritized_findings"),
                attack_paths=scan_data.get("attack_paths"),
                remediation_plan=scan_data.get("remediation_plan"),
                monitoring_result=scan_data.get("monitoring_result"),
                repository_name=repo_name,
            )
            repo_decisions[repo_name] = dec

            d_val = dec.decision.value if hasattr(dec.decision, "value") else str(dec.decision)
            if d_val in ("GO", "GO_WITH_WARNINGS"):
                go_cnt += 1
            elif d_val == "BLOCKED":
                blocked_cnt += 1
            elif d_val == "NO_GO":
                no_go_cnt += 1
            elif d_val == "REVIEW_REQUIRED":
                review_cnt += 1

        return CrossRepositoryReleasePosture(
            generated_at=datetime.now().isoformat(),
            repository_decisions=repo_decisions,
            total_repositories=len(repo_decisions),
            go_count=go_cnt,
            blocked_count=blocked_cnt,
            no_go_count=no_go_cnt,
            review_required_count=review_cnt,
        )
