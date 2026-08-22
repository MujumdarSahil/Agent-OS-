"""
M20 Security Case Evidence Builder & Escalation Engine.

Assembles SecurityCase instances, chronological case timelines, and HumanReviewRequest escalation payloads.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime
from agentos_swe.orchestration.models import (
    SecurityCase,
    SecurityCaseStatus,
    SecurityCaseTimelineEntry,
    HumanReviewRequest,
    WorkflowState,
)


class SecurityCaseEvidenceBuilder:
    """
    Builds SecurityCase lifecycles and human review escalation requests.
    """

    def build_security_case(
        self,
        repository_name: str,
        finding: Optional[Dict[str, Any]] = None,
        attack_path: Optional[Dict[str, Any]] = None,
        remediation_plan: Optional[Dict[str, Any]] = None,
        monitoring_result: Optional[Dict[str, Any]] = None,
        release_decision: Optional[Dict[str, Any]] = None,
        governance_decision: str = "ALLOW",
        remediation_attempts: int = 0,
        human_review: Optional[HumanReviewRequest] = None,
    ) -> SecurityCase:
        """
        Constructs a complete SecurityCase instance.
        """
        finding = finding or {}
        fid = finding.get("finding_id") or finding.get("id") or "case_1"
        sev = str(finding.get("severity") or "MEDIUM").upper()
        tier = str(finding.get("priority_tier") or "P3").replace("PriorityTier.", "")
        rc = finding.get("root_cause") or finding.get("category") or "UNKNOWN"

        # Determine status
        status = SecurityCaseStatus.OPEN
        rel_dec = str((release_decision or {}).get("decision") or "").upper()

        if rel_dec == "BLOCKED":
            status = SecurityCaseStatus.BLOCKED
        elif human_review or remediation_attempts >= 3:
            status = SecurityCaseStatus.REMEDIATION_FAILED
        elif remediation_plan and "remediation_items" in remediation_plan and len(remediation_plan["remediation_items"]) > 0:
            status = SecurityCaseStatus.REMEDIATION_PLANNED
        elif rel_dec in ("GO", "GO_WITH_WARNINGS"):
            status = SecurityCaseStatus.CLOSED if rc in ("DICT_LOOKUP", "INFO", "TEST_HARNESS", "INTENTIONAL_FALLBACK") else SecurityCaseStatus.REMEDIATED

        # Build timeline
        now_str = datetime.now().isoformat()
        timeline: List[SecurityCaseTimelineEntry] = [
            SecurityCaseTimelineEntry(
                entry_id="t_1_scan",
                timestamp=now_str,
                event="Vulnerability Detected",
                details=f"Finding '{fid}' ({sev} {rc}) identified in {finding.get('affected_file', 'repository')}.",
                state=WorkflowState.SCANNING,
            ),
            SecurityCaseTimelineEntry(
                entry_id="t_2_prio",
                timestamp=now_str,
                event=f"Priority Tier {tier} Assigned",
                details=f"Calculated priority score {finding.get('priority_score', 0)}/100.",
                state=WorkflowState.PRIORITIZING,
            ),
        ]

        if attack_path:
            timeline.append(
                SecurityCaseTimelineEntry(
                    entry_id="t_3_path",
                    timestamp=now_str,
                    event="Attack Path Discovered",
                    details=f"Entrypoint '{attack_path.get('entrypoint', 'INTERNET')}' → Sink '{attack_path.get('sink_type', 'Sink')}'. Risk Score: {attack_path.get('risk_score', 0)}.",
                    state=WorkflowState.ATTACK_PATH_ANALYSIS,
                )
            )

        if remediation_plan:
            timeline.append(
                SecurityCaseTimelineEntry(
                    entry_id="t_4_rem",
                    timestamp=now_str,
                    event="Remediation Plan Generated",
                    details=f"Current Security Score: {remediation_plan.get('current_security_score', 100)}, Projected Score: {remediation_plan.get('projected_security_score', 100)}.",
                    state=WorkflowState.REMEDIATION_PLANNING,
                )
            )

        if release_decision:
            timeline.append(
                SecurityCaseTimelineEntry(
                    entry_id="t_5_rel",
                    timestamp=now_str,
                    event=f"Release Readiness Evaluated: {rel_dec}",
                    details=f"Gate Verdict: {release_decision.get('release_status', 'ALLOW_RELEASE')}.",
                    state=WorkflowState.RELEASE_READINESS,
                )
            )

        return SecurityCase(
            case_id=f"SEC-{fid}",
            repository=repository_name,
            finding=finding,
            priority=tier,
            attack_path=attack_path,
            root_cause=rc,
            remediation=remediation_plan,
            monitoring=monitoring_result,
            release_decision=rel_dec,
            governance_decision=governance_decision,
            current_status=status,
            evidence=finding.get("evidence", []) if isinstance(finding.get("evidence"), list) else [],
            timeline=timeline,
            human_review_request=human_review,
            remediation_attempts=remediation_attempts,
            created_at=now_str,
        )

    def create_human_review_request(
        self,
        reason: str,
        severity: str,
        affected_files: List[str],
        evidence: str,
        attempted_actions: List[str],
        recommended_next_step: str,
    ) -> HumanReviewRequest:
        """
        Creates a HumanReviewRequest escalation object.
        """
        return HumanReviewRequest(
            review_id=f"hr_{int(datetime.now().timestamp())}",
            reason=reason,
            severity=severity,
            affected_files=affected_files,
            evidence=evidence,
            attempted_actions=attempted_actions,
            recommended_next_step=recommended_next_step,
            created_at=datetime.now().isoformat(),
        )
