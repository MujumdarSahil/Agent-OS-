"""
M20 Main SecurityEngineeringOrchestrator Facade.

Coordinates end-to-end security engineering workflows, adaptive planning, dependency execution,
next-action decisions, security cases, and cross-repository posture summaries.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime
from agentos_swe.operations.orchestration.models import (
    WorkflowState,
    NextActionDecision,
    SecurityOrchestrationResult,
    SecurityEngineeringSummary,
    SecurityCase,
)
from agentos_swe.operations.orchestration.planner import SecurityWorkflowPlanner
from agentos_swe.operations.orchestration.executor import SecurityWorkflowExecutor


class SecurityEngineeringOrchestrator:
    """
    Main Security Engineering Orchestration Facade.
    """

    def __init__(self):
        self.planner = SecurityWorkflowPlanner()
        self.executor = SecurityWorkflowExecutor()

    def orchestrate_repository(
        self,
        verified_findings: Optional[List[Any]] = None,
        prioritized_findings: Optional[List[Any]] = None,
        attack_paths: Optional[List[Any]] = None,
        remediation_plan: Optional[Any] = None,
        monitoring_result: Optional[Any] = None,
        release_decision: Optional[Any] = None,
        repository_name: str = "Unknown Repo",
        commit_sha: str = "HEAD",
        governance_status: str = "ALLOW",
        remediation_attempts: int = 0,
        force_human_review: bool = False,
    ) -> SecurityOrchestrationResult:
        """
        Orchestrates security engineering pipeline and returns SecurityOrchestrationResult.
        """
        start_t = datetime.now().isoformat()
        verified_findings = verified_findings or []
        prioritized_findings = prioritized_findings or []
        attack_paths = attack_paths or []

        findings_dict = [f.to_dict() if hasattr(f, "to_dict") else f for f in (prioritized_findings or verified_findings)]
        paths_dict = [ap.to_dict() if hasattr(ap, "to_dict") else ap for ap in attack_paths]
        rem_dict = remediation_plan.to_dict() if hasattr(remediation_plan, "to_dict") else (remediation_plan or {})
        mon_dict = monitoring_result.to_dict() if hasattr(monitoring_result, "to_dict") else (monitoring_result or {})
        rel_dict = release_decision.to_dict() if hasattr(release_decision, "to_dict") else (release_decision or {})

        # 1. Construct Adaptive Workflow Plan
        is_clean = len(findings_dict) == 0 and len(paths_dict) == 0
        plan = self.planner.construct_plan(
            repository_name=repository_name,
            commit_sha=commit_sha,
            findings=findings_dict,
            is_clean_scan=is_clean,
        )

        # 2. Execute Dependency-Aware Workflow
        exec_res = self.executor.execute_workflow(
            repository_name=repository_name,
            commit_sha=commit_sha,
            plan=plan,
            verified_findings=findings_dict,
            prioritized_findings=findings_dict,
            attack_paths=paths_dict,
            remediation_plan=rem_dict,
            monitoring_result=mon_dict,
            release_decision=rel_dict,
            governance_decision=governance_status,
            remediation_attempts=remediation_attempts,
            force_human_review=force_human_review,
        )

        # 3. Assemble Summary
        summary = SecurityEngineeringSummary(
            repositories_scanned=1,
            total_findings=len(findings_dict),
            critical_findings=sum(1 for f in findings_dict if str(f.get("severity") or "").upper() == "CRITICAL"),
            high_findings=sum(1 for f in findings_dict if str(f.get("severity") or "").upper() == "HIGH"),
            active_attack_paths=len(paths_dict),
            open_remediations=len(rem_dict.get("remediation_items", [])),
            regressions=1 if mon_dict and "CRITICAL" in str(mon_dict.get("regression_severity", "")).upper() else 0,
            blocked_releases=1 if rel_dict and rel_dict.get("decision") == "BLOCKED" else 0,
            review_required=1 if exec_res["human_review"] is not None else 0,
            repositories_release_ready=1 if rel_dict and rel_dict.get("decision") in ("GO", "GO_WITH_WARNINGS") else 0,
        )

        return SecurityOrchestrationResult(
            workflow_id=f"wf_{repository_name}_{commit_sha[:7]}",
            repository=repository_name,
            commit=commit_sha[:7],
            current_state=exec_res["current_state"],
            previous_state=exec_res["previous_state"],
            state_history=exec_res["state_history"],
            plan=plan,
            cases=exec_res["cases"],
            next_action=exec_res["next_action"],
            next_action_reason=exec_res["next_action_reason"],
            human_review=exec_res["human_review"],
            summary=summary,
            started_at=start_t,
            completed_at=datetime.now().isoformat(),
            errors=exec_res["errors"],
            warnings=exec_res["warnings"],
        )

    def orchestrate_repositories(
        self,
        repositories_scans: Dict[str, Dict[str, Any]],
    ) -> SecurityEngineeringSummary:
        """
        Executes multi-repository orchestration pass and returns global SecurityEngineeringSummary.
        """
        tot_scanned = len(repositories_scans)
        tot_find = 0
        crit_find = 0
        high_find = 0
        active_paths = 0
        open_rems = 0
        regressions = 0
        blocked_rel = 0
        review_req = 0
        rel_ready = 0

        for repo_name, scan_data in repositories_scans.items():
            res = self.orchestrate_repository(
                verified_findings=scan_data.get("verified_findings"),
                prioritized_findings=scan_data.get("prioritized_findings"),
                attack_paths=scan_data.get("attack_paths"),
                remediation_plan=scan_data.get("remediation_plan"),
                monitoring_result=scan_data.get("monitoring_result"),
                release_decision=scan_data.get("release_decision"),
                repository_name=repo_name,
            )

            tot_find += res.summary.total_findings if res.summary else 0
            crit_find += res.summary.critical_findings if res.summary else 0
            high_find += res.summary.high_findings if res.summary else 0
            active_paths += res.summary.active_attack_paths if res.summary else 0
            open_rems += res.summary.open_remediations if res.summary else 0
            regressions += res.summary.regressions if res.summary else 0
            blocked_rel += res.summary.blocked_releases if res.summary else 0
            review_req += res.summary.review_required if res.summary else 0
            rel_ready += res.summary.repositories_release_ready if res.summary else 0

        return SecurityEngineeringSummary(
            repositories_scanned=tot_scanned,
            total_findings=tot_find,
            critical_findings=crit_find,
            high_findings=high_find,
            active_attack_paths=active_paths,
            open_remediations=open_rems,
            regressions=regressions,
            blocked_releases=blocked_rel,
            review_required=review_req,
            repositories_release_ready=rel_ready,
            generated_at=datetime.now().isoformat(),
        )
