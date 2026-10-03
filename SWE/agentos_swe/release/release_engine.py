"""
M30 Master Release Readiness Engine Facade.

Consolidates outputs from M14-M29 to evaluate 12 release gates,
calculate 0-100 readiness score, conduct configuration and dependency audits,
measure performance benchmarks, validate regressions, check packaging, and generate system manifests.
"""

import logging
from typing import List, Dict, Any, Optional

from agentos_swe.release.models import (
    ReleaseValidationResult,
    SecurityGateStatus,
    ReleaseBlocker,
    RegressionStatus,
    PackagingStatus,
    CrossRepositoryReleasePosture,
    ReleaseDiff,
    ReleaseDeltaState,
    CheckStatus,
    ReadinessLevel,
)
from agentos_swe.release.validator import ReleaseGateValidator
from agentos_swe.release.readiness import ReleaseReadinessCalculator
from agentos_swe.release.configuration import SecurityConfigurationAuditor
from agentos_swe.release.dependency_audit import DependencyAuditor
from agentos_swe.release.performance import PerformanceBenchmarker
from agentos_swe.release.regression import ReleaseRegressionValidator
from agentos_swe.release.packaging import PackagingValidator
from agentos_swe.release.manifest import SystemCapabilityManifest

logger = logging.getLogger(__name__)


class ReleaseReadinessEngine:
    """
    Master Release Readiness facade.
    """

    def __init__(self):
        self.validator = ReleaseGateValidator()

    def evaluate_release_readiness(
        self,
        repository_name: str,
        commit_sha: str = "HEAD",
        verified_findings: Optional[List[Any]] = None,
        prioritized_findings: Optional[List[Any]] = None,
        attack_paths: Optional[List[Any]] = None,
        decision_result: Optional[Any] = None,
        learning_result: Optional[Any] = None,
        drift_result: Optional[Any] = None,
        control_plane_result: Optional[Any] = None,
        monitoring_health: Optional[Any] = None,
        incident_result: Optional[Any] = None,
        repair_validations: Optional[List[Any]] = None,
        stage_runtimes: Optional[Dict[str, float]] = None,
        repository_path: Optional[str] = None,
        **kwargs,
    ) -> ReleaseValidationResult:
        """
        Orchestrates full M30 enterprise release readiness evaluation.
        """
        repo_path = repository_path or kwargs.get("repo_path") or kwargs.get("scan_target_path")
        findings = prioritized_findings or verified_findings or []
        findings_dict = [f.to_dict() if hasattr(f, "to_dict") else f for f in findings]

        active_findings = [
            f for f in findings_dict
            if not f.get("sanitized") and not f.get("is_safe") and f.get("root_cause") not in {
                "DICT_LOOKUP", "INTENTIONAL_FALLBACK", "TEST_HARNESS_DIAGNOSTIC", "FORMATTING_ONLY", "COMMENT_ONLY"
            }
        ]

        rem_plan = kwargs.get("remediation_plan") or kwargs.get("plan")
        if rem_plan:
            rem_items = getattr(rem_plan, "remediation_items", []) if not isinstance(rem_plan, dict) else rem_plan.get("remediation_items", [])
            for item in rem_items:
                tier = getattr(item, "priority_tier", None) if not isinstance(item, dict) else item.get("priority_tier")
                root_cause = getattr(item, "root_cause", "VULNERABILITY") if not isinstance(item, dict) else item.get("root_cause", "VULNERABILITY")
                if tier in ("P0", "TIER_0"):
                    active_findings.append({"severity": "CRITICAL", "priority": "P0", "root_cause": root_cause})
                elif tier in ("P1", "TIER_1"):
                    active_findings.append({"severity": "HIGH", "priority": "P1", "root_cause": root_cause})

        mon_hlth = monitoring_health or kwargs.get("monitoring_result")
        gates = self.validator.evaluate_gates(
            verified_findings=verified_findings,
            prioritized_findings=prioritized_findings,
            attack_paths=attack_paths,
            decision_result=decision_result,
            learning_result=learning_result,
            drift_result=drift_result,
            control_plane_result=control_plane_result,
            monitoring_health=mon_hlth,
            incident_result=incident_result,
            repair_validations=repair_validations,
            remediation_plan=rem_plan,
        )

        # 2. Extract Release Blockers
        blockers: List[ReleaseBlocker] = []
        for g in gates:
            if g.status == SecurityGateStatus.BLOCKED:
                blockers.append(
                    ReleaseBlocker(
                        blocker_id=f"blk_{g.gate_id}",
                        source_module="ReleaseGateValidator",
                        title=f"{g.name} Failed",
                        description=g.rationale,
                        severity=g.severity,
                    )
                )

        # 3. Calculate 0-100 Score and Readiness Level
        gov_dec = "ALLOW"
        if decision_result:
            gov_dec = str(getattr(decision_result, "overall_decision", None) or "ALLOW").upper()

        m_status = "ACTIVE"
        if mon_hlth:
            m_status = str(getattr(mon_hlth, "status", None) or getattr(mon_hlth, "monitoring_health", None) or "ACTIVE").upper()

        level, score_obj, summary = ReleaseReadinessCalculator.calculate_readiness(
            repository_name=repository_name,
            commit_sha=commit_sha,
            gates=gates,
            active_findings=active_findings,
            monitoring_health_str=m_status,
            governance_dec=gov_dec,
            remediation_plan=rem_plan,
        )

        if level in (ReadinessLevel.BLOCKED, ReadinessLevel.NO_GO) and not blockers:
            blockers.append(
                ReleaseBlocker(
                    blocker_id="blk_NO_GO",
                    source_module="ReleaseGateValidator",
                    title="Release Readiness Blocked",
                    description=summary.recommendation,
                    severity="HIGH",
                )
            )

        # 4. Perform M30 Release Readiness Audits and Benchmarks
        cfg_audit = SecurityConfigurationAuditor.audit_configuration(repo_path)
        dep_audit = DependencyAuditor.audit_dependencies(repo_path)
        perf_bm = PerformanceBenchmarker.benchmark_pipeline(stage_runtimes)
        reg_res = ReleaseRegressionValidator.validate_regressions()
        pkg_res = PackagingValidator.validate_packaging()
        manifest_res = SystemCapabilityManifest.generate_manifest()

        prev_dec = kwargs.get("previous_decision")
        rel_diff = None
        if prev_dec is not None:
            prev_val = prev_dec.value if hasattr(prev_dec, "value") else str(prev_dec)
            curr_val = summary.readiness_level.value if hasattr(summary.readiness_level, "value") else str(summary.readiness_level)
            diff_status = "UNCHANGED"
            delta_state = ReleaseDeltaState.UNCHANGED
            if prev_val in ("BLOCKED", "NO_GO") and curr_val in ("RELEASE_READY", "GO"):
                diff_status = "RECOVERED"
                delta_state = ReleaseDeltaState.RECOVERED
            elif prev_val in ("RELEASE_READY", "GO") and curr_val in ("BLOCKED", "NO_GO"):
                diff_status = "DEGRADED"
                delta_state = ReleaseDeltaState.DEGRADED
            elif curr_val in ("RELEASE_READY", "GO") and prev_val not in ("RELEASE_READY", "GO"):
                diff_status = "IMPROVED"
                delta_state = ReleaseDeltaState.IMPROVED

            rel_diff = ReleaseDiff(
                release_delta_state=delta_state,
                status=diff_status,
                score_delta=0.0,
                previous_decision=prev_val,
                current_decision=curr_val,
            )

        res = ReleaseValidationResult(
            summary=summary,
            readiness_score=score_obj,
            gates=gates,
            blockers=blockers,
            checks=[],
            configuration_audit=cfg_audit,
            dependency_audit=dep_audit,
            performance_benchmark=perf_bm,
            regression_status=RegressionStatus.CLEAN if reg_res.get("is_clean") else RegressionStatus.REGRESSION_DETECTED,
            packaging_status=PackagingStatus.VALID if pkg_res.get("is_valid") else PackagingStatus.INVALID,
            manifest=manifest_res,
            release_diff=rel_diff,
        )
        res._attack_path_ids = [ap.get("id") if isinstance(ap, dict) else getattr(ap, "id", str(ap)) for ap in (attack_paths or []) if ap]
        rem_items = (getattr(rem_plan, "remediation_items", []) if not isinstance(rem_plan, dict) else (rem_plan.get("remediation_items") or [])) if rem_plan else []
        res._remediation_item_ids = [item.item_id if hasattr(item, "item_id") else item.get("item_id", "") for item in rem_items if item]
        return res

    def evaluate_cross_repository_release_posture(self, repository_scans: Dict[str, Any]) -> CrossRepositoryReleasePosture:
        """
        M19 backward-compatibility method for cross-repository posture evaluation.
        """
        results = {}
        for repo_name, scan_data in repository_scans.items():
            if isinstance(scan_data, dict):
                results[repo_name] = self.evaluate_release_readiness(
                    repository_name=repo_name,
                    **scan_data
                )
            else:
                results[repo_name] = self.evaluate_release_readiness(
                    repository_name=repo_name
                )
        return CrossRepositoryReleasePosture(
            total_repositories=len(results),
            repository_decisions=results,
        )
