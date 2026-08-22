"""
M18 Main SecurityMonitor Orchestration Engine.

Orchestrates continuous security monitoring, commit diff analysis, regression detection,
remediation validity checking, alert generation, timeline building, and cross-repository posture tracking.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime
from agentos_swe.monitoring.models import (
    SecurityMonitoringResult,
    CrossRepositoryMonitoringResult,
    SecurityChangeImpact,
    SecurityTimelineEntry,
    RegressionSeverity,
    TrendDirection,
)
from agentos_swe.monitoring.snapshot_manager import SnapshotManager
from agentos_swe.monitoring.change_detector import ChangeDetector
from agentos_swe.monitoring.regression_detector import RegressionDetector
from agentos_swe.monitoring.trend_analyzer import TrendAnalyzer
from agentos_swe.monitoring.alert_engine import AlertEngine


class SecurityMonitor:
    """
    Continuous Security Monitoring Engine Facade.
    """

    def __init__(self, storage_dir: Optional[str] = None):
        self.snapshot_manager = SnapshotManager(storage_dir=storage_dir)
        self.change_detector = ChangeDetector()
        self.regression_detector = RegressionDetector()
        self.trend_analyzer = TrendAnalyzer()
        self.alert_engine = AlertEngine()

    def monitor_repository(
        self,
        current_scan: Dict[str, Any],
        previous_scan: Optional[Dict[str, Any]] = None,
        historical_comparison: Optional[Any] = None,
        attack_paths: Optional[List[Any]] = None,
        remediation_plan: Optional[Any] = None,
        repository_name: str = "Unknown Repo",
    ) -> SecurityMonitoringResult:
        """
        Executes an on-demand continuous security monitoring assessment comparing current scan vs baseline snapshot.
        """
        attack_paths = attack_paths or []

        # Extract commits and repository metadata
        curr_meta = current_scan.get("metadata", {})
        curr_commit = curr_meta.get("commit") or current_scan.get("commit_sha") or "HEAD"
        repo = repository_name or current_scan.get("repository") or curr_meta.get("repo_name") or "Unknown Repo"

        # Baseline retrieval from snapshot manager if not explicitly provided
        if not previous_scan:
            previous_scan = self.snapshot_manager.get_previous_snapshot(repo)

        prev_meta = (previous_scan or {}).get("metadata", {})
        prev_commit = prev_meta.get("commit") or (previous_scan or {}).get("commit_sha") or "PREV_HEAD"

        # Security scores
        score_after = current_scan.get("security_score", 100)
        if hasattr(remediation_plan, "current_security_score"):
            score_after = remediation_plan.current_security_score
        elif isinstance(remediation_plan, dict) and "current_security_score" in remediation_plan:
            score_after = remediation_plan["current_security_score"]

        score_before = (previous_scan or {}).get("security_score", 100)
        score_delta = score_after - score_before

        # Findings extraction
        curr_findings = current_scan.get("prioritized_findings") or current_scan.get("verified_findings") or current_scan.get("findings") or []
        prev_findings = (previous_scan or {}).get("prioritized_findings") or (previous_scan or {}).get("findings") or []

        curr_findings_dict = [f.to_dict() if hasattr(f, "to_dict") else f for f in curr_findings]
        prev_findings_dict = [f.to_dict() if hasattr(f, "to_dict") else f for f in prev_findings]

        # 1. Change Detection
        new_findings, fixed_findings, unchanged_findings, reopened_findings = self.change_detector.detect_finding_changes(
            current_findings=curr_findings_dict,
            previous_findings=prev_findings_dict,
            history_comparator=historical_comparison,
        )

        prev_paths = (previous_scan or {}).get("attack_paths", [])
        new_attack_paths, removed_attack_paths, changed_attack_paths = self.change_detector.detect_attack_path_changes(
            current_paths=attack_paths,
            previous_paths=prev_paths,
        )

        # Changed files extraction
        changed_files = list({f.get("affected_file") or f.get("file") or "" for f in new_findings if f.get("affected_file") or f.get("file")})

        # M17 Remediation Plan Impact
        remediation_impact = self.change_detector.evaluate_remediation_impact(
            remediation_plan=remediation_plan,
            changed_files=changed_files,
            new_findings=new_findings,
        )

        # 2. Regression Classification
        regression_sev, summary_exp = self.regression_detector.evaluate_regression(
            new_findings=new_findings,
            reopened_findings=reopened_findings,
            attack_path_changes=changed_attack_paths,
            remediation_impact=remediation_impact,
            score_delta=score_delta,
        )

        # 3. Security Trend Analysis
        snapshots = self.snapshot_manager.get_latest_snapshots(repo, limit=5)
        trend = self.trend_analyzer.analyze_trend(
            historical_snapshots=snapshots,
            current_score=score_after,
            score_delta=score_delta,
        )

        # 4. Security Alerts Generation
        alerts = self.alert_engine.generate_alerts(
            repository=repo,
            commit=curr_commit,
            regression_severity=regression_sev,
            new_findings=new_findings,
            reopened_findings=reopened_findings,
            attack_path_changes=changed_attack_paths,
            remediation_impact=remediation_impact,
            score_delta=score_delta,
        )

        # 5. Security Change Impact Entry
        change_impacts: List[SecurityChangeImpact] = []
        if changed_files:
            for cf in changed_files:
                change_impacts.append(
                    SecurityChangeImpact(
                        commit=curr_commit[:7],
                        file=cf,
                        affected_findings_count=len(new_findings),
                        affected_attack_paths_count=len(new_attack_paths),
                        affected_remediation_items_count=len(remediation_impact.invalidated_items) if remediation_impact else 0,
                        risk_score_delta=score_delta,
                        status_description=f"File diff generated {len(new_findings)} new finding(s) with regression severity `{regression_sev.value}`.",
                    )
                )

        # 6. Security Timeline Entry
        timeline_entry = SecurityTimelineEntry(
            commit=curr_commit[:7],
            timestamp=datetime.now().isoformat()[:16].replace("T", " "),
            code_changes_summary=f"{len(changed_files)} file(s) modified",
            finding_changes_summary=f"+{len(new_findings)} new, -{len(fixed_findings)} fixed, {len(reopened_findings)} reopened",
            attack_path_changes_summary=f"+{len(new_attack_paths)} new attack paths",
            score_before=score_before,
            score_after=score_after,
            score_delta=score_delta,
            remediation_status_summary=remediation_impact.status.value if remediation_impact else "VALID",
            regression_severity=regression_sev,
        )

        timeline = [timeline_entry]

        # 7. Governance Verdict
        gov_verdict = "ALLOW"
        if regression_sev in (RegressionSeverity.CRITICAL_REGRESSION, RegressionSeverity.SIGNIFICANT_REGRESSION):
            gov_verdict = "REVIEW_REQUIRED"

        res = SecurityMonitoringResult(
            repository=repo,
            current_commit=curr_commit[:7],
            previous_commit=prev_commit[:7],
            scan_timestamp=datetime.now().isoformat(),
            security_score_before=score_before,
            security_score_after=score_after,
            score_delta=score_delta,
            risk_trend=trend,
            regression_severity=regression_sev,
            new_findings=new_findings,
            fixed_findings=fixed_findings,
            unchanged_findings=unchanged_findings,
            reopened_findings=reopened_findings,
            new_attack_paths=new_attack_paths,
            removed_attack_paths=removed_attack_paths,
            changed_attack_paths=changed_attack_paths,
            remediation_impact=remediation_impact,
            change_impacts=change_impacts,
            timeline=timeline,
            alerts=alerts,
            monitoring_status="COMPLETE",
            governance_verdict=gov_verdict,
            summary_explanation=summary_exp,
        )

        # Persist snapshot for subsequent monitoring passes
        snapshot_entry = {
            "scan_id": current_scan.get("metadata", {}).get("scan_id") or "scan_curr",
            "repository": repo,
            "commit_sha": curr_commit,
            "security_score": score_after,
            "findings_count": len(curr_findings_dict),
            "timestamp": datetime.now().isoformat(),
            "prioritized_findings": curr_findings_dict,
            "attack_paths": [ap.to_dict() if hasattr(ap, "to_dict") else ap for ap in attack_paths],
        }
        self.snapshot_manager.save_snapshot(repo, snapshot_entry)

        return res

    def monitor_cross_repository(
        self,
        repositories_scans: Dict[str, Dict[str, Any]],
    ) -> CrossRepositoryMonitoringResult:
        """
        Executes a batch cross-repository monitoring pass across multiple repositories.
        """
        repo_results: Dict[str, SecurityMonitoringResult] = {}
        degrading_cnt = 0
        crit_reg_cnt = 0

        for repo_name, scan_data in repositories_scans.items():
            res = self.monitor_repository(
                current_scan=scan_data,
                repository_name=repo_name,
            )
            repo_results[repo_name] = res

            if res.risk_trend == TrendDirection.DEGRADING:
                degrading_cnt += 1
            if res.regression_severity == RegressionSeverity.CRITICAL_REGRESSION:
                crit_reg_cnt += 1

        return CrossRepositoryMonitoringResult(
            scan_timestamp=datetime.now().isoformat(),
            repository_results=repo_results,
            total_repositories=len(repo_results),
            degrading_repositories_count=degrading_cnt,
            critical_regressions_count=crit_reg_cnt,
        )
