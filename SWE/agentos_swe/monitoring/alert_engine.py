"""
M18 Security Alert Engine.

Generates deterministic, actionable security monitoring alerts sorted by severity.
"""

from typing import List, Dict, Any, Optional
from agentos_swe.monitoring.models import (
    SecurityAlert,
    AlertCategory,
    AlertSeverity,
    RegressionSeverity,
    AttackPathChange,
    RemediationImpact,
    RemediationPlanStatus,
)


class AlertEngine:
    """
    Deterministic alert generation engine.
    """

    def generate_alerts(
        self,
        repository: str,
        commit: str,
        regression_severity: RegressionSeverity,
        new_findings: List[Dict[str, Any]],
        reopened_findings: List[Dict[str, Any]],
        attack_path_changes: List[AttackPathChange],
        remediation_impact: Optional[RemediationImpact],
        score_delta: int,
    ) -> List[SecurityAlert]:
        """
        Builds a sorted list of SecurityAlert objects based on monitoring delta telemetry.
        """
        alerts: List[SecurityAlert] = []

        # 1. Critical Regression Alert
        if regression_severity == RegressionSeverity.CRITICAL_REGRESSION:
            alerts.append(
                SecurityAlert(
                    alert_id=f"alt_{len(alerts)+1}",
                    category=AlertCategory.CRITICAL_SECURITY_REGRESSION,
                    severity=AlertSeverity.CRITICAL,
                    title="Critical Security Regression Detected",
                    repository=repository,
                    commit=commit,
                    reason="Commit introduced high-risk security regressions into codebase.",
                    evidence=f"New CRITICAL findings / attack paths or score drop ({score_delta} pts).",
                    affected_files=list({f.get("affected_file") or f.get("file") or "" for f in new_findings if f.get("affected_file") or f.get("file")}),
                    affected_findings=[f.get("finding_id") or f.get("id") or "f_new" for f in new_findings if str(f.get("severity")).upper() == "CRITICAL"],
                    affected_attack_paths=[c.path_id for c in attack_path_changes],
                    recommended_action="Immediately review git diff and apply defensive input validation or revert commit.",
                )
            )

        # 2. New Critical Findings Alert
        crit_findings = [f for f in new_findings if str(f.get("severity") or "").upper() == "CRITICAL"]
        if crit_findings:
            alerts.append(
                SecurityAlert(
                    alert_id=f"alt_{len(alerts)+1}",
                    category=AlertCategory.NEW_CRITICAL_FINDING,
                    severity=AlertSeverity.CRITICAL,
                    title="New CRITICAL Vulnerability Introduced",
                    repository=repository,
                    commit=commit,
                    reason=f"{len(crit_findings)} new CRITICAL vulnerability introduced in recent code diff.",
                    evidence=f"Root cause: {crit_findings[0].get('root_cause', 'UNKNOWN')} in {crit_findings[0].get('affected_file', 'codebase')}.",
                    affected_files=[crit_findings[0].get("affected_file") or "app/main.py"],
                    affected_findings=[f.get("finding_id") or "f_crit" for f in crit_findings],
                    recommended_action="Replace shell=True / unsanitized queries with safe parameterized interfaces.",
                )
            )

        # 3. New High Findings Alert
        high_findings = [f for f in new_findings if str(f.get("severity") or "").upper() == "HIGH"]
        if high_findings:
            alerts.append(
                SecurityAlert(
                    alert_id=f"alt_{len(alerts)+1}",
                    category=AlertCategory.NEW_HIGH_FINDING,
                    severity=AlertSeverity.HIGH,
                    title="New HIGH Vulnerability Introduced",
                    repository=repository,
                    commit=commit,
                    reason=f"{len(high_findings)} new HIGH severity vulnerability introduced.",
                    evidence=f"Root cause: {high_findings[0].get('root_cause', 'UNKNOWN')} in {high_findings[0].get('affected_file', 'codebase')}.",
                    affected_files=[high_findings[0].get("affected_file") or "app/main.py"],
                    affected_findings=[f.get("finding_id") or "f_high" for f in high_findings],
                    recommended_action="Apply defensive sanitization and narrow exception scopes.",
                )
            )

        # 4. Authentication Weakened Alert
        auth_weakened_changes = [c for c in attack_path_changes if c.auth_weakened]
        if auth_weakened_changes:
            alerts.append(
                SecurityAlert(
                    alert_id=f"alt_{len(alerts)+1}",
                    category=AlertCategory.AUTHENTICATION_WEAKENED,
                    severity=AlertSeverity.HIGH,
                    title="Authentication Boundary Weakened",
                    repository=repository,
                    commit=commit,
                    reason="Attack path entrypoint transitioned from AUTHENTICATED to UNAUTHENTICATED.",
                    evidence=f"Path {auth_weakened_changes[0].path_id} in {auth_weakened_changes[0].affected_file}.",
                    affected_files=[auth_weakened_changes[0].affected_file],
                    affected_attack_paths=[c.path_id for c in auth_weakened_changes],
                    recommended_action="Re-enforce authentication middleware or decorator on public entrypoint route.",
                )
            )

        # 5. Exposure Increased Alert
        exp_increased_changes = [c for c in attack_path_changes if c.exposure_increased]
        if exp_increased_changes:
            alerts.append(
                SecurityAlert(
                    alert_id=f"alt_{len(alerts)+1}",
                    category=AlertCategory.EXPOSURE_INCREASED,
                    severity=AlertSeverity.MEDIUM,
                    title="Entrypoint Internet Exposure Increased",
                    repository=repository,
                    commit=commit,
                    reason="Attack path entrypoint exposed to external INTERNET scope.",
                    evidence=f"Path {exp_increased_changes[0].path_id} in {exp_increased_changes[0].affected_file}.",
                    affected_files=[exp_increased_changes[0].affected_file],
                    affected_attack_paths=[c.path_id for c in exp_increased_changes],
                    recommended_action="Restrict entrypoint network exposure scope or restrict CORS policy.",
                )
            )

        # 6. Remediation Invalidated Alert
        if remediation_impact and remediation_impact.status == RemediationPlanStatus.REQUIRES_REPLAN:
            alerts.append(
                SecurityAlert(
                    alert_id=f"alt_{len(alerts)+1}",
                    category=AlertCategory.REMEDIATION_INVALIDATED,
                    severity=AlertSeverity.MEDIUM,
                    title="Active Remediation Plan Invalidated",
                    repository=repository,
                    commit=commit,
                    reason=remediation_impact.reason,
                    evidence=f"Invalidated items: {', '.join(remediation_impact.invalidated_items)}.",
                    affected_files=remediation_impact.affected_files,
                    recommended_action="Re-run M17 Remediation Planner to update target symbol break points.",
                )
            )

        # 7. Reopened Vulnerability Alert
        if reopened_findings:
            alerts.append(
                SecurityAlert(
                    alert_id=f"alt_{len(alerts)+1}",
                    category=AlertCategory.REOPENED_VULNERABILITY,
                    severity=AlertSeverity.HIGH,
                    title="Previously Resolved Vulnerability Reopened",
                    repository=repository,
                    commit=commit,
                    reason=f"{len(reopened_findings)} previously resolved security finding re-introduced.",
                    evidence=f"Root cause: {reopened_findings[0].get('root_cause', 'UNKNOWN')} in {reopened_findings[0].get('affected_file', 'codebase')}.",
                    affected_files=[reopened_findings[0].get("affected_file") or "app/main.py"],
                    affected_findings=[f.get("finding_id") or "f_reopened" for f in reopened_findings],
                    recommended_action="Verify regression test coverage to prevent recurrence of fixed bugs.",
                )
            )

        # 8. Security Score Drop Alert
        if score_delta <= -10 and not any(a.category == AlertCategory.CRITICAL_SECURITY_REGRESSION for a in alerts):
            alerts.append(
                SecurityAlert(
                    alert_id=f"alt_{len(alerts)+1}",
                    category=AlertCategory.SECURITY_SCORE_DROP,
                    severity=AlertSeverity.MEDIUM,
                    title="Security Score Degradation",
                    repository=repository,
                    commit=commit,
                    reason=f"Repository security score dropped by {abs(score_delta)} points.",
                    evidence=f"Score drop delta: {score_delta} pts.",
                    recommended_action="Review recent code diffs to address new security findings.",
                )
            )

        # 9. Clean Scan Info Alert
        if not alerts:
            alerts.append(
                SecurityAlert(
                    alert_id=f"alt_{len(alerts)+1}",
                    category=AlertCategory.NO_REGRESSION,
                    severity=AlertSeverity.INFO,
                    title="Clean Security Scan Pass",
                    repository=repository,
                    commit=commit,
                    reason="No security regressions or new vulnerabilities detected.",
                    evidence="Repository posture remains stable or improving.",
                    recommended_action="No security remediation required.",
                )
            )

        # Sort alerts by severity (CRITICAL > HIGH > MEDIUM > LOW > INFO)
        sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        alerts.sort(key=lambda a: sev_rank.get(a.severity.value if hasattr(a.severity, "value") else str(a.severity), 5))

        return alerts
