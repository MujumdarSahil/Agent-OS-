"""
M23 Security Alert Engine.

Generates structured, actionable security alerts for critical drift events.
"""

import uuid
from typing import List, Dict, Any, Optional
from agentos_swe.operations.monitoring.models import SecurityDrift, SecurityAlert


class SecurityAlertEngine:
    """
    Generates actionable security alerts from security drift.
    """

    def generate_alerts(
        self,
        drift: SecurityDrift,
        repository_name: str,
        commit_sha: str,
    ) -> List[SecurityAlert]:
        """
        Creates SecurityAlert payloads based on drift analysis.
        """
        alerts: List[SecurityAlert] = []

        if drift.new_findings:
            crit_new = [f for f in drift.new_findings if str(f.get("severity", "")).upper() == "CRITICAL"]
            if crit_new:
                alerts.append(
                    SecurityAlert(
                        alert_id=f"alt_{uuid.uuid4().hex[:8]}",
                        alert_type="CRITICAL_VULNERABILITY_INTRODUCED",
                        severity="CRITICAL",
                        repository=repository_name,
                        commit_sha=commit_sha,
                        title=f"{len(crit_new)} Critical Vulnerability Introduced",
                        evidence=[f"Finding ID: {f.get('finding_id', '1')}" for f in crit_new],
                        recommended_action="Block release and run immediate remediation.",
                    )
                )

        if drift.new_attack_paths:
            alerts.append(
                SecurityAlert(
                    alert_id=f"alt_{uuid.uuid4().hex[:8]}",
                    alert_type="ATTACK_PATH_INTRODUCED",
                    severity="HIGH",
                    repository=repository_name,
                    commit_sha=commit_sha,
                    title=f"{len(drift.new_attack_paths)} New Attack Path Discovered",
                    evidence=[f"Path: {ap.get('entrypoint', 'N/A')} -> {ap.get('sink', 'N/A')}" for ap in drift.new_attack_paths],
                    recommended_action="Review trust boundary transitions and add input validation.",
                )
            )

        if drift.reopened_findings:
            alerts.append(
                SecurityAlert(
                    alert_id=f"alt_{uuid.uuid4().hex[:8]}",
                    alert_type="FINDING_REOPENED",
                    severity="HIGH",
                    repository=repository_name,
                    commit_sha=commit_sha,
                    title=f"{len(drift.reopened_findings)} Reopened Vulnerability Detected",
                    evidence=[f"Reopened ID: {rf.get('finding_id', '1')}" for rf in drift.reopened_findings],
                    recommended_action="Verify historical fix pattern and enforce regression test.",
                )
            )

        return alerts
