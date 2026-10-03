"""
RiskAnalyzer - Deterministic risk scoring and classification for AgentOS-SWE (M5).
"""

import logging
from typing import List, Dict, Any, Optional

from agentos_swe.core.models import Finding
from agentos_swe.remediation.repair.models import ValidatedPatch, ImpactReport
from agentos_swe.remediation.pr.models import RiskLevel, RiskAssessment

logger = logging.getLogger(__name__)

SECURITY_SENSITIVE_KEYWORDS = {
    "auth", "login", "password", "secret", "token", "credential",
    "security", "crypto", "perm", "permission", "db", "config", "eval", "exec", "subshell",
}


class RiskAnalyzer:
    """
    Evaluates deterministic risk signals for a validated patch.
    """

    def analyze_risk(self, finding: Finding, patch: ValidatedPatch) -> RiskAssessment:
        risk_score = 0.0
        risk_signals: List[str] = []

        changed_files = patch.changed_files
        impact: ImpactReport = patch.impact_report

        # 1. Changed Files Count
        if len(changed_files) > 3:
            risk_score += 30.0
            risk_signals.append(f"Multiple files modified ({len(changed_files)} files).")

        # 2. Changed Lines Count
        diff_lines = patch.patch_diff.splitlines()
        added_count = len([l for l in diff_lines if l.startswith("+") and not l.startswith("+++")])
        removed_count = len([l for l in diff_lines if l.startswith("-") and not l.startswith("---")])
        total_line_changes = added_count + removed_count

        if total_line_changes > 50:
            risk_score += 40.0
            risk_signals.append(f"Large line change volume (+{added_count} / -{removed_count} lines).")
        elif total_line_changes > 20:
            risk_score += 15.0

        # 3. Security Sensitive Keyword Check
        for f in changed_files:
            f_lower = f.lower()
            for kw in SECURITY_SENSITIVE_KEYWORDS:
                if kw in f_lower:
                    risk_score += 25.0
                    risk_signals.append(f"Security-sensitive file modified: '{f}' (matches '{kw}').")
                    break

        # 4. Finding Severity
        sev = (finding.severity or "medium").lower()
        if sev == "critical":
            risk_score += 35.0
            risk_signals.append("Finding severity is CRITICAL.")
        elif sev == "high":
            risk_score += 20.0
            risk_signals.append("Finding severity is HIGH.")

        # 5. Blast Radius (Callers & Dependents)
        if len(impact.callers) > 5:
            risk_score += 20.0
            risk_signals.append(f"High caller fan-in ({len(impact.callers)} callers).")
        if len(impact.dependents) > 5:
            risk_score += 20.0
            risk_signals.append(f"High dependent fan-out ({len(impact.dependents)} dependents).")

        # Classification Level Matrix
        if risk_score >= 60.0 or sev == "critical":
            level = RiskLevel.CRITICAL if risk_score >= 80.0 else RiskLevel.HIGH
        elif risk_score >= 30.0 or sev == "high":
            level = RiskLevel.MEDIUM
        else:
            level = RiskLevel.LOW

        summary = f"Risk Assessment: {level.value} (Score: {risk_score:.1f}) based on {len(risk_signals)} risk signals."

        return RiskAssessment(
            finding_id=finding.id,
            risk_level=level,
            risk_score=risk_score,
            risk_signals=risk_signals,
            summary=summary,
        )
