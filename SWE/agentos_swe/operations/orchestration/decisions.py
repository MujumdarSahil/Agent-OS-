"""
M20 Action Decision Engine.

Determines the exact deterministic NextActionDecision for a repository based on scan findings,
attack paths, remediation state, monitoring regressions, and release readiness.
"""

from typing import List, Dict, Any, Optional, Tuple
from agentos_swe.operations.orchestration.models import NextActionDecision


class ActionDecisionEngine:
    """
    Evaluates system telemetry to select the optimal NextActionDecision.
    """

    def determine_next_action(
        self,
        verified_findings: List[Dict[str, Any]],
        prioritized_findings: List[Dict[str, Any]],
        attack_paths: List[Dict[str, Any]],
        remediation_plan: Optional[Dict[str, Any]],
        monitoring_result: Optional[Dict[str, Any]],
        release_decision: Optional[Dict[str, Any]],
        remediation_attempts: int = 0,
        human_review_requested: bool = False,
    ) -> Tuple[NextActionDecision, str]:
        """
        Determines next action and explanation string.
        """
        # 1. Bounded Remediation Retry Exceeded
        if remediation_attempts >= 3 or human_review_requested:
            return (
                NextActionDecision.REQUIRE_HUMAN_REVIEW,
                f"Maximum remediation attempts ({remediation_attempts}) exceeded or human review explicitly requested.",
            )

        rel_dec = str((release_decision or {}).get("decision") or "").upper()
        reg_sev = str((monitoring_result or {}).get("regression_severity") or "").upper()

        rem_status = ""
        if remediation_plan and "remediation_impact" in (monitoring_result or {}):
            rem_imp = monitoring_result["remediation_impact"]
            rem_status = str(rem_imp.get("status") if isinstance(rem_imp, dict) else getattr(rem_imp, "status", "")).upper()

        # 2. Release Gate Blocked
        if rel_dec == "BLOCKED":
            return (
                NextActionDecision.BLOCK_RELEASE,
                "Release is BLOCKED by active CRITICAL exploitable vulnerabilities, attack paths, or critical security regressions.",
            )

        # 3. M18 Critical Security Regression
        if "CRITICAL" in reg_sev:
            return (
                NextActionDecision.INVESTIGATE_FINDING,
                "M18 CRITICAL_REGRESSION detected. Immediate vulnerability investigation required.",
            )

        # 4. M17 Remediation Invalidation / Replanning Required
        if rem_status == "REQUIRES_REPLAN":
            return (
                NextActionDecision.REPLAN_REMEDIATION,
                "M17 Remediation Plan invalidated by recent code modifications (REQUIRES_REPLAN). Replanning required.",
            )

        # 5. M19 Release Gate NO_GO
        if rel_dec == "NO_GO":
            return (
                NextActionDecision.CREATE_REMEDIATION_PLAN,
                "Release decision is NO_GO due to HIGH severity vulnerabilities or unresolved P1 remediation items.",
            )

        # 6. M19 Release Gate Review Required
        if rel_dec == "REVIEW_REQUIRED":
            return (
                NextActionDecision.REQUIRE_HUMAN_REVIEW,
                "Release decision is REVIEW_REQUIRED due to remediation conflicts or security score degradation.",
            )

        # 7. Unresolved Attack Paths
        has_exploitable_path = any(
            str(ap.get("classification") or "").upper() == "EXPLOITABLE" and ap.get("risk_score", 0) >= 70
            for ap in attack_paths
        )
        if has_exploitable_path:
            return (
                NextActionDecision.ANALYZE_ATTACK_PATH,
                "Active exploitable attack path detected across trust boundaries.",
            )

        # 8. Unresolved Findings
        has_unresolved_findings = any(
            str(pf.get("severity") or "").upper() in ("CRITICAL", "HIGH")
            and str(pf.get("root_cause") or "").upper() not in ("DICT_LOOKUP", "INFO", "TEST_HARNESS", "INTENTIONAL_FALLBACK")
            for pf in (prioritized_findings or verified_findings)
        )
        if has_unresolved_findings:
            return (
                NextActionDecision.INVESTIGATE_FINDING,
                "Unresolved high-priority findings present requiring root-cause analysis.",
            )

        # 9. Clean Scan / Release Ready GO
        return (
            NextActionDecision.NO_ACTION_REQUIRED,
            "Repository is release-ready. No blocking security risks detected.",
        )
