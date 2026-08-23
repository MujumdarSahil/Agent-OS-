"""
M19 Risk-Based Release Policy Engine.

Evaluates multi-factor release policies incorporating severity, exploitability, reachability,
authentication, attack paths, regressions, remediation state, and governance.
"""

from typing import List, Dict, Any, Tuple, Optional
from agentos_swe.release.models import ReleaseDecisionState


class RiskPolicyEngine:
    """
    Evaluates multi-factor risk policies for repository release decision making.
    """

    def evaluate_policy(
        self,
        findings: List[Dict[str, Any]],
        prioritized_findings: List[Dict[str, Any]],
        attack_paths: List[Dict[str, Any]],
        remediation_plan: Optional[Dict[str, Any]],
        monitoring_result: Optional[Dict[str, Any]],
        security_score: int,
        governance_status: str,
    ) -> Tuple[ReleaseDecisionState, List[str]]:
        """
        Evaluates policy rules and returns (ReleaseDecisionState, list_of_policy_triggers).
        """
        triggers: List[str] = []

        # 1. BLOCKED Triggers
        has_critical_exploitable = any(
            (str(f.get("severity") or "").upper() == "CRITICAL" or str(f.get("priority_tier") or "") in ("P0", "PriorityTier.P0"))
            and str(f.get("exploitability") or "").upper() != "NOT_EXPLOITABLE"
            and str(f.get("root_cause") or "").upper() not in ("DICT_LOOKUP", "INFO", "TEST_HARNESS", "INTENTIONAL_FALLBACK")
            for f in (prioritized_findings or findings)
        )

        has_unauth_internet_attack_path = any(
            str(ap.get("classification") or "").upper() == "EXPLOITABLE"
            and str(ap.get("entrypoint_type") or "").upper() == "INTERNET"
            and str(ap.get("auth_status") or "").upper() in ("UNAUTHENTICATED", "UNKNOWN")
            for ap in attack_paths
        )

        mon_dict = monitoring_result.to_dict() if hasattr(monitoring_result, "to_dict") else (monitoring_result if isinstance(monitoring_result, dict) else {})
        monitoring_reg = str(getattr(monitoring_result, "regression_severity", None) or mon_dict.get("regression_severity") or "").upper()
        has_critical_regression = "CRITICAL" in monitoring_reg

        p0_remediations = []
        if remediation_plan and "remediation_items" in remediation_plan:
            p0_remediations = [it for it in remediation_plan["remediation_items"] if str(it.get("priority_tier") or "") == "P0"]

        has_unresolved_p0 = len(p0_remediations) > 0

        has_auth_weakened = False
        changed_paths = getattr(monitoring_result, "changed_attack_paths", None) or mon_dict.get("changed_attack_paths", [])
        if changed_paths:
            has_auth_weakened = any(getattr(cap, "auth_weakened", False) or (isinstance(cap, dict) and cap.get("auth_weakened")) for cap in changed_paths)

        if has_critical_exploitable or has_unauth_internet_attack_path or has_critical_regression or has_unresolved_p0 or has_auth_weakened:
            if has_critical_exploitable:
                triggers.append("Active CRITICAL exploitable vulnerability exists")
            if has_unauth_internet_attack_path:
                triggers.append("Unauthenticated INTERNET → dangerous sink attack path exists")
            if has_critical_regression:
                triggers.append("M18 CRITICAL_REGRESSION detected")
            if has_unresolved_p0:
                triggers.append(f"{len(p0_remediations)} unresolved P0 remediation item(s) present")
            if has_auth_weakened:
                triggers.append("Authentication boundary weakened into an exploitable attack path")

            return ReleaseDecisionState.BLOCKED, triggers

        # 2. NO_GO Triggers
        has_high_exploitable = any(
            (str(f.get("severity") or "").upper() == "HIGH" or str(f.get("priority_tier") or "") in ("P1", "PriorityTier.P1"))
            and str(f.get("exploitability") or "").upper() != "NOT_EXPLOITABLE"
            and str(f.get("root_cause") or "").upper() not in ("DICT_LOOKUP", "INFO", "TEST_HARNESS", "INTENTIONAL_FALLBACK")
            for f in (prioritized_findings or findings)
        )

        p1_remediations = []
        if remediation_plan and "remediation_items" in remediation_plan:
            p1_remediations = [it for it in remediation_plan["remediation_items"] if str(it.get("priority_tier") or "") == "P1"]

        has_unresolved_p1 = len(p1_remediations) > 0
        has_significant_regression = "SIGNIFICANT" in monitoring_reg

        if has_high_exploitable or has_unresolved_p1 or has_significant_regression:
            if has_high_exploitable:
                triggers.append("Active HIGH exploitable vulnerability exists")
            if has_unresolved_p1:
                triggers.append(f"{len(p1_remediations)} unresolved P1 remediation item(s) present")
            if has_significant_regression:
                triggers.append("M18 SIGNIFICANT_REGRESSION detected")

            return ReleaseDecisionState.NO_GO, triggers

        # 3. REVIEW_REQUIRED Triggers
        has_remediation_conflicts = False
        if remediation_plan and remediation_plan.get("conflicts"):
            has_remediation_conflicts = True

        remediation_requires_replan = False
        rem_imp = getattr(monitoring_result, "remediation_impact", None) or mon_dict.get("remediation_impact")
        if rem_imp:
            rem_stat = rem_imp.get("status") if isinstance(rem_imp, dict) else getattr(rem_imp, "status", "")
            if str(rem_stat) == "REQUIRES_REPLAN":
                remediation_requires_replan = True

        has_medium_exploitable = any(
            (str(f.get("severity") or "").upper() == "MEDIUM" or str(f.get("priority_tier") or "") in ("P2", "PriorityTier.P2"))
            and str(f.get("exploitability") or "").upper() != "NOT_EXPLOITABLE"
            and str(f.get("root_cause") or "").upper() not in ("DICT_LOOKUP", "INFO", "TEST_HARNESS", "INTENTIONAL_FALLBACK")
            for f in (prioritized_findings or findings)
        )

        score_delta_val = getattr(monitoring_result, "score_delta", 0) or mon_dict.get("score_delta", 0)
        score_degraded = security_score < 80 or score_delta_val <= -15

        if has_remediation_conflicts or remediation_requires_replan or has_medium_exploitable or score_degraded or governance_status == "REVIEW_REQUIRED":
            if has_remediation_conflicts:
                triggers.append("Remediation strategy conflicts detected across proposed fixes")
            if remediation_requires_replan:
                triggers.append("M17 Remediation Plan is in REQUIRES_REPLAN status")
            if has_medium_exploitable:
                triggers.append("Active MEDIUM exploitable vulnerability requires review")
            if score_degraded:
                triggers.append(f"Security score degraded ({security_score} / 100)")
            if governance_status == "REVIEW_REQUIRED":
                triggers.append("Governance policy requires human security review")

            return ReleaseDecisionState.REVIEW_REQUIRED, triggers

        # 4. GO_WITH_WARNINGS Triggers
        has_non_exploitable_findings = len(findings) > 0 or len(prioritized_findings) > 0

        if has_non_exploitable_findings and security_score < 100:
            triggers.append("Only non-exploitable LOW/MEDIUM findings or minor items remain")
            return ReleaseDecisionState.GO_WITH_WARNINGS, triggers

        # 5. GO Decision
        triggers.append("Zero exploitable findings, zero attack paths, clean remediation, and clean governance")
        return ReleaseDecisionState.GO, triggers
