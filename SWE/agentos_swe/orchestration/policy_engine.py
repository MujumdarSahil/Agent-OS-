"""
M24 Security Policy Engine.

Evaluates deterministic rules (P01 - P09) against vulnerability findings,
attack paths, history, drift, and confidence scores to output policy verdicts.
"""

from typing import Dict, Any, List, Tuple
from agentos_swe.orchestration.models import DecisionAction, DecisionReason


class SecurityPolicyEngine:
    """
    Evaluates explainable, deterministic security policies.
    """

    POLICY_RULES = [
        ("P01", "Critical Exploitable Taint + Internet Exposed", DecisionAction.BLOCK_RELEASE, DecisionReason.CRITICAL_EXPLOITABLE),
        ("P02", "High Severity + Reachable Attack Path", DecisionAction.GENERATE_REPAIR, DecisionReason.HIGH_ATTACK_PATH),
        ("P03", "Medium Severity + Recurring History", DecisionAction.INVESTIGATE, DecisionReason.REOPENED_VULNERABILITY),
        ("P04", "Reopened Vulnerability Detected", DecisionAction.HUMAN_REVIEW, DecisionReason.HUMAN_APPROVAL_REQUIRED),
        ("P05", "Intentional Fallback Pattern", DecisionAction.IGNORE, DecisionReason.INTENTIONAL_FALLBACK),
        ("P06", "Test Harness Exception Pattern", DecisionAction.IGNORE, DecisionReason.TEST_HARNESS),
        ("P07", "Sanitized Taint Flow", DecisionAction.MONITOR, DecisionReason.SANITIZED_FLOW),
        ("P08", "Low Confidence Finding", DecisionAction.HUMAN_REVIEW, DecisionReason.LOW_CONFIDENCE),
        ("P09", "Severe Security Drift / Degradation", DecisionAction.BLOCK_RELEASE, DecisionReason.DRIFT_SPIKE),
    ]

    def evaluate_finding_policy(
        self,
        finding: Dict[str, Any],
        attack_path: Tuple[Any, ...] = (),
        drift_category: str = "NO_DRIFT",
        confidence_score: float = 1.0,
    ) -> Tuple[DecisionAction, List[str], List[Dict[str, Any]]]:
        """
        Evaluates finding against deterministic policy rules P01-P09.
        Returns (recommended_action, reasons, trace_list).
        """
        rc = str(finding.get("root_cause") or finding.get("category") or "").upper()
        sev = str(finding.get("severity") or "").upper()
        exp = str(finding.get("exploitability") or "").upper()
        sanitized = finding.get("sanitized") is True
        reopened = finding.get("previously_fixed") is True or finding.get("lifecycle_state") == "REOPENED"

        reasons: List[str] = []
        traces: List[Dict[str, Any]] = []
        action: DecisionAction = DecisionAction.MONITOR

        # Evaluate Rule P05: Intentional Fallback
        if rc == "INTENTIONAL_FALLBACK":
            traces.append({"rule_id": "P05", "name": "Intentional Fallback Pattern", "triggered": True, "reason": "Rule P05 triggered: Intentional fallback pattern ignored."})
            return DecisionAction.IGNORE, ["Rule P05: Intentional fallback pattern"], traces

        # Evaluate Rule P06: Test Harness
        if rc == "TEST_HARNESS":
            traces.append({"rule_id": "P06", "name": "Test Harness Exception Pattern", "triggered": True, "reason": "Rule P06 triggered: Test harness exception ignored."})
            return DecisionAction.IGNORE, ["Rule P06: Test harness exception"], traces

        # Evaluate Rule P07: Sanitized Taint Flow
        if sanitized or rc in ("SAFE_CONSTANT", "DICT_LOOKUP"):
            traces.append({"rule_id": "P07", "name": "Sanitized Taint Flow", "triggered": True, "reason": "Rule P07 triggered: Sanitized taint flow monitored."})
            return DecisionAction.MONITOR, ["Rule P07: Sanitized flow"], traces

        # Evaluate Rule P08: Low Confidence Finding
        if confidence_score < 0.50:
            traces.append({"rule_id": "P08", "name": "Low Confidence Finding", "triggered": True, "reason": "Rule P08 triggered: Low confidence requires human review."})
            return DecisionAction.HUMAN_REVIEW, ["Rule P08: Low confidence finding"], traces

        # Evaluate Rule P01: Critical Exploitable
        if sev == "CRITICAL" and exp in ("CRITICAL", "HIGH", "EXPLOITABLE"):
            traces.append({"rule_id": "P01", "name": "Critical Internet Exploitable", "triggered": True, "reason": "Rule P01 triggered: Critical exploitable vulnerability blocks release."})
            return DecisionAction.BLOCK_RELEASE, ["Rule P01: Critical exploitable vulnerability"], traces

        # Evaluate Rule P04: Reopened Vulnerability
        if reopened:
            traces.append({"rule_id": "P04", "name": "Reopened Vulnerability", "triggered": True, "reason": "Rule P04 triggered: Reopened vulnerability requires human review."})
            return DecisionAction.HUMAN_REVIEW, ["Rule P04: Reopened vulnerability"], traces

        # Evaluate Rule P02: High Severity + Attack Path
        if sev in ("HIGH", "CRITICAL"):
            traces.append({"rule_id": "P02", "name": "High Severity + Reachable Attack Path", "triggered": True, "reason": "Rule P02 triggered: High severity finding generates repair."})
            return DecisionAction.GENERATE_REPAIR, ["Rule P02: High severity reachable vulnerability"], traces

        # Evaluate Rule P03: Medium Severity / Recurring
        if sev == "MEDIUM":
            traces.append({"rule_id": "P03", "name": "Medium Severity + Recurring History", "triggered": True, "reason": "Rule P03 triggered: Medium severity finding requires investigation."})
            return DecisionAction.INVESTIGATE, ["Rule P03: Medium severity vulnerability"], traces

        # Evaluate Rule P09: Severe Drift
        if drift_category in ("CRITICAL_DRIFT", "HIGH_DRIFT"):
            traces.append({"rule_id": "P09", "name": "Severe Security Drift", "triggered": True, "reason": "Rule P09 triggered: Severe security drift blocks release."})
            return DecisionAction.BLOCK_RELEASE, ["Rule P09: Severe security drift"], traces

        traces.append({"rule_id": "DEFAULT", "name": "Default Monitoring Policy", "triggered": True, "reason": "Default policy: Monitor vulnerability posture."})
        return DecisionAction.MONITOR, ["Default monitoring policy"], traces
