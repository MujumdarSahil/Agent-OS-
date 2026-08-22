"""
M19 Explainable Evidence Chain Builder.

Assembles step-by-step explainable evidence chains supporting release decisions.
"""

from typing import List, Dict, Any, Optional
from agentos_swe.release.models import DecisionEvidence, ReleaseDecisionState


class EvidenceChainBuilder:
    """
    Builds structured, explainable evidence chains supporting release readiness verdicts.
    """

    def build_evidence_chain(
        self,
        decision_state: ReleaseDecisionState,
        policy_triggers: List[str],
        findings: List[Dict[str, Any]],
        attack_paths: List[Dict[str, Any]],
        remediation_plan: Optional[Dict[str, Any]],
        monitoring_result: Optional[Dict[str, Any]],
    ) -> List[DecisionEvidence]:
        """
        Constructs an ordered list of DecisionEvidence entries explaining the release decision.
        """
        chain: List[DecisionEvidence] = []

        # 1. Primary Policy Trigger Evidence
        for idx, trigger in enumerate(policy_triggers, 1):
            chain.append(
                DecisionEvidence(
                    evidence_id=f"ev_trig_{idx}",
                    policy_rule=f"Policy Rule #{idx}: {trigger}",
                    evidence_text=f"Release evaluation resulted in state `{decision_state.value}` because: {trigger}.",
                    validation_status="VERIFIED",
                )
            )

        # 2. Finding Evidence
        for f in findings[:3]:
            fid = f.get("finding_id") or f.get("id") or "f_1"
            rc = f.get("root_cause") or f.get("category") or "UNKNOWN"
            sev = f.get("severity", "MEDIUM")
            aff = f.get("affected_file") or f.get("file") or "N/A"

            if rc in ("DICT_LOOKUP", "INFO", "TEST_HARNESS", "INTENTIONAL_FALLBACK"):
                continue

            chain.append(
                DecisionEvidence(
                    evidence_id=f"ev_find_{len(chain)+1}",
                    policy_rule=f"Vulnerability Analysis ({rc})",
                    finding_id=fid,
                    evidence_text=f"Finding '{fid}' ({sev} {rc}) detected in {aff}.",
                    validation_status="CONFIRMED_TRUE_POSITIVE",
                )
            )

        # 3. Attack Path Evidence
        for ap in attack_paths[:2]:
            ap_id = ap.get("id", "ap_1")
            ep = ap.get("entrypoint", "INTERNET")
            sink = ap.get("sink_type", "Sink")
            score = ap.get("risk_score", 0)

            chain.append(
                DecisionEvidence(
                    evidence_id=f"ev_path_{len(chain)+1}",
                    policy_rule="Attack Path Discovery (M16)",
                    attack_path_id=ap_id,
                    evidence_text=f"Attack path '{ap_id}' ({ep} → {sink}, Risk Score: {score}/100) exposes sink to untrusted input.",
                    validation_status="EXPLOITABLE_PATH",
                )
            )

        # 4. Monitoring & Regression Evidence
        if monitoring_result:
            reg_sev = str(monitoring_result.get("regression_severity") or "NO_REGRESSION")
            chain.append(
                DecisionEvidence(
                    evidence_id=f"ev_mon_{len(chain)+1}",
                    policy_rule="Continuous Security Monitoring (M18)",
                    historical_context=f"Regression Severity: {reg_sev}, Risk Trend: {monitoring_result.get('risk_trend', 'STABLE')}.",
                    evidence_text=str(monitoring_result.get("summary_explanation") or "Security posture monitored across commits."),
                    validation_status="MONITORED",
                )
            )

        # 5. Remediation Plan Evidence
        if remediation_plan and "remediation_items" in remediation_plan:
            items = remediation_plan["remediation_items"]
            if items:
                top_item = items[0]
                chain.append(
                    DecisionEvidence(
                        evidence_id=f"ev_rem_{len(chain)+1}",
                        policy_rule="Remediation Plan (M17)",
                        remediation_id=top_item.get("item_id"),
                        evidence_text=f"Remediation item '{top_item.get('item_id')}' requires '{top_item.get('repair_strategy')}' at break point '{top_item.get('earliest_break_point')}'.",
                        validation_status=top_item.get("governance_status", "READY_FOR_REVIEW"),
                    )
                )

        return chain
