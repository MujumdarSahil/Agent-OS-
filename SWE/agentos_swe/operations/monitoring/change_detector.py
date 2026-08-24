"""
M18 Change Detector for Security Telemetry.

Analyzes delta between baseline and current security scans including finding lifecycle transitions,
attack path structural shifts (auth weakening, exposure broadening), and M17 remediation plan validity.
"""

from typing import List, Dict, Any, Tuple, Optional
from agentos_swe.operations.monitoring.models import (
    AttackPathChange,
    AttackPathChangeType,
    RemediationImpact,
    RemediationPlanStatus,
    SecurityChangeImpact,
)
from agentos_swe.intelligence.history.fingerprint import FindingFingerprinter


class ChangeDetector:
    """
    Detects structural and security posture changes across commits.
    """

    def __init__(self):
        self.fingerprinter = FindingFingerprinter()

    def detect_finding_changes(
        self,
        current_findings: List[Dict[str, Any]],
        previous_findings: List[Dict[str, Any]],
        history_comparator: Optional[Any] = None,
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Diffs findings to detect new, fixed, unchanged, and reopened vulnerabilities.
        """
        curr_map = {self.fingerprinter.compute_fingerprint(f): f for f in current_findings}
        prev_map = {self.fingerprinter.compute_fingerprint(f): f for f in previous_findings}

        curr_fps = set(curr_map.keys())
        prev_fps = set(prev_map.keys())

        new_fps = curr_fps - prev_fps
        fixed_fps = prev_fps - curr_fps
        unchanged_fps = curr_fps & prev_fps

        new_findings = [curr_map[fp] for fp in new_fps]
        fixed_findings = [prev_map[fp] for fp in fixed_fps]
        unchanged_findings = [curr_map[fp] for fp in unchanged_fps]

        # Reopened findings (findings previously resolved in history that re-appeared)
        reopened_findings = []
        if history_comparator and hasattr(history_comparator, "comparison"):
            reopened_findings = getattr(history_comparator.comparison, "reopened_findings", [])
        else:
            for f in new_findings:
                if str(f.get("recurrence") or "").upper() == "REOPENED":
                    reopened_findings.append(f)

        return new_findings, fixed_findings, unchanged_findings, reopened_findings

    def detect_attack_path_changes(
        self,
        current_paths: List[Any],
        previous_paths: List[Any],
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[AttackPathChange]]:
        """
        Compares M16 attack paths between scans to detect new, removed, or structurally altered paths.
        """
        curr_dict_map = {}
        for ap in current_paths:
            ap_dict = ap.to_dict() if hasattr(ap, "to_dict") else ap
            fp = ap_dict.get("fingerprint") or f"{ap_dict.get('source_file')}:{ap_dict.get('sink_type')}"
            curr_dict_map[fp] = ap_dict

        prev_dict_map = {}
        for ap in previous_paths:
            ap_dict = ap.to_dict() if hasattr(ap, "to_dict") else ap
            fp = ap_dict.get("fingerprint") or f"{ap_dict.get('source_file')}:{ap_dict.get('sink_type')}"
            prev_dict_map[fp] = ap_dict

        new_fps = set(curr_dict_map.keys()) - set(prev_dict_map.keys())
        removed_fps = set(prev_dict_map.keys()) - set(curr_dict_map.keys())
        common_fps = set(curr_dict_map.keys()) & set(prev_dict_map.keys())

        new_paths = [curr_dict_map[fp] for fp in new_fps]
        removed_paths = [prev_dict_map[fp] for fp in removed_fps]
        changed_changes: List[AttackPathChange] = []

        # Process new attack paths as changes
        for fp in new_fps:
            ap = curr_dict_map[fp]
            changed_changes.append(
                AttackPathChange(
                    path_id=ap.get("id", "ap_new"),
                    change_type=AttackPathChangeType.NEW_ATTACK_PATH,
                    description=f"New exploitable attack path detected: {ap.get('entrypoint', 'Internal')} → {ap.get('sink_type', 'Sink')}",
                    current_risk_score=ap.get("risk_score", 70),
                    auth_weakened=str(ap.get("auth_status") or "").upper() == "UNAUTHENTICATED",
                    exposure_increased=str(ap.get("entrypoint_type") or "").upper() == "INTERNET",
                    affected_file=ap.get("source_file", ""),
                    root_cause=ap.get("root_cause", "UNKNOWN"),
                )
            )

        # Process common attack paths for structural changes
        for fp in common_fps:
            curr_ap = curr_dict_map[fp]
            prev_ap = prev_dict_map[fp]

            curr_auth = str(curr_ap.get("auth_status") or "").upper()
            prev_auth = str(prev_ap.get("auth_status") or "").upper()
            auth_weakened = (prev_auth == "AUTHENTICATED" and curr_auth == "UNAUTHENTICATED")

            curr_exp = str(curr_ap.get("entrypoint_type") or "").upper()
            prev_exp = str(prev_ap.get("entrypoint_type") or "").upper()
            exp_increased = (prev_exp != "INTERNET" and curr_exp == "INTERNET")

            risk_delta = curr_ap.get("risk_score", 0) - prev_ap.get("risk_score", 0)

            if auth_weakened or exp_increased or abs(risk_delta) > 5:
                desc_parts = []
                if auth_weakened:
                    desc_parts.append("Authentication boundary weakened (AUTHENTICATED → UNAUTHENTICATED)")
                if exp_increased:
                    desc_parts.append("Exposure increased to INTERNET")
                if risk_delta > 0:
                    desc_parts.append(f"Risk score increased (+{risk_delta} pts)")

                changed_changes.append(
                    AttackPathChange(
                        path_id=curr_ap.get("id", "ap_mod"),
                        change_type=AttackPathChangeType.MODIFIED_ATTACK_PATH,
                        description="; ".join(desc_parts) or "Attack path modified",
                        previous_risk_score=prev_ap.get("risk_score", 0),
                        current_risk_score=curr_ap.get("risk_score", 0),
                        auth_weakened=auth_weakened,
                        exposure_increased=exp_increased,
                        affected_file=curr_ap.get("source_file", ""),
                        root_cause=curr_ap.get("root_cause", "UNKNOWN"),
                    )
                )

        return new_paths, removed_paths, changed_changes

    def evaluate_remediation_impact(
        self,
        remediation_plan: Optional[Any],
        changed_files: List[str],
        new_findings: List[Dict[str, Any]],
    ) -> RemediationImpact:
        """
        Evaluates whether an active M17 Remediation Plan has been invalidated by recent code changes.
        """
        if not remediation_plan or not getattr(remediation_plan, "remediation_items", []):
            return RemediationImpact(
                plan_id="plan_none",
                status=RemediationPlanStatus.VALID,
                reason="No active remediation plan required.",
            )

        plan_dict = remediation_plan.to_dict() if hasattr(remediation_plan, "to_dict") else remediation_plan
        plan_id = plan_dict.get("plan_id", "plan_active")
        items = plan_dict.get("remediation_items", [])

        invalidated_items = []
        affected_files_set = set()

        for item in items:
            iid = item.get("item_id", "rem_#")
            item_files = item.get("affected_files", [])
            item_rc = item.get("root_cause", "")

            # Check if code change touches remediation item target file
            for cf in changed_files:
                if any(cf.endswith(ifile) or ifile.endswith(cf) for ifile in item_files):
                    invalidated_items.append(iid)
                    affected_files_set.add(cf)

            # Check if new critical finding occurred in same file
            for nf in new_findings:
                nf_file = nf.get("affected_file") or nf.get("file") or ""
                if any(nf_file.endswith(ifile) or ifile.endswith(nf_file) for ifile in item_files):
                    if iid not in invalidated_items:
                        invalidated_items.append(iid)
                        affected_files_set.add(nf_file)

        if invalidated_items:
            return RemediationImpact(
                plan_id=plan_id,
                status=RemediationPlanStatus.REQUIRES_REPLAN,
                reason=f"Target remediation helper/file altered in code diff for {len(invalidated_items)} item(s). Replanning required.",
                invalidated_items=invalidated_items,
                affected_files=list(affected_files_set),
            )

        return RemediationImpact(
            plan_id=plan_id,
            status=RemediationPlanStatus.VALID,
            reason="Remediation plan remains valid across recent code changes.",
        )
