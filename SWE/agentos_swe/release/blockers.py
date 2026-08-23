"""
M19 Release Blocker Identification Engine.

Extracts specific, actionable ReleaseBlocker objects from security findings, attack paths, and remediation plans.
"""

from typing import List, Dict, Any, Optional
from agentos_swe.release.models import ReleaseBlocker


class BlockerEngine:
    """
    Identifies specific conditions blocking or preventing repository release.
    """

    def identify_blockers(
        self,
        prioritized_findings: List[Dict[str, Any]],
        attack_paths: List[Dict[str, Any]],
        remediation_plan: Optional[Dict[str, Any]],
        monitoring_result: Optional[Dict[str, Any]],
    ) -> List[ReleaseBlocker]:
        """
        Builds a list of ReleaseBlocker objects detailing blocking security items.
        """
        blockers: List[ReleaseBlocker] = []

        # 1. Blocking Findings (CRITICAL / HIGH / P0 / P1)
        for pf in prioritized_findings:
            fid = pf.get("finding_id") or pf.get("id") or "f_1"
            sev = str(pf.get("severity") or "MEDIUM").upper()
            tier = str(pf.get("priority_tier") or "P3").replace("PriorityTier.", "")
            rc = pf.get("root_cause") or pf.get("category") or "UNKNOWN"
            aff_file = pf.get("affected_file") or pf.get("file") or "N/A"
            aff_func = pf.get("affected_function") or "main"
            exploitability = str(pf.get("exploitability") or "").upper()

            if rc in ("DICT_LOOKUP", "INFO", "TEST_HARNESS", "INTENTIONAL_FALLBACK") or exploitability == "NOT_EXPLOITABLE":
                continue

            if sev in ("CRITICAL", "HIGH") or tier in ("P0", "P1"):
                blockers.append(
                    ReleaseBlocker(
                        blocker_id=f"blk_{len(blockers)+1}",
                        severity=sev,
                        category=rc,
                        title=f"Blocking Vulnerability ({rc.replace('_', ' ').title()})",
                        file=aff_file,
                        line=pf.get("line") or 1,
                        finding_id=fid,
                        reason=f"{sev} severity {rc} vulnerability in {aff_file}:{aff_func}.",
                        evidence=str(pf.get("why_this_matters") or pf.get("code_context") or "Exploitable vulnerability detected."),
                        recommended_action=str(pf.get("recommended_action") or "Apply defensive input validation and argument-array execution."),
                    )
                )

        # 2. Blocking Attack Paths (EXPLOITABLE & Risk Score >= 70)
        for ap in attack_paths:
            ap_id = ap.get("id", "ap_1")
            cls_type = str(ap.get("classification") or "").upper()
            score = ap.get("risk_score", 0)
            rc = ap.get("root_cause", "UNKNOWN")
            src_file = ap.get("source_file", "app/main.py")
            entrypoint = ap.get("entrypoint", "INTERNET")
            auth = str(ap.get("auth_status") or "").upper()

            if cls_type == "EXPLOITABLE" and score >= 70:
                blockers.append(
                    ReleaseBlocker(
                        blocker_id=f"blk_{len(blockers)+1}",
                        severity="CRITICAL" if score >= 85 else "HIGH",
                        category="ATTACK_PATH",
                        title=f"Exploitable Attack Path ({entrypoint} → {ap.get('sink_type', 'Sink')})",
                        file=src_file,
                        line=ap.get("source_line") or 1,
                        attack_path_id=ap_id,
                        reason=f"Active {auth} attack path from {entrypoint} to {ap.get('sink_type')} sink.",
                        evidence=f"Path Risk Score: {score}/100. Entrypoint: {entrypoint}.",
                        recommended_action=str(ap.get("repair_strategy") or "Replace shell execution / unsanitized sink with safe interface."),
                    )
                )

        # 3. Blocking Remediation Items (P0 Items)
        if remediation_plan and "remediation_items" in remediation_plan:
            for item in remediation_plan["remediation_items"]:
                iid = item.get("item_id", "rem_1")
                tier = str(item.get("priority_tier") or "P2")
                if tier == "P0":
                    blockers.append(
                        ReleaseBlocker(
                            blocker_id=f"blk_{len(blockers)+1}",
                            severity="CRITICAL",
                            category="REMEDIATION_ITEM",
                            title=f"Unresolved P0 Remediation Item ({iid})",
                            file=", ".join(item.get("affected_files", [])) or "app/main.py",
                            remediation_id=iid,
                            reason=f"Top-priority P0 remediation item '{item.get('title')}' remains un-executed.",
                            evidence=f"Earliest break point: {item.get('earliest_break_point')}.",
                            recommended_action=str(item.get("recommended_fix") or "Execute sandboxed remediation patch."),
                        )
                    )

        # 4. Blocking Regressions (M18 CRITICAL_REGRESSION)
        if monitoring_result:
            mon_dict = monitoring_result.to_dict() if hasattr(monitoring_result, "to_dict") else (monitoring_result if isinstance(monitoring_result, dict) else {})
            reg_sev = str(getattr(monitoring_result, "regression_severity", None) or mon_dict.get("regression_severity") or "").upper()
            if "CRITICAL" in reg_sev:
                repo_val = getattr(monitoring_result, "repository", None) or mon_dict.get("repository", "repository")
                expl_val = getattr(monitoring_result, "summary_explanation", None) or mon_dict.get("summary_explanation") or "Security score or vulnerability regression detected."
                blockers.append(
                    ReleaseBlocker(
                        blocker_id=f"blk_{len(blockers)+1}",
                        severity="CRITICAL",
                        category="SECURITY_REGRESSION",
                        title="Critical Security Regression",
                        file=repo_val,
                        reason=str(expl_val),
                        evidence=f"Regression Severity: {reg_sev}.",
                        recommended_action="Revert recent regressive commit or apply hotfix before release.",
                    )
                )

        return blockers
