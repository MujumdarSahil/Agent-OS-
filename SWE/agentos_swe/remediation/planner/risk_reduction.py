"""
M17 Risk Reduction Estimator.

Calculates deterministic current security score (0-100), projected risk reduction per remediation item,
and projected post-fix security score.
"""

from typing import List, Dict, Any, Tuple, Optional
from agentos_swe.remediation.models import RemediationItem


class RiskReductionCalculator:
    """
    Deterministic Risk Reduction and Security Score Calculator.
    """

    def calculate_scores(
        self,
        items: List[RemediationItem],
        findings: Optional[List[Dict[str, Any]]] = None,
        attack_paths: Optional[List[Any]] = None,
    ) -> Tuple[int, int, int]:
        """
        Returns (current_security_score, total_risk_reduction, projected_security_score).
        Scores range from 0 to 100.
        """
        findings = findings or []
        attack_paths = attack_paths or []

        # 1. Base Security Score (Starts at 100, deducted by severity & risk scores)
        total_deductions = 0
        for f in findings:
            rc = str(f.get("root_cause") or "").upper()
            exp = str(f.get("exploitability") or "").upper()
            if exp == "NOT_EXPLOITABLE" or rc in ("DICT_LOOKUP", "INFO", "TEST_HARNESS", "INTENTIONAL_FALLBACK"):
                continue

            sev = str(f.get("severity") or "MEDIUM").upper()
            if sev == "CRITICAL":
                total_deductions += 25
            elif sev == "HIGH":
                total_deductions += 15
            elif sev == "MEDIUM":
                total_deductions += 8
            elif sev == "LOW":
                total_deductions += 3

        for ap in attack_paths:
            cls_val = getattr(ap, "classification", "EXPLOITABLE")
            cls_str = cls_val.value if hasattr(cls_val, "value") else str(cls_val)
            if cls_str == "EXPLOITABLE":
                total_deductions += min(15, getattr(ap, "risk_score", 50) // 5)

        current_score = max(10, min(100, 100 - total_deductions))

        # 2. Total Projected Risk Reduction from Remediation Queue
        total_reduction = 0
        for item in items:
            # High priority / exploitable items eliminate more risk points
            rc = item.root_cause
            if rc in ("COMMAND_INJECTION", "CODE_INJECTION", "SQL_INJECTION"):
                item_reduction = 25
            elif rc in ("SSRF", "PATH_TRAVERSAL", "UNSAFE_DESERIALIZATION"):
                item_reduction = 15
            elif rc == "EXCEPTION_SWALLOWING":
                item_reduction = 8
            else:
                item_reduction = 5

            # Scale reduction if multiple findings/attack paths are eliminated by single item
            extra_scale = max(0, len(item.affected_finding_ids) - 1) * 3 + max(0, len(item.affected_attack_path_ids) - 1) * 4
            item_reduction += extra_scale

            item.projected_risk_reduction = item_reduction
            total_reduction += item_reduction

        projected_score = max(current_score, min(100, current_score + total_reduction))

        # Update item projected post score
        for item in items:
            item.current_risk_score = current_score
            item.projected_post_score = min(100, current_score + item.projected_risk_reduction)

        return current_score, total_reduction, projected_score
