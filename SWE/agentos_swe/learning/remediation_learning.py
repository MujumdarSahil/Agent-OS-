"""
M25 Remediation Efficacy Learning Engine.

Tracks and aggregates historical repair strategy outcomes per root cause across scan history.
Determines strategy success rates, regression counts, and recommended repair strategies.
"""

from typing import List, Dict, Any, Tuple
from collections import defaultdict

from agentos_swe.learning.models import RemediationLearningRecord, RemediationStatus
from agentos_swe.history.models import ScanRecord


class RemediationLearningEngine:
    """
    Learns repair strategy efficacy per root cause from historical repair executions.
    """

    def analyze_remediation_efficacy(
        self,
        historical_scans: List[ScanRecord],
        finding_memories: List[Dict[str, Any]],
    ) -> List[RemediationLearningRecord]:
        """
        Aggregates repair strategy performance by root cause and strategy name across history.
        """
        # Key: (root_cause, repair_strategy) -> counts dict
        strategy_stats: Dict[Tuple[str, str], Dict[str, int]] = defaultdict(lambda: {
            "success": 0, "failed": 0, "regression": 0, "partial": 0
        })

        for scan in historical_scans:
            validations = getattr(scan, "repair_validations", []) or []
            repairs = getattr(scan, "repair_results", []) or []

            # Map root cause to strategy
            rc_strategy_map = {}
            for r in repairs:
                rc = r.get("root_cause")
                strat = r.get("strategy") or r.get("patch_type") or "AUTOMATED_REPAIR"
                if rc:
                    rc_strategy_map[rc] = strat

            for val in validations:
                rc = val.get("root_cause") or "UNKNOWN"
                strat = val.get("strategy") or rc_strategy_map.get(rc, "AUTOMATED_REPAIR")
                verdict = (val.get("verdict") or val.get("status") or "").upper()

                if verdict in ["PASS", "SUCCESS", "PASSED"]:
                    strategy_stats[(rc, strat)]["success"] += 1
                elif verdict in ["REGRESSION", "REGRESSION_DETECTED"]:
                    strategy_stats[(rc, strat)]["regression"] += 1
                elif verdict in ["PARTIAL", "PARTIALLY_SUCCESSFUL"]:
                    strategy_stats[(rc, strat)]["partial"] += 1
                elif verdict in ["FAIL", "FAILED"]:
                    strategy_stats[(rc, strat)]["failed"] += 1

        for mem in finding_memories:
            rc = mem.get("root_cause") or "UNKNOWN"
            strat = mem.get("previous_remediation") or "AUTOMATED_REPAIR"
            val = (mem.get("repair_validation_result") or "").upper()
            reg = (mem.get("security_regression_result") or "").upper()

            if strat != "NONE" and (val != "NOT_TESTED" or reg != "NO_REGRESSION"):
                if val in ["PASS", "SUCCESS"]:
                    strategy_stats[(rc, strat)]["success"] += 1
                elif reg in ["REGRESSION", "REGRESSION_DETECTED"]:
                    strategy_stats[(rc, strat)]["regression"] += 1
                elif val in ["FAIL", "FAILED"]:
                    strategy_stats[(rc, strat)]["failed"] += 1

        records: List[RemediationLearningRecord] = []

        for (rc, strat), stats in strategy_stats.items():
            succ = stats["success"]
            fail = stats["failed"]
            reg = stats["regression"]
            total = succ + fail + reg

            if total > 0:
                success_rate = round(succ / total, 2)
            else:
                success_rate = 0.0

            if reg > 0 and reg >= succ:
                status = RemediationStatus.REGRESSION
            elif fail > 0 and succ == 0:
                status = RemediationStatus.FAILED
            elif stats["partial"] > 0 or (succ > 0 and fail > 0):
                status = RemediationStatus.PARTIALLY_SUCCESSFUL
            elif succ > 0:
                status = RemediationStatus.SUCCESSFUL
            else:
                status = RemediationStatus.NOT_ATTEMPTED

            records.append(
                RemediationLearningRecord(
                    root_cause=rc,
                    repair_strategy=strat,
                    status=status,
                    successful_repairs=succ,
                    failed_repairs=fail,
                    regressions=reg,
                    success_rate=success_rate,
                )
            )

        return records

    def get_best_strategy_for_root_cause(
        self,
        records: List[RemediationLearningRecord],
        root_cause: str,
    ) -> Tuple[str, float]:
        """
        Returns the historically most successful repair strategy for a given root cause.
        """
        matching = [r for r in records if r.root_cause == root_cause and r.success_rate > 0.0]
        if not matching:
            return ("DEFAULT_REPAIR", 0.5)

        best = max(matching, key=lambda r: (r.success_rate, r.successful_repairs))
        return (best.repair_strategy, best.success_rate)
