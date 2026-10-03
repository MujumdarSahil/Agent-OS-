"""
M25 Vulnerability Recurrence Analyzer.

Calculates recurrence metrics (fix duration, reopen counts, persistence) and classifies
vulnerability lifecycle patterns into FIRST_SEEN, OCCASIONAL, RECURRING, PERSISTENT, or CHRONIC.
"""

from typing import List, Dict, Any
from datetime import datetime

from agentos_swe.intelligence.learning.models import FindingRecurrence, RecurrenceClassification


class RecurrenceAnalyzer:
    """
    Analyzes vulnerability recurrence, persistence duration, and repair attempt histories.
    """

    def analyze_recurrence(self, finding_memories: List[Dict[str, Any]]) -> List[FindingRecurrence]:
        """
        Processes historical finding memories and computes FindingRecurrence metrics.
        """
        results: List[FindingRecurrence] = []

        for mem in finding_memories:
            fp = mem.get("fingerprint", "")
            rc = mem.get("root_cause", "UNKNOWN")
            file_path = mem.get("file", "")
            rec_count = mem.get("recurrence_count", 1)
            reopen_count = mem.get("reopened_count", 0)

            val_res = mem.get("repair_validation_result", "")
            failed_repairs = 1 if val_res in ["FAIL", "FAILED", "REGRESSION"] else 0
            succ_repairs = 1 if val_res in ["PASS", "SUCCESS", "PASSED"] else 0

            # Persistence duration calculation
            first_seen_str = mem.get("first_seen")
            last_seen_str = mem.get("last_seen")
            persistence_days = 0.0

            if first_seen_str and last_seen_str:
                try:
                    dt1 = datetime.fromisoformat(first_seen_str)
                    dt2 = datetime.fromisoformat(last_seen_str)
                    persistence_days = round((dt2 - dt1).total_seconds() / 86400.0, 2)
                except Exception:
                    persistence_days = len(mem.get("scan_occurrences", [1])) * 1.0

            # Classification logic
            if reopen_count >= 2 or (rec_count >= 3 and failed_repairs >= 2):
                classification = RecurrenceClassification.CHRONIC
            elif rec_count >= 5 or persistence_days >= 30.0:
                classification = RecurrenceClassification.PERSISTENT
            elif rec_count in [3, 4]:
                classification = RecurrenceClassification.RECURRING
            elif rec_count == 2:
                classification = RecurrenceClassification.OCCASIONAL
            else:
                classification = RecurrenceClassification.FIRST_SEEN

            avg_fix = round(persistence_days / succ_repairs, 2) if succ_repairs > 0 else 0.0
            avg_reopen = round(persistence_days / reopen_count, 2) if reopen_count > 0 else 0.0

            results.append(
                FindingRecurrence(
                    fingerprint=fp,
                    root_cause=rc,
                    file=file_path,
                    recurrence_count=rec_count,
                    reopen_count=reopen_count,
                    persistence_duration=persistence_days,
                    average_time_to_fix=avg_fix,
                    average_time_to_reopen=avg_reopen,
                    failed_repair_count=failed_repairs,
                    successful_repair_count=succ_repairs,
                    classification=classification,
                )
            )

        return results
