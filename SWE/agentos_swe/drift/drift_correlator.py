"""
M26 Security Drift Correlator.

Cross-correlates drift events with M14 lifecycle, M15 priorities, M16 attack paths,
M24 orchestration decisions, and M25 learning patterns.
"""

from typing import List, Dict, Any, Optional

from agentos_swe.drift.models import SecurityDriftEvent, DriftSeverity, DriftType


class SecurityDriftCorrelator:
    """
    Correlates security drift events across all preceding AgentOS-SWE intelligence layers.
    """

    def correlate_drift_events(
        self,
        events: List[SecurityDriftEvent],
        historical_memories: Optional[List[Dict[str, Any]]] = None,
        learning_patterns: Optional[List[Any]] = None,
        orchestration_result: Optional[Any] = None,
    ) -> List[SecurityDriftEvent]:
        """
        Enriches and correlates drift events with historical, attack-path, and learning signals.
        """
        correlated: List[SecurityDriftEvent] = []

        mem_map = {m.get("fingerprint"): m for m in (historical_memories or []) if m.get("fingerprint")}

        for e in events:
            fp = e.fingerprint
            if fp and fp in mem_map:
                mem = mem_map[fp]
                e.metadata["historical_recurrence_count"] = mem.get("recurrence_count", 1)
                e.metadata["historical_reopen_count"] = mem.get("reopened_count", 0)

                # Escalate severity if chronic recurrence or reopened in public exposure
                if mem.get("reopened_count", 0) >= 2 or mem.get("recurrence_count", 1) >= 4:
                    if e.severity != DriftSeverity.CRITICAL:
                        e.severity = DriftSeverity.CRITICAL
                        e.description += " [Escalated to CRITICAL: Chronic vulnerability recurrence history]."
                        e.evidence.append(f"M25 Learning Signal: Chronic recurrence count = {mem.get('recurrence_count')}")

            if learning_patterns:
                matched_p = [p for p in learning_patterns if hasattr(p, "affected_files") and e.file in getattr(p, "affected_files", [])]
                if matched_p:
                    e.metadata["learning_pattern_matches"] = [getattr(p, "title", str(p)) for p in matched_p]

            correlated.append(e)

        return correlated
