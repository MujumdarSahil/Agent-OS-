"""
M26 Security Drift Investigator.

Answers 'WHY DID SECURITY DRIFT?' with audit-ready, evidence-backed investigation reports.
"""

from typing import List, Dict, Any, Optional

from agentos_swe.intelligence.drift.models import SecurityDriftEvent, DriftInvestigationReport, DriftSeverity


class SecurityDriftInvestigator:
    """
    Produces deterministic investigation reports for security drift events.
    """

    def investigate_drift_events(
        self,
        events: List[SecurityDriftEvent],
        comparison: Optional[Any] = None,
        surface: Optional[Any] = None,
    ) -> List[DriftInvestigationReport]:
        """
        Generates DriftInvestigationReport for significant security drift events.
        """
        reports: List[DriftInvestigationReport] = []

        for e in events:
            # Skip minor low-severity fixed event reports unless requested
            if e.severity == DriftSeverity.NONE:
                continue

            what_changed = e.title
            where_it_changed = f"File: {e.file or 'Repository Wide'} (Root Cause: {e.root_cause or 'N/A'})"
            impact_str = f"Drift Event Severity: {e.severity.value}. Impact: {e.description}"

            prev_str = str(e.previous_state) if e.previous_state else "Baseline: Clean / Unexposed"
            curr_str = str(e.current_state) if e.current_state else "Current: Active finding / Exposed"

            rec_action = (
                "BLOCK_RELEASE" if e.severity == DriftSeverity.CRITICAL
                else ("GENERATE_REPAIR" if e.severity == DriftSeverity.HIGH
                      else ("INVESTIGATE" if e.severity == DriftSeverity.MEDIUM else "MONITOR"))
            )

            reports.append(
                DriftInvestigationReport(
                    event_id=e.event_id,
                    what_changed=what_changed,
                    where_it_changed=where_it_changed,
                    security_impact=impact_str,
                    previous_state=prev_str,
                    current_state=curr_str,
                    evidence=e.evidence,
                    related_findings=[e.finding_id] if e.finding_id else [],
                    related_attack_paths=[e.metadata.get("attack_path_id")] if e.metadata.get("attack_path_id") else [],
                    related_history=[f"Recurrence Count: {e.metadata.get('historical_recurrence_count', 1)}"],
                    related_learning_signals=e.metadata.get("learning_pattern_matches", []),
                    recommended_action=rec_action,
                )
            )

        return reports
