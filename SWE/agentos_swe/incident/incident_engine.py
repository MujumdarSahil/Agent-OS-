"""
M29 Security Incident Response Engine Facade.

Master orchestrator consuming M14-M28 pipeline outputs to perform
incident detection, correlation, timeline reconstruction, impact analysis,
forensic investigation, response planning, and transparent explainability generation.
"""

import logging
from typing import List, Dict, Any, Optional

from agentos_swe.incident.models import (
    SecurityIncident,
    IncidentInvestigationResult,
    IncidentSeverity,
)
from agentos_swe.incident.detector import SecurityIncidentDetector
from agentos_swe.incident.correlation import IncidentEvidenceCorrelator
from agentos_swe.incident.timeline import IncidentTimelineReconstructor
from agentos_swe.incident.impact import IncidentImpactAssessor
from agentos_swe.incident.investigation import SecurityIncidentInvestigator
from agentos_swe.incident.response import IncidentResponsePlanner
from agentos_swe.incident.explainability import IncidentExplainabilityEngine

logger = logging.getLogger(__name__)


class SecurityIncidentResponseEngine:
    """
    Master orchestrator facade for Security Incident Response & Investigation.
    """

    def __init__(self):
        self.detector = SecurityIncidentDetector()

    def process_security_incidents(
        self,
        repository_name: str,
        commit_sha: str = "HEAD",
        verified_findings: Optional[List[Any]] = None,
        prioritized_findings: Optional[List[Any]] = None,
        attack_paths: Optional[List[Any]] = None,
        decision_result: Optional[Any] = None,
        learning_result: Optional[Any] = None,
        drift_result: Optional[Any] = None,
        control_plane_result: Optional[Any] = None,
        monitoring_events: Optional[List[Any]] = None,
    ) -> IncidentInvestigationResult:
        """
        Orchestrates full M29 incident analysis pipeline.
        """
        # 1. Detection
        raw_incidents = self.detector.detect_incidents(
            repository_name=repository_name,
            commit_sha=commit_sha,
            verified_findings=verified_findings,
            prioritized_findings=prioritized_findings,
            attack_paths=attack_paths,
            decision_result=decision_result,
            learning_result=learning_result,
            drift_result=drift_result,
            control_plane_result=control_plane_result,
            monitoring_events=monitoring_events,
        )

        # 2. Correlation & Deduplication
        incidents = IncidentEvidenceCorrelator.correlate_and_deduplicate(raw_incidents)

        # 3. Process each incident through Timeline, Impact, Investigation, Response, & Explainability
        for inc in incidents:
            inc.timeline = IncidentTimelineReconstructor.reconstruct_timeline(inc)
            inc.impact = IncidentImpactAssessor.assess_impact(inc)
            SecurityIncidentInvestigator.investigate(inc)
            IncidentResponsePlanner.plan_response(inc)
            IncidentExplainabilityEngine.generate_explanation(inc)

        active_count = len(incidents)
        crit_count = sum(1 for inc in incidents if inc.severity == IncidentSeverity.CRITICAL)

        summary_msg = (
            f"Processed incident response pipeline for '{repository_name}'. "
            f"Active incidents: {active_count} (Critical: {crit_count})."
        ) if active_count > 0 else f"Zero active security incidents identified for '{repository_name}'."

        return IncidentInvestigationResult(
            incidents=incidents,
            active_incident_count=active_count,
            critical_incident_count=crit_count,
            summary_explanation=summary_msg,
        )
