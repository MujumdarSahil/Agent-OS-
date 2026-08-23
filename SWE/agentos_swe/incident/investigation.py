"""
M29 Security Incident Investigator.

Answers the 10 core security investigation questions with evidence-backed reasoning
and investigation confidence scoring.
"""

import logging
from typing import Dict, Any, Optional
from agentos_swe.incident.models import SecurityIncident, InvestigationConfidence, IncidentSeverity

logger = logging.getLogger(__name__)


class SecurityIncidentInvestigator:
    """
    Produces structured answers to the 10 core security investigation questions.
    """

    @classmethod
    def investigate(cls, incident: SecurityIncident) -> Dict[str, Any]:
        """
        Conducts forensic investigation answering WHAT, WHEN, WHERE, WHY, HOW, etc.
        """
        aff_files = incident.impact.affected_files if incident.impact else ["N/A"]
        blast_score = incident.impact.blast_radius_score if incident.impact else 0.0

        # Assess confidence
        has_finding_ev = any((e.evidence_type.value if hasattr(e.evidence_type, "value") else str(e.evidence_type)) == "FINDING" for e in incident.evidence_list)
        has_path_ev = len(incident.attack_paths) > 0 or any((e.evidence_type.value if hasattr(e.evidence_type, "value") else str(e.evidence_type)) == "ATTACK_PATH" for e in incident.evidence_list)

        if has_finding_ev and has_path_ev:
            conf = InvestigationConfidence.VERY_HIGH
        elif has_finding_ev:
            conf = InvestigationConfidence.HIGH
        elif has_path_ev:
            conf = InvestigationConfidence.MEDIUM
        else:
            conf = InvestigationConfidence.LOW

        incident.confidence = conf

        # Formulate 10 answers
        investigation_report = {
            "what_happened": incident.title,
            "when_did_it_happen": incident.created_at,
            "where_did_it_happen": f"Repository '{incident.repository_name}' at commit `{incident.commit_sha[:7]}` in files: {', '.join(aff_files)}",
            "why_did_it_happen": incident.description,
            "how_could_attack_work": f"Attack path connecting source inputs to vulnerable sink functions in {', '.join(aff_files)}",
            "what_changed": f"Code modifications in {', '.join(aff_files)} introduced or exposed security vulnerability.",
            "what_evidence_supports_this": [f"[{e.evidence_type}] {e.title}: {e.description}" for e in incident.evidence_list],
            "what_is_the_impact": f"Blast radius score: {blast_score}/100; Affected files: {len(aff_files)}",
            "what_is_the_confidence": conf.value,
            "what_remains_unknown": incident.unknowns or ["Runtime exploitation capability without live environment context."],
        }

        incident.explanation = investigation_report
        return investigation_report
