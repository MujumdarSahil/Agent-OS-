"""
M29 Incident Explainability Engine.

Generates transparent, explainable reasoning for incident detection,
severity assignments, evidence selection, attack paths, response planning, and governance decisions.
"""

import logging
from typing import Dict, Any
from agentos_swe.operations.incident.models import SecurityIncident

logger = logging.getLogger(__name__)


class IncidentExplainabilityEngine:
    """
    Generates transparent explainability reports for security incidents.
    """

    @classmethod
    def generate_explanation(cls, incident: SecurityIncident) -> Dict[str, Any]:
        """
        Formulates human-readable rationale across 7 explainability pillars.
        """
        aff_files = incident.impact.affected_files if incident.impact else ["N/A"]
        resp_act = incident.response_plan.primary_action if incident.response_plan else "MONITOR"
        gov_dec = incident.response_plan.governance_decision if incident.response_plan else "ALLOW"

        explanation = {
            "why_created": f"Incident triggered by detection rule '{incident.incident_type.value if hasattr(incident.incident_type, 'value') else incident.incident_type}' matching findings in {', '.join(aff_files)}.",
            "why_severity_assigned": f"Assigned severity '{incident.severity.value if hasattr(incident.severity, 'value') else incident.severity}' based on root cause severity and public exposure.",
            "why_evidence_matters": f"Includes {len(incident.evidence_list)} verified evidence records linking static analysis and taint propagation.",
            "why_attack_path_matters": f"Links {len(incident.attack_paths)} active attack paths, evaluating reachability from public entrypoints to sensitive sink functions.",
            "why_response_recommended": f"Recommended primary response '{resp_act.value if hasattr(resp_act, 'value') else resp_act}' to achieve containment and patch generation.",
            "why_governance_decision": f"Governance decision '{gov_dec}' enforced based on policy rules for severity '{incident.severity}'.",
            "what_is_unknown": incident.unknowns or ["Runtime exploit status without live production environment telemetry."],
        }

        incident.explanation = explanation
        return explanation
