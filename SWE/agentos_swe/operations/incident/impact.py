"""
M29 Incident Impact Assessor.

Calculates blast radius, affected surfaces, trust boundaries, and attack-path reachability
based strictly on empirical evidence without claiming actual exploitation.
"""

import logging
from typing import List, Dict, Any, Optional
from agentos_swe.operations.incident.models import SecurityIncident, IncidentImpact, IncidentSeverity

logger = logging.getLogger(__name__)


class IncidentImpactAssessor:
    """
    Assesses blast radius and quantitative impact of a security incident.
    """

    @classmethod
    def assess_impact(cls, incident: SecurityIncident) -> IncidentImpact:
        """
        Calculates blast radius score and identifies affected surfaces.
        """
        affected_files = set()
        affected_functions = set()
        affected_surfaces = set()
        affected_boundaries = set()
        internet_exposed = False
        path_reachable = False

        for ev in incident.evidence_list:
            if ev.file_path:
                affected_files.add(ev.file_path)
            if "function" in ev.raw_data:
                affected_functions.add(ev.raw_data["function"])
            if "surface" in ev.raw_data:
                affected_surfaces.add(ev.raw_data["surface"])
            if "boundary" in ev.raw_data:
                affected_boundaries.add(ev.raw_data["boundary"])

            ev_type_str = ev.evidence_type.value if hasattr(ev.evidence_type, "value") else str(ev.evidence_type)
            if "INTERNET" in str(ev.description).upper() or ev_type_str == "ATTACK_PATH":
                internet_exposed = True
                path_reachable = True

        for ap in incident.attack_paths:
            if ap.is_internet_exposed:
                internet_exposed = True
            if ap.exploitable:
                path_reachable = True

        sev_weight = {
            IncidentSeverity.LOW: 1.0,
            IncidentSeverity.MEDIUM: 2.5,
            IncidentSeverity.HIGH: 5.0,
            IncidentSeverity.CRITICAL: 10.0,
        }.get(incident.severity, 2.5)

        exposure_multiplier = 2.0 if internet_exposed else 1.0
        blast_score = round(min((len(affected_files) * 2.0 + len(affected_surfaces) * 1.5 + 1.0) * sev_weight * exposure_multiplier, 100.0), 2)

        return IncidentImpact(
            repository_name=incident.repository_name,
            affected_files=list(affected_files) or ["N/A"],
            affected_functions=list(affected_functions) or ["N/A"],
            affected_security_surfaces=list(affected_surfaces) or ["CODEBASE"],
            affected_trust_boundaries=list(affected_boundaries) or ["APPLICATION_BOUNDARY"],
            internet_exposed=internet_exposed,
            attack_path_reachable=path_reachable,
            severity=incident.severity,
            blast_radius_score=blast_score,
            recurrence_classification="FIRST_SEEN",
        )
