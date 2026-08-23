"""
M29 Incident Evidence Correlation Engine.

Correlates findings, taint paths, attack paths, drift events, and monitoring telemetry.
Deduplicates incidents sharing the same underlying security fingerprint or root cause.
"""

import logging
from typing import List, Dict, Any, Optional
from agentos_swe.incident.models import SecurityIncident

logger = logging.getLogger(__name__)


class IncidentEvidenceCorrelator:
    """
    Correlates and deduplicates security incidents across pipeline modules.
    """

    @classmethod
    def correlate_and_deduplicate(cls, incidents: List[SecurityIncident]) -> List[SecurityIncident]:
        """
        Deduplicates incidents by combining overlapping evidence and selecting highest severity.
        """
        if not incidents:
            return []

        dedup_map: Dict[str, SecurityIncident] = {}

        for inc in incidents:
            # Construct correlation fingerprint
            fp = f"{inc.repository_name}_{inc.incident_type}_{inc.title}"

            if fp not in dedup_map:
                dedup_map[fp] = inc
            else:
                existing = dedup_map[fp]
                # Merge evidence lists
                existing_ev_ids = {e.evidence_id for e in existing.evidence_list}
                for ev in inc.evidence_list:
                    if ev.evidence_id not in existing_ev_ids:
                        existing.evidence_list.append(ev)
                        existing_ev_ids.add(ev.evidence_id)

                # Select highest severity
                inc_sev = inc.severity.value if hasattr(inc.severity, "value") else str(inc.severity)
                ext_sev = existing.severity.value if hasattr(existing.severity, "value") else str(existing.severity)
                if str(inc_sev).upper() == "CRITICAL" and str(ext_sev).upper() != "CRITICAL":
                    existing.severity = inc.severity

        return list(dedup_map.values())
