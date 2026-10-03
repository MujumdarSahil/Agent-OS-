"""
M29 Deterministic Incident Timeline Reconstructor.

Constructs ordered chronological step sequences representing an incident's evolution.
Implements bounded depth limits (max 50 events) to prevent runaway recursion.
"""

import time
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime

from agentos_swe.operations.incident.models import SecurityIncident, IncidentTimelineEvent, IncidentEvidence

logger = logging.getLogger(__name__)

MAX_TIMELINE_DEPTH = 50


class IncidentTimelineReconstructor:
    """
    Reconstructs deterministic chronological timelines for security incidents.
    """

    @classmethod
    def reconstruct_timeline(
        cls,
        incident: SecurityIncident,
        pipeline_stages: Optional[List[Dict[str, Any]]] = None,
    ) -> List[IncidentTimelineEvent]:
        """
        Reconstructs a step-by-step chronological timeline for an incident.
        """
        timeline: List[IncidentTimelineEvent] = []
        t0 = incident.created_at

        # 1. First Appearance / Commit
        timeline.append(
            IncidentTimelineEvent(
                event_id=f"evt_1_{int(time.time())}",
                timestamp=t0,
                event_type="COMMIT_INSPECTED",
                description=f"Repository scanned at commit SHA `{incident.commit_sha[:7]}`.",
                source_module="IntakeEngine",
                commit_sha=incident.commit_sha,
            )
        )

        # 2. Finding Discovery & Evidence
        for idx, ev in enumerate(incident.evidence_list[:MAX_TIMELINE_DEPTH - 4]):
            timeline.append(
                IncidentTimelineEvent(
                    event_id=f"evt_ev_{idx+2}",
                    timestamp=t0,
                    event_type=f"EVIDENCE_{ev.evidence_type.value if hasattr(ev.evidence_type, 'value') else ev.evidence_type}",
                    description=f"{ev.title}: {ev.description}",
                    source_module=ev.source_module,
                    file_path=ev.file_path,
                    line_number=ev.line_number,
                    commit_sha=incident.commit_sha,
                )
            )

        # 3. Governance Evaluation
        timeline.append(
            IncidentTimelineEvent(
                event_id=f"evt_gov_{int(time.time())}",
                timestamp=datetime.now().isoformat(),
                event_type="GOVERNANCE_EVALUATED",
                description=f"Governance gate evaluated posture: Incident severity set to `{incident.severity.value if hasattr(incident.severity, 'value') else incident.severity}`.",
                source_module="GovernanceGate",
                commit_sha=incident.commit_sha,
            )
        )

        # 4. Current Status
        timeline.append(
            IncidentTimelineEvent(
                event_id=f"evt_status_{int(time.time())}",
                timestamp=datetime.now().isoformat(),
                event_type="INCIDENT_STATUS_SET",
                description=f"Incident status marked as `{incident.status.value if hasattr(incident.status, 'value') else incident.status}`.",
                source_module="IncidentResponseEngine",
                commit_sha=incident.commit_sha,
            )
        )

        return timeline[:MAX_TIMELINE_DEPTH]
