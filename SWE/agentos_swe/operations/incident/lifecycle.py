"""
M29 Security Incident Lifecycle Manager.

State machine enforcing valid transitions across incident lifecycle stages.
Rejects invalid state transitions safely with ValueError.
"""

import logging
from typing import Dict, Any, List
from agentos_swe.operations.incident.models import IncidentStatus, SecurityIncident

logger = logging.getLogger(__name__)


class IncidentLifecycleManager:
    """
    Enforces state machine transitions for security incidents.
    """

    VALID_TRANSITIONS: Dict[IncidentStatus, List[IncidentStatus]] = {
        IncidentStatus.DETECTED: [IncidentStatus.TRIAGED, IncidentStatus.INVESTIGATING, IncidentStatus.BLOCKED, IncidentStatus.ESCALATED],
        IncidentStatus.TRIAGED: [IncidentStatus.INVESTIGATING, IncidentStatus.CONTAINMENT_RECOMMENDED, IncidentStatus.BLOCKED, IncidentStatus.ESCALATED],
        IncidentStatus.INVESTIGATING: [IncidentStatus.CONTAINMENT_RECOMMENDED, IncidentStatus.REPAIR_PENDING, IncidentStatus.BLOCKED, IncidentStatus.ESCALATED],
        IncidentStatus.CONTAINMENT_RECOMMENDED: [IncidentStatus.REPAIR_PENDING, IncidentStatus.BLOCKED, IncidentStatus.ESCALATED],
        IncidentStatus.REPAIR_PENDING: [IncidentStatus.VALIDATING, IncidentStatus.BLOCKED, IncidentStatus.FAILED],
        IncidentStatus.VALIDATING: [IncidentStatus.MONITORING, IncidentStatus.RESOLVED, IncidentStatus.FAILED],
        IncidentStatus.MONITORING: [IncidentStatus.RESOLVED, IncidentStatus.REOPENED, IncidentStatus.ESCALATED],
        IncidentStatus.RESOLVED: [IncidentStatus.REOPENED],
        IncidentStatus.REOPENED: [IncidentStatus.INVESTIGATING, IncidentStatus.TRIAGED, IncidentStatus.ESCALATED],
        IncidentStatus.ESCALATED: [IncidentStatus.INVESTIGATING, IncidentStatus.CONTAINMENT_RECOMMENDED, IncidentStatus.REPAIR_PENDING, IncidentStatus.BLOCKED],
        IncidentStatus.BLOCKED: [IncidentStatus.INVESTIGATING, IncidentStatus.REPAIR_PENDING, IncidentStatus.RESOLVED],
        IncidentStatus.FAILED: [IncidentStatus.INVESTIGATING, IncidentStatus.REPAIR_PENDING, IncidentStatus.ESCALATED],
    }

    @classmethod
    def transition(cls, incident: SecurityIncident, target_status: IncidentStatus) -> IncidentStatus:
        """
        Transitions incident to target status if valid, or raises ValueError.
        """
        current = incident.status
        if current == target_status:
            return current

        allowed = cls.VALID_TRANSITIONS.get(current, [])
        if target_status not in allowed:
            raise ValueError(
                f"Invalid incident lifecycle transition: '{current.value if hasattr(current, 'value') else current}' -> '{target_status.value if hasattr(target_status, 'value') else target_status}'."
            )

        incident.status = target_status
        return target_status
