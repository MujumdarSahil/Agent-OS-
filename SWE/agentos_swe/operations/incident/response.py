"""
M29 Deterministic Incident Response Planner.

Formulates governed incident response plans combining recommended actions,
risk levels, and human approval requirements.
"""

import time
import logging
from typing import List, Dict, Any, Optional

from agentos_swe.operations.incident.models import (
    SecurityIncident,
    IncidentResponsePlan,
    ResponseAction,
    IncidentSeverity,
)

logger = logging.getLogger(__name__)


class IncidentResponsePlanner:
    """
    Formulates governed response recommendation plans for security incidents.
    Never automatically applies patches or remote changes.
    """

    @classmethod
    def plan_response(cls, incident: SecurityIncident) -> IncidentResponsePlan:
        """
        Generates an actionable response plan for an incident.
        """
        actions: List[ResponseAction] = []
        is_crit = incident.severity == IncidentSeverity.CRITICAL
        is_high = incident.severity == IncidentSeverity.HIGH
        is_exp = incident.impact and incident.impact.internet_exposed

        if is_crit and is_exp:
            primary = ResponseAction.BLOCK_RELEASE
            actions = [ResponseAction.BLOCK_RELEASE, ResponseAction.GENERATE_REPAIR, ResponseAction.REQUEST_HUMAN_APPROVAL]
            gov_dec = "DENY"
            risk_lvl = "CRITICAL"
            req_appr = True
            rat = "Critical vulnerability on internet-exposed attack path mandates immediate release block and governed patch generation."
        elif is_crit:
            primary = ResponseAction.BLOCK_RELEASE
            actions = [ResponseAction.BLOCK_RELEASE, ResponseAction.GENERATE_REPAIR, ResponseAction.REQUEST_HUMAN_APPROVAL]
            gov_dec = "DENY"
            risk_lvl = "CRITICAL"
            req_appr = True
            rat = "Critical vulnerability requires release block until patch generation and review complete."
        elif is_high:
            primary = ResponseAction.GENERATE_REPAIR
            actions = [ResponseAction.GENERATE_REPAIR, ResponseAction.REQUEST_HUMAN_APPROVAL, ResponseAction.INVESTIGATE]
            gov_dec = "REVIEW_REQUIRED"
            risk_lvl = "HIGH"
            req_appr = True
            rat = "High severity vulnerability detected; repair generation recommended for lead review."
        else:
            primary = ResponseAction.MONITOR
            actions = [ResponseAction.MONITOR, ResponseAction.INVESTIGATE]
            gov_dec = "ALLOW"
            risk_lvl = "LOW"
            req_appr = False
            rat = "Low severity security finding monitored without release blocking."

        plan = IncidentResponsePlan(
            plan_id=f"plan_{incident.incident_id}_{int(time.time())}",
            incident_id=incident.incident_id,
            recommended_actions=actions,
            primary_action=primary,
            risk_level=risk_lvl,
            governance_decision=gov_dec,
            rationale=rat,
            requires_human_approval=req_appr,
        )

        incident.response_plan = plan
        return plan
