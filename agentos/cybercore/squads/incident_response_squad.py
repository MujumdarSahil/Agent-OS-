"""
Incident Response Squad
investigator_agent + compliance_agent + reviewer_agent
"""

from agentos.core.squad import Squad, SquadRole
from agentos.core.umb_adapter import UMBAdapter
from agentos.cybercore.agents.investigator_agent import InvestigatorAgent
from agentos.cybercore.agents.compliance_agent import ComplianceAgent
from agentos.core.cybersecurity_agents import ReviewerAgent


class IncidentResponseSquad(Squad):
    """Incident Response Squad"""
    
    def __init__(
        self,
        name: str = "Incident Response Squad",
        shared_memory_ref: UMBAdapter = None,
        investigator_agent: InvestigatorAgent = None,
        compliance_agent: ComplianceAgent = None,
        reviewer_agent: ReviewerAgent = None,
    ):
        super().__init__(name=name, shared_memory_ref=shared_memory_ref)
        
        if investigator_agent:
            self.add_agent(investigator_agent, SquadRole.WORKER)
        if compliance_agent:
            self.add_agent(compliance_agent, SquadRole.WORKER)
        if reviewer_agent:
            self.add_agent(reviewer_agent, SquadRole.REVIEWER)

