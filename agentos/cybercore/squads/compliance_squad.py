"""
Compliance Squad
compliance_agent + password_policy_agent
"""

from agentos.core.squad import Squad, SquadRole
from agentos.core.umb_adapter import UMBAdapter
from agentos.cybercore.agents.compliance_agent import ComplianceAgent


class ComplianceSquad(Squad):
    """Compliance Squad"""
    
    def __init__(
        self,
        name: str = "Compliance Squad",
        shared_memory_ref: UMBAdapter = None,
        compliance_agent: ComplianceAgent = None,
    ):
        super().__init__(name=name, shared_memory_ref=shared_memory_ref)
        
        if compliance_agent:
            self.add_agent(compliance_agent, SquadRole.WORKER)

