"""
SOC Squad - Security Operations Center squad
triage_agent + investigator_agent + sandbox_analysis_agent
"""

from agentos.core.squad import Squad
from agentos.core.umb_adapter import UMBAdapter
from agentos.cybercore.agents.triage_agent import TriageAgent
from agentos.cybercore.agents.investigator_agent import InvestigatorAgent
from agentos.cybercore.agents.sandbox_analysis_agent import SandboxAnalysisAgent
from agentos.core.squad import Squad, SquadRole


class SOCSquad(Squad):
    """SOC Squad - Security Operations Center team"""
    
    def __init__(
        self,
        name: str = "SOC Squad",
        shared_memory_ref: UMBAdapter = None,
        triage_agent: TriageAgent = None,
        investigator_agent: InvestigatorAgent = None,
        sandbox_agent: SandboxAnalysisAgent = None,
    ):
        super().__init__(name=name, shared_memory_ref=shared_memory_ref)
        
        # Add agents if provided
        if triage_agent:
            self.add_agent(triage_agent, SquadRole.WORKER)
        if investigator_agent:
            self.add_agent(investigator_agent, SquadRole.WORKER)
        if sandbox_agent:
            self.add_agent(sandbox_agent, SquadRole.WORKER)
    
    @classmethod
    def create(
        cls,
        name: str = "SOC Squad",
        shared_memory_ref: UMBAdapter = None,
        triage_mcps: Dict[str, Any] = None,
        investigator_mcps: Dict[str, Any] = None,
        sandbox_mcp: Any = None,
    ) -> 'SOCSquad':
        """Create SOC squad with agents"""
        triage = TriageAgent(
            name="TriageAgent",
            memory_ref=shared_memory_ref,
            **triage_mcps or {}
        )
        
        investigator = InvestigatorAgent(
            name="InvestigatorAgent",
            memory_ref=shared_memory_ref,
            **investigator_mcps or {}
        )
        
        sandbox = SandboxAnalysisAgent(
            name="SandboxAnalyst",
            memory_ref=shared_memory_ref,
            sandbox_mcp=sandbox_mcp,
        )
        
        return cls(
            name=name,
            shared_memory_ref=shared_memory_ref,
            triage_agent=triage,
            investigator_agent=investigator,
            sandbox_agent=sandbox,
        )

