"""
Red Team Simulation Squad - SIMULATION ONLY
redteam_sim_agent + reviewer_agent
human approval required at every step
"""

from agentos.core.squad import Squad, SquadRole
from agentos.core.umb_adapter import UMBAdapter
from agentos.cybercore.agents.redteam_sim_agent import RedTeamSimAgent
from agentos.core.cybersecurity_agents import ReviewerAgent


class RedTeamSimSquad(Squad):
    """Red Team Simulation Squad - SIMULATION ONLY"""
    
    def __init__(
        self,
        name: str = "Red Team Simulation Squad",
        shared_memory_ref: UMBAdapter = None,
        redteam_agent: RedTeamSimAgent = None,
        reviewer_agent: ReviewerAgent = None,
    ):
        super().__init__(name=name, shared_memory_ref=shared_memory_ref)
        
        if redteam_agent:
            self.add_agent(redteam_agent, SquadRole.WORKER)
        if reviewer_agent:
            self.add_agent(reviewer_agent, SquadRole.REVIEWER)
        
        self.requires_approval = True  # All actions require approval

