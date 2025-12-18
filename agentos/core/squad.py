"""
Squad - Hierarchical team of agents with commander, leader, and workers
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from enum import Enum
import uuid
from datetime import datetime


class SquadRole(Enum):
    """Roles in a squad hierarchy"""
    COMMANDER = "commander"
    SQUAD_LEADER = "squad_leader"
    WORKER = "worker"
    REVIEWER = "reviewer"


@dataclass
class Mission:
    """Mission/task for a squad"""
    id: str
    goal: str
    description: str
    created_at: str
    status: str = "pending"
    assigned_agents: List[str] = field(default_factory=list)
    task_graph: Optional[Any] = None
    results: Dict[str, Any] = field(default_factory=dict)


class Squad:
    """
    Squad represents a hierarchical team of agents with shared memory and missions.
    """
    
    def __init__(
        self,
        id: Optional[str] = None,
        name: str = "Squad",
        commander_id: Optional[str] = None,
        leader_id: Optional[str] = None,
        shared_memory_ref: Optional[Any] = None,
        policies: Dict[str, Any] = None,
    ):
        self.id = id or str(uuid.uuid4())
        self.name = name
        self.commander_id = commander_id
        self.leader_id = leader_id
        
        # Agent registry
        self.agents: Dict[str, Any] = {}  # agent_id -> Agent
        self.agent_roles: Dict[str, SquadRole] = {}  # agent_id -> role
        
        # Memory
        self.shared_memory_ref = shared_memory_ref
        
        # Missions
        self.missions: Dict[str, Mission] = {}
        self.active_mission_id: Optional[str] = None
        
        # Policies
        self.policies = policies or {}
        
        # Mission references (for memory scoping)
        self.mission_refs: Dict[str, Any] = {}
    
    def add_agent(self, agent: Any, role: SquadRole = SquadRole.WORKER) -> bool:
        """
        Add an agent to the squad.
        
        Args:
            agent: Agent instance
            role: Role in squad hierarchy
            
        Returns:
            True if added successfully
        """
        if agent.id in self.agents:
            return False
        
        self.agents[agent.id] = agent
        self.agent_roles[agent.id] = role
        
        # Set commander/leader if not set
        if role == SquadRole.COMMANDER and not self.commander_id:
            self.commander_id = agent.id
        elif role == SquadRole.SQUAD_LEADER and not self.leader_id:
            self.leader_id = agent.id
        
        # Update agent's memory reference to squad shared memory
        if self.shared_memory_ref:
            agent.memory_ref = self.shared_memory_ref
        
        return True
    
    def remove_agent(self, agent_id: str) -> bool:
        """Remove an agent from the squad"""
        if agent_id not in self.agents:
            return False
        
        # Don't allow removing commander or leader if they're the only ones
        role = self.agent_roles.get(agent_id)
        if role == SquadRole.COMMANDER:
            # Check if there's another commander
            if not any(
                r == SquadRole.COMMANDER and aid != agent_id
                for aid, r in self.agent_roles.items()
            ):
                return False
        
        del self.agents[agent_id]
        del self.agent_roles[agent_id]
        
        if self.commander_id == agent_id:
            self.commander_id = None
        if self.leader_id == agent_id:
            self.leader_id = None
        
        return True
    
    def assign_agent(self, agent_id: str, role: SquadRole) -> bool:
        """
        Assign or reassign an agent's role in the squad.
        
        Args:
            agent_id: Agent ID
            role: New role
            
        Returns:
            True if assigned successfully
        """
        if agent_id not in self.agents:
            return False
        
        self.agent_roles[agent_id] = role
        
        if role == SquadRole.COMMANDER:
            self.commander_id = agent_id
        elif role == SquadRole.SQUAD_LEADER:
            self.leader_id = agent_id
        
        return True
    
    def create_mission(
        self,
        goal: str,
        description: str = "",
        mission_id: Optional[str] = None
    ) -> Mission:
        """
        Create a new mission for the squad.
        
        Args:
            goal: Mission goal
            description: Mission description
            mission_id: Optional mission ID
            
        Returns:
            Created Mission object
        """
        mission = Mission(
            id=mission_id or str(uuid.uuid4()),
            goal=goal,
            description=description,
            created_at=datetime.now().isoformat(),
        )
        
        self.missions[mission.id] = mission
        return mission
    
    async def start_mission(
        self,
        mission_id: str,
        task_graph: Optional[Any] = None,
        assigned_agents: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Start a mission execution.
        
        Args:
            mission_id: Mission ID
            task_graph: Optional task graph (from planner)
            assigned_agents: Optional list of agent IDs to assign
            
        Returns:
            Mission start result
        """
        if mission_id not in self.missions:
            return {
                "success": False,
                "error": f"Mission {mission_id} not found",
            }
        
        mission = self.missions[mission_id]
        mission.status = "active"
        mission.task_graph = task_graph
        mission.assigned_agents = assigned_agents or list(self.agents.keys())
        
        self.active_mission_id = mission_id
        
        # Create mission-scoped memory reference
        if self.shared_memory_ref:
            self.mission_refs[mission_id] = {
                "scope": "mission",
                "mission_id": mission_id,
                "memory_ref": self.shared_memory_ref,  # Will be filtered by scope
            }
        
        return {
            "success": True,
            "mission_id": mission_id,
            "assigned_agents": mission.assigned_agents,
        }
    
    def get_agents_by_role(self, role: SquadRole) -> List[Any]:
        """Get all agents with a specific role"""
        return [
            agent for agent_id, agent in self.agents.items()
            if self.agent_roles.get(agent_id) == role
        ]
    
    def get_commander(self) -> Optional[Any]:
        """Get the squad commander"""
        if self.commander_id:
            return self.agents.get(self.commander_id)
        return None
    
    def get_leader(self) -> Optional[Any]:
        """Get the squad leader"""
        if self.leader_id:
            return self.agents.get(self.leader_id)
        return None
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize squad to dictionary"""
        return {
            "id": self.id,
            "name": self.name,
            "commander_id": self.commander_id,
            "leader_id": self.leader_id,
            "agent_count": len(self.agents),
            "agent_ids": list(self.agents.keys()),
            "missions": {
                mid: {
                    "id": m.id,
                    "goal": m.goal,
                    "status": m.status,
                }
                for mid, m in self.missions.items()
            },
            "active_mission_id": self.active_mission_id,
        }

