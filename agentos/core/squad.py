"""
Squad - Hierarchical team of agents executing via CrewAI
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from enum import Enum
import uuid
import os
import asyncio
from datetime import datetime
import logging
import crewai

logger = logging.getLogger(__name__)

from agentos.core.base import BaseAgent, BaseMemory
from agentos.core.agent import Agent

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
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    status: str = "pending"
    assigned_agents: List[str] = field(default_factory=list)
    task_graph: Optional[Any] = None
    results: Dict[str, Any] = field(default_factory=dict)


class Squad:
    """
    Squad represents a team of agents executing missions using CrewAI under governance policies.
    """
    
    def __init__(
        self,
        id: Optional[str] = None,
        name: str = "Squad",
        commander_id: Optional[str] = None,
        leader_id: Optional[str] = None,
        shared_memory_ref: Optional[Any] = None,
        policies: Dict[str, Any] = None,
        governance: Optional[Any] = None,
        checkpoint_store: Optional[Any] = None,
    ):
        self.id = id or str(uuid.uuid4())
        self.checkpoint_store = checkpoint_store
        self.name = name
        self.commander_id = commander_id
        self.leader_id = leader_id
        
        # Agent registry
        self.agents: Dict[str, BaseAgent] = {}  # agent_id -> Agent
        self.agent_roles: Dict[str, SquadRole] = {}  # agent_id -> role
        
        # Memory
        self.shared_memory_ref = shared_memory_ref
        
        # Missions
        self.missions: Dict[str, Mission] = {}
        self.active_mission_id: Optional[str] = None
        
        # Policies / Governance
        self.policies = policies or {}
        
        # Avoid circular import
        from agentos.core.governance import GovernanceEngine
        self.governance = governance or GovernanceEngine()
        
    def add_agent(self, agent: BaseAgent, role: SquadRole = SquadRole.WORKER) -> bool:
        """Add an agent to the squad."""
        if agent.id in self.agents:
            return False
        
        self.agents[agent.id] = agent
        self.agent_roles[agent.id] = role
        
        # Set commander/leader if not set
        if role == SquadRole.COMMANDER and not self.commander_id:
            self.commander_id = agent.id
        elif role == SquadRole.SQUAD_LEADER and not self.leader_id:
            self.leader_id = agent.id
        
        return True
        
    def remove_agent(self, agent_id: str) -> bool:
        """Remove an agent from the squad."""
        if agent_id not in self.agents:
            return False
            
        del self.agents[agent_id]
        del self.agent_roles[agent_id]
        
        if self.commander_id == agent_id:
            self.commander_id = None
        if self.leader_id == agent_id:
            self.leader_id = None
            
        return True

    def assign_agent(self, agent_id: str, role: SquadRole) -> bool:
        """Assign or reassign an agent's role."""
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
        """Create a new mission."""
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
        assigned_agents: Optional[List[str]] = None,
        resume: bool = False
    ) -> Dict[str, Any]:
        """
        Runs the mission asynchronously using the new run_mission implementation.
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
        
        try:
            # Run the mission using our synchronous-to-async execution
            result = self.run_mission(mission, resume=resume)
            return {
                "success": True,
                "mission_id": mission_id,
                "result": str(result),
            }
        except Exception as e:
            mission.status = "failed"
            return {
                "success": False,
                "error": str(e),
            }

    def run_mission(self, mission: Mission, resume: bool = False) -> Any:
        """
        Delegates the mission execution to CrewAI.
        Translates agents to crewai.Agent, tasks to crewai.Task, maps roles,
        enforces pre-execution policy checks, and runs kickoff.
        Supports task-level checkpointing and resume.
        """
        # Convert AgentOS agents to CrewAI agents
        crewai_agents = [agent.to_crewai_agent() for agent in self.agents.values()]
        
        # Convert task nodes
        crewai_tasks = []
        if hasattr(mission, "task_graph") and mission.task_graph and hasattr(mission.task_graph, "nodes"):
            for node in mission.task_graph.nodes:
                assigned = None
                if node.assigned_agent:
                    assigned = self.agents.get(node.assigned_agent)
                    if not assigned:
                        for a in self.agents.values():
                            if a.name == node.assigned_agent:
                                assigned = a
                                break
                crew_agent = assigned.to_crewai_agent() if assigned else None
                crewai_tasks.append(crewai.Task(
                    description=node.description,
                    expected_output="Result of: " + node.description,
                    agent=crew_agent
                ))
        else:
            default_agent = None
            if self.agents:
                default_agent = list(self.agents.values())[0].to_crewai_agent()
            crewai_tasks.append(crewai.Task(
                description=mission.description or mission.goal,
                expected_output="Result of: " + mission.goal,
                agent=default_agent
            ))

        # Enforce pre-execution governance check via before_kickoff_callbacks hook
        def governance_before_kickoff(inputs):
            if self.governance:
                try:
                    loop = asyncio.get_event_loop()
                except RuntimeError:
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    
                for task in crewai_tasks:
                    task_node = {"description": task.description, "id": str(uuid.uuid4())}
                    for agent_id, agent in self.agents.items():
                        decision = loop.run_until_complete(
                            self.governance.check(
                                agent_id=agent_id,
                                action="execute",
                                context={"task": task_node, "agent": agent}
                            )
                        )
                        if not decision.allowed:
                            raise ValueError(f"Task execution blocked by policy: {decision.reason}")
            return inputs

        # Check for Commander for hierarchical process
        commander = None
        for agent_id, role in self.agent_roles.items():
            if role == SquadRole.COMMANDER or (isinstance(role, str) and role.lower() == "commander"):
                commander = self.agents[agent_id]
                break

        # Checkpoint store logic
        start_index = 0
        outputs = []
        checkpoint = None
        if resume and self.checkpoint_store:
            checkpoint = self.checkpoint_store.load_latest_checkpoint(mission.id)
            if checkpoint:
                status = checkpoint.get("status")
                if status in ["in_progress", "failed"]:
                    start_index = checkpoint.get("task_index", 0)
                    outputs = checkpoint.get("outputs", [])
                    logger.info(f"Resuming mission {mission.id} from task index {start_index}")
                elif status == "completed":
                    logger.info(f"Mission {mission.id} is already completed.")
                    return checkpoint.get("outputs", [""])[-1]

        # Configure and run Crew
        if commander:
            # Hierarchical process: Checkpoint at Crew-level (whole mission restart)
            # Code comment: Hierarchical resume is limited to crew-level restart in this phase.
            logger.info("Hierarchical process detected. Checkpointing at the crew-level (whole mission retry).")
            if self.checkpoint_store:
                self.checkpoint_store.save_checkpoint(mission.id, 0, {
                    "status": "in_progress",
                    "task_index": 0,
                    "outputs": [],
                    "timestamp": datetime.now().isoformat()
                })
            try:
                manager_agent = commander.to_crewai_agent()
                crew = crewai.Crew(
                    agents=crewai_agents,
                    tasks=crewai_tasks,
                    process=crewai.Process.hierarchical,
                    manager_agent=manager_agent,
                    before_kickoff_callbacks=[governance_before_kickoff],
                    verbose=True
                )
                result = crew.kickoff()
                
                if self.checkpoint_store:
                    self.checkpoint_store.save_checkpoint(mission.id, 0, {
                        "status": "completed",
                        "task_index": 0,
                        "outputs": [str(result)],
                        "timestamp": datetime.now().isoformat()
                    })
                    self.checkpoint_store.mark_complete(mission.id)
                mission.status = "completed"
                mission.results = {"output": str(result)}
                return result
            except Exception as e:
                if self.checkpoint_store:
                    self.checkpoint_store.save_checkpoint(mission.id, 0, {
                        "status": "failed",
                        "task_index": 0,
                        "outputs": [],
                        "error": str(e),
                        "timestamp": datetime.now().isoformat()
                    })
                raise e
        else:
            # Sequential process: Checkpoint at task-level (fine-grained resume)
            for idx in range(start_index, len(crewai_tasks)):
                task = crewai_tasks[idx]
                
                # Checkpoint task in-progress
                if self.checkpoint_store:
                    self.checkpoint_store.save_checkpoint(mission.id, idx, {
                        "status": "in_progress",
                        "task_index": idx,
                        "outputs": outputs,
                        "timestamp": datetime.now().isoformat()
                    })
                
                # Feed previous outputs back as context into task description
                description = task.description
                if outputs:
                    description = (
                        "Context from previously completed tasks:\n" +
                        "\n".join(f"- Task output: {out}" for out in outputs) +
                        f"\n\nTask to execute:\n{description}"
                    )
                
                try:
                    single_task = crewai.Task(
                        description=description,
                        expected_output=task.expected_output,
                        agent=task.agent
                    )
                    crew = crewai.Crew(
                        agents=crewai_agents,
                        tasks=[single_task],
                        process=crewai.Process.sequential,
                        before_kickoff_callbacks=[governance_before_kickoff],
                        verbose=True
                    )
                    if os.environ.get("FORCE_CRASH") == "1" and idx == 1:
                        raise RuntimeError("Simulated Crash in Task 2!")
                    task_result = crew.kickoff()
                    outputs.append(str(task_result))
                    
                    # Checkpoint task completed
                    if self.checkpoint_store:
                        self.checkpoint_store.save_checkpoint(mission.id, idx + 1, {
                            "status": "in_progress",
                            "task_index": idx + 1,
                            "outputs": outputs,
                            "timestamp": datetime.now().isoformat()
                        })
                except Exception as e:
                    # Checkpoint task failure
                    if self.checkpoint_store:
                        self.checkpoint_store.save_checkpoint(mission.id, idx, {
                            "status": "failed",
                            "task_index": idx,
                            "outputs": outputs,
                            "error": str(e),
                            "timestamp": datetime.now().isoformat()
                        })
                    raise e
            
            # Mark complete
            if self.checkpoint_store:
                self.checkpoint_store.mark_complete(mission.id)
                
            mission.status = "completed"
            final_output = outputs[-1] if outputs else ""
            mission.results = {"output": final_output}
            return final_output

    def get_agents_by_role(self, role: SquadRole) -> List[BaseAgent]:
        """Get agents with a specific role."""
        return [
            agent for agent_id, agent in self.agents.items()
            if self.agent_roles.get(agent_id) == role
        ]

    def get_commander(self) -> Optional[BaseAgent]:
        """Get the commander agent."""
        if self.commander_id:
            return self.agents.get(self.commander_id)
        return None

    def get_leader(self) -> Optional[BaseAgent]:
        """Get the squad leader."""
        if self.leader_id:
            return self.agents.get(self.leader_id)
        return None

    def to_dict(self) -> Dict[str, Any]:
        """Serialize squad information."""
        return {
            "id": self.id,
            "name": self.name,
            "commander_id": self.commander_id,
            "leader_id": self.leader_id,
            "agent_count": len(self.agents),
            "agent_ids": list(self.agents.keys()),
        }
