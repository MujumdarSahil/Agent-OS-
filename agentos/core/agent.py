"""
Agent - Core Agent implementation inheriting from BaseAgent
"""

import uuid
import asyncio
from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Callable
import crewai

from agentos.core.base import BaseAgent, BaseTool, BaseMemory
from agentos.llm.llm_client import LLMClient, AgentOSCrewAILLM

class AgentStatus(Enum):
    """Agent execution status"""
    IDLE = "idle"
    PLANNING = "planning"
    EXECUTING = "executing"
    WAITING = "waiting"
    MERGED = "merged"
    ERROR = "error"


@dataclass
class AgentIdentity:
    """Agent identity information"""
    public_id: str
    name: str
    personality_vector: List[float] = field(default_factory=list)
    reputation_score: float = 0.0
    strengths: List[str] = field(default_factory=list)
    weaknesses: List[str] = field(default_factory=list)
    credentials: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ResourceQuota:
    """Resource limits and usage tracking"""
    token_limit: int = 100000
    token_used: int = 0
    api_call_limit: int = 1000
    api_calls_used: int = 0
    cpu_limit: float = 1.0  # CPU cores
    memory_limit: float = 1024.0  # MB
    wall_time_limit: float = 3600.0  # seconds


class Agent(BaseAgent):
    """
    Core Agent class representing an autonomous agent with skills, memory, and execution capabilities.
    Wraps a CrewAI Agent.
    """
    
    def __init__(
        self,
        name: str = "Agent",
        role: str = "General Assistant",
        goal: str = "Assist the user",
        backstory: str = "A helpful AI assistant",
        llm_client: Optional[LLMClient] = None,
        tools: Optional[List[BaseTool]] = None,
        memory: Optional[BaseMemory] = None,
        **kwargs: Any
    ):
        if llm_client is None:
            from agentos.llm.llm_client import LLMClient
            llm_client = LLMClient()

        super().__init__(
            name=name,
            role=role,
            goal=goal,
            backstory=backstory,
            llm_client=llm_client,
            tools=tools,
            memory=memory,
            **kwargs
        )
        self.id = kwargs.get("id") or str(uuid.uuid4())
        self.status = AgentStatus.IDLE
        self.roles = [role]
        self.skills = kwargs.get("skills") or []
        self.memory_ref = kwargs.get("memory_ref") or memory
        self.execution_history = []
        self.resource_metrics = {
            "token_usage": 0,
            "api_calls": 0,
            "cpu_estimate": 0.0,
            "memory_estimate": 0.0,
            "wall_time": 0.0,
        }

    @property
    def skill_vector(self) -> Dict[str, float]:
        """Build skill vector mapping each skill to a default score of 1.0"""
        return {skill: 1.0 for skill in self.skills}

    async def plan(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Scaffold a simple task graph/plan with subtasks for execution"""
        self.status = AgentStatus.PLANNING
        plan_dict = {
            "agent_id": self.id,
            "task_id": task.get("id"),
            "subtasks": [task]
        }
        self.status = AgentStatus.IDLE
        return plan_dict

        
    def to_crewai_agent(self) -> crewai.Agent:
        """
        Translates this agent to a CrewAI Agent.
        """
        # Convert all tools
        crewai_tools = [t.to_crewai_tool() for t in self.tools] if self.tools else []
        
        # Instantiate CrewAI LLM wrapper
        llm = None
        if self.llm_client:
            llm = AgentOSCrewAILLM(llm_client=self.llm_client)
            
        return crewai.Agent(
            role=self.role,
            goal=self.goal,
            backstory=self.backstory,
            tools=crewai_tools,
            llm=llm,
            verbose=True
        )

    async def execute(self, task_node: Dict[str, Any], context: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Runs the agent against a task description using a single CrewAI agent execution wrapper.
        """
        self.status = AgentStatus.EXECUTING
        context = context or {}
        governance = context.get("governance")
        
        # Run governance policy check if provided
        if governance:
            decision = await governance.check(
                agent_id=self.id,
                action="execute",
                context={"task": task_node, "agent": self}
            )
            if not decision.allowed:
                self.status = AgentStatus.ERROR
                return {
                    "success": False,
                    "error": f"Policy violation: {decision.reason}",
                    "task_id": task_node.get("id"),
                }
                
        # Run execution using CrewAI
        try:
            crew_agent = self.to_crewai_agent()
            crew_task = crewai.Task(
                description=task_node.get("description", ""),
                expected_output="Detailed result of: " + task_node.get("description", ""),
                agent=crew_agent
            )
            crew = crewai.Crew(
                agents=[crew_agent],
                tasks=[crew_task],
                verbose=False
            )
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = None

            if loop and loop.is_running():
                output = await loop.run_in_executor(None, crew.kickoff)
            else:
                output = crew.kickoff()
            
            # Save task/result to memory if memory reference is present
            memory_ref = self.kwargs.get("memory_ref") or getattr(self, "memory_ref", None) or self.memory
            if memory_ref:
                await memory_ref.upsert({
                    "text": f"Task '{task_node.get('description')}' executed successfully by agent '{self.name}'. Result: {output}",
                    "metadata": {
                        "author_agent": self.id,
                        "permission_level": "agent_private",
                        "task_id": task_node.get("id"),
                    }
                })
            
            # Simple result structure
            res = {
                "success": True,
                "outputs": {"result": str(output)},
                "task_id": task_node.get("id"),
                "agent_id": self.id,
            }
            self.execution_history.append(res)
            self.status = AgentStatus.IDLE
            return res
        except Exception as e:
            self.status = AgentStatus.ERROR
            return {
                "success": False,
                "error": str(e),
                "task_id": task_node.get("id"),
            }

    def register_tool(self, tool: BaseTool) -> None:
        """Register a tool to the agent."""
        if not self.tools:
            self.tools = []
        self.tools.append(tool)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize agent state to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "role": self.role,
            "goal": self.goal,
            "backstory": self.backstory,
            "status": self.status.value,
            "skills": self.skills,
        }
