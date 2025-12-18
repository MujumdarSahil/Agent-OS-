"""
Agent - Core agent class with identity, skills, memory, and execution capabilities
"""

from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
import uuid
import asyncio
from datetime import datetime


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


class Agent:
    """
    Core Agent class representing an autonomous agent with skills, memory, and execution capabilities.
    """
    
    def __init__(
        self,
        id: Optional[str] = None,
        name: str = "Agent",
        roles: List[str] = None,
        skills: List[str] = None,
        personality_vector: List[float] = None,
        memory_ref: Optional[Any] = None,
        resource_quota: Optional[ResourceQuota] = None,
    ):
        self.id = id or str(uuid.uuid4())
        self.name = name
        self.roles = roles or []
        self.skills = skills or []
        self.skill_vector = self._build_skill_vector(skills or [])
        self.status = AgentStatus.IDLE
        
        # Identity
        self.identity = AgentIdentity(
            public_id=self.id,
            name=name,
            personality_vector=personality_vector or [],
        )
        
        # Memory reference (will be UMB adapter)
        self.memory_ref = memory_ref
        
        # Resources
        self.resource_quota = resource_quota or ResourceQuota()
        self.resource_metrics = {
            "token_usage": 0,
            "api_calls": 0,
            "cpu_estimate": 0.0,
            "memory_estimate": 0.0,
            "wall_time": 0.0,
        }
        
        # Execution context
        self.current_task = None
        self.execution_history = []
        
        # Tool registry
        self.tools: Dict[str, Callable] = {}
        
        # Security tools registry (for security MCPs)
        self.security_tools: Dict[str, Any] = {}
    
    def load_security_tools(self, security_mcps: Optional[Dict[str, Any]] = None):
        """
        Load security tools into skill registry from security MCP servers.
        
        Args:
            security_mcps: Dictionary mapping MCP names to MCP connector instances
        """
        if not security_mcps:
            return
        
        for mcp_name, mcp_connector in security_mcps.items():
            if hasattr(mcp_connector, 'get_skills'):
                skills = mcp_connector.get_skills()
                for skill in skills:
                    skill_name = skill.get("name", "")
                    if skill_name:
                        # Register skill as callable that routes to MCP
                        async def make_mcp_call(mcp=mcp_connector, skill=skill_name):
                            return lambda params: mcp.call_skill(skill, params)
                        
                        # Store MCP reference for async calls
                        self.security_tools[skill_name] = {
                            "mcp": mcp_connector,
                            "skill_name": skill_name,
                            "skill_metadata": skill,
                        }
                        
                        # Register as tool
                        async def tool_wrapper(params: Dict[str, Any], mcp=mcp_connector, skill=skill_name):
                            return await mcp.call_skill(skill, params)
                        
                        self.tools[skill_name] = tool_wrapper
        
    def _build_skill_vector(self, skills: List[str]) -> Dict[str, float]:
        """Build a skill vector from skill list"""
        return {skill: 1.0 for skill in skills}
    
    async def plan(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Plan execution for a task. Can call planner/MAGP or propose decomposition.
        
        Args:
            task: Task description with goal, constraints, etc.
            
        Returns:
            Plan dictionary with subtasks and execution strategy
        """
        self.status = AgentStatus.PLANNING
        
        # Simple planning logic - can be extended with LLM calls
        plan = {
            "agent_id": self.id,
            "task_id": task.get("id", str(uuid.uuid4())),
            "subtasks": [task],  # Default: single task
            "strategy": "sequential",
            "estimated_cost": self._estimate_cost(task),
            "created_at": datetime.now().isoformat(),
        }
        
        self.status = AgentStatus.IDLE
        return plan
    
    async def execute(self, task_node: Dict[str, Any], context: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Execute a task node. Checks policies, calls tools, updates memory, emits events.
        
        Args:
            task_node: Task node from planning graph
            context: Execution context (governance, squad info, etc.)
            
        Returns:
            Execution result with outputs and metadata
        """
        self.status = AgentStatus.EXECUTING
        self.current_task = task_node
        
        context = context or {}
        governance = context.get("governance")
        
        # Policy check (if governance provided)
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
        
        # Execute task
        try:
            result = await self._execute_task(task_node)
            
            # Update memory if available
            if self.memory_ref and result.get("outputs"):
                await self._update_memory(task_node, result)
            
            # Update resource metrics
            self._update_resource_metrics(result)
            
            # Record execution
            self.execution_history.append({
                "task_id": task_node.get("id"),
                "result": result,
                "timestamp": datetime.now().isoformat(),
            })
            
            self.status = AgentStatus.IDLE
            return result
            
        except Exception as e:
            self.status = AgentStatus.ERROR
            return {
                "success": False,
                "error": str(e),
                "task_id": task_node.get("id"),
            }
    
    async def _execute_task(self, task_node: Dict[str, Any]) -> Dict[str, Any]:
        """Internal task execution logic"""
        task_type = task_node.get("type", "generic")
        description = task_node.get("description", "")
        
        # Check if we have a tool for this task
        if task_type in self.tools:
            tool_func = self.tools[task_type]
            return await tool_func(task_node)
        
        # Default execution
        return {
            "success": True,
            "outputs": {"result": f"Executed: {description}"},
            "task_id": task_node.get("id"),
            "agent_id": self.id,
        }
    
    async def _update_memory(self, task_node: Dict[str, Any], result: Dict[str, Any]):
        """Update memory with task execution results"""
        if not self.memory_ref:
            return
        
        memory_entry = {
            "id": str(uuid.uuid4()),
            "text": f"Task: {task_node.get('description')}\nResult: {result.get('outputs', {})}",
            "vector": [],  # Will be computed by UMB
            "metadata": {
                "author_agent": self.id,
                "timestamp": datetime.now().isoformat(),
                "permission_level": "agent_private",
                "task_id": task_node.get("id"),
            }
        }
        
        await self.memory_ref.upsert(memory_entry)
    
    def _estimate_cost(self, task: Dict[str, Any]) -> Dict[str, float]:
        """Estimate resource cost for a task"""
        return {
            "tokens": 1000,  # Default estimate
            "api_calls": 1,
            "cpu_time": 0.1,
            "wall_time": 5.0,
        }
    
    def _update_resource_metrics(self, result: Dict[str, Any]):
        """Update resource usage metrics"""
        cost = result.get("cost", {})
        self.resource_metrics["token_usage"] += cost.get("tokens", 0)
        self.resource_metrics["api_calls"] += cost.get("api_calls", 0)
        self.resource_metrics["cpu_estimate"] += cost.get("cpu_time", 0)
        self.resource_metrics["wall_time"] += cost.get("wall_time", 0)
    
    async def debate(self, proposal: Dict[str, Any], other_agents: List['Agent']) -> Dict[str, Any]:
        """
        Participate in a debate with other agents about a proposal.
        
        Args:
            proposal: Proposal to debate
            other_agents: Other agents in the debate
            
        Returns:
            Debate response (vote, counter-proposal, etc.)
        """
        # Simple debate logic - can be extended with LLM reasoning
        return {
            "agent_id": self.id,
            "proposal_id": proposal.get("id"),
            "vote": "approve",  # Default
            "reasoning": f"{self.name} approves based on skills: {self.skills}",
            "confidence": 0.8,
        }
    
    def request_tool(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Request a tool execution (delegated to tool registry or MCP).
        
        Args:
            tool_name: Name of the tool
            params: Tool parameters
            
        Returns:
            Tool execution result
        """
        if tool_name in self.tools:
            return asyncio.run(self.tools[tool_name](params))
        
        return {
            "success": False,
            "error": f"Tool '{tool_name}' not available",
        }
    
    def register_tool(self, name: str, tool_func: Callable):
        """Register a tool function"""
        self.tools[name] = tool_func
    
    def merge_with(
        self,
        other_agents: List['Agent'],
        merge_policy: str = "union",
        temporary: bool = True,
        mission_id: Optional[str] = None
    ) -> Any:  # Returns CompositeAgent, but using Any to avoid circular import
        """
        Merge with other agents to create a composite agent.
        
        Args:
            other_agents: List of agents to merge with
            merge_policy: "union", "intersection", or "weighted"
            temporary: Whether merge is temporary (mission-scoped)
            mission_id: Mission ID if temporary
            
        Returns:
            CompositeAgent instance
        """
        # Import here to avoid circular dependency
        from agentos.core.composite_agent import CompositeAgent
        
        return CompositeAgent.create(
            agents=[self] + other_agents,
            merge_policy=merge_policy,
            temporary=temporary,
            mission_id=mission_id,
        )
    
    def adapt_strategy(self, metrics: Dict[str, Any]):
        """
        Adapt execution strategy based on resource metrics.
        
        Args:
            metrics: Current resource metrics
        """
        # Check if approaching limits
        quota = self.resource_quota
        
        if metrics.get("token_usage", 0) > quota.token_limit * 0.8:
            # Switch to cost-saving mode
            self.resource_metrics["strategy"] = "cost_saving"
        elif metrics.get("wall_time", 0) > quota.wall_time_limit * 0.7:
            # Switch to fast mode
            self.resource_metrics["strategy"] = "fast_mode"
        else:
            # Default thorough mode
            self.resource_metrics["strategy"] = "thorough_mode"
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize agent to dictionary"""
        return {
            "id": self.id,
            "name": self.name,
            "roles": self.roles,
            "skills": self.skills,
            "status": self.status.value,
            "identity": {
                "public_id": self.identity.public_id,
                "reputation_score": self.identity.reputation_score,
            },
            "resource_metrics": self.resource_metrics,
        }

