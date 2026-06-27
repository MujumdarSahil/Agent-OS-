"""
Base Abstractions - Class-based core components for AgentOS
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
import crewai
from crewai.tools import BaseTool as CrewAIBaseTool

from agentos.llm.llm_client import LLMClient, AgentOSChatModel

# Pydantic Schemas for validation
class AgentConfig(BaseModel):
    name: str = Field(..., min_length=1, description="Name of the agent")
    role: str = Field(..., min_length=1, description="Role/description of the agent's function")
    goal: str = Field(..., min_length=1, description="Goal the agent is trying to accomplish")
    backstory: str = Field(default="", description="Backstory/personality detail for the agent")

class ToolConfig(BaseModel):
    name: str = Field(..., min_length=1, description="Name of the tool")
    description: str = Field(..., min_length=1, description="Description of what the tool does")

class MCPPluginConfig(BaseModel):
    name: str = Field(..., min_length=1)
    manifest: dict = Field(default_factory=dict)


class BaseAgent(ABC):
    """
    Every agent type subclasses this. Wraps a CrewAI Agent or LangGraph node.
    """
    def __init__(
        self,
        name: str,
        role: str,
        goal: str,
        backstory: str = "",
        llm_client: Optional[LLMClient] = None,
        tools: Optional[List["BaseTool"]] = None,
        memory: Optional["BaseMemory"] = None,
        **kwargs: Any
    ):
        # Validate configuration using Pydantic
        config = AgentConfig(name=name, role=role, goal=goal, backstory=backstory)
        self.name = config.name
        self.role = config.role
        self.goal = config.goal
        self.backstory = config.backstory
        
        self.llm_client = llm_client
        self.tools = tools or []
        self.memory = memory
        self.kwargs = kwargs

    @abstractmethod
    def to_crewai_agent(self) -> crewai.Agent:
        """Translates AgentOS agent configuration into a CrewAI Agent instance."""
        pass

    def to_langgraph_node(self) -> Any:
        """Optional override to represent this agent as a LangGraph node."""
        raise NotImplementedError("LangGraph node representation not implemented.")


class BaseTool(ABC):
    """
    Every tool subclasses this. Wraps a CrewAI/LangChain tool.
    """
    name: str
    description: str

    def __init__(self, **kwargs: Any):
        name = getattr(self, "name", None) or kwargs.get("name")
        description = getattr(self, "description", None) or kwargs.get("description")
        
        # Validate configuration using Pydantic
        config = ToolConfig(name=name, description=description)
        self.name = config.name
        self.description = config.description
        self.kwargs = kwargs

    @abstractmethod
    def run(self, **kwargs: Any) -> str:
        """Main execution logic of the tool."""
        pass

    def to_crewai_tool(self) -> CrewAIBaseTool:
        """Wraps self.run in crewai.tools.BaseTool dynamically."""
        tool_self = self
        
        class WrappedTool(CrewAIBaseTool):
            name: str = tool_self.name
            description: str = tool_self.description
            
            def _run(self, **kwargs: Any) -> str:
                return tool_self.run(**kwargs)
                
        return WrappedTool()


class BaseMemory(ABC):
    """
    Pluggable memory backend (defaults to CrewAI's built-in memory).
    """
    @abstractmethod
    def save(self, key: str, value: Dict[str, Any]) -> None:
        """Save a key-value pair to memory."""
        pass

    @abstractmethod
    def load(self, key: str) -> Optional[Dict[str, Any]]:
        """Load a key-value pair from memory."""
        pass


class BaseMCPPlugin(ABC):
    """
    Custom MCP addon plugins implement this.
    """
    name: str
    manifest: dict  # {version, permissions, entrypoint}

    def __init__(self, **kwargs: Any):
        name = getattr(self, "name", None) or kwargs.get("name")
        manifest = getattr(self, "manifest", None) or kwargs.get("manifest", {})
        
        # Validate using Pydantic
        config = MCPPluginConfig(name=name, manifest=manifest)
        self.name = config.name
        self.manifest = config.manifest
        self.kwargs = kwargs

    @abstractmethod
    def register_tools(self) -> List[BaseTool]:
        """Registers and returns a list of tools provided by the plugin."""
        pass


class AgentRegistry:
    """
    Simple in-memory Agent registry for runtime registration and creation.
    """
    def __init__(self):
        self._registry = {}

    def register(self, agent_cls: type) -> None:
        """Register an agent class."""
        self._registry[agent_cls.__name__] = agent_cls

    def create(self, class_name: str, **kwargs: Any) -> BaseAgent:
        """Create and return an agent instance from the registry."""
        if class_name not in self._registry:
            raise ValueError(f"Agent class '{class_name}' is not registered.")
        return self._registry[class_name](**kwargs)


class ToolRegistry:
    """
    Simple in-memory Tool registry for runtime registration and creation.
    """
    def __init__(self):
        self._registry = {}
        self._instances = {}

    def register(self, tool_cls: type) -> None:
        """Register a tool class."""
        self._registry[tool_cls.__name__] = tool_cls

    def register_instance(self, name: str, tool_instance: BaseTool) -> None:
        """Register a pre-instantiated tool instance under a specific namespaced key."""
        self._instances[name] = tool_instance

    def create(self, class_name: str, **kwargs: Any) -> BaseTool:
        """Create and return a tool instance from the registry."""
        if class_name in self._instances:
            return self._instances[class_name]
        if class_name not in self._registry:
            raise ValueError(f"Tool class or instance '{class_name}' is not registered.")
        return self._registry[class_name](**kwargs)
