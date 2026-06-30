from typing import Any, Optional, List
from agentos.core.agent import Agent
from agentos.llm.llm_client import LLMClient
from agentos.core.base import BaseTool, BaseMemory

class DemoCustomAgent(Agent):
    """
    DemoCustomAgent - A custom agent defined in an external python package.
    """
    def __init__(
        self,
        name: str = "DemoCustom",
        role: str = "External Demo Specialist",
        goal: str = "Demonstrate AgentOS external extensibility",
        backstory: str = "",
        llm_client: Optional[LLMClient] = None,
        tools: Optional[List[BaseTool]] = None,
        memory: Optional[BaseMemory] = None,
        **kwargs: Any
    ):
        if not backstory:
            backstory = "An agent loaded dynamically from an external package to showcase AgentOS extensibility."
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
        self.is_custom_demo_agent = True
