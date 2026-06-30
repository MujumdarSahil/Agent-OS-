"""
Researcher Agent - Specialized agent for deep research and analysis
"""

from typing import Any, Optional, List
from agentos.core.agent import Agent
from agentos.core.base import BaseTool, BaseMemory
from agentos.llm.llm_client import LLMClient

class ResearcherAgent(Agent):
    """
    ResearcherAgent - A specialized agent class for performing research.
    """
    def __init__(
        self,
        name: str = "Researcher",
        role: str = "Research Specialist",
        goal: str = "Perform thorough research on any given topic",
        backstory: str = "",
        llm_client: Optional[LLMClient] = None,
        tools: Optional[List[BaseTool]] = None,
        memory: Optional[BaseMemory] = None,
        **kwargs: Any
    ):
        if not backstory:
            backstory = "A specialized agent focused on deep research, analysis, and information synthesis."
            
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
        self.is_researcher_subclass = True
