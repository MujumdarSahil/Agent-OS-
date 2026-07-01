"""
Crew Builder - Proposes complete agent teams, processes, and task structures from project goals
"""

import logging
from typing import Dict, Any, List
from pydantic import BaseModel, Field

from agentos.llm import LLMClient

logger = logging.getLogger(__name__)

class BuilderAgentInCrew(BaseModel):
    """Schema for agents generated within a crew context"""
    name: str = Field(..., description="Short alphanumeric identifier, e.g. Researcher")
    role: str = Field(..., description="Role/description of agent's function")
    goal: str = Field(..., description="Core objective of this agent")
    backstory: str = Field(default="", description="Detailed personality backstory")
    suggested_tools: List[str] = Field(default_factory=list, description="Suggested tool names")


class BuilderTaskInCrew(BaseModel):
    """Schema for tasks generated within a crew context"""
    description: str = Field(..., description="Details of the task to perform")
    assigned_agent: str = Field(..., description="Name of the agent assigned to this task")


class BuilderCrewSchema(BaseModel):
    """Schema for overall crew generation output"""
    name: str = Field(..., description="Name of the crew, e.g. ResearchAndWriteCrew")
    process: str = Field("sequential", description="Process execution type, e.g. sequential or hierarchical")
    agents: List[BuilderAgentInCrew] = Field(..., description="List of proposed agents")
    tasks: List[BuilderTaskInCrew] = Field(..., description="List of sequential tasks for the mission")


class CrewBuilder:
    """
    Constructs entire AgentOS Crew configurations from natural language project goals.
    """
    
    def __init__(self, llm_client: LLMClient):
        self.llm_client = llm_client

    def create_from_goal(self, project_goal: str) -> Dict[str, Any]:
        """
        Sends structured prompts to LLMClient.complete() requesting JSON with crew definition.
        """
        system_prompt = (
            "You are an expert multi-agent squad architect for the AgentOS framework.\n"
            "Given a project goal, propose a squad configuration matching this exact JSON schema:\n"
            "{\n"
            "  \"name\": \"ResearchCrew\",\n"
            "  \"process\": \"sequential\",\n"
            "  \"agents\": [\n"
            "    {\n"
            "      \"name\": \"Researcher\",\n"
            "      \"role\": \"Senior Web Researcher\",\n"
            "      \"goal\": \"Search for raw facts on the requested topic\",\n"
            "      \"backstory\": \"An analytical agent specializing in search retrieval\",\n"
            "      \"suggested_tools\": [\"web_search\"]\n"
            "    }\n"
            "  ],\n"
            "  \"tasks\": [\n"
            "    {\n"
            "      \"description\": \"Use web search tool to find raw facts about AgentOS.\",\n"
            "      \"assigned_agent\": \"Researcher\"\n"
            "    }\n"
            "  ]\n"
            "}\n"
            "Output ONLY raw JSON. Do NOT wrap it in markdown code blocks."
        )
        
        user_prompt = f"Project goal: {project_goal}"
        
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]
        
        try:
            res = self.llm_client.complete(messages=messages)
            content = res.get("choices", [{}])[0].get("message", {}).get("content", "").strip()
            content = self._clean_json(content)
            return BuilderCrewSchema.model_validate_json(content).model_dump()
        except Exception as e:
            logger.warning(f"Initial crew generation failed: {e}. Retrying once...")
            messages.append({"role": "assistant", "content": locals().get("content", "")})
            messages.append({
                "role": "user",
                "content": f"Your last response was not valid JSON or failed schema validation: {e}. Please return ONLY the raw JSON conforming to the schema."
            })
            res = self.llm_client.complete(messages=messages)
            content = res.get("choices", [{}])[0].get("message", {}).get("content", "").strip()
            content = self._clean_json(content)
            return BuilderCrewSchema.model_validate_json(content).model_dump()

    def _clean_json(self, text: str) -> str:
        text = text.strip()
        if text.startswith("```json"):
            text = text[7:]
        elif text.startswith("```"):
            text = text[3:]
        if text.endswith("```"):
            text = text[:-3]
        return text.strip()
