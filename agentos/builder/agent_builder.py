"""
Agent Builder - Uses LLMClient to generate validated agent configurations from descriptions
"""

import json
import logging
from typing import Dict, Any, Optional, List
from pydantic import BaseModel, Field

from agentos.llm import LLMClient

logger = logging.getLogger(__name__)

class BuilderAgentSchema(BaseModel):
    """Pydantic schema to validate generated agent configurations"""
    name: str = Field(..., description="Short alphanumeric name of the agent, e.g. Researcher")
    role: str = Field(..., description="Role/description of agent's function")
    goal: str = Field(..., description="Specific goal the agent is tasked to accomplish")
    backstory: str = Field(default="", description="Personality backstory details")
    suggested_tools: List[str] = Field(default_factory=list, description="List of suggested tool names")


class AgentBuilder:
    """
    Constructs AgentOS agent YAML structure from natural language descriptions using LLMClient.
    """
    
    def __init__(self, llm_client: LLMClient):
        self.llm_client = llm_client

    def create_from_description(self, description: str) -> Dict[str, Any]:
        """
        Sends a structured prompt to LLMClient.complete() requesting valid JSON matching the schema.
        Retries once on validation failure.
        """
        system_prompt = (
            "You are an expert AI agent designer for the AgentOS multi-agent framework.\n"
            "Generate a structured agent configuration matching this exact JSON schema:\n"
            "{\n"
            "  \"name\": \"Short alphanumeric identifier, e.g. CodeReviewer\",\n"
            "  \"role\": \"Role description, e.g. Security Analyst\",\n"
            "  \"goal\": \"Core objective of this agent\",\n"
            "  \"backstory\": \"Detailed description of agent personality and experience\",\n"
            "  \"suggested_tools\": [\"tool1\", \"tool2\"]\n"
            "}\n"
            "Output ONLY raw JSON. Do NOT include markdown code blocks, explanation text, or other wrappers."
        )
        
        user_prompt = f"Agent description: {description}"
        
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]
        
        logger.info("Requesting agent configuration from LLMClient...")
        try:
            res = self.llm_client.complete(messages=messages)
            content = res.get("choices", [{}])[0].get("message", {}).get("content", "").strip()
            # Clean content if the model wrapped it in markdown code block
            content = self._clean_json(content)
            return BuilderAgentSchema.model_validate_json(content).model_dump()
        except Exception as e:
            logger.warning(f"Initial LLM agent generation or parsing failed: {e}. Retrying once...")
            
            # Retry once with correction instruction
            messages.append({"role": "assistant", "content": locals().get("content", "")})
            messages.append({
                "role": "user",
                "content": f"Your last response was not valid JSON or failed schema validation: {e}. Please return ONLY the raw JSON conforming to the schema."
            })
            
            res = self.llm_client.complete(messages=messages)
            content = res.get("choices", [{}])[0].get("message", {}).get("content", "").strip()
            content = self._clean_json(content)
            return BuilderAgentSchema.model_validate_json(content).model_dump()

    def _clean_json(self, text: str) -> str:
        text = text.strip()
        if text.startswith("```json"):
            text = text[7:]
        elif text.startswith("```"):
            text = text[3:]
        if text.endswith("```"):
            text = text[:-3]
        return text.strip()
