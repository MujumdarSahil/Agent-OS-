"""
Config Models - Pydantic validation schemas for project YAML files
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

class GovernanceConfig(BaseModel):
    """Governance section of agentos.config.yaml"""
    llm_judge_enabled: bool = False  # Opt-in: adds ~1 LLM call per task check. Default=False for zero latency impact.


class ProjectConfig(BaseModel):
    """Schema for agentos.config.yaml"""
    preferred_tags: List[str] = Field(default_factory=list)
    default_model: Optional[str] = None
    governance: GovernanceConfig = Field(default_factory=GovernanceConfig)


class AgentYAMLConfig(BaseModel):
    """Schema for agents/*.yaml"""
    name: str = Field(..., min_length=1)
    role: str = Field(..., min_length=1)
    goal: str = Field(..., min_length=1)
    backstory: str = ""
    type: str = "Agent"
    llm_tags: List[str] = Field(default_factory=list)
    tool_refs: List[str] = Field(default_factory=list)
    memory_ref: Optional[str] = None


class ToolYAMLConfig(BaseModel):
    """Schema for tools/*.yaml"""
    name: str = Field(..., min_length=1)
    description: str = Field(..., min_length=1)


class CrewYAMLConfig(BaseModel):
    """Schema for crews/*.yaml"""
    name: str = Field(..., min_length=1)
    agents: List[str] = Field(..., min_length=1)
    process: str = "sequential"  # sequential or hierarchical


class TaskYAMLConfig(BaseModel):
    """Schema for individual tasks inside a mission"""
    description: str = Field(..., min_length=1)
    assigned_agent: Optional[str] = None


class MissionYAMLConfig(BaseModel):
    """Schema for missions/*.yaml"""
    name: str = Field(..., min_length=1)
    goal: str = Field(..., min_length=1)
    description: str = ""
    crew: str = Field(..., min_length=1)
    tasks: List[TaskYAMLConfig] = Field(default_factory=list)
