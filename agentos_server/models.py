"""
API Pydantic request/response models for the AgentOS FastAPI server.
These are thin wrappers / companions to config_models.py — no duplication
of validation logic; all constraints come from the shared core schemas.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from agentos.core.config_models import (
    AgentYAMLConfig,
    CrewYAMLConfig,
    MissionYAMLConfig,
)


# ---------------------------------------------------------------------------
# Re-export core schemas as API request bodies (no divergence)
# ---------------------------------------------------------------------------
AgentCreateRequest = AgentYAMLConfig
CrewCreateRequest = CrewYAMLConfig
MissionCreateRequest = MissionYAMLConfig


# ---------------------------------------------------------------------------
# Tool
# ---------------------------------------------------------------------------
class ToolScaffoldRequest(BaseModel):
    name: str = Field(..., min_length=1, description="snake_case tool name")
    description: str = ""


class ToolInfo(BaseModel):
    name: str
    file: str


# ---------------------------------------------------------------------------
# Run management
# ---------------------------------------------------------------------------
class RunRequest(BaseModel):
    resume: bool = False
    license_key: Optional[str] = None


class RunStatusResponse(BaseModel):
    run_id: str
    mission_name: str
    status: str          # queued | running | completed | failed
    task_index: int = 0
    outputs: List[str] = Field(default_factory=list)
    error: Optional[str] = None
    provider: Optional[str] = None   # Which LLM provider served the last call


class RunStartResponse(BaseModel):
    run_id: str
    mission_name: str
    status: str = "queued"


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------
class BuilderDescriptionRequest(BaseModel):
    description: str = Field(..., min_length=1)


class BuilderPreviewResponse(BaseModel):
    """Returned by /api/builder/*/preview — nothing written to disk yet."""
    config: Dict[str, Any]
    preview_token: str   # Opaque token the confirm endpoint accepts


class BuilderConfirmRequest(BaseModel):
    config: Dict[str, Any]


class BuilderConfirmResponse(BaseModel):
    file_path: str
    config: Dict[str, Any]


# ---------------------------------------------------------------------------
# Governance
# ---------------------------------------------------------------------------
class PolicyInfo(BaseModel):
    id: str
    name: str
    policy_type: str
    priority: int


class PolicyCreateRequest(BaseModel):
    name: str = Field(..., min_length=1)
    policy_type: str = "action"   # action | privacy | resource | safety
    denied_keywords: List[str] = Field(default_factory=list)
    allowed_keywords: List[str] = Field(default_factory=list)
    priority: int = 0


# ---------------------------------------------------------------------------
# MCP Plugins
# ---------------------------------------------------------------------------
class MCPPluginInfo(BaseModel):
    name: str
    version: str
    author: str
    permissions: List[str]
    entrypoint: str
    mcp_server_url: Optional[str]


class MCPPluginScaffoldRequest(BaseModel):
    name: str = Field(..., min_length=1)


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------
class HealthResponse(BaseModel):
    status: str = "ok"
    version: str = "0.0.0"
    project: str
    has_project: bool = False
    agents: int = 0
    tools: int = 0
    crews: int = 0
    missions: int = 0
    last_used_model: Optional[str] = "No model used yet"
    fallback_events: int = 0


# ---------------------------------------------------------------------------
# Packaging
# ---------------------------------------------------------------------------
class PackBuildRequest(BaseModel):
    include_agents: List[str] = Field(default_factory=list)
    include_tools: List[str] = Field(default_factory=list)
    include_crews: List[str] = Field(default_factory=list)
    output_name: str = "bundle.agentpack"


class PackSignRequest(BaseModel):
    pack_path: str
    private_key_path: str


class PackVerifyRequest(BaseModel):
    pack_path: str


class PackVerifyResponse(BaseModel):
    valid: bool
    signer_fingerprint: Optional[str]
    detail: str


class PackInstallRequest(BaseModel):
    pack_path: str
    target_project_path: str
    force: bool = False
    license_key: Optional[str] = None


# ---------------------------------------------------------------------------
# Checkpoints
# ---------------------------------------------------------------------------
class CheckpointRecord(BaseModel):
    mission_id: str
    task_index: int
    status: str
    timestamp: str
    provider: Optional[str] = "unknown"

# ---------------------------------------------------------------------------
# Provider management
# ---------------------------------------------------------------------------
class ProviderStatusResponse(BaseModel):
    name: str
    display_name: str
    litellm_model: str
    priority: int
    tags: List[str]
    api_key_configured: bool
    api_key_env: Optional[str] = None
    api_base_env: Optional[str] = None
    status: str
    is_local: bool

class ProviderKeysRequest(BaseModel):
    provider_name: str
    api_key: Optional[str] = None
    api_base_url: Optional[str] = None
    model_name: Optional[str] = None

class ProviderKeysResponse(BaseModel):
    success: bool
    provider_name: str
    key_env_var: Optional[str] = None

class FallbackChainItem(BaseModel):
    order: int
    name: str
    display_name: str
    litellm_model: str
    status: str

class ProviderTestResponse(BaseModel):
    success: bool
    latency_ms: int
    response: Optional[str] = None
    error: Optional[str] = None
