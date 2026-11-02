"""
Stored entity models for the 2.0 repositories.

Agents and missions reuse the v1 YAML schemas unchanged so both backends round-trip
v1 projects. Everything else is new in 2.0.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field, model_validator

from agentos.core.config_models import AgentYAMLConfig, CrewYAMLConfig, MissionYAMLConfig
from agentos.core.project_ops import _slug


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def entity_key(name: str) -> str:
    """Storage key for a named entity; identical to the v1 project file slug."""
    return _slug(name)


AgentRecord = AgentYAMLConfig
MissionRecord = MissionYAMLConfig


class SquadRecord(CrewYAMLConfig):
    """A v1 crew plus optional squad roles per member, e.g. {"lead": "commander"}."""
    roles: Dict[str, str] = Field(default_factory=dict)


class ToolRecord(BaseModel):
    """
    A tool definition. ``code`` is stored as text and is never imported or executed
    by the storage layer (spec principle 6: stored code runs only in a sandbox).

    ``origin="project"`` marks a v1 ``tools/*.py`` file, which the v1 runtime
    (``build_squad_from_project``) does import; such records are read-only here.
    """
    name: str = Field(..., min_length=1)
    description: str = ""
    language: Literal["python"] = "python"
    code: str = ""
    origin: Literal["stored", "project"] = "stored"


class MCPServerRecord(BaseModel):
    """An external MCP server. Values in ``env`` must not be secrets; use ``secret_env``."""
    name: str = Field(..., min_length=1)
    transport: Literal["stdio", "sse", "http"]
    command: Optional[str] = None
    args: List[str] = Field(default_factory=list)
    url: Optional[str] = None
    env: Dict[str, str] = Field(default_factory=dict)
    secret_env: Dict[str, str] = Field(default_factory=dict)  # ENV_VAR -> vault credential name
    # stdio servers launch host commands, so records start disabled until allowed.
    enabled: bool = False

    @model_validator(mode="after")
    def _check_target(self):
        if self.transport == "stdio" and not self.command:
            raise ValueError("stdio MCP servers need a command")
        if self.transport in ("sse", "http") and not self.url:
            raise ValueError(f"{self.transport} MCP servers need a url")
        return self


class ProviderConfigRecord(BaseModel):
    """Per-provider fallback policy override (order, enabled, timeout)."""
    name: str = Field(..., min_length=1)
    order: int = Field(..., ge=0)
    enabled: bool = True
    timeout_s: Optional[float] = Field(default=None, gt=0)


class EncryptedSecretRecord(BaseModel):
    """
    One vault entry, already encrypted (AES-256-GCM envelope: a per-secret data key
    wrapped by a key-encryption key that never lives in the same store).
    Repositories only store and return these fields; they never see plaintext.
    """
    name: str = Field(..., min_length=1)
    provider: Optional[str] = None
    algorithm: Literal["AES-256-GCM"] = "AES-256-GCM"
    key_id: str
    wrapped_dek: str  # base64
    nonce: str  # base64
    ciphertext: str  # base64, includes the GCM tag
    hint: str = ""  # masked display value, never the secret
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)


class RunRecord(BaseModel):
    run_id: str = Field(..., min_length=1)
    mission_name: str
    status: str = "pending"
    task_index: int = 0
    outputs: Dict[str, Any] = Field(default_factory=dict)
    error: Optional[str] = None
    provider: Optional[str] = None
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)


class EventRecord(BaseModel):
    """Append-only run event; ``seq`` is 1-based and gap-free per run."""
    run_id: str
    seq: int = Field(..., ge=1)
    type: str
    data: Dict[str, Any] = Field(default_factory=dict)
    ts: datetime = Field(default_factory=utcnow)
