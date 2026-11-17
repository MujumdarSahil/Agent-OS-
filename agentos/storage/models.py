"""
Stored entity models for the 2.0 repositories.

Agents and missions reuse the v1 YAML schemas unchanged so both backends round-trip
v1 projects. Everything else is new in 2.0.
"""

from datetime import datetime, timezone
from typing import Annotated, Any, Dict, List, Literal, Optional

from pydantic import AfterValidator, BaseModel, Field, model_validator

from agentos.core.config_models import AgentYAMLConfig, CrewYAMLConfig, MissionYAMLConfig, ProjectConfig
from agentos.core.project_ops import _slug


def _normalize_ts(value: datetime) -> datetime:
    """UTC, millisecond precision: what BSON can store, so every backend round-trips exactly."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    value = value.astimezone(timezone.utc)
    return value.replace(microsecond=value.microsecond // 1000 * 1000)


Timestamp = Annotated[datetime, AfterValidator(_normalize_ts)]


def utcnow() -> datetime:
    return _normalize_ts(datetime.now(timezone.utc))


def entity_key(name: str) -> str:
    """Storage key for a named entity; identical to the v1 project file slug."""
    return _slug(name)


AgentRecord = AgentYAMLConfig
MissionRecord = MissionYAMLConfig

PROJECT_SETTINGS = "project"


class ProjectSettingsRecord(ProjectConfig):
    """``agentos.config.yaml`` as a stored entity; there is one record, named "project"."""
    name: Literal["project"] = PROJECT_SETTINGS
    # v1 file stems that differ from the entity slug, e.g. {"missions": {"plangoal": "plan_goal"}}.
    # Kept so an export restores the original file names (`agentos run --mission plan_goal`
    # finds missions by file name). Never written into agentos.config.yaml.
    v1_file_names: Dict[str, Dict[str, str]] = Field(default_factory=dict)


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
    created_at: Timestamp = Field(default_factory=utcnow)
    updated_at: Timestamp = Field(default_factory=utcnow)


class FlowRecord(BaseModel):
    """
    A declarative workflow graph record.
    Status transitions: draft -> published -> archived.
    A published flow has an immutable integer version and content_sha256.
    """
    id: str = Field(..., min_length=1)
    name: str = ""
    status: Literal["draft", "published", "archived"] = "draft"
    version: Optional[int] = None
    entrypoint: str
    nodes: Dict[str, Any] = Field(default_factory=dict)
    edges: List[Dict[str, Any]] = Field(default_factory=list)
    loops: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    content_sha256: Optional[str] = None
    policy_hash: Optional[str] = None
    # 2.3: static analysis summary of a published version (reused when called as a subflow)
    analysis: Optional[Dict[str, Any]] = None
    created_at: Timestamp = Field(default_factory=utcnow)
    updated_at: Timestamp = Field(default_factory=utcnow)
    published_at: Optional[Timestamp] = None


class RunRecord(BaseModel):
    run_id: str = Field(..., min_length=1)
    mission_name: str
    flow_id: Optional[str] = None
    flow_version: Optional[int] = None
    status: str = "pending"
    task_index: int = 0
    outputs: Dict[str, Any] = Field(default_factory=dict)
    error: Optional[str] = None
    provider: Optional[str] = None
    current_lease_id: Optional[str] = None
    idempotency_key: Optional[str] = None
    # 2.3: epoch seconds when a run waiting on a wait-node timer becomes due (None otherwise)
    resume_at: Optional[float] = None
    created_at: Timestamp = Field(default_factory=utcnow)
    updated_at: Timestamp = Field(default_factory=utcnow)


class WebhookRecord(BaseModel):
    """
    Webhook trigger registration.
    The secret path is random (>=128 bits) and stored hashed (SHA-256).
    The HMAC signing secret is stored in the Credentials Vault.
    """
    webhook_id: str = Field(..., min_length=1)
    name: str = Field(..., min_length=1)
    flow_id: str = Field(..., min_length=1)
    secret_path_hash: str = Field(..., min_length=1)
    secret_key_ref: str = Field(..., min_length=1)
    rate_limit_per_minute: int = 60
    enabled: bool = True
    created_at: Timestamp = Field(default_factory=utcnow)
    updated_at: Timestamp = Field(default_factory=utcnow)


class ScheduleRecord(BaseModel):
    """
    Cron trigger registration.
    Supports standard 5-field cron expressions with explicit timezone (default UTC),
    and configurable misfire policy ("skip" | "fire_once").
    """
    schedule_id: str = Field(..., min_length=1)
    name: str = Field(..., min_length=1)
    flow_id: str = Field(..., min_length=1)
    cron_expression: str = Field(..., min_length=1)
    timezone: str = "UTC"
    inputs: Dict[str, Any] = Field(default_factory=dict)
    misfire_policy: str = "skip"  # "skip" | "fire_once"
    enabled: bool = True
    last_run_at: Optional[float] = None
    next_run_at: Optional[float] = None
    created_at: Timestamp = Field(default_factory=utcnow)
    updated_at: Timestamp = Field(default_factory=utcnow)


class EventRecord(BaseModel):
    """Append-only run event; ``seq`` is 1-based and gap-free per run."""
    run_id: str
    seq: int = Field(..., ge=1)
    type: str
    data: Dict[str, Any] = Field(default_factory=dict)
    ts: Timestamp = Field(default_factory=utcnow)
    lease_id: Optional[str] = None
