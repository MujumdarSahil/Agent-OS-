"""
Repository interfaces (ports). No storage library is imported here: adapters live in
``agentos.storage.file`` and ``agentos.storage.mongo``.

Every method is async so the Mongo adapter can use PyMongo's async API directly.
"""

from dataclasses import dataclass
from typing import Any, Dict, Generic, List, Optional, Protocol, TypeVar, runtime_checkable

from agentos.storage.models import (
    AgentRecord,
    DeploymentRecord,
    EncryptedSecretRecord,
    EnvironmentSettings,
    EventRecord,
    FlowRecord,
    MCPServerRecord,
    MissionRecord,
    ProjectSettingsRecord,
    ProviderConfigRecord,
    RunRecord,
    ScheduleRecord,
    SquadRecord,
    StagingChannels,
    ToolRecord,
    WebhookRecord,
)

T = TypeVar("T")


class ReadOnlyEntityError(Exception):
    """Raised when writing or deleting an entity the backend exposes read-only."""


class FencingTokenError(Exception):
    """Raised when a write or operation is attempted with an expired or superseded lease."""


class DeploymentConflict(Exception):
    """4.3: an environment no longer points to the version the caller expected (another promote or rollback won)."""

    def __init__(self, flow_id: str, environment: str, expected: Optional[int], current: Optional[int]) -> None:
        super().__init__(f"{flow_id} {environment}: expected v{expected}, now v{current}")
        self.expected = expected
        self.current = current


class DuplicateIdempotencyKeyError(Exception):
    """Raised when creating a run with an idempotency key that already exists."""


@runtime_checkable
class NamedRepository(Protocol, Generic[T]):
    """Entities addressed by ``name``; keys are case/space-insensitive (v1 slug rules)."""

    async def list(self) -> List[T]: ...

    async def get(self, name: str) -> Optional[T]: ...

    async def put(self, item: T) -> None:
        """Create or replace."""
        ...

    async def delete(self, name: str) -> bool:
        """Return True if something was deleted."""
        ...


@runtime_checkable
class RunRepository(Protocol):
    async def put(self, run: RunRecord) -> None: ...

    async def get(self, run_id: str) -> Optional[RunRecord]: ...

    async def list(self, limit: int = 100) -> List[RunRecord]:
        """Newest first."""
        ...


@runtime_checkable
class CheckpointRepository(Protocol):
    """Async mirror of ``agentos.core.checkpoint.CheckpointStore`` (same shapes and semantics)."""

    async def save_checkpoint(self, mission_id: str, task_index: int, state: Dict[str, Any]) -> None: ...

    async def load_latest_checkpoint(self, mission_id: str) -> Optional[Dict[str, Any]]: ...

    async def list_runs(self, mission_id: Optional[str] = None) -> List[Dict[str, Any]]: ...

    async def mark_complete(self, mission_id: str) -> None: ...


@runtime_checkable
class FlowRepository(Protocol):
    """
    Repository for versioned workflow graphs (flows).
    Drafts are mutable; published versions are immutable.
    """

    async def get_draft(self, flow_id: str) -> Optional[FlowRecord]: ...

    async def put_draft(self, flow: FlowRecord) -> None: ...

    async def get_version(self, flow_id: str, version: int) -> Optional[FlowRecord]: ...

    async def list_versions(self, flow_id: str) -> List[FlowRecord]: ...

    async def list_flows(self) -> List[FlowRecord]: ...

    async def publish(
        self, flow_id: str, content_sha256: str, policy_hash: str, analysis: Optional[Dict[str, Any]] = None,
        published_by: Optional[str] = None, change_note: Optional[str] = None,
    ) -> FlowRecord: ...

    async def delete_flow(self, flow_id: str) -> bool:
        """Delete an unpublished flow. Raises ValueError if published versions exist."""
        ...

    async def archive_flow(self, flow_id: str) -> FlowRecord: ...


@runtime_checkable
class EventRepository(Protocol):
    async def append(
        self,
        run_id: str,
        type: str,
        data: Optional[Dict[str, Any]] = None,
        lease_id: Optional[str] = None,
    ) -> EventRecord:
        """Append an event; the repository assigns the next ``seq`` for the run."""
        ...

    async def list(self, run_id: str, after_seq: int = 0) -> List[EventRecord]:
        """Events with ``seq > after_seq`` in ascending order (for stream replay)."""
        ...


@runtime_checkable
class WebhookRepository(Protocol):
    async def list(self) -> List[WebhookRecord]: ...
    async def get(self, webhook_id: str) -> Optional[WebhookRecord]: ...
    async def get_by_path_hash(self, secret_path_hash: str) -> Optional[WebhookRecord]: ...
    async def put(self, webhook: WebhookRecord) -> None: ...
    async def delete(self, webhook_id: str) -> bool: ...


@runtime_checkable
class ScheduleRepository(Protocol):
    async def list(self) -> List[ScheduleRecord]: ...
    async def get(self, schedule_id: str) -> Optional[ScheduleRecord]: ...
    async def put(self, schedule: ScheduleRecord) -> None: ...
    async def delete(self, schedule_id: str) -> bool: ...


@runtime_checkable
class DeploymentRepository(Protocol):
    """4.3: environment pointers (staging / production -> published version), their history and per-flow settings.
    ``set`` is a compare-and-set: it raises DeploymentConflict unless the environment still points to
    ``expected_version`` (None = not deployed yet), so two concurrent promotions cannot both win."""

    async def get(self, flow_id: str, environment: str) -> Optional[DeploymentRecord]: ...
    async def current(self, flow_id: str) -> Dict[str, DeploymentRecord]: ...
    async def set(self, record: DeploymentRecord, expected_version: Optional[int]) -> DeploymentRecord: ...
    async def history(self, flow_id: str, limit: int = 100) -> List[DeploymentRecord]: ...
    async def get_settings(self, flow_id: str) -> Optional[EnvironmentSettings]: ...
    async def put_settings(self, settings: EnvironmentSettings) -> None: ...
    async def create_settings(self, settings: EnvironmentSettings) -> bool:
        """Create the settings record only if none exists; True if this call created it."""
        ...
    async def archived_versions(self, flow_id: str) -> List[int]: ...
    async def archive_version(self, flow_id: str, version: int) -> None: ...
    async def get_staging_channels(self) -> StagingChannels: ...
    async def put_staging_channels(self, channels: StagingChannels) -> None: ...


@dataclass
class Storage:
    """All repositories of one backend."""
    backend: str
    agents: NamedRepository[AgentRecord]
    squads: NamedRepository[SquadRecord]
    missions: NamedRepository[MissionRecord]
    tools: NamedRepository[ToolRecord]
    mcp_servers: NamedRepository[MCPServerRecord]
    provider_configs: NamedRepository[ProviderConfigRecord]
    credentials: NamedRepository[EncryptedSecretRecord]
    runs: RunRepository
    checkpoints: CheckpointRepository
    events: EventRepository
    flows: Optional[FlowRepository] = None
    webhooks: Optional[WebhookRepository] = None
    schedules: Optional[ScheduleRepository] = None
    settings: Optional[NamedRepository[ProjectSettingsRecord]] = None
    # 4.3: environments (staging / production) per flow
    deployments: Optional[DeploymentRepository] = None
    # Project directory for the File backend, None for Mongo.
    location: Optional[str] = None

    async def close(self) -> None:
        closer = getattr(self, "_closer", None)
        if closer is not None:
            await closer()
