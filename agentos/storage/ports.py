"""
Repository interfaces (ports). No storage library is imported here: adapters live in
``agentos.storage.file`` and ``agentos.storage.mongo``.

Every method is async so the Mongo adapter can use PyMongo's async API directly.
"""

from dataclasses import dataclass
from typing import Any, Dict, Generic, List, Optional, Protocol, TypeVar, runtime_checkable

from agentos.storage.models import (
    AgentRecord,
    EncryptedSecretRecord,
    EventRecord,
    MCPServerRecord,
    MissionRecord,
    ProjectSettingsRecord,
    ProviderConfigRecord,
    RunRecord,
    SquadRecord,
    ToolRecord,
)

T = TypeVar("T")


class ReadOnlyEntityError(Exception):
    """Raised when writing or deleting an entity the backend exposes read-only."""


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
class EventRepository(Protocol):
    async def append(self, run_id: str, type: str, data: Optional[Dict[str, Any]] = None) -> EventRecord:
        """Append an event; the repository assigns the next ``seq`` for the run."""
        ...

    async def list(self, run_id: str, after_seq: int = 0) -> List[EventRecord]:
        """Events with ``seq > after_seq`` in ascending order (for stream replay)."""
        ...


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
    settings: Optional[NamedRepository[ProjectSettingsRecord]] = None
    # Project directory for the File backend, None for Mongo.
    location: Optional[str] = None

    async def close(self) -> None:
        closer = getattr(self, "_closer", None)
        if closer is not None:
            await closer()
