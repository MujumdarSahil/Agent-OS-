"""
Standalone storage backend: today's v1 project layout, no server needed.

  agents, squads (crews), missions -> <project>/{agents,crews,missions}/*.yaml via project_ops
  checkpoints                      -> SQLiteCheckpointStore at <project>/checkpoints/run_history.db
  tools (stored), MCP servers,
  provider configs, runs, events   -> JSON under <project>/.agentos/
  credentials (encrypted)          -> one JSON file, default ~/.agentos/vault.json

Single-process: event sequence numbers are serialised with an in-process lock.
"""

import asyncio
import glob
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Dict, Generic, List, Optional, Type, TypeVar

import yaml
from pydantic import BaseModel

from agentos.core import project_ops
from agentos.core.checkpoint import SQLiteCheckpointStore
from agentos.core.config_models import CrewYAMLConfig
from agentos.storage.models import (
    AgentRecord,
    EncryptedSecretRecord,
    EventRecord,
    PROJECT_SETTINGS,
    MCPServerRecord,
    MissionRecord,
    ProjectSettingsRecord,
    ProviderConfigRecord,
    RunRecord,
    SquadRecord,
    ToolRecord,
    entity_key,
)
from agentos.storage.ports import ReadOnlyEntityError, Storage

M = TypeVar("M", bound=BaseModel)

_SAFE_KEY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.\-]*")


def safe_key(name: str) -> str:
    """Slug a name and refuse anything that could escape its directory."""
    key = entity_key(name)
    if not _SAFE_KEY.fullmatch(key) or ".." in key:
        raise ValueError(f"Invalid entity name for file storage: {name!r}")
    return key


def _atomic_write(path: Path, text: str, private: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        if private:
            os.chmod(tmp, 0o600)  # best effort on Windows
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise


# ---------------------------------------------------------------------------
# v1 YAML entities
# ---------------------------------------------------------------------------

class FileAgentRepository:
    def __init__(self, project_path: str):
        self._p = project_path

    async def list(self) -> List[AgentRecord]:
        return project_ops.list_agents(self._p)

    async def get(self, name: str) -> Optional[AgentRecord]:
        safe_key(name)
        try:
            return project_ops.read_agent(self._p, name)
        except FileNotFoundError:
            return None

    async def put(self, item: AgentRecord) -> None:
        safe_key(item.name)
        project_ops.write_agent(self._p, AgentRecord(**item.model_dump()))

    async def delete(self, name: str) -> bool:
        safe_key(name)
        return project_ops.delete_agent(self._p, name)


class FileSquadRepository:
    """Crews as squads. Plain crews are written byte-identical to v1; ``roles`` is an extra key v1 ignores."""

    def __init__(self, project_path: str):
        self._p = project_path
        self._dir = os.path.join(project_path, "crews")

    async def list(self) -> List[SquadRecord]:
        results = []
        for fpath in glob.glob(os.path.join(self._dir, "*.yaml")):
            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    results.append(SquadRecord(**(yaml.safe_load(f) or {})))
            except Exception as e:  # same skip-invalid behaviour as project_ops.list_crews
                project_ops.logger.warning(f"Skipping invalid crew file {fpath}: {e}")
        return results

    async def get(self, name: str) -> Optional[SquadRecord]:
        path = os.path.join(self._dir, f"{safe_key(name)}.yaml")
        if not os.path.exists(path):
            return None
        with open(path, "r", encoding="utf-8") as f:
            return SquadRecord(**(yaml.safe_load(f) or {}))

    async def put(self, item: SquadRecord) -> None:
        key = safe_key(item.name)
        if not item.roles:
            project_ops.write_crew(self._p, CrewYAMLConfig(**item.model_dump(exclude={"roles"})))
            return
        _atomic_write(Path(self._dir) / f"{key}.yaml", yaml.safe_dump(item.model_dump()))

    async def delete(self, name: str) -> bool:
        safe_key(name)
        return project_ops.delete_crew(self._p, name)


class FileMissionRepository:
    def __init__(self, project_path: str):
        self._p = project_path

    async def list(self) -> List[MissionRecord]:
        return project_ops.list_missions(self._p)

    async def get(self, name: str) -> Optional[MissionRecord]:
        path = os.path.join(self._p, "missions", f"{safe_key(name)}.yaml")
        if not os.path.exists(path):
            return None
        return project_ops.read_mission(self._p, name)

    async def put(self, item: MissionRecord) -> None:
        safe_key(item.name)
        project_ops.write_mission(self._p, MissionRecord(**item.model_dump()))

    async def delete(self, name: str) -> bool:
        safe_key(name)
        return project_ops.delete_mission(self._p, name)


# ---------------------------------------------------------------------------
# 2.0 entities as JSON documents
# ---------------------------------------------------------------------------

class JsonDirRepository(Generic[M]):
    """One ``<key>.json`` per entity in a directory."""

    def __init__(self, directory: Path, model: Type[M]):
        self._dir = directory
        self._model = model

    def _path(self, name: str) -> Path:
        return self._dir / f"{safe_key(name)}.json"

    async def list(self) -> List[M]:
        if not self._dir.exists():
            return []
        return [self._model.model_validate_json(p.read_text(encoding="utf-8"))
                for p in sorted(self._dir.glob("*.json"))]

    async def get(self, name: str) -> Optional[M]:
        path = self._path(name)
        if not path.exists():
            return None
        return self._model.model_validate_json(path.read_text(encoding="utf-8"))

    async def put(self, item: M) -> None:
        _atomic_write(self._path(item.name), item.model_dump_json(indent=2))

    async def delete(self, name: str) -> bool:
        path = self._path(name)
        if not path.exists():
            return False
        path.unlink()
        return True


class FileToolRepository(JsonDirRepository[ToolRecord]):
    """
    Stored tools live in ``.agentos/tools/*.json`` and are never written to ``tools/``,
    because the v1 runtime imports every ``tools/*.py``. v1 tool files are listed
    read-only with ``origin="project"``.
    """

    def __init__(self, project_path: str):
        super().__init__(Path(project_path) / ".agentos" / "tools", ToolRecord)
        self._project_tools = Path(project_path) / "tools"

    def _project_tool(self, name: str) -> Optional[ToolRecord]:
        path = self._project_tools / f"{safe_key(name)}.py"
        if not path.exists():
            return None
        return ToolRecord(name=path.stem, code=path.read_text(encoding="utf-8"), origin="project")

    async def list(self) -> List[ToolRecord]:
        stored = await super().list()
        names = {entity_key(t.name) for t in stored}
        project = [self._project_tool(p.stem) for p in sorted(self._project_tools.glob("*.py"))
                   if entity_key(p.stem) not in names] if self._project_tools.exists() else []
        return stored + project

    async def get(self, name: str) -> Optional[ToolRecord]:
        return await super().get(name) or self._project_tool(name)

    async def put(self, item: ToolRecord) -> None:
        if item.origin != "stored" or self._project_tool(item.name) is not None:
            raise ReadOnlyEntityError(f"Tool '{item.name}' is a v1 project file (tools/*.py); edit it on disk")
        await super().put(item)

    async def delete(self, name: str) -> bool:
        if await super().get(name) is None and self._project_tool(name) is not None:
            raise ReadOnlyEntityError(f"Tool '{name}' is a v1 project file (tools/*.py); delete it on disk")
        return await super().delete(name)


class JsonFileMapRepository(Generic[M]):
    """All entities in a single JSON object file (used for the Standalone vault)."""

    def __init__(self, path: Path, model: Type[M], private: bool = False):
        self._path = path
        self._model = model
        self._private = private

    def _load(self) -> Dict[str, Any]:
        if not self._path.exists():
            return {}
        return json.loads(self._path.read_text(encoding="utf-8") or "{}")

    def _save(self, data: Dict[str, Any]) -> None:
        _atomic_write(self._path, json.dumps(data, indent=2, sort_keys=True), private=self._private)

    async def list(self) -> List[M]:
        return [self._model.model_validate(v) for _, v in sorted(self._load().items())]

    async def get(self, name: str) -> Optional[M]:
        raw = self._load().get(safe_key(name))
        return self._model.model_validate(raw) if raw is not None else None

    async def put(self, item: M) -> None:
        data = self._load()
        data[safe_key(item.name)] = item.model_dump(mode="json")
        self._save(data)

    async def delete(self, name: str) -> bool:
        data = self._load()
        if data.pop(safe_key(name), None) is None:
            return False
        self._save(data)
        return True


# ---------------------------------------------------------------------------
# Runs, events, checkpoints
# ---------------------------------------------------------------------------

class FileRunRepository:
    def __init__(self, project_path: str):
        self._dir = Path(project_path) / ".agentos" / "runs"

    def _path(self, run_id: str) -> Path:
        if not _SAFE_KEY.fullmatch(run_id):
            raise ValueError(f"Invalid run id: {run_id!r}")
        return self._dir / f"{run_id}.json"

    async def put(self, run: RunRecord) -> None:
        _atomic_write(self._path(run.run_id), run.model_dump_json(indent=2))

    async def get(self, run_id: str) -> Optional[RunRecord]:
        path = self._path(run_id)
        return RunRecord.model_validate_json(path.read_text(encoding="utf-8")) if path.exists() else None

    async def list(self, limit: int = 100) -> List[RunRecord]:
        if not self._dir.exists():
            return []
        runs = [RunRecord.model_validate_json(p.read_text(encoding="utf-8")) for p in self._dir.glob("*.json")]
        runs.sort(key=lambda r: r.created_at, reverse=True)
        return runs[:limit]


class FileEventRepository:
    def __init__(self, project_path: str):
        self._dir = Path(project_path) / ".agentos" / "events"
        self._locks: Dict[str, asyncio.Lock] = {}

    def _path(self, run_id: str) -> Path:
        if not _SAFE_KEY.fullmatch(run_id):
            raise ValueError(f"Invalid run id: {run_id!r}")
        return self._dir / f"{run_id}.jsonl"

    def _read(self, run_id: str) -> List[EventRecord]:
        path = self._path(run_id)
        if not path.exists():
            return []
        with open(path, "r", encoding="utf-8") as f:
            return [EventRecord.model_validate_json(line) for line in f if line.strip()]

    async def append(self, run_id: str, type: str, data: Optional[Dict[str, Any]] = None) -> EventRecord:
        lock = self._locks.setdefault(run_id, asyncio.Lock())
        async with lock:
            events = self._read(run_id)
            event = EventRecord(run_id=run_id, seq=len(events) + 1, type=type, data=data or {})
            self._dir.mkdir(parents=True, exist_ok=True)
            with open(self._path(run_id), "a", encoding="utf-8") as f:
                f.write(event.model_dump_json() + "\n")
            return event

    async def list(self, run_id: str, after_seq: int = 0) -> List[EventRecord]:
        return [e for e in self._read(run_id) if e.seq > after_seq]


class FileCheckpointRepository:
    """
    Async wrapper over the v1 SQLiteCheckpointStore (same db file the v1 runtime uses).
    The db is opened on first use, so reading a project never creates files in it.
    """

    def __init__(self, project_path: str):
        self._db_path = os.path.join(project_path, "checkpoints", "run_history.db")
        self._store_instance: Optional[SQLiteCheckpointStore] = None

    @property
    def _store(self) -> SQLiteCheckpointStore:
        if self._store_instance is None:
            self._store_instance = SQLiteCheckpointStore(self._db_path)
        return self._store_instance

    async def save_checkpoint(self, mission_id: str, task_index: int, state: Dict[str, Any]) -> None:
        await asyncio.to_thread(self._store.save_checkpoint, mission_id, task_index, dict(state))

    async def load_latest_checkpoint(self, mission_id: str) -> Optional[Dict[str, Any]]:
        return await asyncio.to_thread(self._store.load_latest_checkpoint, mission_id)

    async def list_runs(self, mission_id: Optional[str] = None) -> List[Dict[str, Any]]:
        return await asyncio.to_thread(self._store.list_runs, mission_id)

    async def mark_complete(self, mission_id: str) -> None:
        await asyncio.to_thread(self._store.mark_complete, mission_id)


class FileSettingsRepository:
    """``agentos.config.yaml`` exposed as the single "project" settings record."""

    def __init__(self, project_path: str):
        self._p = project_path
        self._path = Path(project_path) / "agentos.config.yaml"

    async def list(self) -> List[ProjectSettingsRecord]:
        record = await self.get(PROJECT_SETTINGS)
        return [record] if record else []

    async def get(self, name: str) -> Optional[ProjectSettingsRecord]:
        if entity_key(name) != PROJECT_SETTINGS or not self._path.exists():
            return None
        return ProjectSettingsRecord(**project_ops.load_project_config(self._p).model_dump())

    async def put(self, item: ProjectSettingsRecord) -> None:
        # File names are the files themselves here, so v1_file_names is not persisted.
        _atomic_write(self._path, yaml.safe_dump(item.model_dump(exclude={"name", "v1_file_names"})))

    async def delete(self, name: str) -> bool:
        raise ReadOnlyEntityError("agentos.config.yaml defines the project; delete the project directory instead")


def default_vault_path() -> Path:
    return Path(os.environ.get("AGENTOS_VAULT_PATH") or Path.home() / ".agentos" / "vault.json")


def open_file_storage(project_path: str, vault_path: Optional[str] = None) -> Storage:
    project_path = os.path.abspath(project_path)
    meta = Path(project_path) / ".agentos"
    return Storage(
        backend="file",
        agents=FileAgentRepository(project_path),
        squads=FileSquadRepository(project_path),
        missions=FileMissionRepository(project_path),
        tools=FileToolRepository(project_path),
        mcp_servers=JsonDirRepository(meta / "mcp_servers", MCPServerRecord),
        provider_configs=JsonDirRepository(meta / "providers", ProviderConfigRecord),
        credentials=JsonFileMapRepository(
            Path(vault_path) if vault_path else default_vault_path(), EncryptedSecretRecord, private=True
        ),
        runs=FileRunRepository(project_path),
        checkpoints=FileCheckpointRepository(project_path),
        events=FileEventRepository(project_path),
        settings=FileSettingsRepository(project_path),
        location=project_path,
    )
