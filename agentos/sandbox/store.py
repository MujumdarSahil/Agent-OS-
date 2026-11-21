"""Sandbox settings store, following the storage backend like the usage settings (3.5, D6).

File: ``<project>/.agentos/state/sandbox.json`` (atomic). Mongo: collection ``sandbox_settings`` (one document).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from agentos.sandbox.models import SandboxSettings
from agentos.storage.atomic import atomic_write_text


class FileSandboxSettings:
    def __init__(self, project_path: str) -> None:
        self.path = Path(project_path) / ".agentos" / "state" / "sandbox.json"

    async def get(self) -> SandboxSettings:
        if not self.path.exists():
            return SandboxSettings()
        return SandboxSettings.model_validate_json(self.path.read_text(encoding="utf-8"))

    async def put(self, settings: SandboxSettings) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(self.path, settings.model_dump_json(indent=2))


class MongoSandboxSettings:
    def __init__(self, coll: Any) -> None:
        self._c = coll

    async def get(self) -> SandboxSettings:
        doc = await self._c.find_one({"_id": "settings"})
        if not doc:
            return SandboxSettings()
        doc = dict(doc)
        doc.pop("_id", None)
        return SandboxSettings.model_validate(doc)

    async def put(self, settings: SandboxSettings) -> None:
        await self._c.replace_one({"_id": "settings"}, {"_id": "settings", **settings.model_dump()}, upsert=True)


def sandbox_settings_store_for(storage: Any) -> Any:
    if getattr(storage, "backend", "file") == "mongo":
        return MongoSandboxSettings(storage.runs._c.database.sandbox_settings)
    return FileSandboxSettings(storage.location)
