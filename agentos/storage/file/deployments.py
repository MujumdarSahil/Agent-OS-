"""4.3: file-backed environments (staging / production) per flow.

Layout: ``<project>/.agentos/flows/<flow_id>/environments.json`` ({current, history, settings, archived_versions})
and ``<project>/.agentos/state/environments.json`` (global staging channel mapping).

Every read-check-write runs under an in-process lock AND an exclusive lock file (``O_CREAT | O_EXCL``), so a
compare-and-set is atomic across threads and processes. The file itself is replaced atomically
(``atomic_write_text``), so a crash leaves either the old or the new content.
"""

from __future__ import annotations

import json
import os
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from agentos.storage.atomic import atomic_write_text
from agentos.storage.models import DeploymentRecord, EnvironmentSettings, StagingChannels
from agentos.storage.ports import DeploymentConflict

HISTORY_KEEP = 500
LOCK_TIMEOUT_S = 10.0
STALE_LOCK_S = 30.0

_locks_guard = threading.Lock()
_locks: Dict[str, threading.Lock] = {}


def _thread_lock(path: Path) -> threading.Lock:
    key = str(path).lower()
    with _locks_guard:
        return _locks.setdefault(key, threading.Lock())


@contextmanager
def _locked(path: Path) -> Iterator[None]:
    """In-process lock plus an exclusive lock file next to ``path`` (cross-process)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_file = path.with_name(path.name + ".lock")
    tlock = _thread_lock(path)
    if not tlock.acquire(timeout=LOCK_TIMEOUT_S):
        raise TimeoutError(f"could not lock {path.name}")
    try:
        deadline = time.monotonic() + LOCK_TIMEOUT_S
        while True:
            try:
                fd = os.open(str(lock_file), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.close(fd)
                break
            except FileExistsError:
                try:
                    if time.time() - lock_file.stat().st_mtime > STALE_LOCK_S:
                        lock_file.unlink(missing_ok=True)  # left behind by a crashed process
                        continue
                except FileNotFoundError:
                    continue
                if time.monotonic() > deadline:
                    raise TimeoutError(f"could not lock {path.name}") from None
                time.sleep(0.02)
        try:
            yield
        finally:
            lock_file.unlink(missing_ok=True)
    finally:
        tlock.release()


def _read(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    text = path.read_text(encoding="utf-8")
    return json.loads(text) if text.strip() else {}


def _write(path: Path, doc: Dict[str, Any]) -> None:
    atomic_write_text(path, json.dumps(doc, indent=2, default=str))


class FileDeploymentRepository:
    def __init__(self, project_path: str) -> None:
        from agentos.storage.file import safe_key

        self._safe_key = safe_key
        self._flows = Path(project_path) / ".agentos" / "flows"
        self._global = Path(project_path) / ".agentos" / "state" / "environments.json"

    def _path(self, flow_id: str) -> Path:
        return self._flows / self._safe_key(flow_id) / "environments.json"

    # ------------------------------------------------------------------ deployments
    async def get(self, flow_id: str, environment: str) -> Optional[DeploymentRecord]:
        d = (_read(self._path(flow_id)).get("current") or {}).get(environment)
        return DeploymentRecord.model_validate(d) if d else None

    async def current(self, flow_id: str) -> Dict[str, DeploymentRecord]:
        cur = _read(self._path(flow_id)).get("current") or {}
        return {env: DeploymentRecord.model_validate(d) for env, d in cur.items() if d}

    async def set(self, record: DeploymentRecord, expected_version: Optional[int]) -> DeploymentRecord:
        path = self._path(record.flow_id)
        with _locked(path):
            doc = _read(path)
            cur = (doc.get("current") or {}).get(record.environment)
            now = cur.get("version") if cur else None
            if now != expected_version:
                raise DeploymentConflict(record.flow_id, record.environment, expected_version, now)
            record = record.model_copy(update={"previous_version": now})
            data = record.model_dump(mode="json")
            doc.setdefault("current", {})[record.environment] = data
            hist = doc.setdefault("history", [])
            hist.append(data)
            del hist[:-HISTORY_KEEP]
            _write(path, doc)
        return record

    async def history(self, flow_id: str, limit: int = 100) -> List[DeploymentRecord]:
        hist = _read(self._path(flow_id)).get("history") or []
        return [DeploymentRecord.model_validate(d) for d in reversed(hist[-limit:])]

    # ------------------------------------------------------------------ settings
    async def get_settings(self, flow_id: str) -> Optional[EnvironmentSettings]:
        d = _read(self._path(flow_id)).get("settings")
        return EnvironmentSettings.model_validate(d) if d else None

    async def put_settings(self, settings: EnvironmentSettings) -> None:
        path = self._path(settings.flow_id)
        with _locked(path):
            doc = _read(path)
            doc["settings"] = settings.model_dump(mode="json")
            _write(path, doc)

    async def create_settings(self, settings: EnvironmentSettings) -> bool:
        path = self._path(settings.flow_id)
        with _locked(path):
            doc = _read(path)
            if doc.get("settings"):
                return False
            doc["settings"] = settings.model_dump(mode="json")
            _write(path, doc)
            return True

    async def archived_versions(self, flow_id: str) -> List[int]:
        return sorted(int(v) for v in _read(self._path(flow_id)).get("archived_versions") or [])

    async def archive_version(self, flow_id: str, version: int) -> None:
        path = self._path(flow_id)
        with _locked(path):
            doc = _read(path)
            vs = set(doc.get("archived_versions") or [])
            vs.add(int(version))
            doc["archived_versions"] = sorted(vs)
            _write(path, doc)

    # ------------------------------------------------------------------ global
    async def get_staging_channels(self) -> StagingChannels:
        d = _read(self._global).get("staging_channels")
        return StagingChannels.model_validate(d) if d else StagingChannels()

    async def put_staging_channels(self, channels: StagingChannels) -> None:
        with _locked(self._global):
            doc = _read(self._global)
            doc["staging_channels"] = channels.model_dump(mode="json")
            _write(self._global, doc)
