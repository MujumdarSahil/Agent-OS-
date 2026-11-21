"""Small document stores for notifications (3.3): channels, alert rules, alerts, outbox.

File backend: ``<project>/.agentos/state/notify_<name>.json`` = ``{"version": 1, "docs": {id: doc}}``, one asyncio
lock per file, atomic writes. Mongo backend: agentos/storage/mongo/notify.py (same interface; ``_id`` = id).
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, Callable, Optional

from agentos.storage.atomic import atomic_write_text

KEEP_ALERTS = 5000  # file backend: oldest alerts beyond this are dropped (their outbox entries are finished)


class FileDocs:
    def __init__(self, path: Path, keep: Optional[int] = None) -> None:
        self.path = path
        self.keep = keep
        self._lock = asyncio.Lock()

    def _load(self) -> dict[str, dict[str, Any]]:
        if not self.path.exists():
            return {}
        try:
            return json.loads(self.path.read_text(encoding="utf-8")).get("docs", {})
        except ValueError:
            return {}

    def _save(self, docs: dict[str, dict[str, Any]]) -> None:
        if self.keep is not None and len(docs) > self.keep:
            ordered = sorted(docs.values(), key=lambda d: d.get("created_ts") or 0)
            docs = {d["id"]: d for d in ordered[-self.keep:]}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(self.path, json.dumps({"version": 1, "docs": docs}, sort_keys=True))

    async def get(self, id_: str) -> Optional[dict[str, Any]]:
        d = self._load().get(id_)
        return dict(d) if d else None

    async def list(self) -> list[dict[str, Any]]:
        return [dict(d) for d in self._load().values()]

    async def put(self, doc: dict[str, Any]) -> None:
        async with self._lock:
            docs = self._load()
            docs[doc["id"]] = doc
            self._save(docs)

    async def insert_if_absent(self, doc: dict[str, Any]) -> bool:
        async with self._lock:
            docs = self._load()
            if doc["id"] in docs:
                return False
            docs[doc["id"]] = doc
            self._save(docs)
            return True

    async def delete(self, id_: str) -> bool:
        async with self._lock:
            docs = self._load()
            found = docs.pop(id_, None) is not None
            if found:
                self._save(docs)
            return found

    async def update(self, id_: str, fn: Callable[[dict[str, Any]], Optional[dict[str, Any]]]) -> Optional[dict[str, Any]]:
        """Read-modify-write under the lock. ``fn`` returns the new doc, or None to leave it unchanged."""
        async with self._lock:
            docs = self._load()
            cur = docs.get(id_)
            if cur is None:
                return None
            new = fn(dict(cur))
            if new is None:
                return None
            docs[id_] = new
            self._save(docs)
            return dict(new)


class NotifyStore:
    def __init__(self, channels: Any, rules: Any, alerts: Any, outbox: Any) -> None:
        self.channels = channels
        self.rules = rules
        self.alerts = alerts
        self.outbox = outbox


def notify_store_for(storage: Any) -> NotifyStore:
    if getattr(storage, "backend", "file") == "mongo":
        from agentos.storage.mongo.notify import MongoDocs

        db = storage.runs._c.database
        return NotifyStore(MongoDocs(db.notify_channels), MongoDocs(db.alert_rules), MongoDocs(db.alerts),
                           MongoDocs(db.alert_outbox))
    base = Path(storage.location) / ".agentos" / "state"
    return NotifyStore(FileDocs(base / "notify_channels.json"), FileDocs(base / "notify_alert_rules.json"),
                       FileDocs(base / "notify_alerts.json", keep=KEEP_ALERTS), FileDocs(base / "notify_outbox.json"))
