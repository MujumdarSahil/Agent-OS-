"""AuditLog (3.1): record, verify, query and export the tamper-evident audit chain.

``record`` raises AuditUnavailable when the entry cannot be written; callers must then NOT apply the audited
action (fail closed). The HMAC key is derived from the master key in memory and never leaves this object.
"""

from __future__ import annotations

import datetime as _dt
import json
from typing import Any, Callable

from agentos.audit.chain import (
    AuditDetailsError,
    AuditUnavailable,
    build_entry,
    check_anchor,
    derive_key,
    make_anchor,
    make_head,
    verify_chain,
)


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="milliseconds")


class AuditLog:
    def __init__(self, store: Any, master_key: bytes, clock: Callable[[], str] = _now, anchor: Any = None) -> None:
        self.store = store
        # 3.2 (0a): an independent anchor in the main storage (not the audit folder); None = not checked
        self.anchor = anchor
        self._key = derive_key(master_key)
        self._clock = clock

    def __repr__(self) -> str:  # never print key material
        return f"AuditLog(store={type(self.store).__name__})"

    async def record(self, action: str, target_type: str, target_id: str, *, outcome: str = "ok",
                     details: dict[str, Any] | None = None, actor: str = "local-admin",
                     source: str = "api") -> dict[str, Any]:
        def build(prev: dict[str, Any] | None) -> tuple[dict[str, Any], dict[str, Any]]:
            try:
                entry = build_entry(self._key, prev, ts=self._clock(), actor=actor, source=source, action=action,
                                    target_type=target_type, target_id=target_id, outcome=outcome,
                                    details=details or {})
            except AuditDetailsError as e:
                raise AuditUnavailable(f"audit entry rejected: {e}") from None
            return entry, make_head(self._key, entry)

        entry = await self.store.append(build)
        if self.anchor is not None:  # written after the entry and head: a lagging anchor is fine, a missing one not
            try:
                await self.anchor.write(make_anchor(self._key, entry))
            except Exception as e:
                raise AuditUnavailable(f"audit anchor not writable ({type(e).__name__})") from None
        return entry

    async def verify(self) -> dict[str, Any]:
        entries, partial = await self.store.read_all()
        head = await self.store.read_head()
        result = verify_chain(entries, head, self._key, partial_tail_ignored=partial)
        if self.anchor is None:
            return result
        return check_anchor(result, entries, head, await self.anchor.read(), self._key)

    async def entries(self) -> list[dict[str, Any]]:
        entries, _ = await self.store.read_all()
        return [e for e in entries if isinstance(e, dict)]

    async def query(self, *, action: str | None = None, actor: str | None = None, target_type: str | None = None,
                    target_id: str | None = None, outcome: str | None = None, since: str | None = None,
                    until: str | None = None, before_seq: int | None = None, limit: int = 50) -> dict[str, Any]:
        """Newest first; ``before_seq`` is the cursor. ``action`` is a prefix (``flow.`` or ``flow.publish``)."""
        limit = max(1, min(int(limit), 200))
        out: list[dict[str, Any]] = []
        for e in reversed(await self.entries()):
            if before_seq is not None and e["seq"] >= before_seq:
                continue
            if action and not (e["action"] == action or e["action"].startswith(action.rstrip(".") + ".")):
                continue
            if actor and e["actor"] != actor:
                continue
            if target_type and e["target"]["type"] != target_type:
                continue
            if target_id and e["target"]["id"] != target_id:
                continue
            if outcome and e["outcome"] != outcome:
                continue
            if since and e["ts"] < since:
                continue
            if until and e["ts"] > until:
                continue
            out.append(e)
            if len(out) >= limit:
                break
        next_cursor = out[-1]["seq"] if len(out) == limit and out[-1]["seq"] > 1 else None
        return {"entries": out, "next_before_seq": next_cursor}

    async def export_jsonl(self) -> str:
        return "".join(json.dumps(e, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
                       for e in await self.entries())

    async def last(self, action: str) -> dict[str, Any] | None:
        for e in reversed(await self.entries()):
            if e["action"] == action:
                return e
        return None


def audit_anchor_for(storage: Any) -> Any:
    """3.2 (0a): the independent anchor store of a Storage backend (file: .agentos/state; mongo: audit_anchor)."""
    from agentos.audit.store import FileAnchorStore

    if getattr(storage, "backend", "file") == "mongo":
        from agentos.storage.mongo.audit import MongoAnchorStore

        return MongoAnchorStore(storage.runs._c.database.audit_anchor)
    return FileAnchorStore(storage.location)


def audit_store_for(storage: Any) -> Any:
    """The audit store of a Storage backend (file: the project dir; mongo: the same database)."""
    from agentos.audit.store import FileAuditStore

    if getattr(storage, "backend", "file") == "mongo":
        from agentos.storage.mongo.audit import MongoAuditStore  # pymongo only in Platform mode

        db = storage.runs._c.database
        return MongoAuditStore(db.audit, db.audit_head)
    return FileAuditStore(storage.location)
