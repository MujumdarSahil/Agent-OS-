"""Mongo audit store (3.1): ``audit`` (seq as _id, unique prev_hash: no forks) + ``audit_head``.
See agentos/audit/store.py for the file store and docs/evidence/3.1.md for the design."""

from __future__ import annotations

from typing import Any

from pymongo.errors import DuplicateKeyError

from agentos.audit.chain import AuditUnavailable
from agentos.audit.store import Builder


class MongoAuditStore:
    """``audit`` (unique seq as _id, unique prev_hash: no forks) + ``audit_head``. An insert that conflicts on
    seq or prev_hash is retried against the new head."""

    MAX_RETRIES = 20

    def __init__(self, entries: Any, heads: Any) -> None:
        self._c = entries
        self._h = heads
        self._indexed = False

    async def _ensure_indexes(self) -> None:
        if not self._indexed:
            await self._c.create_index("prev_hash", unique=True)
            self._indexed = True

    @staticmethod
    def _strip(doc: dict[str, Any] | None) -> dict[str, Any] | None:
        if doc is None:
            return None
        d = dict(doc)
        d.pop("_id", None)
        return d

    async def read_all(self) -> tuple[list[Any], bool]:
        docs = await self._c.find({}).sort("seq", 1).to_list(None)
        return [self._strip(d) for d in docs], False

    async def read_head(self) -> dict[str, Any] | None:
        return self._strip(await self._h.find_one({"_id": "head"}))

    async def append(self, build: Builder) -> dict[str, Any]:
        try:
            await self._ensure_indexes()
            for _ in range(self.MAX_RETRIES):
                last = self._strip(await self._c.find_one({}, sort=[("seq", -1)]))
                entry, head = build(last)
                try:
                    await self._c.insert_one({"_id": entry["seq"], **entry})
                except DuplicateKeyError:
                    continue  # another writer appended first: build again on the new head
                try:
                    await self._h.update_one({"_id": "head", "seq": {"$lt": entry["seq"]}}, {"$set": head}, upsert=True)
                except DuplicateKeyError:
                    pass  # the head is already ahead of this entry
                return entry
        except AuditUnavailable:
            raise
        except Exception as e:
            raise AuditUnavailable(f"audit log not writable ({type(e).__name__})") from None
        raise AuditUnavailable("audit log append kept conflicting; retry")
