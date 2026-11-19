"""Mongo document store for 3.3 notifications (channels, alert rules, alerts, outbox); same interface as
agentos/notify/store.FileDocs. ``update`` is a read-modify-write retried on a version conflict (optimistic)."""

from __future__ import annotations

from typing import Any, Callable, Optional


def _out(d: Optional[dict[str, Any]]) -> Optional[dict[str, Any]]:
    if not d:
        return None
    d = dict(d)
    d.pop("_id", None)
    d.pop("_v", None)
    return d


class MongoDocs:
    def __init__(self, coll: Any) -> None:
        self._c = coll

    async def get(self, id_: str) -> Optional[dict[str, Any]]:
        return _out(await self._c.find_one({"_id": id_}))

    async def list(self) -> list[dict[str, Any]]:
        return [_out(d) for d in await self._c.find({}).to_list(None)]

    async def put(self, doc: dict[str, Any]) -> None:
        await self._c.update_one({"_id": doc["id"]}, {"$set": {k: v for k, v in doc.items()}, "$inc": {"_v": 1}},
                                 upsert=True)

    async def insert_if_absent(self, doc: dict[str, Any]) -> bool:
        res = await self._c.update_one({"_id": doc["id"]}, {"$setOnInsert": {**doc, "_v": 1}}, upsert=True)
        return res.upserted_id is not None

    async def delete(self, id_: str) -> bool:
        return (await self._c.delete_one({"_id": id_})).deleted_count > 0

    async def update(self, id_: str, fn: Callable[[dict[str, Any]], Optional[dict[str, Any]]]) -> Optional[dict[str, Any]]:
        for _ in range(10):
            raw = await self._c.find_one({"_id": id_})
            if raw is None:
                return None
            version = raw.get("_v") or 0
            new = fn(_out(raw) or {})
            if new is None:
                return None
            res = await self._c.replace_one({"_id": id_, "_v": raw.get("_v")},
                                            {**new, "_id": id_, "_v": version + 1})
            if res.matched_count:
                return dict(new)
        raise RuntimeError(f"notify store: too many concurrent updates of {id_!r}")
