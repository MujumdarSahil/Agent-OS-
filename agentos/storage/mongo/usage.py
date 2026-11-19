"""Mongo usage ledger and usage settings (3.2): ``usage_ledger`` ($inc upserts keyed by day|flow|provider|model)
and ``usage_settings`` (one document). Design: docs/evidence/3.2.md."""

from __future__ import annotations

from typing import Any, Optional

from agentos.usage.ledger import COUNTERS, UsageSettings, row_key


class MongoUsageLedger:
    def __init__(self, coll: Any) -> None:
        self._c = coll

    async def add(self, incs: list[dict[str, Any]]) -> None:
        for inc in incs:
            k = row_key(inc["day"], inc["flow_id"], inc["provider"], inc["model"])
            await self._c.update_one(
                {"_id": k},
                {"$inc": {c: inc.get(c, 0) for c in COUNTERS},
                 "$setOnInsert": {"day": inc["day"], "flow_id": inc["flow_id"], "provider": inc["provider"],
                                  "model": inc["model"]}},
                upsert=True,
            )

    async def rows(self, since: Optional[str] = None, until: Optional[str] = None) -> list[dict[str, Any]]:
        q: dict[str, Any] = {}
        if since or until:
            q["day"] = {**({"$gte": since} if since else {}), **({"$lte": until} if until else {})}
        out = []
        for d in await self._c.find(q).to_list(None):
            d = dict(d)
            d.pop("_id", None)
            out.append(d)
        return out

    async def replace(self, rows: list[dict[str, Any]]) -> None:
        await self._c.delete_many({})
        if rows:
            await self._c.insert_many([{"_id": row_key(r["day"], r["flow_id"], r["provider"], r["model"]), **r}
                                       for r in rows])


class MongoUsageSettings:
    def __init__(self, coll: Any) -> None:
        self._c = coll

    async def get(self) -> UsageSettings:
        doc = await self._c.find_one({"_id": "settings"})
        if not doc:
            return UsageSettings()
        doc = dict(doc)
        doc.pop("_id", None)
        return UsageSettings.model_validate(doc)

    async def put(self, settings: UsageSettings) -> None:
        await self._c.replace_one({"_id": "settings"}, {"_id": "settings", **settings.model_dump()}, upsert=True)
