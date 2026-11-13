"""
Platform storage backend: MongoDB through PyMongo's async API (``AsyncMongoClient``).

Requires the optional extra ``agentos[platform]``. This is the only package in
``agentos`` allowed to import ``pymongo`` (enforced by the boundary test).

Collections: settings, agents, squads, missions, tools, mcp_servers, provider_configs,
credentials, runs, events, event_counters, checkpoints. Named entities use the
v1 slug of their name as ``_id``, so keys behave exactly like the File backend.
"""

from datetime import datetime
from typing import Any, Dict, Generic, List, Optional, Type, TypeVar

from pydantic import BaseModel
from pymongo import ASCENDING, DESCENDING, AsyncMongoClient, ReturnDocument

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
    entity_key,
)
from agentos.storage.ports import Storage

M = TypeVar("M", bound=BaseModel)

DEFAULT_DB = "agentos"


def _strip_id(doc: Dict[str, Any]) -> Dict[str, Any]:
    doc = dict(doc)
    doc.pop("_id", None)
    return doc


class MongoNamedRepository(Generic[M]):
    def __init__(self, collection, model: Type[M]):
        self._c = collection
        self._model = model

    async def list(self) -> List[M]:
        docs = await self._c.find({}).sort("_id", ASCENDING).to_list(None)
        return [self._model.model_validate(_strip_id(d)) for d in docs]

    async def get(self, name: str) -> Optional[M]:
        doc = await self._c.find_one({"_id": entity_key(name)})
        return self._model.model_validate(_strip_id(doc)) if doc else None

    async def put(self, item: M) -> None:
        key = entity_key(item.name)
        await self._c.replace_one({"_id": key}, {"_id": key, **item.model_dump()}, upsert=True)

    async def delete(self, name: str) -> bool:
        result = await self._c.delete_one({"_id": entity_key(name)})
        return result.deleted_count == 1


class MongoRunRepository:
    def __init__(self, collection):
        self._c = collection

    async def put(self, run: RunRecord) -> None:
        await self._c.replace_one({"_id": run.run_id}, {"_id": run.run_id, **run.model_dump()}, upsert=True)

    async def get(self, run_id: str) -> Optional[RunRecord]:
        doc = await self._c.find_one({"_id": run_id})
        return RunRecord.model_validate(_strip_id(doc)) if doc else None

    async def list(self, limit: int = 100) -> List[RunRecord]:
        docs = await self._c.find({}).sort("created_at", DESCENDING).limit(limit).to_list(None)
        return [RunRecord.model_validate(_strip_id(d)) for d in docs]


class MongoEventRepository:
    """Gap-free per-run sequence via an atomic counter; (run_id, seq) is unique."""

    def __init__(self, events, counters):
        self._events = events
        self._counters = counters

    async def append(self, run_id: str, type: str, data: Optional[Dict[str, Any]] = None) -> EventRecord:
        counter = await self._counters.find_one_and_update(
            {"_id": run_id}, {"$inc": {"seq": 1}}, upsert=True, return_document=ReturnDocument.AFTER
        )
        event = EventRecord(run_id=run_id, seq=counter["seq"], type=type, data=data or {})
        await self._events.insert_one(event.model_dump())
        return event

    async def list(self, run_id: str, after_seq: int = 0) -> List[EventRecord]:
        docs = await self._events.find({"run_id": run_id, "seq": {"$gt": after_seq}}).sort("seq", ASCENDING).to_list(None)
        return [EventRecord.model_validate(_strip_id(d)) for d in docs]


class MongoCheckpointRepository:
    """Same semantics as SQLiteCheckpointStore, keyed by (mission_id, task_index)."""

    def __init__(self, collection):
        self._c = collection

    async def save_checkpoint(self, mission_id: str, task_index: int, state: Dict[str, Any]) -> None:
        from agentos.llm.llm_client import get_last_used_provider

        state = dict(state)
        status = state.get("status", "in_progress")
        state["timestamp"] = state.get("timestamp") or datetime.now().isoformat()
        state["provider"] = state.get("provider") or get_last_used_provider() or "unknown"
        key = f"{mission_id}:{task_index}"
        await self._c.replace_one(
            {"_id": key},
            {"_id": key, "mission_id": mission_id, "task_index": task_index, "state": state,
             "status": status, "timestamp": state["timestamp"], "provider": state["provider"]},
            upsert=True,
        )

    async def load_latest_checkpoint(self, mission_id: str) -> Optional[Dict[str, Any]]:
        doc = await self._c.find_one({"mission_id": mission_id}, sort=[("task_index", DESCENDING)])
        return doc["state"] if doc else None

    async def list_runs(self, mission_id: Optional[str] = None) -> List[Dict[str, Any]]:
        query = {"mission_id": mission_id} if mission_id else {}
        docs = await self._c.find(query).sort("timestamp", DESCENDING).to_list(None)
        return [
            {"mission_id": d["mission_id"], "task_index": d["task_index"], "status": d["status"],
             "timestamp": d["timestamp"], "provider": d.get("provider") or "unknown"}
            for d in docs
        ]

    async def mark_complete(self, mission_id: str) -> None:
        await self._c.update_many({"mission_id": mission_id}, {"$set": {"status": "completed"}})


async def ensure_indexes(db) -> None:
    await db.events.create_index([("run_id", ASCENDING), ("seq", ASCENDING)], unique=True)
    await db.checkpoints.create_index([("mission_id", ASCENDING), ("task_index", DESCENDING)])
    await db.runs.create_index([("created_at", DESCENDING)])


async def open_mongo_storage(uri: str, db_name: str = DEFAULT_DB, timeout_ms: int = 5000) -> Storage:
    client = AsyncMongoClient(uri, tz_aware=True, serverSelectionTimeoutMS=timeout_ms)
    try:
        await client.admin.command("ping")
        db = client[db_name]
        await ensure_indexes(db)
    except BaseException:
        await client.close()
        raise
    storage = Storage(
        backend="mongo",
        agents=MongoNamedRepository(db.agents, AgentRecord),
        squads=MongoNamedRepository(db.squads, SquadRecord),
        missions=MongoNamedRepository(db.missions, MissionRecord),
        tools=MongoNamedRepository(db.tools, ToolRecord),
        mcp_servers=MongoNamedRepository(db.mcp_servers, MCPServerRecord),
        provider_configs=MongoNamedRepository(db.provider_configs, ProviderConfigRecord),
        credentials=MongoNamedRepository(db.credentials, EncryptedSecretRecord),
        runs=MongoRunRepository(db.runs),
        checkpoints=MongoCheckpointRepository(db.checkpoints),
        events=MongoEventRepository(db.events, db.event_counters),
        settings=MongoNamedRepository(db.settings, ProjectSettingsRecord),
    )
    storage._closer = client.close
    return storage
