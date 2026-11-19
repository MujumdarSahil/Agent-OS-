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
    FlowRecord,
    MCPServerRecord,
    MissionRecord,
    ProjectSettingsRecord,
    ProviderConfigRecord,
    RunRecord,
    ScheduleRecord,
    SquadRecord,
    ToolRecord,
    WebhookRecord,
    entity_key,
    utcnow,
)
from agentos.storage.ports import DuplicateIdempotencyKeyError, FencingTokenError, Storage

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
        try:
            await self._c.replace_one({"_id": run.run_id}, {"_id": run.run_id, **run.model_dump()}, upsert=True)
        except Exception as e:
            if run.idempotency_key and ("duplicate key" in str(e).lower() or type(e).__name__ == "DuplicateKeyError"):
                raise DuplicateIdempotencyKeyError(
                    f"Run with idempotency_key {run.idempotency_key!r} already exists"
                ) from e
            raise

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
        self._fencing_checker = None

    async def append(
        self,
        run_id: str,
        type: str,
        data: Optional[Dict[str, Any]] = None,
        lease_id: Optional[str] = None,
    ) -> EventRecord:
        if self._fencing_checker is not None and not self._fencing_checker(run_id, lease_id):
            raise FencingTokenError(f"Lease {lease_id!r} expired or superseded for run {run_id!r}")
        counter = await self._counters.find_one_and_update(
            {"_id": run_id}, {"$inc": {"seq": 1}}, upsert=True, return_document=ReturnDocument.AFTER
        )
        event = EventRecord(run_id=run_id, seq=counter["seq"], type=type, data=data or {}, lease_id=lease_id)
        await self._events.insert_one(event.model_dump())
        return event

    async def list(self, run_id: str, after_seq: int = 0) -> List[EventRecord]:
        docs = await self._events.find({"run_id": run_id, "seq": {"$gt": after_seq}}).sort("seq", ASCENDING).to_list(None)
        return [EventRecord.model_validate(_strip_id(d)) for d in docs]


class MongoFlowRepository:
    """
    MongoDB repository for versioned flows.
    Documents in db.flows:
      Draft: {"_id": f"{flow_id}:draft", "flow_id": flow_id, "record_type": "draft", ...}
      Version: {"_id": f"{flow_id}:v{version}", "flow_id": flow_id, "version": version, "record_type": "version", ...}
    Atomic version allocation via db.flow_counters find_one_and_update.
    """

    def __init__(self, collection, counters):
        self._c = collection
        self._counters = counters

    async def get_draft(self, flow_id: str) -> Optional[FlowRecord]:
        doc = await self._c.find_one({"_id": f"{entity_key(flow_id)}:draft"})
        if not doc:
            return None
        clean = _strip_id(doc)
        clean.pop("record_type", None)
        return FlowRecord.model_validate(clean)

    async def put_draft(self, flow: FlowRecord) -> None:
        from agentos.flows.models import FlowDefinition

        # Validate DAG + bounded loops + specs
        FlowDefinition(
            id=flow.id,
            name=flow.name,
            entrypoint=flow.entrypoint,
            nodes=flow.nodes,
            edges=flow.edges,
            loops=flow.loops,
        )
        key = f"{entity_key(flow.id)}:draft"
        flow_copy = flow.model_copy(update={"updated_at": utcnow()})
        data = flow_copy.model_dump()
        data["_id"] = key
        data["flow_id"] = flow.id
        data["record_type"] = "draft"
        await self._c.replace_one({"_id": key}, data, upsert=True)

    async def get_version(self, flow_id: str, version: int) -> Optional[FlowRecord]:
        doc = await self._c.find_one({"_id": f"{entity_key(flow_id)}:v{version}"})
        if not doc:
            return None
        clean = _strip_id(doc)
        clean.pop("record_type", None)
        return FlowRecord.model_validate(clean)

    async def list_versions(self, flow_id: str) -> List[FlowRecord]:
        docs = await self._c.find({
            "flow_id": flow_id,
            "record_type": "version",
        }).sort("version", ASCENDING).to_list(None)
        res = []
        for d in docs:
            clean = _strip_id(d)
            clean.pop("record_type", None)
            res.append(FlowRecord.model_validate(clean))
        return res

    async def list_flows(self) -> List[FlowRecord]:
        docs = await self._c.find({"record_type": "draft"}).sort("flow_id", ASCENDING).to_list(None)
        res = []
        for d in docs:
            clean = _strip_id(d)
            clean.pop("record_type", None)
            res.append(FlowRecord.model_validate(clean))
        return res

    async def publish(
        self, flow_id: str, content_sha256: str, policy_hash: str, analysis: Optional[Dict[str, Any]] = None
    ) -> FlowRecord:
        draft = await self.get_draft(flow_id)
        if draft is None:
            raise ValueError(f"Flow {flow_id!r} draft not found")

        # Atomic version counter allocation
        counter = await self._counters.find_one_and_update(
            {"_id": flow_id},
            {"$inc": {"version": 1}},
            upsert=True,
            return_document=ReturnDocument.AFTER,
        )
        v = counter["version"]

        published = FlowRecord(
            id=draft.id,
            name=draft.name,
            status="published",
            version=v,
            entrypoint=draft.entrypoint,
            nodes=draft.nodes,
            edges=draft.edges,
            loops=draft.loops,
            content_sha256=content_sha256,
            policy_hash=policy_hash,
            analysis=analysis,
            created_at=draft.created_at,
            updated_at=utcnow(),
            published_at=utcnow(),
        )
        key = f"{entity_key(flow_id)}:v{v}"
        data = published.model_dump()
        data["_id"] = key
        data["flow_id"] = flow_id
        data["record_type"] = "version"
        await self._c.insert_one(data)

        # Update draft
        draft_updated = draft.model_copy(update={"updated_at": utcnow()})
        draft_data = draft_updated.model_dump()
        draft_data["_id"] = f"{entity_key(flow_id)}:draft"
        draft_data["flow_id"] = flow_id
        draft_data["version"] = None
        draft_data["record_type"] = "draft"
        await self._c.replace_one({"_id": draft_data["_id"]}, draft_data, upsert=True)
        return published

    async def delete_flow(self, flow_id: str) -> bool:
        # Requirement 7: Deletion guard
        count_published = await self._c.count_documents({"flow_id": flow_id, "record_type": "version"})
        if count_published > 0:
            raise ValueError(f"Cannot delete flow {flow_id!r}: published versions exist")
        res = await self._c.delete_one({"_id": f"{entity_key(flow_id)}:draft"})
        return res.deleted_count == 1

    async def archive_flow(self, flow_id: str) -> FlowRecord:
        draft = await self.get_draft(flow_id)
        if draft is None:
            raise ValueError(f"Flow {flow_id!r} not found")
        archived = draft.model_copy(update={"status": "archived", "updated_at": utcnow()})
        data = archived.model_dump()
        data["_id"] = f"{entity_key(flow_id)}:draft"
        data["flow_id"] = flow_id
        data["record_type"] = "draft"
        await self._c.replace_one({"_id": data["_id"]}, data, upsert=True)
        return archived


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


class MongoWebhookRepository:
    def __init__(self, collection):
        self._c = collection

    async def list(self) -> List[WebhookRecord]:
        docs = await self._c.find({}).sort("created_at", DESCENDING).to_list(None)
        return [WebhookRecord.model_validate(_strip_id(d)) for d in docs]

    async def get(self, webhook_id: str) -> Optional[WebhookRecord]:
        doc = await self._c.find_one({"_id": webhook_id})
        return WebhookRecord.model_validate(_strip_id(doc)) if doc else None

    async def get_by_path_hash(self, secret_path_hash: str) -> Optional[WebhookRecord]:
        doc = await self._c.find_one({"secret_path_hash": secret_path_hash})
        return WebhookRecord.model_validate(_strip_id(doc)) if doc else None

    async def put(self, webhook: WebhookRecord) -> None:
        await self._c.replace_one(
            {"_id": webhook.webhook_id},
            {"_id": webhook.webhook_id, **webhook.model_dump()},
            upsert=True,
        )

    async def delete(self, webhook_id: str) -> bool:
        res = await self._c.delete_one({"_id": webhook_id})
        return res.deleted_count == 1


class MongoScheduleRepository:
    def __init__(self, collection):
        self._c = collection

    async def list(self) -> List[ScheduleRecord]:
        docs = await self._c.find({}).sort("created_at", DESCENDING).to_list(None)
        return [ScheduleRecord.model_validate(_strip_id(d)) for d in docs]

    async def get(self, schedule_id: str) -> Optional[ScheduleRecord]:
        doc = await self._c.find_one({"_id": schedule_id})
        return ScheduleRecord.model_validate(_strip_id(doc)) if doc else None

    async def put(self, schedule: ScheduleRecord) -> None:
        await self._c.replace_one(
            {"_id": schedule.schedule_id},
            {"_id": schedule.schedule_id, **schedule.model_dump()},
            upsert=True,
        )

    async def delete(self, schedule_id: str) -> bool:
        res = await self._c.delete_one({"_id": schedule_id})
        return res.deleted_count == 1


async def ensure_indexes(db) -> None:
    await db.events.create_index([("run_id", ASCENDING), ("seq", ASCENDING)], unique=True)
    await db.checkpoints.create_index([("mission_id", ASCENDING), ("task_index", DESCENDING)])
    await db.runs.create_index([("created_at", DESCENDING)])
    await db.runs.create_index(
        [("idempotency_key", ASCENDING)],
        unique=True,
        partialFilterExpression={"idempotency_key": {"$type": "string"}},
    )
    await db.flows.create_index(
        [("flow_id", ASCENDING), ("version", ASCENDING)],
        unique=True,
        partialFilterExpression={"record_type": "version"},
    )
    await db.flows.create_index([("record_type", ASCENDING)])
    await db.webhooks.create_index([("secret_path_hash", ASCENDING)], unique=True)
    await db.schedules.create_index([("flow_id", ASCENDING)])
    # 3.1 audit chain: seq is the _id (unique); prev_hash unique so the chain cannot fork
    await db.audit.create_index("prev_hash", unique=True)


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
        flows=MongoFlowRepository(db.flows, db.flow_counters),
        webhooks=MongoWebhookRepository(db.webhooks),
        schedules=MongoScheduleRepository(db.schedules),
        settings=MongoNamedRepository(db.settings, ProjectSettingsRecord),
    )
    storage._closer = client.close
    return storage
