"""4.3: Mongo-backed environments (staging / production) per flow.

Collections: ``flow_deployments`` (``_id = <flow_key>:<environment>``, the current pointer),
``flow_deployment_history`` (append-only), ``flow_env_settings`` (``_id = flow_id``, settings + archived_versions),
``environment_settings`` (``_id = "global"``, staging channel mapping).

Compare-and-set: ``find_one_and_update({_id, version: expected})``; for a first deployment (expected None) an
``insert_one``, where a duplicate key means another deployment won. Both are single-document atomic operations.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pymongo import DESCENDING, ReturnDocument
from pymongo.errors import DuplicateKeyError

from agentos.storage.models import DeploymentRecord, EnvironmentSettings, StagingChannels, entity_key
from agentos.storage.ports import DeploymentConflict

_SETTING_FIELDS = set(EnvironmentSettings.model_fields)


def _clean(doc: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not doc:
        return None
    return {k: v for k, v in doc.items() if k != "_id"}


class MongoDeploymentRepository:
    def __init__(self, db: Any) -> None:
        self._cur = db.flow_deployments
        self._hist = db.flow_deployment_history
        self._settings = db.flow_env_settings
        self._global = db.environment_settings

    @staticmethod
    def _id(flow_id: str, environment: str) -> str:
        return f"{entity_key(flow_id)}:{environment}"

    async def get(self, flow_id: str, environment: str) -> Optional[DeploymentRecord]:
        d = _clean(await self._cur.find_one({"_id": self._id(flow_id, environment)}))
        return DeploymentRecord.model_validate(d) if d else None

    async def current(self, flow_id: str) -> Dict[str, DeploymentRecord]:
        out: Dict[str, DeploymentRecord] = {}
        async for d in self._cur.find({"flow_id": flow_id}):
            rec = DeploymentRecord.model_validate(_clean(d))
            out[rec.environment] = rec
        return out

    async def set(self, record: DeploymentRecord, expected_version: Optional[int]) -> DeploymentRecord:
        key = self._id(record.flow_id, record.environment)
        record = record.model_copy(update={"previous_version": expected_version})
        data = record.model_dump()
        if expected_version is None:
            try:
                await self._cur.insert_one({"_id": key, **data})
            except DuplicateKeyError:
                now = await self.get(record.flow_id, record.environment)
                raise DeploymentConflict(record.flow_id, record.environment, None, now.version if now else None)
        else:
            res = await self._cur.find_one_and_update({"_id": key, "version": expected_version}, {"$set": data},
                                                      return_document=ReturnDocument.AFTER)
            if res is None:
                now = await self.get(record.flow_id, record.environment)
                raise DeploymentConflict(record.flow_id, record.environment, expected_version,
                                         now.version if now else None)
        await self._hist.insert_one(dict(data))
        return record

    async def history(self, flow_id: str, limit: int = 100) -> List[DeploymentRecord]:
        docs = await self._hist.find({"flow_id": flow_id}).sort("deployed_at", DESCENDING).limit(limit).to_list(None)
        return [DeploymentRecord.model_validate(_clean(d)) for d in docs]

    async def get_settings(self, flow_id: str) -> Optional[EnvironmentSettings]:
        d = _clean(await self._settings.find_one({"_id": flow_id}))
        if not d or "auto_deploy_staging" not in d:  # a doc holding only archived_versions is not a settings record
            return None
        return EnvironmentSettings.model_validate({k: v for k, v in d.items() if k in _SETTING_FIELDS})

    async def put_settings(self, settings: EnvironmentSettings) -> None:
        await self._settings.update_one({"_id": settings.flow_id}, {"$set": settings.model_dump()}, upsert=True)

    async def create_settings(self, settings: EnvironmentSettings) -> bool:
        res = await self._settings.update_one(
            {"_id": settings.flow_id, "auto_deploy_staging": {"$exists": False}},
            {"$set": settings.model_dump()}, upsert=False)
        if res.modified_count == 1:
            return True
        try:
            await self._settings.insert_one({"_id": settings.flow_id, **settings.model_dump()})
            return True
        except DuplicateKeyError:
            return False

    async def archived_versions(self, flow_id: str) -> List[int]:
        d = await self._settings.find_one({"_id": flow_id})
        return sorted(int(v) for v in (d or {}).get("archived_versions") or [])

    async def archive_version(self, flow_id: str, version: int) -> None:
        await self._settings.update_one({"_id": flow_id}, {"$addToSet": {"archived_versions": int(version)}},
                                        upsert=True)

    async def get_staging_channels(self) -> StagingChannels:
        d = _clean(await self._global.find_one({"_id": "global"}))
        return StagingChannels.model_validate(d["staging_channels"]) if d and d.get("staging_channels") \
            else StagingChannels()

    async def put_staging_channels(self, channels: StagingChannels) -> None:
        await self._global.update_one({"_id": "global"}, {"$set": {"staging_channels": channels.model_dump()}},
                                      upsert=True)
