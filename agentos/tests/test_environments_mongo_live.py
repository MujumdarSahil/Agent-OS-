"""4.3 LIVE Mongo: environments on the Mongo backend (flow_deployments, flow_deployment_history, flow_env_settings,
environment_settings): compare-and-set (two concurrent promotions, one wins), history, settings create-once,
archived versions, staging channel mapping, and the legacy migration.

Runs in CI's mongo-live job (AGENTOS_REQUIRE_LIVE_MONGO=1 turns a skip into a failure); skipped locally without
AGENTOS_MONGO_URI. Each test uses a throwaway database that is dropped afterwards.
"""

from __future__ import annotations

import asyncio

import pytest
import pytest_asyncio

from agentos.flows.environments import migrate_all
from agentos.storage.models import DeploymentRecord, EnvironmentSettings, FlowRecord, StagingChannels
from agentos.storage.ports import DeploymentConflict
from agentos.tests.test_storage_contract_1_2 import _live_mongo_storage

pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture
async def mongo():
    async for s in _live_mongo_storage():
        yield s


def _flow(fid: str) -> FlowRecord:
    return FlowRecord(id=fid, name=fid, entrypoint="trig",
                      nodes={"trig": {"id": "trig", "type": "manual_trigger", "config": {}}})


async def test_mongo_deployments_cas_history_settings(mongo):
    repo = mongo.deployments
    assert type(repo).__name__ == "MongoDeploymentRepository"
    rec = lambda v, who: DeploymentRecord(flow_id="f1", environment="production", version=v, deployed_by=who)  # noqa: E731
    results = await asyncio.gather(repo.set(rec(1, "a"), None), repo.set(rec(2, "b"), None), return_exceptions=True)
    assert sum(isinstance(r, DeploymentConflict) for r in results) == 1
    won = next(r for r in results if not isinstance(r, Exception))
    assert (await repo.get("f1", "production")).version == won.version
    with pytest.raises(DeploymentConflict):
        await repo.set(rec(3, "c"), 99)
    moved = await repo.set(rec(3, "c"), won.version)
    assert moved.previous_version == won.version
    assert [h.version for h in await repo.history("f1")][0] == 3
    assert set(await repo.current("f1")) == {"production"}
    assert await repo.create_settings(EnvironmentSettings(flow_id="f1")) is True
    assert await repo.create_settings(EnvironmentSettings(flow_id="f1", legacy=True)) is False
    await repo.archive_version("f1", 1)
    assert await repo.archived_versions("f1") == [1]
    assert (await repo.get_settings("f1")).legacy is False  # archiving does not touch the settings
    await repo.put_staging_channels(StagingChannels(email_channel="testbox"))
    assert (await repo.get_staging_channels()).email_channel == "testbox"


async def test_mongo_legacy_migration(mongo):
    await mongo.flows.put_draft(_flow("legacy"))
    await mongo.flows.publish("legacy", "sha", "p")
    await mongo.flows.publish("legacy", "sha2", "p")
    assert await migrate_all(mongo) == 1 and await migrate_all(mongo) == 0
    assert (await mongo.deployments.get("legacy", "production")).version == 2
    assert (await mongo.deployments.get_settings("legacy")).auto_deploy_production is True
