"""4.2 LIVE Mongo: flow test cases, suite-run history (pruned per flow), gate settings and the summary on the Mongo
backend (collections flow_test_cases / flow_test_runs / flow_test_settings). Same interface as the file store.

Runs in CI's mongo-live job (AGENTOS_REQUIRE_LIVE_MONGO=1 turns a skip into a failure); skipped locally without
AGENTOS_MONGO_URI. Each test uses a throwaway database that is dropped afterwards.
"""

from __future__ import annotations

import pytest
import pytest_asyncio

from agentos.flowtests import GateSettings, SuiteRun, TestCase, flowtests_store_for
from agentos.flowtests.models import CaseResult
from agentos.flowtests.store import KEEP_RUNS_PER_FLOW
from agentos.tests.test_storage_contract_1_2 import _live_mongo_storage

pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture
async def mongo():
    async for s in _live_mongo_storage():
        yield s


async def test_mongo_cases_runs_gate_and_summary(mongo):
    store = flowtests_store_for(mongo)
    assert type(store.cases).__name__ == "MongoDocs"
    a = await store.put_case(TestCase(flow_id="f1", name="a", tags=["security"],
                                      expectations=[{"kind": "status", "equals": "succeeded"}]))
    await store.put_case(TestCase(flow_id="f1", name="b"))
    await store.put_case(TestCase(flow_id="f2", name="other"))
    assert [c.name for c in await store.list_cases("f1")] == ["a", "b"]
    assert [c.name for c in await store.list_cases("f1", ["security"])] == ["a"]
    got = await store.get_case(a.id)
    assert got.expectations[0].kind == "status"
    for i in range(KEEP_RUNS_PER_FLOW + 2):
        await store.save_run(SuiteRun(flow_id="f1", started_at=1000.0 + i, model="mock",
                                      results=[CaseResult(case_id=a.id, name="a", status="pass" if i % 2 else "fail")]))
    runs = await store.list_runs("f1")
    assert len(runs) == KEEP_RUNS_PER_FLOW and runs[0].started_at == 1000.0 + KEEP_RUNS_PER_FLOW + 1
    assert (await store.previous_run("f1", "mock")).id == runs[0].id
    assert await store.previous_run("f1", "router") is None
    await store.put_gate(GateSettings(flow_id="f1", mode="block", model="mock"))
    assert (await store.get_gate("f1")).mode == "block" and (await store.get_gate("f2")).mode == "off"
    summary = await store.summary()
    assert summary["f1"]["cases"] == 2 and summary["f1"]["last_pass_rate"] == 100.0 and summary["f2"]["cases"] == 1
    assert await store.delete_case(a.id) and await store.get_case(a.id) is None
