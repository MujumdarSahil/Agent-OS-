"""3.3 (0b): LIVE Mongo tests for the 3.2 usage store (MongoUsageLedger, MongoUsageSettings, rebuild from events).

Runs in CI's mongo-live job (AGENTOS_REQUIRE_LIVE_MONGO=1 turns a skip into a failure); skipped locally without
AGENTOS_MONGO_URI. Each test uses a throwaway database that is dropped afterwards.
"""

from __future__ import annotations

import asyncio

import pytest
import pytest_asyncio

from agentos.storage.models import RunRecord
from agentos.tests.test_storage_contract_1_2 import _live_mongo_storage
from agentos.usage import UsageSettings, rebuild_rows, usage_stores_for
from agentos.usage.ledger import COUNTERS, increments, row_key, today_utc

pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture
async def mongo():
    async for s in _live_mongo_storage():
        yield s


def _inc(day="2026-11-19", flow="f1", provider="p1", model="m1", **counts):
    return {"day": day, "flow_id": flow, "provider": provider, "model": model,
            **{c: 0 for c in COUNTERS}, **counts}


def _by_key(rows):
    return {row_key(r["day"], r["flow_id"], r["provider"], r["model"]): {c: r[c] for c in COUNTERS} for r in rows}


async def test_parallel_increments_are_exact(mongo):
    ledger, _ = usage_stores_for(mongo)
    n = 50
    # 50 concurrent writers on ONE row, and 50 more spread over 5 rows
    await asyncio.gather(*(ledger.add([_inc(calls=1, prompt_tokens=10, cost_usd=0.001)]) for _ in range(n)))
    await asyncio.gather(*(ledger.add([_inc(provider=f"p{i % 5}", flow="f2", calls=1, errors=1)]) for i in range(n)))
    rows = _by_key(await ledger.rows())
    one = rows[row_key("2026-11-19", "f1", "p1", "m1")]
    assert one["calls"] == n and one["prompt_tokens"] == 10 * n and abs(one["cost_usd"] - 0.001 * n) < 1e-9
    spread = [v for k, v in rows.items() if "|f2|" in k]
    assert len(spread) == 5 and sum(v["calls"] for v in spread) == n and all(v["errors"] == 10 for v in spread)


async def test_rows_query_by_day_window(mongo):
    ledger, _ = usage_stores_for(mongo)
    for day in ("2026-11-01", "2026-11-15", "2026-11-30"):
        await ledger.add([_inc(day=day, calls=1)])
    assert sorted(r["day"] for r in await ledger.rows(since="2026-11-10", until="2026-11-20")) == ["2026-11-15"]
    assert sorted(r["day"] for r in await ledger.rows(since="2026-11-15")) == ["2026-11-15", "2026-11-30"]
    assert sorted(r["day"] for r in await ledger.rows(until="2026-11-01")) == ["2026-11-01"]
    assert all("_id" not in r for r in await ledger.rows())


@pytest_asyncio.fixture(params=["file", "mongo"])
async def any_storage(request, tmp_path):
    """The rebuild check on both backends: file always runs (local evidence), mongo is LIVE."""
    if request.param == "file":
        from agentos.storage import open_storage

        (tmp_path / "agentos.config.yaml").write_text("preferred_tags: []\n", encoding="utf-8")
        s = await open_storage(str(tmp_path), backend="file", vault_path=str(tmp_path / "vault.json"))
        yield s
        await s.close()
        return
    async for s in _live_mongo_storage():
        yield s


async def test_rebuild_from_events_equals_the_ledger(any_storage):
    # ONE day for both sides: the UTC day the engine stamps on an llm_call when it is recorded (no fake dates)
    day = today_utc()
    ledger, _ = usage_stores_for(any_storage)
    records = [
        {"status": "ok", "provider": "p1", "model": "m1", "prompt_tokens": 100, "completion_tokens": 50,
         "total_tokens": 150, "cost_usd": 0.0002, "latency_ms": 80.0, "day": day},
        {"status": "ok", "provider": "p2", "model": "m2", "prompt_tokens": 10, "completion_tokens": 5,
         "total_tokens": 15, "cost_usd": None, "latency_ms": 40.0, "day": day,
         "attempts": [{"provider": "p1", "model": "m1", "error_class": "RateLimitError"}]},
        {"status": "failed", "day": day,
         "attempts": [{"provider": "p1", "model": "m1", "error_class": "Timeout"},
                      {"provider": "p2", "model": "m2", "error_class": "skipped (cooldown)"}]},
    ]
    for i, flow in enumerate(("flow_a", "flow_b")):
        run_id = f"run_live_{i}"
        await any_storage.runs.put(RunRecord(run_id=run_id, mission_name=flow, flow_id=flow, status="succeeded"))
        for rec in records:
            await any_storage.events.append(run_id=run_id, type="llm_call", data=rec)
            await ledger.add(increments(rec, flow, day))
    built = _by_key(await ledger.rows())
    rebuilt = _by_key(await rebuild_rows(any_storage))
    # 2 flows x 2 provider/model pairs (p1/m1, p2/m2) on one day = 4 rows
    assert len(built) == 4 and {k.split("|")[0] for k in built} == {day}
    assert built == rebuilt
    p1 = built[row_key(day, "flow_a", "p1", "m1")]
    assert (p1["calls"], p1["errors"]) == (3, 2)  # ok call + RateLimitError + Timeout (the cooldown skip is not a call)
    await ledger.replace(await rebuild_rows(any_storage))
    assert _by_key(await ledger.rows()) == built


async def test_settings_round_trip_with_billing_plans(mongo):
    _, settings = usage_stores_for(mongo)
    assert await settings.get() == UsageSettings()
    s = UsageSettings.model_validate({"budgets": {"global_daily": 2.5}, "billing_plans": {"groq_gpt_oss_20b": "free"},
                                      "run_limits": {"max_model_calls": 7}})
    await settings.put(s)
    assert await settings.get() == s
