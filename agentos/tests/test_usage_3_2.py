"""3.2 usage, cost and budgets (MOCK: litellm.completion replaced by a scripted function with FIXED token counts;
no keys, no network).

cost maths per provider (override, free-tier, local, LiteLLM map, unknown); ledger totals = sum of events;
rebuild from events matches; run limits (calls and tokens, also on $0 models) stop the run; each budget type
blocks the call; the fallback chain cannot escape a budget by switching to a paid provider (a $0 one is allowed);
unknown price + USD budget refused; budgets audited (503 fail closed); parallel runs overshoot by at most the
calls in flight (documented bound); API (group by, budgets, run usage, auth).
"""

from __future__ import annotations

import asyncio
import time
from types import SimpleNamespace as NS

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

import agentos.llm.router_llm as rl
from agentos.flows.engine import FlowEngine
from agentos.flows.models import FlowDefinition
from agentos.flows.state import RunStatus
from agentos.storage import open_storage
from agentos.usage import UsageContext, UsageSettings, cost_usd, price_for, rebuild_rows
from agentos.usage.ledger import FileUsageLedger, FileUsageSettings, increments, today_utc

PRICES = {"paid_a": {"input_per_1m": 1.0, "output_per_1m": 2.0}, "paid_b": {"input_per_1m": 3.0, "output_per_1m": 4.0}}
PAID_A = {"provider": "paid_a", "model": "vendor/paid-a", "local": False}
PAID_B = {"provider": "paid_b", "model": "vendor/paid-b", "local": False}
FREE = {"provider": "openrouter_mistral_7b_free", "model": "openrouter/mistralai/mistral-7b-instruct:free", "local": False}
LOCAL = {"provider": "ollama_qwen", "model": "ollama/qwen2.5-coder", "local": True}
UNKNOWN = {"provider": "mystery", "model": "mystery/no-such-model-x", "local": False}
PROMPT, COMPLETION = 1000, 500  # fixed token counts per call
COST_A = round(PROMPT * 1.0 / 1e6 + COMPLETION * 2.0 / 1e6, 8)  # 0.002


@pytest_asyncio.fixture
async def env(tmp_path, monkeypatch):
    (tmp_path / "agentos.config.yaml").write_text("preferred_tags: []\n", encoding="utf-8")
    storage = await open_storage(str(tmp_path), backend="file", vault_path=str(tmp_path / "vault.json"))
    monkeypatch.delenv("AGENTOS_MOCK_LLM", raising=False)
    rl.reset_cooldowns()
    calls: list[str] = []

    def completion(**kw):
        calls.append(kw["model"])
        if getattr(completion, "slow", 0):
            time.sleep(completion.slow)
        return NS(choices=[NS(message=NS(content="answer", tool_calls=None))],
                  usage=NS(prompt_tokens=PROMPT, completion_tokens=COMPLETION, total_tokens=PROMPT + COMPLETION))

    monkeypatch.setattr(rl, "_completion", completion)
    ctx = UsageContext(FileUsageLedger(str(tmp_path)), FileUsageSettings(str(tmp_path)), PRICES)
    yield NS(storage=storage, calls=calls, completion=completion, ctx=ctx, tmp=tmp_path, mp=monkeypatch)
    await storage.close()


def chain(monkeypatch, *entries):
    monkeypatch.setattr(rl, "default_chain", lambda: [dict(e) for e in entries])


def llm_flow(n: int = 1, fid: str = "usage_flow") -> FlowDefinition:
    nodes = {"trig": {"id": "trig", "type": "manual_trigger"}}
    edges = []
    prev, field = "trig", "payload"
    for i in range(1, n + 1):
        nid = f"llm{i}"
        nodes[nid] = {"id": nid, "type": "llm", "config": {}}
        edges.append({"source": prev, "target": nid, "arg_mapping": {"prompt": field}})
        prev, field = nid, "completion"
    return FlowDefinition(id=fid, entrypoint="trig", nodes=nodes, edges=edges)


async def run(env, fd, run_id, **settings):
    if settings:
        await env.ctx.settings.put(UsageSettings.model_validate(settings))
    return await FlowEngine(fd, env.storage, usage=env.ctx).run(run_id=run_id, inputs={"text": "hi"})


async def events(env, run_id, type_=None):
    evs = await env.storage.events.list(run_id, after_seq=0)
    return [e for e in evs if type_ is None or e.type == type_]


# ------------------------------------------------------------------ prices

def test_cost_maths_per_provider():
    assert price_for("paid_a", "vendor/paid-a", PRICES).source == "override"
    free = price_for(FREE["provider"], FREE["model"])
    assert free.source == "free_tier" and free.free
    loc = price_for(LOCAL["provider"], LOCAL["model"])
    assert loc.source == "local" and loc.free
    unk = price_for(UNKNOWN["provider"], UNKNOWN["model"])
    assert unk.source == "unknown" and cost_usd(unk, 10, 10) is None  # never guessed
    assert cost_usd(price_for("paid_a", None, PRICES), 1_000_000, 1_000_000) == 3.0
    assert cost_usd(free, 5_000_000, 5_000_000) == 0.0
    import litellm

    if "gpt-4o" in (getattr(litellm, "model_cost", None) or {}):  # the bundled map is the fallback
        p = price_for("not_in_registry", "gpt-4o")
        assert p.source == "litellm" and p.known


# ------------------------------------------------------------------ cost on events, ledger, rebuild

@pytest.mark.asyncio
async def test_llm_call_events_carry_cost_and_ledger_equals_sum_of_events(env):
    chain(env.mp, PAID_A)
    st = await run(env, llm_flow(2), "r_cost")
    assert st.status == RunStatus.SUCCEEDED
    calls = [e.data for e in await events(env, "r_cost", "llm_call")]
    assert [c["cost_usd"] for c in calls] == [COST_A, COST_A] and {c["price_source"] for c in calls} == {"override"}
    chain(env.mp, UNKNOWN)
    st2 = await run(env, llm_flow(1), "r_unknown")
    unk = (await events(env, "r_unknown", "llm_call"))[0].data
    assert st2.status == RunStatus.SUCCEEDED and unk["cost_usd"] is None and unk["price_source"] == "unknown"
    rows = await env.ctx.ledger.rows()
    by = {(r["provider"]): r for r in rows}
    assert by["paid_a"]["calls"] == 2 and by["paid_a"]["prompt_tokens"] == 2 * PROMPT
    assert round(by["paid_a"]["cost_usd"], 8) == round(2 * COST_A, 8)
    assert by["mystery"]["cost_unknown_calls"] == 1 and by["mystery"]["cost_usd"] == 0
    # ledger totals == sum over the events
    every = [e.data for r in ("r_cost", "r_unknown") for e in await events(env, r, "llm_call")]
    assert sum(r["calls"] for r in rows) == sum(len(increments(d, "usage_flow", today_utc())) for d in every)
    # rebuild from events matches the live ledger
    rebuilt = await rebuild_rows(env.storage)
    key = lambda r: (r["day"], r["flow_id"], r["provider"], r["model"])  # noqa: E731
    assert sorted(rebuilt, key=key) == sorted(rows, key=key)


# ------------------------------------------------------------------ run limits

@pytest.mark.asyncio
async def test_run_limit_model_calls_stops_the_run_also_on_free_models(env):
    chain(env.mp, FREE)  # $0: runaway protection still applies
    st = await run(env, llm_flow(3), "r_calls", run_limits={"max_model_calls": 2})
    assert st.status == RunStatus.FAILED and "run limit exceeded: model calls 2/2" in (st.error or "")
    assert len(env.calls) == 2  # no further model call
    ev = await events(env, "r_calls", "run_limit_exceeded")
    assert ev and ev[0].data == {"limit": "calls", "used": 2, "max": 2}


@pytest.mark.asyncio
async def test_run_limit_tokens_and_flow_limit_only_lowers(env):
    chain(env.mp, PAID_A)
    st = await run(env, llm_flow(3), "r_tokens",
                   run_limits={"max_model_calls": 50, "max_total_tokens": 100000,
                               "flows": {"usage_flow": {"max_total_tokens": 2000}}})
    # 1500 tokens per call: the second call crosses 2000, the third is refused
    assert st.status == RunStatus.FAILED and "run limit exceeded: total tokens 3000/2000" in (st.error or "")
    assert len(env.calls) == 2
    s = UsageSettings.model_validate({"run_limits": {"max_model_calls": 5, "flows": {"f": {"max_model_calls": 99}}}})
    assert s.limits_for("f") == (5, 300000)  # a flow value never raises the global limit


# ------------------------------------------------------------------ budgets

async def _spent(env, provider="paid_a", flow="usage_flow", cost=0.01):
    await env.ctx.ledger.add([{**{k: 0 for k in ("calls", "errors", "fallbacks", "prompt_tokens", "completion_tokens",
                                                  "cost_unknown_calls", "latency_ms_sum", "latency_count")},
                               "day": today_utc(), "flow_id": flow, "provider": provider, "model": "m",
                               "calls": 1, "cost_usd": cost}])


@pytest.mark.parametrize("budgets,which", [
    ({"global_daily": 0.01}, "global_daily"),
    ({"global_monthly": 0.01}, "global_monthly"),
    ({"flow_daily": {"usage_flow": 0.01}}, "flow_daily[usage_flow]"),
    ({"provider_monthly": {"paid_a": 0.01}}, "provider_monthly[paid_a]"),
])
@pytest.mark.asyncio
async def test_each_budget_type_blocks_the_call(env, budgets, which):
    chain(env.mp, PAID_A)
    await _spent(env)
    st = await run(env, llm_flow(1), f"r_budget_{which[:6]}", budgets=budgets)
    assert st.status == RunStatus.FAILED and f"budget exceeded: {which}" in (st.error or "")
    assert env.calls == []  # the call was not made
    assert (await events(env, f"r_budget_{which[:6]}", "budget_exceeded"))[0].data["budget"] == which


@pytest.mark.asyncio
async def test_budget_for_another_flow_or_provider_does_not_apply(env):
    chain(env.mp, PAID_A)
    await _spent(env, provider="paid_b", flow="other")
    st = await run(env, llm_flow(1), "r_other", budgets={"flow_daily": {"other": 0.001}, "provider_monthly": {"paid_b": 0.001}})
    assert st.status == RunStatus.SUCCEEDED and len(env.calls) == 1


@pytest.mark.asyncio
async def test_fallback_cannot_escape_a_budget_via_a_paid_provider_but_may_use_a_free_one(env):
    await _spent(env)
    chain(env.mp, PAID_A, PAID_B, FREE)  # paid_a over its budget; paid_b has none; free is $0
    st = await run(env, llm_flow(1), "r_escape_free", budgets={"provider_monthly": {"paid_a": 0.01}})
    assert st.status == RunStatus.SUCCEEDED and env.calls == [FREE["model"]]  # paid_b was NOT used
    rec = (await events(env, "r_escape_free", "llm_call"))[0].data
    assert [a["error_class"] for a in rec["attempts"]] == ["BudgetExceeded", "BudgetExceeded"]
    env.calls.clear()
    chain(env.mp, PAID_A, PAID_B)  # no $0 provider: fail closed with the budget reason
    st2 = await run(env, llm_flow(1), "r_escape_paid")
    assert st2.status == RunStatus.FAILED and "budget exceeded: provider_monthly[paid_a]" in (st2.error or "")
    assert env.calls == []


@pytest.mark.asyncio
async def test_unknown_price_with_a_usd_budget_is_refused(env):
    chain(env.mp, UNKNOWN)
    st = await run(env, llm_flow(1), "r_unknown_budget", budgets={"global_daily": 100})
    assert st.status == RunStatus.FAILED and "price of mystery/mystery/no-such-model-x is unknown" in (st.error or "")
    assert "usage.prices" in (st.error or "") and env.calls == []
    chain(env.mp, LOCAL)  # local Ollama is $0: allowed under the same budget
    st2 = await run(env, llm_flow(1), "r_local_budget")
    assert st2.status == RunStatus.SUCCEEDED
    assert (await events(env, "r_local_budget", "llm_call"))[0].data["price_source"] == "local"


@pytest.mark.asyncio
async def test_parallel_runs_overshoot_at_most_the_calls_in_flight(env):
    """No reservation (documented): N concurrent calls all pass the check before any of them is recorded, so a
    budget can be overshot by at most N calls' cost. The next call after that is refused."""
    chain(env.mp, PAID_A)
    await env.ctx.settings.put(UsageSettings.model_validate({"budgets": {"global_daily": 0.001}}))  # < one call
    env.completion.slow = 0.3
    n = 5
    states = await asyncio.gather(*(FlowEngine(llm_flow(1), env.storage, usage=env.ctx).run(run_id=f"r_par_{i}",
                                                                                           inputs={"text": "x"})
                                    for i in range(n)))
    env.completion.slow = 0
    spent = await env.ctx.spend(month=False)
    assert all(s.status == RunStatus.SUCCEEDED for s in states)
    assert spent <= 0.001 + n * COST_A  # the documented bound
    after = await run(env, llm_flow(1), "r_par_after")
    assert after.status == RunStatus.FAILED and "budget exceeded: global_daily" in (after.error or "")


# ------------------------------------------------------------------ API + audit

@pytest.mark.asyncio
async def test_api_usage_budgets_run_usage_audit_and_auth(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTOS_API_TOKEN", "test-token-usage")
    monkeypatch.delenv("AGENTOS_MONGO_URI", raising=False)
    (tmp_path / "agentos.config.yaml").write_text(
        "preferred_tags: []\nusage:\n  prices:\n    paid_a: {input_per_1m: 1.0, output_per_1m: 2.0}\n", encoding="utf-8")
    from agentos_server.app import create_app

    app = create_app(project_path=str(tmp_path))
    assert app.state.usage.price_overrides["paid_a"] == {"input_per_1m": 1.0, "output_per_1m": 2.0}
    rec = {"status": "ok", "provider": "paid_a", "model": "vendor/paid-a", "prompt_tokens": PROMPT,
           "completion_tokens": COMPLETION, "total_tokens": PROMPT + COMPLETION, "cost_usd": COST_A, "latency_ms": 120.0,
           "attempts": [{"provider": "paid_b", "model": "vendor/paid-b", "error_class": "RateLimitError"}]}
    await app.state.usage.ledger.add(increments(rec, "flow_x", today_utc()))
    hdr = {"Authorization": "Bearer test-token-usage", "Host": "localhost"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://localhost", headers=hdr) as c:
        u = (await c.get("/api/v2/usage", params={"group_by": "provider"})).json()
        by = {r["provider"]: r for r in u["rows"]}
        assert by["paid_a"]["cost_usd"] == COST_A and by["paid_a"]["fallbacks"] == 1 and by["paid_b"]["errors"] == 1
        assert (await c.get("/api/v2/usage", params={"group_by": "nope"})).status_code == 400
        put = await c.put("/api/v2/budgets", json={"budgets": {"global_daily": 5, "provider_monthly": {"paid_a": 1}},
                                                   "run_limits": {"max_model_calls": 20}})
        assert put.status_code == 200
        b = (await c.get("/api/v2/budgets")).json()
        assert b["settings"]["run_limits"]["max_model_calls"] == 20
        assert {x["name"]: x["pct_used"] for x in b["budgets"]} == {
            "global_daily": round(100 * COST_A / 5, 1), "provider_monthly[paid_a]": round(100 * COST_A / 1, 1)}
        entry = [e for e in await app.state.audit.entries() if e["action"] == "usage.settings.update"][0]
        assert entry["details"]["new"]["global_daily"] == 5 and entry["details"]["old"]["max_model_calls"] == 50
        assert (await c.put("/api/v2/budgets", json={"budgets": {"global_daily": -1}})).status_code == 400
        # fail closed: the audit store is not writable -> 503 and the budgets do not change
        store = app.state.audit.store
        import shutil

        shutil.rmtree(store.dir)
        store.dir.mkdir()
        store.path.mkdir()
        store._loaded = False
        assert (await c.put("/api/v2/budgets", json={"budgets": {"global_daily": 999}})).status_code == 503
        assert (await c.get("/api/v2/budgets")).json()["settings"]["budgets"]["global_daily"] == 5
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://localhost",
                           headers={"Host": "localhost"}) as anon:
        assert (await anon.get("/api/v2/usage")).status_code == 401
        assert (await anon.put("/api/v2/budgets", json={})).status_code == 401


@pytest.mark.asyncio
async def test_run_usage_endpoint(env, monkeypatch):
    chain(env.mp, PAID_A)
    st = await run(env, llm_flow(2), "r_api_run")
    assert st.status == RunStatus.SUCCEEDED
    monkeypatch.setenv("AGENTOS_API_TOKEN", "test-token-run-usage")
    from agentos_server.app import create_app

    app = create_app(project_path=str(env.tmp), storage=env.storage)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://localhost",
                           headers={"Authorization": "Bearer test-token-run-usage", "Host": "localhost"}) as c:
        r = (await c.get("/api/v2/flows/usage_flow/runs/r_api_run/usage")).json()
    assert r["model_calls"] == 2 and r["total_tokens"] == 2 * (PROMPT + COMPLETION)
    assert r["cost_usd"] == round(2 * COST_A, 8) and [c["node_id"] for c in r["calls"]] == ["llm1", "llm2"]
