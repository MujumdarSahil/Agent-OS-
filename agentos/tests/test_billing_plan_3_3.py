"""3.3 (0a): per-provider billing plan (MOCK: litellm.completion replaced, fixed token counts; no keys, no network).

Groq providers are not tagged free-tier, so without a plan their price comes from LiteLLM's paid table (or is
unknown) and a USD budget blocks the default free chain. On the "free" plan the call costs $0 (source plan_free)
and is allowed under the same budget. "paid" ignores the free-tier tag. The API is audited and fail-closed.
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from agentos.flows.state import RunStatus
from agentos.tests.test_usage_3_2 import chain, env, events, llm_flow, run  # noqa: F401  (env is a fixture)
from agentos.usage import UsageSettings, price_for

GROQ = {"provider": "groq_gpt_oss_20b", "model": "groq/openai/gpt-oss-20b", "local": False}
FREE_TAGGED = ("openrouter_mistral_7b_free", "openrouter/mistralai/mistral-7b-instruct:free")


def test_plan_precedence():
    assert price_for(*FREE_TAGGED).source == "free_tier"
    assert price_for(*FREE_TAGGED, plan="paid").source != "free_tier"  # paid ignores the free-tier tag
    p = price_for("paid_a", "vendor/paid-a", {"paid_a": {"input_per_1m": 5, "output_per_1m": 5}}, plan="free")
    assert (p.source, p.free) == ("plan_free", True)  # free plan wins over an admin price override
    assert price_for(GROQ["provider"], GROQ["model"]).source in ("litellm", "unknown")  # today's default


@pytest.mark.asyncio
async def test_budget_blocks_groq_by_default_but_free_plan_allows_it_at_zero_cost(env):  # noqa: F811
    chain(env.mp, GROQ)
    st = await run(env, llm_flow(1), "r_groq_default", budgets={"global_daily": 0.0})
    assert st.status == RunStatus.FAILED and "budget" in (st.error or "") and env.calls == []

    s = await env.ctx.get_settings()
    await env.ctx.put_settings(s.model_copy(update={"billing_plans": {GROQ["provider"]: "free"}}))
    st2 = await run(env, llm_flow(1), "r_groq_free")
    assert st2.status == RunStatus.SUCCEEDED and env.calls == [GROQ["model"]]
    rec = (await events(env, "r_groq_free", "llm_call"))[0].data
    assert rec["cost_usd"] == 0.0 and rec["price_source"] == "plan_free"
    assert await env.ctx.spend(month=False) == 0.0


@pytest.mark.asyncio
async def test_billing_plan_api_is_audited_and_kept_by_the_budgets_editor(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTOS_API_TOKEN", "test-token-plan")
    monkeypatch.delenv("AGENTOS_MONGO_URI", raising=False)
    (tmp_path / "agentos.config.yaml").write_text("preferred_tags: []\n", encoding="utf-8")
    from agentos_server.app import create_app

    app = create_app(project_path=str(tmp_path))
    hdr = {"Authorization": "Bearer test-token-plan", "Host": "localhost"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://localhost", headers=hdr) as c:
        assert (await c.put("/api/v2/providers/not_a_provider/billing-plan", json={"plan": "free"})).status_code == 404
        assert (await c.put(f"/api/v2/providers/{GROQ['provider']}/billing-plan", json={"plan": "gratis"})).status_code == 422
        r = await c.put(f"/api/v2/providers/{GROQ['provider']}/billing-plan", json={"plan": "free"})
        assert r.status_code == 200 and r.json()["billing_plan"] == "free"
        listed = {p["name"]: p for p in (await c.get("/api/v2/providers")).json()}
        assert listed[GROQ["provider"]]["billing_plan"] == "free"
        assert app.state.usage.price(GROQ["provider"], GROQ["model"]).source == "plan_free"
        # the budgets editor (no billing_plans in its payload) keeps the plan
        assert (await c.put("/api/v2/budgets", json={"budgets": {"global_daily": 1}})).status_code == 200
        assert (await c.get("/api/v2/budgets")).json()["settings"]["billing_plans"] == {GROQ["provider"]: "free"}
        entry = [e for e in await app.state.audit.entries() if e["action"] == "provider.billing_plan.update"][0]
        assert entry["target"]["id"] == GROQ["provider"] and entry["details"] == {"old": "default", "new": "free"}
        # back to default
        await c.put(f"/api/v2/providers/{GROQ['provider']}/billing-plan", json={"plan": "default"})
        assert (await c.get("/api/v2/budgets")).json()["settings"]["billing_plans"] == {}
        # fail closed: audit store not writable -> 503, plan unchanged
        import shutil

        store = app.state.audit.store
        shutil.rmtree(store.dir)
        store.dir.mkdir()
        store.path.mkdir()
        store._loaded = False
        r = await c.put(f"/api/v2/providers/{GROQ['provider']}/billing-plan", json={"plan": "free"})
        assert r.status_code == 503
        assert UsageSettings.model_validate((await c.get("/api/v2/budgets")).json()["settings"]).billing_plans == {}
