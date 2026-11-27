"""
Usage, cost and budgets endpoints (3.2), same token auth as every /api route; metadata only.

- GET /api/v2/usage?group_by=day,provider&since=YYYY-MM-DD&until=YYYY-MM-DD   ledger rows grouped, totals, and
  p50/p95 latency per provider (from the window's llm_call events, newest 500 runs)
- GET /api/v2/budgets      settings (run limits + USD budgets) and today's / this month's spend per budget
- PUT /api/v2/budgets      admin (local token); audited before it applies (503 if the entry cannot be written)
- GET /api/v2/flows/{flow_id}/runs/{run_id}/usage   one run's totals and its model calls
Prices are estimates from the price table; the provider's bill is the truth.
"""

from __future__ import annotations

import datetime as _dt
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import ValidationError

from agentos.usage.ledger import COUNTERS, UsageSettings, calls_in, today_utc
from agentos_server.audit_support import audit

router = APIRouter(tags=["v2-usage"])
GROUPS = ("day", "flow_id", "provider", "model")
_ALIASES = {"flow": "flow_id"}


def _ctx(request: Request) -> Any:
    ctx = getattr(request.app.state, "usage", None)
    if ctx is None or ctx.ledger is None:
        raise HTTPException(status_code=503, detail="Usage ledger is not configured")
    return ctx


def _pct(values: List[float], q: float) -> Optional[float]:
    if not values:
        return None
    v = sorted(values)
    k = max(0, min(len(v) - 1, int(round(q * (len(v) - 1)))))
    return round(v[k], 1)


@router.get("/usage")
async def get_usage(
    request: Request,
    group_by: str = Query("day", max_length=60),
    since: Optional[str] = Query(None, pattern=r"^\d{4}-\d{2}-\d{2}$"),
    until: Optional[str] = Query(None, pattern=r"^\d{4}-\d{2}-\d{2}$"),
) -> Dict[str, Any]:
    keys = [_ALIASES.get(g.strip(), g.strip()) for g in group_by.split(",") if g.strip()]
    bad = [k for k in keys if k not in GROUPS]
    if bad or not keys:
        raise HTTPException(status_code=400, detail="group_by must be a comma list of day, flow, provider, model")
    until = until or today_utc()
    since = since or (_dt.date.fromisoformat(until) - _dt.timedelta(days=29)).isoformat()
    ctx = _ctx(request)
    grouped: dict[tuple, dict[str, Any]] = {}
    totals = {c: 0 for c in COUNTERS}
    for r in await ctx.ledger.rows(since=since, until=until):
        g = tuple(r[k] for k in keys)
        cur = grouped.setdefault(g, {**dict(zip(keys, g)), **{c: 0 for c in COUNTERS}})
        for c in COUNTERS:
            cur[c] += r.get(c, 0)
            totals[c] += r.get(c, 0)
    rows = []
    for v in grouped.values():
        v["cost_usd"] = round(v["cost_usd"], 8)
        v["latency_avg_ms"] = round(v["latency_ms_sum"] / v["latency_count"], 1) if v["latency_count"] else None
        rows.append(v)
    rows.sort(key=lambda x: tuple(str(x[k]) for k in keys))
    totals["cost_usd"] = round(totals["cost_usd"], 8)
    # p50 / p95 latency per provider from the window's llm_call events (bounded scan)
    storage = request.app.state.storage
    lat: dict[str, list[float]] = {}
    for run in await storage.runs.list(limit=500):
        for e in await storage.events.list(run.run_id, after_seq=0):
            d = e.data or {}
            if e.type == "llm_call" and d.get("status") == "ok" and since <= (d.get("day") or "") <= until \
                    and d.get("latency_ms") is not None:
                lat.setdefault(d.get("provider") or "-", []).append(float(d["latency_ms"]))
    latency = [{"provider": p, "p50_ms": _pct(v, 0.5), "p95_ms": _pct(v, 0.95), "samples": len(v)}
               for p, v in sorted(lat.items())]
    return {"group_by": keys, "since": since, "until": until, "rows": rows, "totals": totals, "latency": latency,
            "note": "Costs are estimates from the price table; the provider's bill is the truth."}


async def _budget_status(ctx: Any, settings: UsageSettings) -> List[Dict[str, Any]]:
    b = settings.budgets
    items: List[tuple[str, float, Dict[str, Any]]] = []
    if b.global_daily is not None:
        items.append(("global_daily", b.global_daily, {"month": False}))
    if b.global_monthly is not None:
        items.append(("global_monthly", b.global_monthly, {"month": True}))
    for f, v in sorted(b.flow_daily.items()):
        items.append((f"flow_daily[{f}]", v, {"month": False, "flow_id": f}))
    for p, v in sorted(b.provider_monthly.items()):
        items.append((f"provider_monthly[{p}]", v, {"month": True, "provider": p}))
    out = []
    for name, limit, kw in items:
        spent = await ctx.spend(**kw)
        out.append({"name": name, "limit_usd": limit, "spent_usd": spent,
                    "pct_used": round(100 * spent / limit, 1) if limit else (100.0 if spent > 0 else 0.0)})
    return out


@router.get("/budgets")
async def get_budgets(request: Request) -> Dict[str, Any]:
    ctx = _ctx(request)
    settings = await ctx.get_settings()
    return {"settings": settings.model_dump(), "budgets": await _budget_status(ctx, settings),
            "spend": {"today_usd": await ctx.spend(month=False), "month_usd": await ctx.spend(month=True)}}


def _flat(s: UsageSettings) -> Dict[str, Any]:
    """One level of numbers for the audit entry (names and values only)."""
    out: Dict[str, Any] = {
        "max_model_calls": s.run_limits.max_model_calls, "max_total_tokens": s.run_limits.max_total_tokens,
        "max_sandbox_calls": s.run_limits.max_sandbox_calls,
        "global_daily": s.budgets.global_daily, "global_monthly": s.budgets.global_monthly,
    }
    for f, v in sorted(s.budgets.flow_daily.items()):
        out[f"flow_daily.{f}"[:64]] = v
    for p, v in sorted(s.budgets.provider_monthly.items()):
        out[f"provider_monthly.{p}"[:64]] = v
    for p, plan in sorted(s.billing_plans.items()):
        out[f"billing_plan.{p}"[:64]] = plan
    for f, lim in sorted(s.run_limits.flows.items()):
        out[f"run_limits.{f}"[:64]] = f"{lim.max_model_calls or '-'} calls / {lim.max_total_tokens or '-'} tokens"
    return out


@router.put("/budgets")
async def put_budgets(payload: Dict[str, Any], request: Request) -> Dict[str, Any]:
    ctx = _ctx(request)
    if ctx.settings is None:
        raise HTTPException(status_code=503, detail="Usage settings store is not configured")
    try:
        new = UsageSettings.model_validate(payload)
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=f"Invalid budgets or run limits: {e.errors()[0]['msg']}")
    old = await ctx.get_settings()
    if "billing_plans" not in payload:  # 3.3: the budgets editor does not manage billing plans; keep them
        new = new.model_copy(update={"billing_plans": dict(old.billing_plans)})
    # 3.2: admin change, audited before it applies (fail closed: 503 and nothing changes)
    await audit(request, "usage.settings.update", "usage_settings", "budgets",
                details={"old": _flat(old), "new": _flat(new)})
    await ctx.put_settings(new)
    return {"settings": new.model_dump(), "budgets": await _budget_status(ctx, new)}


@router.get("/flows/{flow_id}/runs/{run_id}/usage")
async def run_usage(flow_id: str, run_id: str, request: Request) -> Dict[str, Any]:
    storage = request.app.state.storage
    if await storage.runs.get(run_id) is None:
        raise HTTPException(status_code=404, detail=f"Run {run_id!r} not found")
    calls, tokens, cost, unknown = 0, 0, 0.0, 0
    items = []
    for e in await storage.events.list(run_id, after_seq=0):
        if e.type != "llm_call":
            continue
        d = e.data or {}
        calls += calls_in(d)
        tokens += int(d.get("total_tokens") or 0)
        if d.get("status") == "ok":
            if d.get("cost_usd") is None:
                unknown += 1
            else:
                cost += float(d["cost_usd"])
        items.append({"seq": e.seq, "node_id": d.get("node_id"), "status": d.get("status"),
                      "provider": d.get("provider"), "model": d.get("model"),
                      "total_tokens": d.get("total_tokens"), "cost_usd": d.get("cost_usd"),
                      "price_source": d.get("price_source"), "reason": d.get("reason")})
    return {"run_id": run_id, "flow_id": flow_id, "model_calls": calls, "total_tokens": tokens,
            "cost_usd": round(cost, 8), "cost_unknown_calls": unknown, "calls": items}
