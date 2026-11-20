"""
2.4e: read-only Overview aggregate (GET /api/v2/overview?window=24h|7d).

Aggregates existing runs, run events, flows, webhooks, provider policy and the router's
circuit breaker. Nothing is written. Same auth as every other /api route (middleware).

Payload rules:
- KPIs, run rows, blocked rows and provider rows carry metadata only (ids, statuses, counts,
  latencies, provider/model names, error class names, rule reasons).
- The only payload values are the waiting approvals' ``sink_args`` / ``arguments`` (the exact call
  the operator approves, from 2.4d-fix). The UI renders them as plain text with their labels.
- Key material is never read into the response: "has key" is a boolean from the provider list.
"""

from __future__ import annotations

import os
import re
import statistics
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Literal, Optional

from fastapi import APIRouter, Query, Request

from agentos.__version__ import __version__

router = APIRouter(tags=["v2-overview"])

RUN_SCAN_LIMIT = 500
BLOCK_TYPES = ("tool_call_blocked", "tool_call_rejected")
# SinkRuleViolationError text: "[node:arg] reason"
_SINK_VIOLATION = re.compile(r"^\[[^:\]]+:[^\]]+\]")
_SECURITY_ERROR_TYPES = ("SinkRuleViolationError", "PinnedArgumentOverrideError", "SSRFBlockedError",
                         "SinkArgumentRejected")
_WINDOWS = {"24h": timedelta(hours=24), "7d": timedelta(days=7)}


def _aware(ts: Any) -> Optional[datetime]:
    if ts is None:
        return None
    if isinstance(ts, str):
        try:
            ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            return None
    if isinstance(ts, datetime):
        return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
    return None


def _iso(ts: Any) -> Optional[str]:
    t = _aware(ts)
    return t.isoformat() if t else None


def is_security_block(ev: Any) -> bool:
    """A blocked tool call, or a node that failed on a sink rule / pinned-argument violation."""
    if ev.type in BLOCK_TYPES:
        return True
    if ev.type != "node_failed":
        return False
    data = ev.data or {}
    err = str(data.get("error") or "")
    if err == "rejected_by_operator":
        return False
    info = data.get("error_info") or {}
    etype = data.get("error_type") or info.get("error_type")  # error_type: node_failed events from 2.4e on
    return bool(_SINK_VIOLATION.match(err)) or etype in _SECURITY_ERROR_TYPES


def _storage_mode(request: Request) -> str:
    storage = request.app.state.storage
    mongo = "mongo" in type(storage.runs).__module__
    return "platform" if (mongo or getattr(request.app.state, "redis", None) is not None) else "standalone"


OLLAMA_CHECK_TIMEOUT_S = 1.5
OLLAMA_CHECK_TTL_S = 30.0  # a real check, reused for 30 s so every Overview load does not wait up to 1.5 s
_ollama_cache: tuple[float, bool] | None = None


async def _ollama_reachable() -> bool:
    """GET <OLLAMA_BASE_URL>/api/tags with a short timeout (in a thread: requests is blocking); cached 30 s."""
    import asyncio
    import time

    from agentos.llm.router_factory import check_ollama_reachable

    global _ollama_cache
    now = time.monotonic()
    if _ollama_cache is not None and now - _ollama_cache[0] < OLLAMA_CHECK_TTL_S:
        return _ollama_cache[1]
    try:
        up = await asyncio.to_thread(check_ollama_reachable, OLLAMA_CHECK_TIMEOUT_S)
    except Exception:
        up = False
    _ollama_cache = (time.monotonic(), up)
    return up


async def _provider_rows(request: Request) -> tuple[List[Dict[str, Any]], bool]:
    """Fallback chain with health, and whether any non-local provider has a key (booleans only)."""
    from agentos.llm.router_llm import cooldown_snapshot
    from agentos_server.routes_v2.providers import get_fallback_policy, list_providers

    policy = await get_fallback_policy(request)
    statuses = await list_providers(request)
    has_key = {p.name: bool(p.api_key_configured) for p in statuses}
    remote_key = any(p.api_key_configured and not p.is_local for p in statuses)
    cooling = cooldown_snapshot()
    local = {p.name for p in statuses if p.is_local}
    ollama_up: bool | None = None  # 3.4 Part 0c: checked at most once per request, only if a local row needs it
    rows: List[Dict[str, Any]] = []
    for item in policy:
        c = cooling.get(item.name)
        if not item.enabled:
            state = "disabled"
        elif not has_key.get(item.name, False):
            state = "no_key"
        elif c:
            state = "cooling"
        elif item.name in local:
            # A local server is "healthy" only after a real reachability check (never assumed)
            if ollama_up is None:
                ollama_up = await _ollama_reachable()
            state = "healthy" if ollama_up else "not_running"
        else:
            state = "healthy"
        rows.append({
            "name": item.name,
            "display_name": item.display_name,
            "order": item.order,
            "state": state,
            "cooling_s": c["seconds_left"] if (c and state == "cooling") else None,
            "cooling_reason": c["error_class"] if (c and state == "cooling") else None,
            "has_key": has_key.get(item.name, False),
        })
    rows.sort(key=lambda r: (r["state"] == "disabled", r["order"]))
    return rows, remote_key


async def _unacked_alerts(request: Request) -> int:
    notify = getattr(request.app.state, "notify", None)
    if notify is None:
        return 0
    try:
        return await notify.unacknowledged_count()
    except Exception:
        return 0


@router.get("/overview")
async def get_overview(
    request: Request, window: Literal["24h", "7d"] = Query("24h")
) -> Dict[str, Any]:
    storage = request.app.state.storage
    now = datetime.now(timezone.utc)
    since = now - _WINDOWS[window]
    today = now.replace(hour=0, minute=0, second=0, microsecond=0)

    runs = await storage.runs.list(limit=RUN_SCAN_LIMIT)
    truncated = len(runs) >= RUN_SCAN_LIMIT
    flow_runs = [r for r in runs if r.flow_id]

    counts = {"total": 0, "succeeded": 0, "failed": 0, "waiting": 0, "running": 0}
    attacks_window = 0
    attacks_today = 0
    latencies: List[float] = []
    model_calls = 0
    fallbacks = 0
    recent: List[Dict[str, Any]] = []
    waiting: List[Dict[str, Any]] = []
    blocked: List[Dict[str, Any]] = []
    first_approval = False

    for r in flow_runs:
        created = _aware(r.created_at) or now
        in_window = created >= since
        status = str(r.status)
        is_waiting = status == "waiting"
        # Older runs are only read while looking for the first approval decision (checklist).
        if not in_window and not is_waiting and first_approval:
            continue
        events = await storage.events.list(r.run_id, after_seq=0)
        if any(e.type == "approval_decision" for e in events):
            first_approval = True
        if not in_window and not is_waiting:
            continue

        answered: Optional[Dict[str, Any]] = None
        for e in events:
            d = e.data or {}
            if e.type == "llm_call":
                if in_window:
                    model_calls += 1
                    if isinstance(d.get("latency_ms"), (int, float)) and d.get("status") == "ok":
                        latencies.append(float(d["latency_ms"]))
                    if d.get("status") == "ok" and d.get("attempts"):
                        fallbacks += 1
                if d.get("status") == "ok":
                    answered = {"provider": d.get("provider"), "model": d.get("model"),
                                "fallback": bool(d.get("attempts")), "mock": bool(d.get("mock"))}
            elif is_security_block(e):
                ts = _aware(e.ts) or created
                if in_window:
                    attacks_window += 1
                    blocked.append({
                        "run_id": r.run_id, "flow_id": r.flow_id, "seq": e.seq, "kind": e.type,
                        "node_id": d.get("agent_node") or d.get("node_id"),
                        "tool_name": d.get("tool_name"),
                        "reason": str(d.get("reason") or d.get("error") or "")[:500],
                        "ts": _iso(ts),
                    })
                if ts >= today:
                    attacks_today += 1

        if is_waiting:
            wait_ev = next((e for e in reversed(events) if e.type == "node_waiting"), None)
            if wait_ev is not None:
                d = wait_ev.data or {}
                waiting.append({
                    "run_id": r.run_id, "flow_id": r.flow_id, "node_id": d.get("node_id"),
                    "prompt": d.get("prompt"), "approves": d.get("approves"),
                    "arguments": d.get("arguments"),
                    "sink_args": d.get("sink_args") or {}, "since": _iso(wait_ev.ts),
                })

        if not in_window:
            continue
        counts["total"] += 1
        if status in ("succeeded", "failed", "waiting"):
            counts[status] += 1
        elif status in ("running", "pending", "queued"):
            counts["running"] += 1
        finished = status in ("succeeded", "failed")
        upd = _aware(r.updated_at)
        duration = int((upd - created).total_seconds() * 1000) if (finished and upd) else None
        if len(recent) < 10:
            recent.append({
                "run_id": r.run_id, "flow_id": r.flow_id, "flow_version": r.flow_version,
                "trigger": r.trigger or "manual", "status": status, "answered_by": answered,
                "started_at": _iso(created), "duration_ms": duration,
            })

    blocked.sort(key=lambda b: b["ts"] or "", reverse=True)

    flows = await storage.flows.list_flows()
    flows_sorted = sorted(flows, key=lambda f: _aware(f.updated_at) or now, reverse=True)
    flow_rows: List[Dict[str, Any]] = []
    flow_published = False
    for f in flows_sorted:
        versions = await storage.flows.list_versions(f.id)
        latest = max((v.version or 0 for v in versions), default=0) or None
        flow_published = flow_published or latest is not None
        if len(flow_rows) < 6 and f.status != "archived":
            flow_rows.append({"flow_id": f.id, "name": f.name or f.id, "latest_version": latest,
                              "updated_at": _iso(f.updated_at)})

    providers, remote_key = await _provider_rows(request)
    vault_names = [i.name for i in await request.app.state.vault.list()]
    webhooks = await storage.webhooks.list() if getattr(storage, "webhooks", None) else []

    return {
        "window": window,
        "generated_at": now.isoformat(),
        "mode": _storage_mode(request),
        "version": __version__,
        "mock_llm": os.environ.get("AGENTOS_MOCK_LLM") == "1",
        "truncated": truncated,
        "kpis": {
            "runs": counts,
            "attacks_blocked": attacks_window,
            "waiting_for_approval": len(waiting),
            "model_calls": {
                "total": model_calls,
                "median_latency_ms": round(statistics.median(latencies), 1) if latencies else None,
                "fallbacks": fallbacks,
            },
        },
        "needs_you": {
            "waiting_approvals": len(waiting),
            "attacks_blocked_today": attacks_today,
            "providers_cooling": sum(1 for p in providers if p["state"] == "cooling"),
            "unacknowledged_alerts": await _unacked_alerts(request),
        },
        "recent_runs": recent,
        "waiting": waiting[:10],
        "blocked": blocked[:50],
        "providers": providers,
        "flows": flow_rows,
        "getting_started": {
            "key_added": bool(vault_names) or remote_key,
            "flow_published": flow_published,
            "first_run": bool(flow_runs),
            "first_approval": first_approval,
            "webhook_created": bool(webhooks),
        },
    }
