"""Usage ledger and usage settings (3.2). Design: docs/evidence/3.2.md.

Ledger rows: (day UTC, flow_id, provider, model) -> calls, errors, fallbacks, prompt/completion tokens, cost_usd,
cost_unknown_calls, latency_ms_sum, latency_count. Updated after each llm_call event; rebuildable from the events
(the events are the source of truth). Settings: run limits + USD budgets, admin-managed (PUT /api/v2/budgets is
audited). The Mongo variants live in agentos/storage/mongo/usage.py (pymongo stays in the Mongo adapter).
"""

from __future__ import annotations

import asyncio
import datetime as _dt
import json
from pathlib import Path
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field

from agentos.storage.atomic import atomic_write_text

COUNTERS = ("calls", "errors", "fallbacks", "prompt_tokens", "completion_tokens", "cost_usd", "cost_unknown_calls",
            "latency_ms_sum", "latency_count")
# recorded attempts that never reached a provider (router_llm.SKIPPED_COOLDOWN and 3.2 budget refusals)
NOT_A_CALL = {"skipped (cooldown)", "BudgetExceeded"}


def today_utc() -> str:
    return _dt.datetime.now(_dt.timezone.utc).date().isoformat()


def row_key(day: str, flow_id: str, provider: str, model: str) -> str:
    return "|".join((day, flow_id or "-", provider or "-", model or "-"))


def _blank(day: str, flow_id: str, provider: str, model: str) -> dict[str, Any]:
    return {"day": day, "flow_id": flow_id or "-", "provider": provider or "-", "model": model or "-",
            **{c: 0 for c in COUNTERS}}


def increments(record: dict[str, Any], flow_id: str, day: str) -> list[dict[str, Any]]:
    """Ledger increments for one llm_call record (one row per provider/model touched)."""
    rows: dict[str, dict[str, Any]] = {}

    def row(provider: Optional[str], model: Optional[str]) -> dict[str, Any]:
        k = row_key(day, flow_id, provider or "-", model or "-")
        if k not in rows:
            rows[k] = _blank(day, flow_id, provider or "-", model or "-")
        return rows[k]

    real_failures = [a for a in (record.get("attempts") or []) if a.get("error_class") not in NOT_A_CALL]
    for a in real_failures:
        r = row(a.get("provider"), a.get("model"))
        r["calls"] += 1
        r["errors"] += 1
    status = record.get("status")
    if status == "ok":
        r = row(record.get("provider"), record.get("model"))
        r["calls"] += 1
        r["prompt_tokens"] += int(record.get("prompt_tokens") or 0)
        r["completion_tokens"] += int(record.get("completion_tokens") or 0)
        if record.get("cost_usd") is None:
            r["cost_unknown_calls"] += 1
        else:
            r["cost_usd"] += float(record["cost_usd"])
        if record.get("latency_ms") is not None:
            r["latency_ms_sum"] += float(record["latency_ms"])
            r["latency_count"] += 1
        if real_failures:
            r["fallbacks"] += 1
    elif status in ("refused", "failed") and not real_failures:
        row(None, None)["errors"] += 1
    return list(rows.values())


def calls_in(record: dict[str, Any]) -> int:
    """Provider attempts in one record (what the run limit counts)."""
    n = len([a for a in (record.get("attempts") or []) if a.get("error_class") not in NOT_A_CALL])
    return n + (1 if record.get("status") == "ok" else 0)


def _merge(into: dict[str, Any], inc: dict[str, Any]) -> None:
    for c in COUNTERS:
        into[c] = round(into.get(c, 0) + inc.get(c, 0), 8) if c == "cost_usd" else into.get(c, 0) + inc.get(c, 0)


class FileUsageLedger:
    """``<project>/.agentos/state/usage_ledger.json`` (one lock, atomic writes)."""

    def __init__(self, project_path: str) -> None:
        self.path = Path(project_path) / ".agentos" / "state" / "usage_ledger.json"
        self._lock = asyncio.Lock()

    def _load(self) -> dict[str, dict[str, Any]]:
        if not self.path.exists():
            return {}
        try:
            return json.loads(self.path.read_text(encoding="utf-8")).get("rows", {})
        except ValueError:
            return {}

    def _save(self, rows: dict[str, dict[str, Any]]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(self.path, json.dumps({"version": 1, "rows": rows}, sort_keys=True))

    async def add(self, incs: list[dict[str, Any]]) -> None:
        if not incs:
            return
        async with self._lock:
            rows = self._load()
            for inc in incs:
                k = row_key(inc["day"], inc["flow_id"], inc["provider"], inc["model"])
                cur = rows.setdefault(k, _blank(inc["day"], inc["flow_id"], inc["provider"], inc["model"]))
                _merge(cur, inc)
            self._save(rows)

    async def rows(self, since: Optional[str] = None, until: Optional[str] = None) -> list[dict[str, Any]]:
        out = [dict(r) for r in self._load().values()]
        return [r for r in out if (not since or r["day"] >= since) and (not until or r["day"] <= until)]

    async def replace(self, rows: list[dict[str, Any]]) -> None:
        async with self._lock:
            self._save({row_key(r["day"], r["flow_id"], r["provider"], r["model"]): r for r in rows})


# ---------------------------------------------------------------------------- settings (limits + budgets)

DEFAULT_MAX_MODEL_CALLS = 50
DEFAULT_MAX_TOTAL_TOKENS = 300_000


class FlowRunLimits(BaseModel):
    max_model_calls: Optional[int] = Field(default=None, ge=1, le=100_000)
    max_total_tokens: Optional[int] = Field(default=None, ge=1, le=1_000_000_000)


class RunLimits(BaseModel):
    max_model_calls: int = Field(default=DEFAULT_MAX_MODEL_CALLS, ge=1, le=100_000)
    max_total_tokens: int = Field(default=DEFAULT_MAX_TOTAL_TOKENS, ge=1, le=1_000_000_000)
    flows: Dict[str, FlowRunLimits] = Field(default_factory=dict)


class Budgets(BaseModel):
    global_daily: Optional[float] = Field(default=None, ge=0)
    global_monthly: Optional[float] = Field(default=None, ge=0)
    flow_daily: Dict[str, float] = Field(default_factory=dict)
    provider_monthly: Dict[str, float] = Field(default_factory=dict)


class UsageSettings(BaseModel):
    run_limits: RunLimits = Field(default_factory=RunLimits)
    budgets: Budgets = Field(default_factory=Budgets)

    def limits_for(self, flow_id: str) -> tuple[int, int]:
        """Effective limits: a per-flow value can only LOWER the global one."""
        rl = self.run_limits
        f = rl.flows.get(flow_id) or FlowRunLimits()
        calls = min(rl.max_model_calls, f.max_model_calls or rl.max_model_calls)
        tokens = min(rl.max_total_tokens, f.max_total_tokens or rl.max_total_tokens)
        return calls, tokens


class FileUsageSettings:
    """``<project>/.agentos/state/budgets.json`` (atomic)."""

    def __init__(self, project_path: str) -> None:
        self.path = Path(project_path) / ".agentos" / "state" / "budgets.json"

    async def get(self) -> UsageSettings:
        if not self.path.exists():
            return UsageSettings()
        return UsageSettings.model_validate_json(self.path.read_text(encoding="utf-8"))

    async def put(self, settings: UsageSettings) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(self.path, settings.model_dump_json(indent=2))


def usage_stores_for(storage: Any) -> tuple[Any, Any]:
    """(ledger, settings) of a Storage backend."""
    if getattr(storage, "backend", "file") == "mongo":
        from agentos.storage.mongo.usage import MongoUsageLedger, MongoUsageSettings

        db = storage.runs._c.database
        return MongoUsageLedger(db.usage_ledger), MongoUsageSettings(db.usage_settings)
    return FileUsageLedger(storage.location), FileUsageSettings(storage.location)


async def rebuild_rows(storage: Any, limit_runs: int = 100_000) -> list[dict[str, Any]]:
    """Recompute every ledger row from the runs' llm_call events (the ledger is never the only source)."""
    totals: dict[str, dict[str, Any]] = {}
    for run in await storage.runs.list(limit=limit_runs):
        for e in await storage.events.list(run.run_id, after_seq=0):
            if e.type != "llm_call":
                continue
            # every llm_call event since 3.2 records its UTC day; older events (none had cost) count as today
            day = (e.data or {}).get("day") or today_utc()
            for inc in increments(e.data or {}, run.flow_id or "-", day):
                k = row_key(inc["day"], inc["flow_id"], inc["provider"], inc["model"])
                cur = totals.setdefault(k, _blank(inc["day"], inc["flow_id"], inc["provider"], inc["model"]))
                _merge(cur, inc)
    return list(totals.values())
