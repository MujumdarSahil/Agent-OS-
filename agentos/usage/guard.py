"""Run limits and budgets, checked before EVERY provider attempt (3.2). Design: docs/evidence/3.2.md.

- Run limits (on by default, also for $0 models): model calls and total tokens per run; exceeding one trips the
  guard (sticky): no further model call in this run, the run fails with "run limit exceeded: ...".
- Budgets (USD): global daily / monthly, per flow daily, per provider monthly. A $0 (known) price is always
  allowed. Otherwise: a budget that applies + unknown price -> refused (set a price); spent >= limit -> refused.
  After any budget refusal in a call, only $0 providers may be tried (the fallback chain cannot escape a budget).
- No reservation: the check reads the ledger before the call; parallel calls in flight can overshoot a budget by
  at most their own cost (documented and tested).

``before_attempt`` runs in the worker thread of the model call; spend totals are read on the engine's event loop.
"""

from __future__ import annotations

import asyncio
from typing import Any, Callable, Optional

from agentos.usage.ledger import UsageSettings, calls_in, today_utc
from agentos.usage.pricing import Price, price_for


class RunLimitExceeded(RuntimeError):
    pass


class BudgetExceeded(RuntimeError):
    pass


class UsageContext:
    """What every engine of this server shares: the ledger, the admin settings and the price overrides."""

    def __init__(self, ledger: Any = None, settings: Any = None, price_overrides: Optional[dict[str, Any]] = None):
        self.ledger = ledger
        self.settings = settings
        self.price_overrides = price_overrides or {}
        # 3.3: billing plans cached here (refreshed on every settings read/write) so price() needs no I/O
        self.billing_plans: dict[str, str] = {}

    @classmethod
    def default(cls) -> "UsageContext":
        """No store (tests, embedded use): default run limits still apply; no budgets; nothing recorded."""
        return cls()

    async def get_settings(self) -> UsageSettings:
        s = await self.settings.get() if self.settings is not None else UsageSettings()
        self.billing_plans = dict(s.billing_plans)
        return s

    async def put_settings(self, settings: UsageSettings) -> None:
        await self.settings.put(settings)
        self.billing_plans = dict(settings.billing_plans)

    def price(self, provider: Optional[str], model: Optional[str], local: bool = False) -> Price:
        return price_for(provider, model, self.price_overrides, local=local,
                         plan=self.billing_plans.get(provider or ""))

    async def spend(self, *, month: bool, flow_id: Optional[str] = None, provider: Optional[str] = None,
                    day: Optional[str] = None) -> float:
        if self.ledger is None:
            return 0.0
        day = day or today_utc()
        since = day[:8] + "01" if month else day
        total = 0.0
        for r in await self.ledger.rows(since=since, until=day):
            if flow_id is not None and r["flow_id"] != flow_id:
                continue
            if provider is not None and r["provider"] != provider:
                continue
            total += float(r.get("cost_usd") or 0)
        return round(total, 8)


class RunGuard:
    def __init__(self, ctx: UsageContext, run_id: str, flow_id: str, settings: UsageSettings,
                 loop: Optional[asyncio.AbstractEventLoop] = None,
                 emit: Optional[Callable[[str, dict[str, Any]], None]] = None) -> None:
        self.ctx = ctx
        self.run_id = run_id
        self.flow_id = flow_id
        self.max_calls, self.max_tokens = settings.limits_for(flow_id)
        self.max_sandbox_calls = settings.sandbox_limit_for(flow_id)
        self.sandbox_calls = 0
        self.budgets = settings.budgets
        self.loop = loop
        self.emit = emit
        self.calls = 0
        self.tokens = 0
        self.tripped: Optional[RunLimitExceeded] = None

    def seed(self, records: list[dict[str, Any]]) -> None:
        """Counters of a resumed run, from its existing llm_call events."""
        for r in records:
            self.observe(r)

    def observe(self, record: dict[str, Any]) -> None:
        self.calls += calls_in(record)
        self.tokens += int(record.get("total_tokens") or 0)

    # -------------------------------------------------------------- checks
    def seed_sandbox(self, count: int) -> None:
        """3.5: sandbox calls already made by a resumed run (from its sandbox events)."""
        self.sandbox_calls = max(self.sandbox_calls, int(count))

    def before_sandbox_call(self) -> None:
        """3.5: max sandbox calls per run; exceeding it trips the guard (the run then fails like on other limits)."""
        if self.tripped is not None:
            raise self.tripped
        if self.sandbox_calls >= self.max_sandbox_calls:
            self._trip("sandbox_calls", self.sandbox_calls, self.max_sandbox_calls)
        self.sandbox_calls += 1

    def _trip(self, kind: str, used: int, limit: int) -> None:
        label = {"calls": "model calls", "tokens": "total tokens", "sandbox_calls": "sandbox calls"}[kind]
        self.tripped = RunLimitExceeded(f"run limit exceeded: {label} {used}/{limit}")
        if self.emit:
            self.emit("run_limit_exceeded", {"limit": kind, "used": used, "max": limit})
        raise self.tripped

    def _spend(self, **kw: Any) -> float:
        coro = self.ctx.spend(**kw)
        if self.loop is None:
            return asyncio.run(coro)
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result(timeout=10)

    def _applicable(self, provider: Optional[str]) -> list[tuple[str, float, dict[str, Any]]]:
        b = self.budgets
        out: list[tuple[str, float, dict[str, Any]]] = []
        if b.global_daily is not None:
            out.append(("global_daily", b.global_daily, {"month": False}))
        if b.global_monthly is not None:
            out.append(("global_monthly", b.global_monthly, {"month": True}))
        if self.flow_id in b.flow_daily:
            out.append((f"flow_daily[{self.flow_id}]", b.flow_daily[self.flow_id],
                        {"month": False, "flow_id": self.flow_id}))
        if provider and provider in b.provider_monthly:
            out.append((f"provider_monthly[{provider}]", b.provider_monthly[provider],
                        {"month": True, "provider": provider}))
        return out

    def _refuse(self, msg: str, details: dict[str, Any]) -> None:
        if self.emit:
            self.emit("budget_exceeded", details)
        raise BudgetExceeded(msg)

    def before_attempt(self, entry: dict[str, Any], after_budget_block: bool = False) -> None:
        if self.tripped is not None:
            raise self.tripped
        if self.calls >= self.max_calls:
            self._trip("calls", self.calls, self.max_calls)
        if self.tokens >= self.max_tokens:
            self._trip("tokens", self.tokens, self.max_tokens)
        provider, model = entry.get("provider"), entry.get("model")
        price = self.ctx.price(provider, model, local=bool(entry.get("local")))
        if not price.free:
            if after_budget_block:
                self._refuse("budget exceeded: only $0 providers may be used after a budget refusal",
                             {"budget": "fallback", "provider": provider, "model": model})
            applicable = self._applicable(provider)
            if applicable and not price.known:
                self._refuse(f"budget applies but the price of {provider}/{model} is unknown; "
                             "set a price in agentos.config.yaml (usage.prices)",
                             {"budget": applicable[0][0], "provider": provider, "model": model, "reason": "price_unknown"})
            for name, limit, kw in applicable:
                spent = self._spend(**kw)
                if spent >= limit:
                    self._refuse(f"budget exceeded: {name} ({limit:.2f} USD)",
                                 {"budget": name, "limit_usd": limit, "spent_usd": spent, "provider": provider,
                                  "model": model})
        self.calls += 1  # counted when attempted (a failed attempt is still a call)

    def after_record(self, record: dict[str, Any]) -> None:
        """Tokens from a finished call (calls were counted at attempt time)."""
        self.tokens += int(record.get("total_tokens") or 0)
