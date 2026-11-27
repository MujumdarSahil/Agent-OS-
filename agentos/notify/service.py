"""NotifyService (3.3): channels, real sends for flows, alerts, persistent outbox and the delivery worker.
Design: docs/evidence/3.3.md.

Alert text is written here from METADATA ONLY (rule, flow id, run id, counts, a fixed AgentOS reason, a link).
Event ``reason`` / ``error`` text, argument values, tool names chosen by a model and any payload never reach an
alert: rule-violation reasons can contain attacker-chosen values.
"""

from __future__ import annotations

import asyncio
import datetime as _dt
import hashlib
import heapq
import logging
import re
import time
import uuid
from typing import Any, Callable, Iterable, Optional

from pydantic import BaseModel, Field, field_validator

from agentos.flows.rules import SinkArgumentRejected
from agentos.notify.channels import (
    ChannelError,
    EmailChannel,
    SlackChannel,
    build_message,
    check_slack_webhook_url,
    message_id,
    parse_channel,
    validate_email_args,
    validate_slack_args,
)
from agentos.notify.senders import DeliveryError, SlackSender, check_smtp_host, smtp_send
from agentos.notify.store import NotifyStore

logger = logging.getLogger(__name__)

__all__ = ["DeliveryError", "NotifyService", "AlertRule", "RULE_TYPES", "ObservedEvents"]

RULE_TYPES: dict[str, str] = {
    "attack_blocked": "Attack blocked",
    "run_failed": "Run failed",
    "approval_waiting": "Approval waiting",
    "provider_down": "Provider down",
    "budget_exceeded": "Budget or run limit exceeded",
    "audit_broken": "Audit chain broken",
}
MAX_ATTEMPTS = 5
BACKOFF_S = 30.0
SAFE_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
SAFE_BUDGET = re.compile(r"^[A-Za-z0-9_.:\[\]-]{1,80}$")
SECURITY_ERROR_TYPES = ("SinkRuleViolationError", "PinnedArgumentOverrideError", "SSRFBlockedError",
                        "SinkArgumentRejected")
_SINK_VIOLATION = re.compile(r"^\[[^:\]]+:[^\]]+\]")
SKIPPED_COOLDOWN = "skipped (cooldown)"
UNCERTAIN = "delivery uncertain (the server stopped during the send); not resent"

# Fixed AgentOS reasons for attack_blocked, keyed by event kind / error class
ATTACK_REASONS = {
    "tool_call_blocked": "a tool call was blocked by a security rule",
    "tool_call_rejected": "a tool call was rejected (unknown tool, or an override of a pinned argument)",
    "SinkRuleViolationError": "a sink rule blocked a send (label check)",
    "PinnedArgumentOverrideError": "an attempt to override a pinned argument was refused",
    "SSRFBlockedError": "the network guard refused a request (blocked address)",
    "SinkArgumentRejected": "a send was refused (unsafe arguments such as header injection)",
    "publish_refused": "publishing a flow was refused: the static check found rule violations",
}


def safe_id(value: Any) -> str:
    return value if isinstance(value, str) and SAFE_ID.fullmatch(value) else "other"


def _iso(ts: float) -> str:
    return _dt.datetime.fromtimestamp(ts, tz=_dt.timezone.utc).isoformat()


def security_block_kind(ev: Any) -> Optional[str]:
    """The ATTACK_REASONS key of a security-block event, or None. (Shared with the Overview read model.)"""
    if ev.type in ("tool_call_blocked", "tool_call_rejected"):
        return ev.type
    if ev.type != "node_failed":
        return None
    data = ev.data or {}
    err = str(data.get("error") or "")
    if err == "rejected_by_operator" or data.get("handled"):
        return None
    info = data.get("error_info") or {}
    etype = data.get("error_type") or info.get("error_type")
    if etype in SECURITY_ERROR_TYPES:
        return etype
    if _SINK_VIOLATION.match(err):
        return "SinkRuleViolationError"
    return None


class AlertRule(BaseModel):
    id: str
    enabled: bool = True
    channels: list[str] = Field(default_factory=list, max_length=10)
    cooldown_min: int = Field(default=15, ge=0, le=1440)
    params: dict[str, int] = Field(default_factory=dict)

    @field_validator("id")
    @classmethod
    def _id(cls, v: str) -> str:
        if v not in RULE_TYPES:
            raise ValueError(f"unknown rule type; one of {sorted(RULE_TYPES)}")
        return v

    @field_validator("params")
    @classmethod
    def _params(cls, v: dict[str, int]) -> dict[str, int]:
        bad = [k for k in v if k != "minutes"]
        if bad:
            raise ValueError("the only parameter is 'minutes' (approval_waiting)")
        if "minutes" in v and not (1 <= int(v["minutes"]) <= 10080):
            raise ValueError("minutes must be between 1 and 10080")
        return v


def default_rules() -> list[AlertRule]:
    return [AlertRule(id=t, params={"minutes": 30} if t == "approval_waiting" else {}) for t in RULE_TYPES]


class NotifyService:
    def __init__(self, store: NotifyStore, vault: Any = None, *, storage: Any = None,
                 smtp_allowlist: Iterable[str] = (), ui_base_url: str = "http://127.0.0.1:8000",
                 clock: Callable[[], float] = time.time, slack_sender: Optional[SlackSender] = None,
                 smtp_resolver: Any = None, ssl_context: Any = None, policy: Any = None) -> None:
        self.store = store
        self.vault = vault
        self.storage = storage
        self.smtp_allowlist = list(smtp_allowlist)
        self.ui_base_url = (ui_base_url or "http://127.0.0.1:8000").rstrip("/")
        self.clock = clock
        self.slack = slack_sender or SlackSender()
        self.smtp_resolver = smtp_resolver
        self.ssl_context = ssl_context  # tests only (a test CA); None = system trust store
        self.policy = policy
        self._timers: list[tuple[float, str, str]] = []  # (due, run_id, node_id) approval_waiting checks
        self._wake: Optional[Callable[[], None]] = None
        self.sent_log: list[dict[str, Any]] = []  # metadata of every delivery attempt (tests and debugging)

    # ------------------------------------------------------------------------------------------- channels
    async def channels(self) -> list[EmailChannel | SlackChannel]:
        out = []
        for d in await self.store.channels.list():
            try:
                out.append(parse_channel(d))
            except Exception:
                logger.warning("ignoring an invalid stored notification channel")
        return sorted(out, key=lambda c: c.name)

    async def channel(self, name: str) -> Optional[EmailChannel | SlackChannel]:
        d = await self.store.channels.get(name)
        return parse_channel(d) if d else None

    async def check_channel(self, ch: EmailChannel | SlackChannel, *, resolve: bool = True) -> None:
        """Save-time checks (ChannelError). Email: TLS rules, flow-channel uniqueness, SMTP host address."""
        ch.check_config()
        if isinstance(ch, EmailChannel):
            if ch.use_for_flows:
                for other in await self.channels():
                    if isinstance(other, EmailChannel) and other.use_for_flows and other.name != ch.name:
                        raise ChannelError(f"email channel {other.name!r} is already used for flows")
            if resolve:
                try:
                    check_smtp_host(ch, self.smtp_allowlist, self.smtp_resolver)
                except DeliveryError as e:
                    raise ChannelError(str(e)) from None

    async def save_channel(self, ch: EmailChannel | SlackChannel, *, secret_value: Optional[str] = None) -> None:
        """Stores a write-only secret in the vault (never in the record), then the record."""
        if secret_value is not None:
            if isinstance(ch, SlackChannel):
                check_slack_webhook_url(secret_value)
                name = f"notify.slack.{ch.name}"
                ch = ch.model_copy(update={"webhook_secret": name})
            else:
                name = f"notify.smtp.{ch.name}"
                ch = ch.model_copy(update={"password_secret": name})
            await self.vault.put(name, secret_value)
        await self.store.channels.put({**ch.model_dump(), "id": ch.name})
        await self.sync_policy()

    async def delete_channel(self, name: str) -> bool:
        ch = await self.channel(name)
        found = await self.store.channels.delete(name)
        if ch is not None and self.vault is not None:
            secret = ch.webhook_secret if isinstance(ch, SlackChannel) else ch.password_secret
            if secret and secret.startswith("notify."):
                try:
                    await self.vault.delete(secret)
                except Exception:
                    pass
        await self.sync_policy()
        return found

    async def sync_policy(self) -> None:
        """security_policy.slack_channels = {name: internal} of the ENABLED Slack channels."""
        if self.policy is not None:
            self.policy.slack_channels = {c.name: bool(c.internal) for c in await self.channels()
                                          if isinstance(c, SlackChannel) and c.enabled}

    async def flow_email_channel(self) -> Optional[EmailChannel]:
        for c in await self.channels():
            if isinstance(c, EmailChannel) and c.use_for_flows and c.enabled:
                return c
        return None

    async def _secret(self, name: Optional[str]) -> Optional[str]:
        if not name:
            return None
        try:
            return await self.vault.reveal(name)
        except Exception:
            return None

    # ------------------------------------------------------------------------------------------- sends
    async def send_email(self, ch: EmailChannel, recipients: list[str], subject: str, body: str,
                         idempotency_key: str) -> dict[str, Any]:
        if not ch.enabled:
            raise DeliveryError(f"email channel {ch.name!r} is disabled")
        ch.check_config()
        ip = check_smtp_host(ch, self.smtp_allowlist, self.smtp_resolver)
        password = await self._secret(ch.password_secret)
        msg = build_message(ch, recipients, subject, body, idempotency_key)
        res = await asyncio.to_thread(smtp_send, ch, ip, password, msg, recipients, self.ssl_context)
        self.sent_log.append({"channel": ch.name, "type": "email", "recipients": len(recipients),
                              "message_id": msg["Message-ID"]})
        return {"status": "sent", "channel": ch.name, "message_id": msg["Message-ID"], "refused": res["refused"]}

    async def send_slack(self, ch: SlackChannel, text: str) -> dict[str, Any]:
        if not ch.enabled:
            raise DeliveryError(f"Slack channel {ch.name!r} is disabled")
        url = await self._secret(ch.webhook_secret)
        if not url:
            raise DeliveryError("the Slack channel has no webhook URL in the vault")
        try:
            res = await asyncio.to_thread(self.slack.post, url, text)
        except ChannelError as e:
            raise DeliveryError(str(e)) from None
        self.sent_log.append({"channel": ch.name, "type": "slack"})
        return {**res, "channel": ch.name}

    async def deliver(self, channel_name: str, subject: str, text: str, idempotency_key: str) -> dict[str, Any]:
        """Alert / test delivery to one channel (DeliveryError on failure)."""
        ch = await self.channel(channel_name)
        if ch is None:
            raise DeliveryError(f"channel {channel_name!r} does not exist")
        if isinstance(ch, SlackChannel):
            return await self.send_slack(ch, f"{subject}\n{text}")
        if not ch.alert_recipients:
            raise DeliveryError("the email channel has no alert recipients")
        return await self.send_email(ch, list(ch.alert_recipients), subject, text, idempotency_key)

    async def test_channel(self, name: str) -> dict[str, Any]:
        key = f"test:{name}:{uuid.uuid4().hex}"
        try:
            await self.deliver(name, "[AgentOS] Test notification",
                               "This is a test message from AgentOS. No action is needed.", key)
            return {"ok": True}
        except DeliveryError as e:
            return {"ok": False, "error": str(e)}

    # ------------------------------------------------------------------------------------------- rules
    async def ensure_default_rules(self) -> None:
        for r in default_rules():
            await self.store.rules.insert_if_absent(r.model_dump())

    async def rules(self) -> list[AlertRule]:
        out = {r.id: r for r in default_rules()}
        for d in await self.store.rules.list():
            try:
                r = AlertRule.model_validate(d)
                out[r.id] = r
            except Exception:
                pass
        return [out[t] for t in RULE_TYPES]

    async def rule(self, rule_id: str) -> AlertRule:
        return next(r for r in await self.rules() if r.id == rule_id)

    async def put_rule(self, rule: AlertRule) -> None:
        await self.store.rules.put(rule.model_dump())

    # ------------------------------------------------------------------------------------------- alerts
    def _text(self, a: dict[str, Any]) -> tuple[str, str]:
        subject = f"[AgentOS] {a['title']} ({a['target']})"
        lines = [f"Rule: {a['title']}", f"Target: {a['target']}", f"Flow: {a.get('flow_id') or '-'}",
                 f"Run: {a.get('run_id') or '-'}", f"Count: {a['count']}", f"Reason: {a['reason']}"]
        if a.get("link"):
            lines.append(f"Open: {a['link']}")
        lines.append(f"Alert: {a['id']}")
        return subject, "\n".join(lines)

    async def fire(self, rule_type: str, target: str, *, reason: str, flow_id: Optional[str] = None,
                   run_id: Optional[str] = None) -> Optional[dict[str, Any]]:
        """Record an alert (or bump the one inside the cooldown) and queue one outbox entry per channel.
        ``reason`` must be AgentOS-written; identifiers are filtered to SAFE_ID here."""
        rule = await self.rule(rule_type)
        if not rule.enabled:
            return None
        now = self.clock()
        target = safe_id(target) if rule_type != "budget_exceeded" else (
            target if isinstance(target, str) and SAFE_BUDGET.fullmatch(target) else "other")
        flow_id = safe_id(flow_id) if flow_id else None
        run_id = safe_id(run_id) if run_id else None
        recent = [a for a in await self.store.alerts.list()
                  if a.get("rule") == rule_type and a.get("target") == target
                  and now - float(a.get("created_ts") or 0) < rule.cooldown_min * 60]
        if recent:
            latest = max(recent, key=lambda a: a["created_ts"])

            def bump(a: dict[str, Any]) -> dict[str, Any]:
                a["count"] = int(a.get("count") or 1) + 1
                a["last_seen"] = _iso(now)
                return a

            return await self.store.alerts.update(latest["id"], bump)
        alert_id = f"al_{uuid.uuid4().hex[:16]}"
        alert = {
            "id": alert_id, "rule": rule_type, "title": RULE_TYPES[rule_type], "target": target,
            "flow_id": flow_id, "run_id": run_id, "reason": reason, "count": 1,
            "created_ts": now, "created_at": _iso(now), "last_seen": _iso(now),
            "link": f"{self.ui_base_url}/runs/{run_id}" if run_id else None,
            "channels": list(rule.channels), "acknowledged": False, "ack_at": None,
        }
        await self.store.alerts.put(alert)
        for ch in rule.channels:
            key = hashlib.sha256(f"{alert_id}|{ch}".encode()).hexdigest()
            await self.store.outbox.insert_if_absent({
                "id": key, "alert_id": alert_id, "channel": ch, "status": "pending", "attempts": 0,
                "next_ts": now, "error": None, "sent_at": None, "created_ts": now,
            })
        if rule.channels and self._wake:
            self._wake()
        return alert

    async def acknowledge(self, alert_id: str) -> Optional[dict[str, Any]]:
        now = self.clock()

        def ack(a: dict[str, Any]) -> dict[str, Any]:
            if not a.get("acknowledged"):
                a["acknowledged"], a["ack_at"] = True, _iso(now)
            return a

        return await self.store.alerts.update(alert_id, ack)

    async def alerts_view(self, *, rule: Optional[str] = None, acknowledged: Optional[bool] = None,
                          status: Optional[str] = None, limit: int = 100) -> list[dict[str, Any]]:
        outbox: dict[str, list[dict[str, Any]]] = {}
        for e in await self.store.outbox.list():
            outbox.setdefault(e["alert_id"], []).append(e)
        out = []
        for a in sorted(await self.store.alerts.list(), key=lambda x: x.get("created_ts") or 0, reverse=True):
            if rule and a.get("rule") != rule:
                continue
            if acknowledged is not None and bool(a.get("acknowledged")) != acknowledged:
                continue
            deliveries = [{"channel": e["channel"], "status": e["status"], "attempts": e["attempts"],
                           "error": e.get("error"), "sent_at": e.get("sent_at")}
                          for e in sorted(outbox.get(a["id"], []), key=lambda e: e["channel"])]
            summary = _summary(deliveries)
            if status and summary != status:
                continue
            out.append({k: v for k, v in a.items() if k != "created_ts"} | {"deliveries": deliveries,
                                                                             "status": summary})
            if len(out) >= limit:
                break
        return out

    async def unacknowledged_count(self) -> int:
        return sum(1 for a in await self.store.alerts.list() if not a.get("acknowledged"))

    # ------------------------------------------------------------------------------------------- outbox
    async def recover(self) -> int:
        """At startup: an entry left in 'sending' may have been delivered; it is never resent."""
        n = 0
        for e in await self.store.outbox.list():
            if e.get("status") == "sending":
                await self.store.outbox.update(e["id"], lambda d: {**d, "status": "failed", "error": UNCERTAIN})
                n += 1
        return n

    async def process_due(self, now: Optional[float] = None) -> int:
        now = self.clock() if now is None else now
        done = 0
        for e in sorted(await self.store.outbox.list(), key=lambda x: x.get("next_ts") or 0):
            if e.get("status") not in ("pending", "retrying") or float(e.get("next_ts") or 0) > now:
                continue

            def claim(d: dict[str, Any]) -> Optional[dict[str, Any]]:
                if d.get("status") not in ("pending", "retrying"):
                    return None
                return {**d, "status": "sending", "attempts": int(d.get("attempts") or 0) + 1}

            claimed = await self.store.outbox.update(e["id"], claim)
            if claimed is None:
                continue
            alert = await self.store.alerts.get(e["alert_id"])
            try:
                if alert is None:
                    raise DeliveryError("the alert no longer exists")
                subject, text = self._text(alert)
                await self.deliver(e["channel"], subject, text, e["id"])
                await self.store.outbox.update(e["id"], lambda d: {**d, "status": "sent", "error": None,
                                                                   "sent_at": _iso(self.clock())})
            except Exception as err:
                msg = str(err) if isinstance(err, (DeliveryError, ChannelError)) else \
                    f"delivery failed ({type(err).__name__})"
                attempts = claimed["attempts"]
                if attempts >= MAX_ATTEMPTS:
                    upd = {"status": "failed", "error": f"{msg} (dead letter after {attempts} attempts)"}
                else:
                    upd = {"status": "retrying", "error": msg,
                           "next_ts": self.clock() + BACKOFF_S * (2 ** (attempts - 1))}
                await self.store.outbox.update(e["id"], lambda d, u=upd: {**d, **u})
            done += 1
        return done

    async def next_due(self) -> Optional[float]:
        dues = [float(e.get("next_ts") or 0) for e in await self.store.outbox.list()
                if e.get("status") in ("pending", "retrying")]
        if self._timers:
            dues.append(self._timers[0][0])
        return min(dues) if dues else None

    # ------------------------------------------------------------------------------------------- approval timers
    def schedule_approval_check(self, due: float, run_id: str, node_id: str) -> None:
        heapq.heappush(self._timers, (due, run_id, node_id))
        if self._wake:
            self._wake()

    async def process_timers(self, now: Optional[float] = None) -> int:
        now = self.clock() if now is None else now
        fired = 0
        while self._timers and self._timers[0][0] <= now:
            _, run_id, node_id = heapq.heappop(self._timers)
            if await self._still_waiting(run_id, node_id):
                run = await self.storage.runs.get(run_id) if self.storage is not None else None
                minutes = (await self.rule("approval_waiting")).params.get("minutes", 30)
                await self.fire("approval_waiting", run_id, flow_id=getattr(run, "flow_id", None), run_id=run_id,
                                reason=f"a run has been waiting for an approval for more than {int(minutes)} minutes")
                fired += 1
        return fired

    async def _is_test_run(self, run_id: Any) -> bool:
        """4.2: test runs never raise alerts or notifications."""
        if self.storage is None or not run_id:
            return False
        run = await self.storage.runs.get(str(run_id))
        return getattr(run, "trigger", None) == "test"

    async def _still_waiting(self, run_id: str, node_id: str) -> bool:
        if self.storage is None or await self._is_test_run(run_id):
            return False
        events = await self.storage.events.list(run_id, after_seq=0)
        last_wait = max((e.seq for e in events if e.type == "node_waiting" and (e.data or {}).get("node_id") == node_id),
                        default=None)
        if last_wait is None:
            return False
        return not any(e.seq > last_wait and e.type in ("approval_decision", "node_succeeded", "node_failed",
                                                         "run_succeeded", "run_failed", "run_cancelled")
                       for e in events)

    async def reschedule_waiting(self) -> int:
        """At startup: approval timers for runs that are still waiting (from their node_waiting event time)."""
        if self.storage is None:
            return 0
        minutes = (await self.rule("approval_waiting")).params.get("minutes", 30)
        n = 0
        for r in await self.storage.runs.list(limit=1000):
            if str(r.status) != "waiting" or getattr(r, "trigger", None) == "test":
                continue
            events = await self.storage.events.list(r.run_id, after_seq=0)
            w = next((e for e in reversed(events) if e.type == "node_waiting"), None)
            if w is None or (w.data or {}).get("reason") == "timer":
                continue
            ts = w.ts.timestamp() if hasattr(w.ts, "timestamp") else self.clock()
            self.schedule_approval_check(ts + minutes * 60, r.run_id, str((w.data or {}).get("node_id")))
            n += 1
        return n

    # ------------------------------------------------------------------------------------------- events -> alerts
    async def on_event(self, ev: Any) -> None:
        """Called after every event the server appends. Never raises."""
        try:
            await self._on_event(ev)
        except Exception as e:
            logger.warning("alert evaluation failed: %s", type(e).__name__)

    async def _flow_of(self, run_id: str) -> Optional[str]:
        if self.storage is None:
            return None
        run = await self.storage.runs.get(run_id)
        return getattr(run, "flow_id", None) if run else None

    async def _on_event(self, ev: Any) -> None:
        if await self._is_test_run(getattr(ev, "run_id", None)):
            return  # 4.2: test runs (fake sinks) fire no alert and send no notification
        d = ev.data or {}
        kind = security_block_kind(ev)
        if kind is not None:
            flow = await self._flow_of(ev.run_id)
            await self.fire("attack_blocked", flow or ev.run_id, flow_id=flow, run_id=ev.run_id,
                            reason=ATTACK_REASONS.get(kind, "a security rule blocked an action"))
            return
        if ev.type == "run_failed":
            flow = await self._flow_of(ev.run_id)
            etype = None
            if self.storage is not None:
                fails = [e for e in await self.storage.events.list(ev.run_id, after_seq=0) if e.type == "node_failed"]
                if fails:
                    etype = (fails[-1].data or {}).get("error_type")
            label = etype if isinstance(etype, str) and SAFE_ID.fullmatch(etype) else "unknown error"
            await self.fire("run_failed", flow or ev.run_id, flow_id=flow, run_id=ev.run_id,
                            reason=f"the run failed ({label})")
        elif ev.type == "node_waiting" and d.get("reason") != "timer":
            minutes = (await self.rule("approval_waiting")).params.get("minutes", 30)
            ts = ev.ts.timestamp() if hasattr(ev.ts, "timestamp") else self.clock()
            self.schedule_approval_check(ts + minutes * 60, ev.run_id, str(d.get("node_id")))
        elif ev.type == "llm_call":
            flow = await self._flow_of(ev.run_id)
            if d.get("status") == "failed" and all(a.get("error_class") != "BudgetExceeded"
                                                   for a in d.get("attempts") or []):
                await self.fire("provider_down", "all_providers", flow_id=flow, run_id=ev.run_id,
                                reason="every provider in the fallback chain failed")
            for a in d.get("attempts") or []:
                if a.get("error_class") == SKIPPED_COOLDOWN:
                    await self.fire("provider_down", safe_id(a.get("provider")), flow_id=flow, run_id=ev.run_id,
                                    reason="a provider's circuit is open (cooling down after errors)")
        elif ev.type == "budget_exceeded":
            flow = await self._flow_of(ev.run_id)
            budget = d.get("budget")
            budget = budget if isinstance(budget, str) and SAFE_BUDGET.fullmatch(budget) else "other"
            await self.fire("budget_exceeded", budget, flow_id=flow, run_id=ev.run_id,
                            reason=f"a USD budget was reached ({budget})")
        elif ev.type == "run_limit_exceeded":
            flow = await self._flow_of(ev.run_id)
            kind_ = "model calls" if d.get("limit") == "calls" else "total tokens"
            used, mx = d.get("used"), d.get("max")
            nums = f" {int(used)}/{int(mx)}" if isinstance(used, int) and isinstance(mx, int) else ""
            await self.fire("budget_exceeded", f"run_limit:{flow or 'other'}", flow_id=flow, run_id=ev.run_id,
                            reason=f"a run limit was exceeded ({kind_}{nums})")

    async def on_publish_refused(self, flow_id: str, violations: int) -> None:
        try:
            await self.fire("attack_blocked", flow_id, flow_id=flow_id,
                            reason=f"{ATTACK_REASONS['publish_refused']} ({int(violations)})")
        except Exception as e:
            logger.warning("alert evaluation failed: %s", type(e).__name__)

    async def on_audit_verify(self, result: dict[str, Any]) -> None:
        if (result or {}).get("status") != "broken":
            return
        reason = re.sub(r"[^A-Za-z0-9 _.,:()-]", "", str(result.get("reason") or "verification failed"))[:160]
        try:
            await self.fire("audit_broken", "audit", reason=f"audit log verification: {reason}")
        except Exception as e:
            logger.warning("alert evaluation failed: %s", type(e).__name__)


def _summary(deliveries: list[dict[str, Any]]) -> str:
    if not deliveries:
        return "no_channel"
    states = {d["status"] for d in deliveries}
    if states == {"sent"}:
        return "sent"
    if states & {"pending", "retrying", "sending"}:
        return "retrying" if "retrying" in states else "pending"
    return "failed" if "sent" not in states else "partial"


# --------------------------------------------------------------------------------------------- flow transports

class ChannelEmailTransport:
    """send_email for flows: the admin's email channel with use_for_flows; without one the send is SIMULATED and
    says so. Arguments are checked before the intent; a pending intent is never resent (retry_safe = False)."""

    retry_safe = False

    def __init__(self, service: NotifyService) -> None:
        self.service = service

    @staticmethod
    def _security_refusal(err: SinkArgumentRejected) -> bool:
        """Header injection and From/Cc/Bcc overrides are refused even when the send is only simulated."""
        msg = str(err)
        return "control characters" in msg or "cannot be set by a flow" in msg

    async def avalidate(self, args: dict[str, Any]) -> None:
        ch = await self.service.flow_email_channel()
        try:
            validate_email_args(args, ch)
        except SinkArgumentRejected as err:
            if ch is not None or self._security_refusal(err):
                raise
            # no channel: the send is simulated; asend says that a real channel would refuse these arguments

    async def asend(self, idempotency_key: str, **args: Any) -> dict[str, Any]:
        ch = await self.service.flow_email_channel()
        if ch is None:
            reason = "simulated: no email channel configured"
            try:
                validate_email_args(args, None)
            except SinkArgumentRejected as err:
                if self._security_refusal(err):
                    raise
                reason += "; a real email channel would refuse these arguments"
            return {"status": "simulated", "reason": reason, "idempotency_key": idempotency_key}
        recipients, subject, body = validate_email_args(args, ch)
        res = await self.service.send_email(ch, recipients, subject, body, idempotency_key)
        return {**res, "idempotency_key": idempotency_key}


class ChannelSlackTransport:
    retry_safe = False

    def __init__(self, service: NotifyService) -> None:
        self.service = service

    async def _channel(self, args: dict[str, Any]) -> tuple[SlackChannel, str]:
        name, text = validate_slack_args(args)
        ch = await self.service.channel(name)
        if not isinstance(ch, SlackChannel) or not ch.enabled:
            raise SinkArgumentRejected(f"send_slack: {name!r} is not an enabled Slack channel")
        return ch, text

    async def avalidate(self, args: dict[str, Any]) -> None:
        await self._channel(args)

    async def asend(self, idempotency_key: str, **args: Any) -> dict[str, Any]:
        ch, text = await self._channel(args)
        res = await self.service.send_slack(ch, text)
        return {**res, "idempotency_key": idempotency_key}


class StagingEmailTransport(ChannelEmailTransport):
    """4.3: send_email in a STAGING run goes to the email channel the admin mapped for staging (normally a test
    mailbox; that channel's own recipient rules apply). A missing or disabled channel -> simulated, never the
    production flow channel."""

    def __init__(self, service: NotifyService, channel_name: str) -> None:
        super().__init__(service)
        self.channel_name = channel_name

    async def _ch(self) -> Optional[EmailChannel]:
        ch = await self.service.channel(self.channel_name)
        return ch if isinstance(ch, EmailChannel) and ch.enabled else None

    async def avalidate(self, args: dict[str, Any]) -> None:
        ch = await self._ch()
        try:
            validate_email_args(args, ch)
        except SinkArgumentRejected as err:
            if ch is not None or self._security_refusal(err):
                raise

    async def asend(self, idempotency_key: str, **args: Any) -> dict[str, Any]:
        ch = await self._ch()
        if ch is None:
            return {"status": "simulated", "environment_simulated": True, "idempotency_key": idempotency_key,
                    "reason": f"staging: simulated, the mapped staging email channel {self.channel_name!r} "
                              "is missing or disabled"}
        recipients, subject, body = validate_email_args(args, ch)
        res = await self.service.send_email(ch, recipients, subject, body, idempotency_key)
        return {**res, "environment": "staging", "idempotency_key": idempotency_key}


class StagingSlackTransport(ChannelSlackTransport):
    """4.3: send_slack in a STAGING run is delivered only to the Slack channels the admin mapped for staging;
    any other channel is simulated."""

    def __init__(self, service: NotifyService, allowed: set[str], fallback: Any) -> None:
        super().__init__(service)
        self.allowed = allowed
        self.fallback = fallback

    def _mapped(self, args: dict[str, Any]) -> bool:
        return isinstance(args.get("channel"), str) and args["channel"] in self.allowed

    async def avalidate(self, args: dict[str, Any]) -> None:
        if self._mapped(args):
            await super().avalidate(args)
        else:
            await self.fallback.avalidate(args)

    async def asend(self, idempotency_key: str, **args: Any) -> dict[str, Any]:
        if self._mapped(args):
            res = await super().asend(idempotency_key, **args)
            return {**res, "environment": "staging"}
        return await self.fallback.asend(idempotency_key, **args)


def staging_registry_factory(service: NotifyService) -> Callable[..., Any]:
    """4.3 (D4): the transports of a staging / draft run. Draft: always simulated. Staging: simulated unless the
    admin mapped an email channel and/or Slack channels for staging."""

    async def factory(environment: str, registry: dict[str, Any]) -> dict[str, Any]:
        from agentos.flows.environments import simulated_registry

        reg = await simulated_registry(environment, registry)
        repo = getattr(service.storage, "deployments", None)  # follows the storage if Mongo replaces it at startup
        if environment != "staging" or repo is None:
            return reg
        mapping = await repo.get_staging_channels()
        if mapping.email_channel:
            reg["send_email"] = StagingEmailTransport(service, mapping.email_channel)
        if mapping.slack_channels:
            reg["send_slack"] = StagingSlackTransport(service, set(mapping.slack_channels), reg["send_slack"])
        return reg

    return factory


# --------------------------------------------------------------------------------------------- event observer

class ObservedEvents:
    """Wraps a Storage's event repository: every appended event is passed to the observer (which never raises)."""

    def __init__(self, inner: Any, observer: Callable[[Any], Any]) -> None:
        object.__setattr__(self, "_inner", inner)
        object.__setattr__(self, "_observer", observer)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    def __setattr__(self, name: str, value: Any) -> None:
        setattr(self._inner, name, value)

    async def append(self, *args: Any, **kwargs: Any) -> Any:
        ev = await self._inner.append(*args, **kwargs)
        await self._observer(ev)
        return ev


class NotifyWorker:
    """One asyncio task: delivers due outbox entries and approval timers, then sleeps until the next due time or
    until woken by a new alert (no fixed polling interval). Stopped on shutdown."""

    def __init__(self, service: NotifyService) -> None:
        self.service = service
        self._event = asyncio.Event()
        self._stop = False
        self._task: Optional[asyncio.Task[Any]] = None
        service._wake = self._event.set

    def start(self) -> None:
        self._task = asyncio.create_task(self._run(), name="agentos-notify-worker")

    async def _run(self) -> None:
        while not self._stop:
            self._event.clear()
            try:
                await self.service.process_due()
                await self.service.process_timers()
                nxt = await self.service.next_due()
            except Exception as e:
                logger.warning("notification worker step failed: %s", type(e).__name__)
                nxt = self.service.clock() + BACKOFF_S
            timeout = None if nxt is None else max(0.05, nxt - self.service.clock())
            try:
                await asyncio.wait_for(self._event.wait(), timeout)
            except asyncio.TimeoutError:
                pass

    async def stop(self) -> None:
        self._stop = True
        self._event.set()
        if self._task is not None:
            try:
                await asyncio.wait_for(self._task, 10)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                self._task.cancel()
            self._task = None
        self.service._wake = None


__all__ += ["ChannelEmailTransport", "ChannelSlackTransport", "StagingEmailTransport", "StagingSlackTransport",
           "staging_registry_factory", "NotifyWorker", "security_block_kind",
            "message_id"]
