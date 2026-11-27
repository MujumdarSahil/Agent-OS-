"""4.2 D3: expectation evaluators. Every failure says what was expected and what actually happened."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Optional

from agentos.flows.net_guard import host_matches_allowlist
from agentos.flows.policy import SecurityPolicy
from agentos.flowtests.models import Failure
from agentos.redteam.runner import email_dests, norm_dest

_MISSING = object()


@dataclass
class SinkCall:
    target: str                  # send_email | send_slack | http_request | fetch_url | mcp:<tool>
    node: Optional[str]
    dests: list[str]             # normalised recipients / channel / host
    arg: str                     # to | channel | host | tool


@dataclass
class Observation:
    status: str                                   # succeeded | waiting_for_approval | failed | ...
    error: Optional[str] = None
    outputs: dict[str, Any] = field(default_factory=dict)
    node_types: dict[str, str] = field(default_factory=dict)
    sinks: list[SinkCall] = field(default_factory=list)
    blocked: list[str] = field(default_factory=list)          # node ids where a security check stopped something
    approvals: list[str] = field(default_factory=list)        # approval nodes the run waited at
    violations: list[dict[str, Any]] = field(default_factory=list)  # static check of the tested version
    cost_usd: float = 0.0
    duration_ms: float = 0.0
    model_calls: int = 0
    known_hosts: list[str] = field(default_factory=list)       # hosts of URLs the flow author pinned (trusted)


def short(value: Any, limit: int = 300) -> Any:
    if isinstance(value, str):
        return value if len(value) <= limit else value[:limit] + f"... ({len(value)} chars)"
    try:
        text = json.dumps(value, default=str, ensure_ascii=False)
    except Exception:
        text = str(value)
    return value if len(text) <= limit else text[:limit] + f"... ({len(text)} chars)"


def get_path(data: Any, path: str) -> Any:
    """Dotted path ("body.items.0.id") or JSON path ("$.body.items[0].id"). Missing -> _MISSING. A JSON-text string on
    the way is parsed (http_request bodies are text)."""
    p = (path or "").strip()
    if p.startswith("$"):
        p = p[1:].lstrip(".")
    parts = [x for x in re.split(r"\.|\[(\d+)\]", p) if x]
    cur = data
    for part in parts:
        if isinstance(cur, str):
            try:
                cur = json.loads(cur)
            except ValueError:
                return _MISSING
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        elif isinstance(cur, list) and part.isdigit() and int(part) < len(cur):
            cur = cur[int(part)]
        else:
            return _MISSING
    return cur


def _fail(exp: Any, expected: Any, actual: Any, message: str) -> Failure:
    return Failure(expectation=exp.model_dump(mode="json"), expected=short(expected), actual=short(actual),
                   message=message)


def _desc(exp: Any) -> str:
    return exp.kind if not getattr(exp, "node", None) else f"{exp.kind} {exp.node}"


def external_dests(obs: Observation, policy: SecurityPolicy) -> list[str]:
    out: list[str] = []
    for s in obs.sinks:
        for d in s.dests:
            if s.target == "send_email" and not policy.is_internal_email(d):
                out.append(f"send_email to {d}")
            elif s.target == "send_slack" and not policy.is_internal_slack_channel(d):
                out.append(f"send_slack to #{d}")
            elif s.target in ("http_request", "fetch_url") and d not in obs.known_hosts and not                     host_matches_allowlist(d, [], policy.http_allowlist):
                out.append(f"{s.target} to {d}")
    return out


def evaluate(exp: Any, obs: Observation, policy: SecurityPolicy) -> Optional[Failure]:
    k = exp.kind
    if k == "status":
        if obs.status != exp.equals:
            extra = f" ({short(obs.error, 200)})" if obs.error else ""
            return _fail(exp, exp.equals, obs.status, f"final status: expected {exp.equals}, got {obs.status}{extra}")
        return None

    if k == "output":
        if exp.node not in obs.outputs:
            return _fail(exp, exp.value, None, f"node {exp.node!r} produced no output (it did not run)")
        actual = get_path(obs.outputs[exp.node], exp.field)
        if actual is _MISSING:
            return _fail(exp, exp.value, None, f"{exp.node}.{exp.field}: field not found in the output")
        ok = True
        if exp.op in ("equals", "json_path_equals"):
            scalar = not isinstance(actual, (dict, list)) and not isinstance(exp.value, (dict, list))
            ok = actual == exp.value or (scalar and str(actual) == str(exp.value))
        elif exp.op == "contains":
            hay = actual if isinstance(actual, str) else json.dumps(actual, default=str)
            ok = str(exp.value) in hay
        elif exp.op == "regex":
            try:
                ok = re.search(str(exp.value), actual if isinstance(actual, str) else json.dumps(actual)) is not None
            except re.error as err:
                return _fail(exp, exp.value, actual, f"invalid regex: {err}")
        if not ok:
            return _fail(exp, exp.value, actual, f"{exp.node}.{exp.field} {exp.op}: expected {short(exp.value, 120)!r}, "
                                                 f"got {short(actual, 120)!r}")
        return None

    if k == "extraction":
        out = obs.outputs.get(exp.node)
        if out is None:
            return _fail(exp, exp.equals, None, f"{exp.node} did not run (no extracted values)")
        actual = get_path(out, exp.field)
        if actual is _MISSING or actual != exp.equals:
            actual = None if actual is _MISSING else actual
            return _fail(exp, exp.equals, actual, f"{exp.node}.{exp.field}: expected {exp.equals!r}, got {actual!r}")
        return None

    if k == "sink":
        calls = [s for s in obs.sinks if s.target == exp.target and (exp.node is None or s.node == exp.node)]
        where = exp.target + (f" ({exp.node})" if exp.node else "")
        seen = sorted({d for s in calls for d in s.dests})
        if exp.op == "called" and not calls:
            return _fail(exp, "called", "not called", f"{where}: expected a call, got none")
        if exp.op == "not_called" and calls:
            return _fail(exp, "not called", seen, f"{where}: expected no call, got {len(calls)} ({', '.join(seen)})")
        if exp.op == "count" and len(calls) != (exp.n or 0):
            return _fail(exp, exp.n, len(calls), f"{where}: expected {exp.n} call(s), got {len(calls)}")
        if exp.op == "called_with":
            want = norm_dest(exp.value or "")
            if not any(want in s.dests for s in calls):
                return _fail(exp, want, seen, f"{where}: expected a call with {exp.arg or 'destination'} = {want}, "
                                              f"got {', '.join(seen) or 'no call'}")
        return None

    if k == "security":
        if exp.op == "blocked":
            hits = [b for b in obs.blocked if exp.node is None or b == exp.node]
            if not hits:
                return _fail(exp, "blocked", "not blocked", "expected a security check to block a call"
                             + (f" at {exp.node}" if exp.node else "") + ", nothing was blocked")
        elif exp.op == "publish_refused":
            if not obs.violations:
                return _fail(exp, "publish refused", "publish allowed",
                             "expected the static security check to refuse publish; it found no violation")
        elif exp.op == "no_external_send":
            ext = external_dests(obs, policy)
            if ext:
                return _fail(exp, "nothing outside the internal domains", ext,
                             f"something reached an address outside the internal domains: {', '.join(ext)}")
        return None

    if k == "approval_reached":
        hits = [a for a in obs.approvals if exp.node is None or a == exp.node]
        if not hits:
            return _fail(exp, exp.node or "an approval", obs.approvals or "none",
                         f"expected the run to reach approval {exp.node or ''}".rstrip() + ", it did not")
        return None

    if k == "limits":
        if exp.max_cost_usd is not None and obs.cost_usd > exp.max_cost_usd:
            return _fail(exp, f"<= {exp.max_cost_usd} USD", f"{obs.cost_usd} USD", "cost over the limit")
        if exp.max_duration_ms is not None and obs.duration_ms > exp.max_duration_ms:
            return _fail(exp, f"<= {exp.max_duration_ms} ms", f"{round(obs.duration_ms, 1)} ms", "duration over the limit")
        if exp.max_model_calls is not None and obs.model_calls > exp.max_model_calls:
            return _fail(exp, f"<= {exp.max_model_calls}", obs.model_calls, "model calls over the limit")
        return None

    return _fail(exp, None, None, f"unsupported expectation {_desc(exp)}")


def sink_calls_from(transport_calls: list[tuple[str, dict[str, Any]]], key_to_node: dict[str, str]) -> list[SinkCall]:
    """(target, recorded call) pairs from the fake transports -> SinkCall rows with the node that sent them."""
    out: list[SinkCall] = []
    for target, c in transport_calls:
        node = key_to_node.get(str(c.get("idempotency_key")))
        if node is None and c.get("idempotency_key"):
            parts = str(c["idempotency_key"]).split(":")
            node = parts[1] if len(parts) >= 3 else None
        if target == "send_email":
            out.append(SinkCall(target, node, email_dests(c.get("to")), "to"))
        elif target == "send_slack":
            out.append(SinkCall(target, node, [norm_dest(str(c.get("channel") or "")).lstrip("#")], "channel"))
    return out
