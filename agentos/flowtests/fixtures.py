"""4.2 D4: test runs NEVER cause real side effects.

- send_email / send_slack: MockTransport recorders (always, also with "live tools").
- http_request / fetch_url: the real HttpRequestTransport (real SSRF guard and allowlist) with a fake resolver and a
  fixture sender. A call without a fixture is recorded as a miss and fails the case ("no fixture for ...").
- MCP tools: FixtureMCPManager (same ``call_tool`` interface the tool proxy uses); fixture by tool name.
- Admin-only live tools: a GET without a fixture may use the real resolver and sender; anything else stays fake.
"""

from __future__ import annotations

import fnmatch
import json
import time
from dataclasses import dataclass
from typing import Any

from agentos.flows import net_guard
from agentos.flows.net_guard import CheckedTarget, HttpRequestTransport, RawResponse
from agentos.flows.proxy import MockTransport
from agentos.flowtests.models import Fixture

FAKE_PUBLIC_IP = "93.184.216.34"  # never contacted: the fixture sender answers instead


class NoFixture(RuntimeError):
    pass


def _body_bytes(body: Any) -> bytes:
    if body is None:
        return b""
    if isinstance(body, (dict, list, int, float, bool)):
        return json.dumps(body).encode("utf-8")
    return str(body).encode("utf-8")


def url_matches(pattern: str, url: str) -> bool:
    if pattern == url:
        return True
    if pattern.endswith("*"):
        return url.startswith(pattern[:-1]) or fnmatch.fnmatchcase(url, pattern)
    return pattern.rstrip("/") == url.rstrip("/")


class FixtureNetwork:
    """Fake resolver + fixture sender behind the real SSRF guard."""

    def __init__(self, fixtures: list[Fixture], allowlist: list[str], *, live_tools: bool = False) -> None:
        self.fixtures = [f for f in fixtures if f.kind == "http"]
        self.live_tools = live_tools
        self.calls: list[dict[str, Any]] = []
        self.misses: list[str] = []
        self.transport = HttpRequestTransport(allowlist=allowlist, resolver=self.resolve, sender=self.send)

    def resolve(self, host: str, port: int) -> list[str]:
        if self.live_tools:
            return net_guard.default_resolver(host, port)  # real DNS only with the admin's live-tools option
        return [FAKE_PUBLIC_IP]

    def find(self, method: str, url: str) -> Fixture | None:
        for f in self.fixtures:
            if f.url and (f.method or "GET").upper() == method.upper() and url_matches(f.url, url):
                return f
        return None

    def send(self, method: str, target: CheckedTarget, path: str, headers: dict[str, str], body: bytes | None,
             timeout_s: float, max_bytes: int) -> RawResponse:
        from agentos.flowtests.models_choice import CURRENT_NODE

        url = target.url
        fx = self.find(method, url)
        call = {"method": method.upper(), "url": url, "host": target.host.lower(), "fixture": fx is not None,
                "node": CURRENT_NODE.get()}
        if fx is not None:
            self.calls.append({**call, "mode": "fixture"})
            data = _body_bytes(fx.body)
            return RawResponse(fx.status, {"content-type": fx.content_type}, data[:max_bytes], len(data) > max_bytes)
        if self.live_tools and method.upper() == "GET":
            self.calls.append({**call, "mode": "live"})
            return net_guard.httpx_sender(method, target, path, headers, body, timeout_s, max_bytes)
        miss = f"no fixture for http {method.upper()} {url}"
        self.misses.append(miss)
        self.calls.append({**call, "mode": "missing"})
        raise NoFixture(miss)


@dataclass
class FixtureMCPResult:
    status: str
    text: str
    duration_ms: float = 0.0
    output_bytes: int = 0
    truncated: bool = False


class FixtureMCPManager:
    """Stands in for agentos.mcp.manager.MCPManager in test runs: no MCP server is ever started."""

    def __init__(self, fixtures: list[Fixture]) -> None:
        self.fixtures = {f.tool: f for f in fixtures if f.kind == "mcp" and f.tool}
        self.calls: list[dict[str, Any]] = []
        self.misses: list[str] = []

    def _fixture(self, record: Any, tool: str) -> Fixture | None:
        server = getattr(record, "name", None) or (record.get("name") if isinstance(record, dict) else None)
        for key in (f"{server}.{tool}" if server else None, f"mcp:{server}.{tool}" if server else None, tool,
                    f"mcp:{tool}"):
            if key and key in self.fixtures:
                return self.fixtures[key]
        return None

    async def call_tool(self, record: Any, tool: str, sha256: str, args: dict[str, Any]) -> FixtureMCPResult:
        from agentos.mcp.manager import MCPError

        from agentos.flowtests.models_choice import CURRENT_NODE

        started = time.perf_counter()
        fx = self._fixture(record, tool)
        self.calls.append({"tool": tool, "args": args, "fixture": fx is not None, "node": CURRENT_NODE.get()})
        if fx is None:
            miss = f"no fixture for mcp:{tool}"
            self.misses.append(miss)
            raise MCPError(miss)
        text = fx.body if isinstance(fx.body, str) else json.dumps(fx.body)
        return FixtureMCPResult(status="ok" if fx.status < 400 else "error", text=text,
                                duration_ms=round((time.perf_counter() - started) * 1000, 2),
                                output_bytes=len(text.encode("utf-8")))


class TestSinks:
    """Every transport a test run gets (built per case; never the app's transports)."""
    __test__ = False

    def __init__(self, fixtures: list[Fixture], allowlist: list[str], *, live_tools: bool = False) -> None:
        self.email, self.slack = MockTransport(), MockTransport()
        self.net = FixtureNetwork(fixtures, allowlist, live_tools=live_tools)      # http_request nodes
        self.fetch = FixtureNetwork(fixtures, allowlist, live_tools=live_tools)    # the fetch_url agent tool
        self.mcp = FixtureMCPManager(fixtures)

    def registry(self) -> dict[str, Any]:
        return {"send_email": self.email, "send_slack": self.slack, "http_request": self.net.transport,
                "fetch_url": self.fetch.transport}

    @property
    def misses(self) -> list[str]:
        return list(dict.fromkeys(self.net.misses + self.fetch.misses + self.mcp.misses))
