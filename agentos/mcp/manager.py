"""MCP server lifecycle and mediated tool calls (2.5a).

One ``MCPManager`` per event loop (the API process creates one; the flow engine receives it).
- Servers start on first use (discovery or a tool call) and stop after an idle timeout, on
  ``stop_all()`` (shutdown), or when killed after a timeout. Killing ends the whole process tree.
- stdio children get the minimal environment from ``agentos.mcp.env`` (never os.environ) and a
  per-server working folder. http servers: the URL goes through ``net_guard.check_url`` (blocked
  ranges + admin allowlist); redirects are refused and every request URL is re-checked (T5).
  ``sse`` is not supported (deprecated in the MCP spec); discovery refuses it.
- Only tools are used. The client advertises no sampling, elicitation or roots capability; if a
  server sends such a request anyway, it is refused and recorded (T7). Resources and prompts are
  never read.
- Calls: per-server concurrency limit, per-call timeout (default 30 s, max 120 s; a timed-out server
  is killed), output cap (default 100 KB, truncated with a flag), max JSON-RPC message size (T6).
- Before a call, the live tool list is compared with the approved hash; a difference blocks the call
  and marks the tool "changed" (T2).
Server-level events are appended to the event store under the run id ``mcp-server-<name>``.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Awaitable, Callable, Iterable

import anyio
import mcp.types as types
from mcp.client.session import ClientSession
from mcp.shared.exceptions import McpError

from agentos.mcp.catalog import merge_discovery, tool_hash
from agentos.mcp.env import build_child_env, validate_env_names
from agentos.mcp.launcher import DEFAULT_MAX_MESSAGE_BYTES, kill_process_tree, stdio_transport
from agentos.storage.models import MCPServerRecord

DEFAULT_CALL_TIMEOUT_S = 30.0
MAX_CALL_TIMEOUT_S = 120.0
DEFAULT_MAX_OUTPUT_BYTES = 100_000
DEFAULT_IDLE_TIMEOUT_S = 300.0
DEFAULT_START_TIMEOUT_S = 20.0
DEFAULT_CONCURRENCY = 4

EventSink = Callable[[str, str, dict[str, Any]], Awaitable[None]]


class MCPError(Exception):
    pass


class MCPServerUnavailable(MCPError):
    pass


class MCPTimeout(MCPError):
    pass


class MCPToolChanged(MCPError):
    pass


def server_run_id(server: str) -> str:
    return f"mcp-server-{server}"


def _leaf(err: BaseException | None) -> BaseException | None:
    """The innermost error of a (nested) exception group, for readable messages."""
    while isinstance(err, BaseExceptionGroup) and err.exceptions:
        err = err.exceptions[0]
    return err


@dataclass
class CallResult:
    text: str
    status: str  # ok | error
    duration_ms: float
    output_bytes: int
    truncated: bool


@dataclass
class _Running:
    stop: asyncio.Event = field(default_factory=asyncio.Event)
    ready: asyncio.Event = field(default_factory=asyncio.Event)
    task: asyncio.Task | None = None
    session: ClientSession | None = None
    process: Any = None
    error: BaseException | None = None
    sem: asyncio.Semaphore | None = None
    live: dict[str, dict[str, Any]] = field(default_factory=dict)  # tool name -> {"sha256", ...}
    tools_dirty: bool = False
    idle: asyncio.TimerHandle | None = None


class _RecordingSession(ClientSession):
    """ClientSession that refuses and records server-initiated requests (sampling, elicitation, roots,
    task requests). Capabilities are left at the SDK default, so none of them is advertised."""

    def __init__(self, *args: Any, on_refused: Callable[[str], Awaitable[None]],
                 on_tools_changed: Callable[[], None], **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._on_refused = on_refused
        self._on_tools_changed = on_tools_changed

    async def _received_request(self, responder: Any) -> None:
        root = responder.request.root
        if isinstance(root, types.PingRequest):
            return await super()._received_request(responder)
        method = getattr(root, "method", type(root).__name__)
        await self._on_refused(str(method))
        with responder:
            await responder.respond(types.ErrorData(code=types.METHOD_NOT_FOUND,
                                                    message=f"{method} is not supported by this client"))
        return None

    async def _received_notification(self, notification: Any) -> None:
        if isinstance(notification.root, types.ToolListChangedNotification):
            self._on_tools_changed()
        await super()._received_notification(notification)


class MCPManager:
    def __init__(
        self,
        project_path: str,
        storage: Any | None = None,
        secret_resolver: Callable[[str], Any] | None = None,
        url_allowlist: Iterable[str] = (),
        resolver: Callable[[str, int], list[str]] | None = None,
        idle_timeout_s: float = DEFAULT_IDLE_TIMEOUT_S,
        call_timeout_s: float = DEFAULT_CALL_TIMEOUT_S,
        max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
        max_concurrency: int = DEFAULT_CONCURRENCY,
        start_timeout_s: float = DEFAULT_START_TIMEOUT_S,
        max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES,
        event_sink: EventSink | None = None,
    ) -> None:
        self.project_path = project_path
        self.storage = storage
        self.secret_resolver = secret_resolver
        self.url_allowlist = list(url_allowlist)
        self.resolver = resolver
        self.idle_timeout_s = idle_timeout_s
        self.call_timeout_s = min(call_timeout_s, MAX_CALL_TIMEOUT_S)
        self.max_output_bytes = max_output_bytes
        self.max_concurrency = max_concurrency
        self.start_timeout_s = start_timeout_s
        self.max_message_bytes = max_message_bytes
        self._event_sink = event_sink
        self._running: dict[str, _Running] = {}
        self._locks: dict[str, asyncio.Lock] = {}

    # ------------------------------------------------------------------ events
    async def event(self, server: str, type_: str, data: dict[str, Any]) -> None:
        payload = {"server": server, **data}
        if self._event_sink is not None:
            await self._event_sink(server, type_, payload)
        elif self.storage is not None:
            await self.storage.events.append(run_id=server_run_id(server), type=type_, data=payload)

    # ------------------------------------------------------------------ lifecycle
    def is_running(self, name: str) -> bool:
        r = self._running.get(name)
        return bool(r and r.session is not None and r.task and not r.task.done())

    def pid(self, name: str) -> int | None:
        r = self._running.get(name)
        return getattr(r.process, "pid", None) if r and r.process is not None else None

    async def _resolve_secrets(self, record: MCPServerRecord) -> dict[str, str]:
        out: dict[str, str] = {}
        for env_name, vault_name in record.secret_env.items():
            if self.secret_resolver is None:
                raise MCPServerUnavailable(f"server {record.name!r} needs vault secrets but no vault is available")
            value = self.secret_resolver(vault_name)
            if asyncio.iscoroutine(value):
                value = await value
            out[env_name] = str(value)
        return out

    def _transport(self, record: MCPServerRecord, r: _Running, secrets: dict[str, str]) -> Any:
        if record.transport == "stdio":
            validate_env_names(record.env, record.secret_env)
            env, cwd = build_child_env(record.name, self.project_path, record.env, secrets)
            return stdio_transport(record.command or "", list(record.args), env, cwd, self.max_message_bytes,
                                   on_process=lambda p: setattr(r, "process", p))
        if record.transport == "http":
            return self._http_transport(record)
        raise MCPServerUnavailable(f"transport {record.transport!r} is not supported (use stdio or http)")

    def _http_transport(self, record: MCPServerRecord) -> Any:
        import httpx
        from contextlib import asynccontextmanager
        from mcp.client.streamable_http import streamable_http_client

        from agentos.flows.net_guard import check_url

        url = record.url or ""
        first = check_url(url, self.url_allowlist, self.resolver)  # raises SSRFBlockedError

        async def recheck(request: httpx.Request) -> None:
            target = check_url(str(request.url), self.url_allowlist, self.resolver)
            if (target.scheme, target.host, target.port) != (first.scheme, first.host, first.port):
                raise httpx.RequestError(f"request to another origin refused: {target.host}", request=request)

        async def refuse_redirects(response: httpx.Response) -> None:
            if response.is_redirect:
                raise httpx.RequestError("redirects are refused for MCP servers", request=response.request)

        @asynccontextmanager
        async def ctx():
            client = httpx.AsyncClient(follow_redirects=False, timeout=httpx.Timeout(30.0, read=300.0),
                                       event_hooks={"request": [recheck], "response": [refuse_redirects]})
            async with client:
                async with streamable_http_client(url, http_client=client) as (read, write, _sid):
                    yield read, write
        return ctx()

    async def _serve(self, record: MCPServerRecord, r: _Running) -> None:
        name = record.name
        started = False
        try:
            secrets = await self._resolve_secrets(record)
            async with self._transport(record, r, secrets) as (read, write):

                async def on_refused(method: str) -> None:
                    await self.event(name, "mcp_server_request_refused", {"method": method})

                def on_tools_changed() -> None:
                    r.tools_dirty = True

                async with _RecordingSession(read, write, read_timeout_seconds=timedelta(seconds=self.start_timeout_s),
                                             on_refused=on_refused, on_tools_changed=on_tools_changed) as session:
                    with anyio.fail_after(self.start_timeout_s):
                        await session.initialize()
                        r.live = await self._list(session)
                    session._session_read_timeout_seconds = timedelta(seconds=self.call_timeout_s)
                    r.session = session
                    started = True
                    await self.event(name, "mcp_server_started", {
                        "transport": record.transport, "pid": getattr(r.process, "pid", None), "tools": len(r.live),
                    })
                    r.ready.set()
                    await r.stop.wait()
        except BaseException as e:  # noqa: BLE001 - recorded and surfaced to the waiting caller
            r.error = _leaf(e)
            if isinstance(e, asyncio.CancelledError):
                raise
        finally:
            r.session = None
            r.ready.set()
            if started:
                await self.event(name, "mcp_server_stopped", {"reason": getattr(r, "stop_reason", "stopped")})
            elif r.error is not None and not isinstance(r.error, asyncio.CancelledError):
                await self.event(name, "mcp_server_start_failed", {"error": type(r.error).__name__,
                                                                   "message": str(r.error)[:300]})

    async def _list(self, session: ClientSession) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        cursor: str | None = None
        for _ in range(50):  # hard page limit
            res = await session.list_tools(cursor) if cursor else await session.list_tools()
            for t in res.tools:
                schema = t.inputSchema or {}
                out[t.name] = {"name": t.name, "description": t.description or "", "input_schema": schema,
                               "sha256": tool_hash(t.name, t.description or "", schema)}
            cursor = res.nextCursor
            if not cursor:
                break
        return out

    async def ensure_started(self, record: MCPServerRecord) -> _Running:
        if not record.enabled:
            raise MCPServerUnavailable(f"MCP server {record.name!r} is not enabled")
        lock = self._locks.setdefault(record.name, asyncio.Lock())
        async with lock:
            r = self._running.get(record.name)
            if r and r.session is not None and r.task and not r.task.done():
                return r
            r = _Running(sem=asyncio.Semaphore(self.max_concurrency))
            self._running[record.name] = r
            r.task = asyncio.get_running_loop().create_task(self._serve(record, r))
            try:
                await asyncio.wait_for(r.ready.wait(), timeout=self.start_timeout_s + 5)
            except asyncio.TimeoutError:
                await self.kill(record.name, "start timeout")
                raise MCPTimeout(f"MCP server {record.name!r} did not start in time")
            if r.session is None:
                self._running.pop(record.name, None)
                err = r.error
                if isinstance(err, TimeoutError) or (
                    isinstance(err, McpError) and getattr(getattr(err, "error", None), "code", None) == 408
                ):
                    raise MCPTimeout(f"MCP server {record.name!r} did not answer the handshake in time") from err
                raise MCPServerUnavailable(
                    f"MCP server {record.name!r} failed to start: {type(err).__name__ if err else 'unknown'}: "
                    f"{str(err)[:300] if err else ''}"
                ) from err
            self._touch(record.name)
            return r

    def _touch(self, name: str) -> None:
        r = self._running.get(name)
        if not r or self.idle_timeout_s <= 0:
            return
        if r.idle:
            r.idle.cancel()
        loop = asyncio.get_running_loop()
        r.idle = loop.call_later(self.idle_timeout_s, lambda: loop.create_task(self.stop(name, "idle")))

    async def stop(self, name: str, reason: str = "stopped") -> None:
        r = self._running.pop(name, None)
        if not r:
            return
        if r.idle:
            r.idle.cancel()
        r.stop_reason = reason  # type: ignore[attr-defined]
        r.stop.set()
        if r.task:
            try:
                await asyncio.wait_for(asyncio.shield(r.task), timeout=10)
            except (asyncio.TimeoutError, Exception):
                if r.process is not None:
                    await kill_process_tree(r.process)
                r.task.cancel()

    async def kill(self, name: str, reason: str) -> None:
        """Hard stop: terminate the whole process tree first, then end the session task."""
        r = self._running.get(name)
        if r and r.process is not None:
            await kill_process_tree(r.process)
        await self.stop(name, reason)

    async def stop_all(self, reason: str = "shutdown") -> None:
        for name in list(self._running):
            await self.stop(name, reason)

    # ------------------------------------------------------------------ discovery and calls
    async def discover(self, record: MCPServerRecord, builtin_names: Iterable[str] = ()) -> MCPServerRecord:
        """List the server's tools and merge them into the record (approvals kept; changes flagged)."""
        r = await self.ensure_started(record)
        r.live = await self._list_with_timeout(record.name, r)
        r.tools_dirty = False
        tools, events = merge_discovery(record, r.live.values(), builtin_names)
        updated = record.model_copy(update={
            "tools": tools,
            "last_discovery": {"at": time.time(), "tool_count": len(r.live), "rejected": [e for e in events if e["type"] == "mcp_tool_name_rejected"]},
        })
        await self.event(record.name, "mcp_discovery", {"tools": {n: s.snapshot.sha256 for n, s in tools.items()}})
        for ev in events:
            await self.event(record.name, ev.pop("type"), ev)
        self._touch(record.name)
        return updated

    async def _list_with_timeout(self, name: str, r: _Running) -> dict[str, dict[str, Any]]:
        assert r.session is not None
        try:
            with anyio.fail_after(self.call_timeout_s):
                return await self._list(r.session)
        except TimeoutError as e:
            await self.kill(name, "list timeout")
            raise MCPTimeout(f"MCP server {name!r} did not list its tools in time") from e
        except McpError as e:
            if getattr(getattr(e, "error", None), "code", None) == 408:
                await self.kill(name, "list timeout")
                raise MCPTimeout(f"MCP server {name!r} did not list its tools in time") from e
            raise

    async def call_tool(
        self,
        record: MCPServerRecord,
        server_tool_name: str,
        expected_sha256: str,
        arguments: dict[str, Any],
        timeout_s: float | None = None,
    ) -> CallResult:
        timeout = min(timeout_s or self.call_timeout_s, MAX_CALL_TIMEOUT_S)
        r = await self.ensure_started(record)
        if r.tools_dirty:
            r.live = await self._list_with_timeout(record.name, r)
            r.tools_dirty = False
        live = r.live.get(server_tool_name)
        if live is None or live["sha256"] != expected_sha256:
            await self._record_change(record, r)
            raise MCPToolChanged(
                f"tool {server_tool_name!r} on {record.name!r} changed since it was approved (blocked until re-reviewed)"
            )
        assert r.sem is not None
        async with r.sem:
            session = r.session
            if session is None:
                raise MCPServerUnavailable(f"MCP server {record.name!r} stopped")
            t0 = time.perf_counter()
            try:
                with anyio.fail_after(timeout):
                    result = await session.call_tool(server_tool_name, arguments)
            except TimeoutError as e:
                await self.kill(record.name, "call timeout")
                raise MCPTimeout(f"tool {server_tool_name!r} on {record.name!r} timed out after {timeout:g}s") from e
            except McpError as e:
                if getattr(getattr(e, "error", None), "code", None) == 408:
                    await self.kill(record.name, "call timeout")
                    raise MCPTimeout(f"tool {server_tool_name!r} on {record.name!r} timed out after {timeout:g}s") from e
                # the server closed the connection (crashed, or a message exceeded max_message_bytes)
                await self.kill(record.name, "connection closed")
                raise MCPServerUnavailable(
                    f"MCP server {record.name!r} closed the connection during {server_tool_name!r}: {str(e)[:200]}"
                ) from e
            duration = round((time.perf_counter() - t0) * 1000, 1)
        self._touch(record.name)
        parts: list[str] = []
        for c in result.content or []:
            if isinstance(c, types.TextContent):
                parts.append(c.text)
            else:
                parts.append(f"[{getattr(c, 'type', 'content')} omitted]")
        text = "\n".join(parts)
        raw = text.encode("utf-8")
        truncated = len(raw) > self.max_output_bytes
        if truncated:
            text = raw[: self.max_output_bytes].decode("utf-8", errors="ignore") + "\n[output truncated]"
        return CallResult(text=text, status="error" if result.isError else "ok", duration_ms=duration,
                          output_bytes=len(raw), truncated=truncated)

    async def _record_change(self, record: MCPServerRecord, r: _Running) -> None:
        """Persist the live snapshot so the tool shows as "changed, needs review" (T2)."""
        tools, events = merge_discovery(record, r.live.values())
        for ev in events:
            await self.event(record.name, ev.pop("type"), ev)
        if self.storage is not None:
            current = await self.storage.mcp_servers.get(record.name) or record
            await self.storage.mcp_servers.put(current.model_copy(update={"tools": tools}))
