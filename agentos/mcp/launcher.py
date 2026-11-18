"""stdio transport for MCP servers with an exact environment (2.5a, threats T4 and T6).

Same wiring as ``mcp.client.stdio.stdio_client`` (mcp==1.30.0), with three differences:
- the child gets exactly the environment we pass (the SDK always merges its own inherited set);
- a single JSON-RPC line larger than ``max_message_bytes`` stops the reader (a server can't exhaust
  memory with one huge message); the pending call then times out and the server is killed;
- stderr goes to the null device by default, so a noisy server can't fill the disk.
Process creation and whole-tree termination reuse the SDK's platform helpers (Windows Job Objects,
POSIX process groups). The SDK is pinned, and the tests exercise these helpers.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator, Callable

import anyio
import mcp.types as types
from anyio.streams.text import TextReceiveStream
from mcp.client.stdio import (
    PROCESS_TERMINATION_TIMEOUT,
    _create_platform_compatible_process,
    _get_executable_command,
    _terminate_process_tree,
)
from mcp.shared.message import SessionMessage

DEFAULT_MAX_MESSAGE_BYTES = 4 * 1024 * 1024


class MCPMessageTooLarge(Exception):
    pass


@asynccontextmanager
async def stdio_transport(
    command: str,
    args: list[str],
    env: dict[str, str],
    cwd: Path,
    max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES,
    on_process: Callable[[Any], None] | None = None,
) -> AsyncIterator[tuple[Any, Any]]:
    read_writer, read_stream = anyio.create_memory_object_stream(0)
    write_stream, write_reader = anyio.create_memory_object_stream(0)
    errlog = open(os.devnull, "w")  # noqa: SIM115 - closed in finally
    try:
        process = await _create_platform_compatible_process(
            command=_get_executable_command(command), args=list(args), env=dict(env), errlog=errlog, cwd=cwd,
        )
    except OSError:
        errlog.close()
        for s in (read_stream, write_stream, read_writer, write_reader):
            await s.aclose()
        raise
    if on_process:
        on_process(process)

    async def stdout_reader() -> None:
        assert process.stdout
        try:
            async with read_writer:
                buffer = ""
                async for chunk in TextReceiveStream(process.stdout, encoding="utf-8", errors="replace"):
                    lines = (buffer + chunk).split("\n")
                    buffer = lines.pop()
                    if len(buffer) > max_message_bytes:
                        await read_writer.send(MCPMessageTooLarge(f"message exceeds {max_message_bytes} bytes"))
                        return
                    for line in lines:
                        if not line.strip():
                            continue
                        if len(line) > max_message_bytes:
                            await read_writer.send(MCPMessageTooLarge(f"message exceeds {max_message_bytes} bytes"))
                            return
                        try:
                            message = types.JSONRPCMessage.model_validate_json(line)
                        except Exception as exc:
                            await read_writer.send(exc)
                            continue
                        await read_writer.send(SessionMessage(message))
        except anyio.ClosedResourceError:
            await anyio.lowlevel.checkpoint()

    async def stdin_writer() -> None:
        assert process.stdin
        try:
            async with write_reader:
                async for session_message in write_reader:
                    data = session_message.message.model_dump_json(by_alias=True, exclude_none=True)
                    await process.stdin.send((data + "\n").encode("utf-8"))
        except anyio.ClosedResourceError:
            await anyio.lowlevel.checkpoint()

    try:
        async with anyio.create_task_group() as tg, process:
            tg.start_soon(stdout_reader)
            tg.start_soon(stdin_writer)
            try:
                yield read_stream, write_stream
            finally:
                with anyio.CancelScope(shield=True):
                    if process.stdin:
                        try:
                            await process.stdin.aclose()
                        except Exception:
                            pass
                    try:
                        with anyio.fail_after(PROCESS_TERMINATION_TIMEOUT):
                            await process.wait()
                    except TimeoutError:
                        pass
                    except ProcessLookupError:
                        pass
                    # Always end the whole tree: a server that exits on its own may leave children behind
                    # (the SDK only terminates the Job Object / process group on a timeout).
                    try:
                        await _terminate_process_tree(process, 1.0)
                    except Exception:
                        pass
                    for s in (read_stream, write_stream, read_writer, write_reader):
                        await s.aclose()
                tg.cancel_scope.cancel()
    finally:
        errlog.close()


async def kill_process_tree(process: Any, timeout_seconds: float = 1.0) -> None:
    """Terminate a server and every process it started (Job Object on Windows, process group on POSIX)."""
    try:
        await _terminate_process_tree(process, timeout_seconds)
    except ProcessLookupError:
        pass
