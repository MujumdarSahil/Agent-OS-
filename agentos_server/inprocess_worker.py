"""
Opt-in in-process flow worker (Standalone mode).

Without a worker, runs enqueued by ``POST /api/v2/flows/{id}/runs`` stay ``queued``.
Setting ``AGENTOS_INPROCESS_WORKER=1`` starts one :class:`FlowWorker` loop inside the
server process for the app's lifespan. It is OFF by default.

- Uses the app's queue, storage and ``security_policy``.
- Uses ``app.state.transport_registry`` when configured. Otherwise it installs a
  ``MockTransport`` for ``send_email`` (nothing is delivered) and logs that clearly. The same
  registry is set on ``app.state`` so approval-resumed sinks use the same transport.
- Stopped and awaited on shutdown; no task outlives the app.
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Any, Optional

from agentos.flows.proxy import MockTransport
from agentos.flows.worker import FlowWorker

logger = logging.getLogger(__name__)

ENV_FLAG = "AGENTOS_INPROCESS_WORKER"


def inprocess_worker_enabled() -> bool:
    return os.environ.get(ENV_FLAG, "").strip() == "1"


class InProcessFlowWorker:
    """Runs ``FlowWorker.run_once`` in a loop until stopped."""

    def __init__(self, app: Any, idle_sleep_s: float = 0.2, lease_timeout_s: float = 30.0) -> None:
        self.app = app
        self.idle_sleep_s = idle_sleep_s
        self.lease_timeout_s = lease_timeout_s
        self._stop = asyncio.Event()
        self._task: Optional[asyncio.Task] = None
        self.worker: Optional[FlowWorker] = None

    def start(self) -> None:
        state = self.app.state
        registry = getattr(state, "transport_registry", None)
        if not registry:
            registry = {"send_email": MockTransport()}
            state.transport_registry = registry
            logger.warning(
                "In-process flow worker: no transport registry configured; using MockTransport "
                "for send_email (MOCK: nothing is delivered)."
            )
        self.worker = FlowWorker(
            queue=state.queue,
            storage=state.storage,
            worker_id="inprocess",
            lease_timeout_s=self.lease_timeout_s,
            policy=getattr(state, "security_policy", None),
            transport_registry=registry,
            # 2.3: {"vault": name} credential headers on http_request resolve through the app vault.
            secret_resolver=(state.vault.reveal if getattr(state, "vault", None) else None),
            # 2.5a: approved MCP tools run through the app's manager (same loop as this worker)
            mcp_manager=getattr(state, "mcp_manager", None),
        )
        self._stop.clear()
        self._task = asyncio.create_task(self._loop(), name="agentos-inprocess-flow-worker")
        logger.info("In-process flow worker started (%s=1).", ENV_FLAG)

    async def _loop(self) -> None:
        assert self.worker is not None
        while not self._stop.is_set():
            try:
                processed = await self.worker.run_once()
            except asyncio.CancelledError:
                raise
            except Exception:  # keep the loop alive; the run itself records its failure
                logger.exception("In-process flow worker: job processing raised")
                processed = None
            if processed is None:
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=self.idle_sleep_s)
                except asyncio.TimeoutError:
                    pass

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            try:
                await asyncio.wait_for(self._task, timeout=10)
            except asyncio.TimeoutError:
                self._task.cancel()
                try:
                    await self._task
                except (asyncio.CancelledError, Exception):
                    pass
            self._task = None
            logger.info("In-process flow worker stopped.")
