"""Worker for leasing, executing, and heartbeat-renewing flow jobs."""

from __future__ import annotations

import asyncio
import logging
import uuid
from typing import Any, Optional

from agentos.flows.engine import FlowEngine
from agentos.flows.models import FlowDefinition
from agentos.flows.policy import SecurityPolicy
from agentos.flows.proxy import MockTransport
from agentos.flows.state import RunStatus
from agentos.queue.ports import QueueBackend, QueueJob
from agentos.storage.ports import FencingTokenError, Storage

logger = logging.getLogger(__name__)


class FlowWorker:
    """
    Executes flow jobs leased from a QueueBackend.
    Maintains a heartbeat task that renews the lease every lease_timeout / 3 seconds.
    Aborts immediately upon FencingTokenError if its lease has been superseded.
    """

    def __init__(
        self,
        queue: QueueBackend,
        storage: Storage,
        worker_id: Optional[str] = None,
        lease_timeout_s: float = 30.0,
        policy: Optional[SecurityPolicy] = None,
        transport_registry: Optional[dict[str, Any]] = None,
        custom_llm: Any | None = None,
        track_labels: bool = True,
    ) -> None:
        self.queue = queue
        self.storage = storage
        self.worker_id = worker_id or f"worker_{uuid.uuid4().hex[:8]}"
        self.lease_timeout_s = lease_timeout_s
        self.policy = policy or SecurityPolicy()
        self.transport_registry = transport_registry or {"send_email": MockTransport()}
        self.custom_llm = custom_llm
        self.track_labels = track_labels

    async def run_once(self) -> Optional[str]:
        """
        Attempt to lease and process one job from the queue.
        Returns the run_id processed, or None if no job was available.
        """
        job = await self.queue.lease(self.worker_id, self.lease_timeout_s)
        if job is None:
            return None

        await self._process_job(job)
        return job.run_id

    async def _heartbeat_loop(self, job: QueueJob, cancel_event: asyncio.Event) -> None:
        """Renew lease every lease_timeout / 3 seconds until cancel_event is set."""
        interval = max(0.05, self.lease_timeout_s / 3.0)
        while not cancel_event.is_set():
            try:
                await asyncio.sleep(interval)
                if cancel_event.is_set():
                    break
                renewed = await self.queue.renew_lease(
                    job.job_id,
                    job.lease_id,  # type: ignore[arg-type]
                    self.lease_timeout_s,
                )
                if not renewed:
                    logger.warning(
                        "Worker %s failed to renew lease for job %s (superseded/expired)",
                        self.worker_id,
                        job.job_id,
                    )
                    break
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Error during lease renewal: %s", e)
                break

    async def _process_job(self, job: QueueJob) -> None:
        """Run or resume a flow job with heartbeat and fencing token."""
        if not job.lease_id:
            raise FencingTokenError(f"Job {job.job_id} has no active lease_id during worker execution")

        cancel_event = asyncio.Event()
        heartbeat_task = asyncio.create_task(self._heartbeat_loop(job, cancel_event))

        try:
            # 1. Fetch published flow version from storage
            if not self.storage.flows:
                raise ValueError("Storage does not have a flows repository configured")

            flow_record = await self.storage.flows.get_version(job.flow_id, job.version)
            if flow_record is None:
                await self.queue.fail(
                    job.job_id,
                    job.lease_id,  # type: ignore[arg-type]
                    f"Flow {job.flow_id!r} v{job.version} not found in storage",
                )
                return

            flow_def = FlowDefinition(
                id=flow_record.id,
                name=flow_record.name,
                entrypoint=flow_record.entrypoint,
                nodes=flow_record.nodes,
                edges=flow_record.edges,
                loops=flow_record.loops,
            )

            # 2. Build engine configured with worker's lease_id and fencing validator
            engine = FlowEngine(
                flow=flow_def,
                storage=self.storage,
                policy=self.policy,
                transport_registry=self.transport_registry,
                custom_llm=self.custom_llm,
                track_labels=self.track_labels,
                lease_id=job.lease_id,
                fencing_checker=self.queue.validate_lease,
            )

            # 3. Requirement 3: Decide run vs resume strictly from event log
            events = await self.storage.events.list(job.run_id, after_seq=0)
            has_started = any(e.type == "run_started" for e in events)

            if has_started:
                state = await engine.resume(job.run_id)
            else:
                state = await engine.run(run_id=job.run_id, inputs=job.inputs)

            # 4. Handle engine outcome and update queue status
            if state.status == RunStatus.WAITING:
                # Approval needed: free the worker (Requirement 4)
                await self.queue.release_for_waiting(
                    job.job_id,
                    job.lease_id,  # type: ignore[arg-type]
                    reason=(state.waiting_details or {}).get("reason") or "waiting_for_approval",
                )
            elif state.status == RunStatus.SUCCEEDED:
                await self.queue.complete(job.job_id, job.lease_id)  # type: ignore[arg-type]
            elif state.status in (RunStatus.FAILED, RunStatus.CANCELLED):
                await self.queue.fail(
                    job.job_id,
                    job.lease_id,  # type: ignore[arg-type]
                    error=state.error or "execution_failed",
                )

        except FencingTokenError as fencing_err:
            # Worker lease expired or was superseded: stop execution immediately
            logger.info(
                "Worker %s lost lease for run %s: %s; stopping execution.",
                self.worker_id,
                job.run_id,
                fencing_err,
            )
        except Exception as err:
            logger.exception("Error processing flow run %s: %s", job.run_id, err)
            try:
                await self.queue.fail(
                    job.job_id,
                    job.lease_id,  # type: ignore[arg-type]
                    error=str(err),
                )
            except FencingTokenError:
                pass
        finally:
            cancel_event.set()
            heartbeat_task.cancel()
            try:
                await heartbeat_task
            except asyncio.CancelledError:
                pass
