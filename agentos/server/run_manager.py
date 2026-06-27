"""
run_manager.py — In-memory async run state tracker.

Manages the lifecycle of mission runs triggered via the API:
  - Assigns a unique run_id to each triggered execution
  - Tracks status / partial outputs in memory
  - Writes checkpoints to SQLite (via the Phase 2 CheckpointStore) for durability
  - Publishes task-level events to a per-run asyncio.Queue for WebSocket streaming
"""

import asyncio
import logging
import os
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class RunState:
    run_id: str
    mission_name: str
    status: str = "queued"          # queued | running | completed | failed
    task_index: int = 0
    outputs: List[str] = field(default_factory=list)
    error: Optional[str] = None
    provider: Optional[str] = None  # last LLM provider that served a call
    event_queue: asyncio.Queue = field(default_factory=asyncio.Queue)


class RunManager:
    """
    Singleton-per-app store for active and recent run states.
    """

    def __init__(self):
        self._runs: Dict[str, RunState] = {}

    def create_run(self, mission_name: str) -> str:
        run_id = str(uuid.uuid4())
        self._runs[run_id] = RunState(run_id=run_id, mission_name=mission_name)
        return run_id

    def get(self, run_id: str) -> Optional[RunState]:
        return self._runs.get(run_id)

    def list_runs(self) -> List[RunState]:
        return list(self._runs.values())

    async def execute(
        self,
        run_id: str,
        project_path: str,
        mission_name: str,
        resume: bool = False,
        license_key: Optional[str] = None,
    ) -> None:
        """
        Execute a mission in the background, updating RunState as tasks progress.
        Called from FastAPI BackgroundTasks — runs in a threadpool executor because
        squad.run_mission() is synchronous (CrewAI is sync).
        """
        state = self._runs.get(run_id)
        if state is None:
            logger.error(f"RunManager.execute: run_id {run_id} not found")
            return

        state.status = "running"
        await state.event_queue.put({"event": "run_started", "run_id": run_id})

        loop = asyncio.get_event_loop()
        try:
            result = await loop.run_in_executor(
                None,
                self._sync_run,
                project_path,
                mission_name,
                resume,
                license_key,
                state,
            )
            state.status = "completed"
            state.outputs.append(str(result))
            await state.event_queue.put({
                "event": "run_completed",
                "run_id": run_id,
                "output": str(result),
            })
        except Exception as e:
            state.status = "failed"
            state.error = str(e)
            logger.exception(f"Run {run_id} failed: {e}")
            await state.event_queue.put({
                "event": "run_failed",
                "run_id": run_id,
                "error": str(e),
            })

    @staticmethod
    def _sync_run(
        project_path: str,
        mission_name: str,
        resume: bool,
        license_key: Optional[str],
        state: RunState,
    ) -> str:
        """Blocking execution called in a thread executor."""
        from agentos.core.project_ops import build_squad_from_project

        # Optional license check before execution
        if license_key:
            _check_license_for_project(project_path, mission_name, license_key)

        squad, mission = build_squad_from_project(project_path, mission_name)
        result = squad.run_mission(mission, resume=resume)
        return str(result)


def _check_license_for_project(
    project_path: str, mission_name: str, license_key: str
) -> None:
    """
    Optionally verify the license key matches the pack that provided agents/crews
    used in this mission. No-op if no pack manifest is found.
    """
    try:
        from agentos.packaging.license_check import verify_license_str
        from agentos.packaging.pack_format import find_pack_manifest_for_mission
        manifest = find_pack_manifest_for_mission(project_path, mission_name)
        if manifest is None:
            return  # Free/open project — no license required
        ok = verify_license_str(license_key, manifest)
        if not ok:
            raise PermissionError(
                f"License key is invalid or does not match pack '{manifest.get('name')}'. "
                "Run is blocked."
            )
    except (ImportError, AttributeError):
        # Packaging module not available yet — skip silently
        pass
