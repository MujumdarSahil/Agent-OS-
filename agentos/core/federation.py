"""
federation.py — Phase 4 Workstream C: Multi-Squad Federation (Sequential)

Implements FederatedMission: sequential handoff across 2+ Squad instances.
Squad A's final output is passed as context into Squad B's first task.

SCOPE:
  - Sequential federation ONLY. Ordered handoff: A → B → C → ...
  - Reuses existing Squad.start_mission(), CheckpointStore, GovernanceEngine unchanged.
  - Federation-level checkpointing (which stage is active/complete).
  - Resume works across squad handoffs, not just within a single squad's tasks.

EXPLICITLY OUT OF SCOPE (future phases):
  - Parallel squad execution
  - Cross-squad shared memory  
  - Negotiation protocols between squads
  - Dynamic routing based on outputs
  See PHASE4_FEDERATION.md for the full limitation list.
"""

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class FederationStage:
    """
    A single stage in a federated mission.
    
    Args:
        squad: The Squad instance that runs this stage
        mission: The Mission object for this stage
        stage_index: Zero-based index in the federation sequence
        name: Optional human-readable name (defaults to squad name)
    """
    squad: Any  # Squad instance
    mission: Any  # Mission instance
    stage_index: int
    name: Optional[str] = None

    def __post_init__(self):
        if self.name is None:
            self.name = getattr(self.squad, "name", f"Stage-{self.stage_index}")


class FederatedMission:
    """
    Orchestrates sequential execution across 2+ Squad instances.

    Squad A's final output is injected as context into Squad B's first task
    description. This enables the "research → write" pattern where Squad B
    genuinely incorporates Squad A's findings.

    Checkpointing:
        Federation-level state is stored in the CheckpointStore using
        federation_id as the mission_id with a "fed_" prefix. This allows
        resume to skip completed stages and restart from the failed one.

    Usage:
        fed = FederatedMission(
            federation_id="my-federation",
            stages=[
                FederationStage(research_squad, research_mission, stage_index=0),
                FederationStage(writing_squad, writing_mission, stage_index=1),
            ],
            checkpoint_store=checkpoint_store,
        )
        result = asyncio.run(fed.run())
    """

    def __init__(
        self,
        federation_id: str,
        stages: List[FederationStage],
        checkpoint_store: Any,  # CheckpointStore instance
    ):
        if len(stages) < 2:
            raise ValueError(
                "FederatedMission requires at least 2 stages. "
                "For a single squad, use Squad.start_mission() directly."
            )
        self.federation_id = federation_id
        self.stages = stages
        self.checkpoint_store = checkpoint_store
        self._fed_mission_id = f"fed_{federation_id}"

    def _checkpoint_key(self, stage_index: int) -> str:
        """Key for federation-level stage checkpoints."""
        return f"{self._fed_mission_id}_stage_{stage_index}"

    def _is_stage_complete(self, stage_index: int) -> bool:
        """Check if a stage has already completed successfully."""
        key = self._checkpoint_key(stage_index)
        checkpoint = self.checkpoint_store.load_latest_checkpoint(key)
        if checkpoint and checkpoint.get("status") == "completed":
            logger.info(f"[Federation] Stage {stage_index} ({self.stages[stage_index].name}) already complete — skipping.")
            return True
        return False

    def _save_stage_complete(self, stage_index: int, output: str) -> None:
        """Persist that a federation stage has completed successfully."""
        key = self._checkpoint_key(stage_index)
        self.checkpoint_store.save_checkpoint(
            mission_id=key,
            task_index=0,
            state={
                "status": "completed",
                "stage_index": stage_index,
                "stage_name": self.stages[stage_index].name,
                "output": output,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )
        self.checkpoint_store.mark_complete(key)

    def _load_stage_output(self, stage_index: int) -> Optional[str]:
        """Load the saved output from a completed stage."""
        key = self._checkpoint_key(stage_index)
        checkpoint = self.checkpoint_store.load_latest_checkpoint(key)
        if checkpoint:
            return checkpoint.get("output")
        return None

    def _inject_context(self, mission: Any, prior_output: str) -> None:
        """
        Inject prior stage output as context into the first task of a mission.

        Modifies the task graph's first node description to include the prior stage's
        output as context. This is string injection — no structured data passing (Phase 5+).
        """
        if not prior_output:
            return
        task_graph = getattr(mission, "task_graph", None)
        if task_graph is None:
            logger.warning("[Federation] Mission has no task_graph — skipping context injection")
            return
        nodes = getattr(task_graph, "nodes", [])
        if not nodes:
            logger.warning("[Federation] Task graph has no nodes — skipping context injection")
            return

        # Inject into the FIRST task's description
        first_node = nodes[0]
        original_desc = getattr(first_node, "description", "")
        injected_desc = (
            f"[CONTEXT FROM PREVIOUS STAGE]\n"
            f"{prior_output}\n"
            f"[END CONTEXT]\n\n"
            f"{original_desc}"
        )
        first_node.description = injected_desc
        logger.info(
            f"[Federation] Injected {len(prior_output)} chars of context into first task "
            f"of next stage"
        )

    async def run(self) -> Dict[str, Any]:
        """
        Run all federation stages sequentially, with resume support.

        Returns:
            Dict with:
              - 'federation_id': str
              - 'stages_completed': int
              - 'total_stages': int
              - 'outputs': List[str] — one output per completed stage
              - 'final_output': str — output from the last stage
        """
        outputs: List[str] = []
        prior_output: Optional[str] = None

        logger.info(
            f"[Federation] Starting federated mission '{self.federation_id}' "
            f"with {len(self.stages)} stages"
        )

        for stage in self.stages:
            stage_idx = stage.stage_index

            # Check if this stage is already complete (resume support)
            if self._is_stage_complete(stage_idx):
                saved_output = self._load_stage_output(stage_idx)
                if saved_output:
                    prior_output = saved_output
                    outputs.append(saved_output)
                    logger.info(f"[Federation] Loaded completed output from stage {stage_idx}")
                continue

            logger.info(
                f"[Federation] Running stage {stage_idx}: '{stage.name}' "
                f"(squad={getattr(stage.squad, 'name', '?')})"
            )

            # Inject prior stage output as context into this stage's first task
            if prior_output:
                self._inject_context(stage.mission, prior_output)

            # Run the squad's mission — reuses existing Squad.start_mission() unchanged
            try:
                stage_output = await self._run_stage(stage)
                prior_output = stage_output
                outputs.append(stage_output)

                # Save federation-level checkpoint for this stage
                self._save_stage_complete(stage_idx, stage_output)

                logger.info(
                    f"[Federation] Stage {stage_idx} '{stage.name}' completed "
                    f"({len(stage_output)} chars output)"
                )
            except Exception as e:
                logger.error(
                    f"[Federation] Stage {stage_idx} '{stage.name}' FAILED: {e}. "
                    f"Federation halted. Completed {stage_idx}/{len(self.stages)} stages. "
                    f"Resume by running the federated mission again."
                )
                raise RuntimeError(
                    f"Federation failed at stage {stage_idx} ({stage.name}): {e}. "
                    f"Stages 0–{stage_idx - 1} are checkpointed and will be skipped on resume."
                ) from e

        final_output = outputs[-1] if outputs else ""
        logger.info(
            f"[Federation] Federated mission '{self.federation_id}' complete. "
            f"{len(self.stages)} stages ran successfully."
        )

        return {
            "federation_id": self.federation_id,
            "stages_completed": len(outputs),
            "total_stages": len(self.stages),
            "outputs": outputs,
            "final_output": final_output,
        }

    async def _run_stage(self, stage: FederationStage) -> str:
        """
        Run a single federation stage by calling Squad.start_mission().
        Extracts and returns the text output from the completed mission.
        """
        squad = stage.squad
        mission = stage.mission

        # Add the mission to the squad and start it
        # Squad.start_mission() runs asynchronously and updates mission state
        squad.missions[mission.id] = mission
        await squad.start_mission(mission.id)

        # Extract output text from completed mission
        output_text = self._extract_mission_output(mission)
        return output_text

    def _extract_mission_output(self, mission: Any) -> str:
        """
        Extract text output from a completed Mission object.
        Returns all task outputs joined as a single string.
        """
        # Try mission.result first (set by squad after completion)
        if hasattr(mission, "result") and mission.result:
            if isinstance(mission.result, str):
                return mission.result
            elif isinstance(mission.result, list):
                return "\n\n".join(str(r) for r in mission.result)
            elif isinstance(mission.result, dict):
                return json.dumps(mission.result, indent=2)

        # Fallback: try task_outputs list on the mission
        if hasattr(mission, "task_outputs") and mission.task_outputs:
            return "\n\n".join(str(o) for o in mission.task_outputs)

        # Last resort: return mission goal as confirmation of completion
        return f"Stage completed: {getattr(mission, 'goal', 'Mission complete')}"
