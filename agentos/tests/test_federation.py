"""
test_federation.py — Phase 4 Workstream C: Multi-Squad Federation Tests

Tests cover:
  1. Basic 2-stage sequential handoff (Squad A → Squad B)
  2. Context injection from prior stage into next stage's first task
  3. Resume behavior: completed stages are not re-run on restart
  4. Federation fails cleanly when a stage fails (error propagates)
  5. FederatedMission requires >= 2 stages (defensive check)

All tests use AGENTOS_MOCK_LLM=1 (no real LLM required).
Windows Safe: uses ignore_cleanup_errors=True on TemporaryDirectory to prevent WinError 32 locking issues.
"""

import asyncio
import os
import pytest
import tempfile
import uuid
from unittest.mock import MagicMock, AsyncMock, patch


# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------

def _make_checkpoint_store(tmp_path: str):
    from agentos.core.checkpoint import SQLiteCheckpointStore
    db = os.path.join(tmp_path, f"fed_test_{uuid.uuid4().hex}.db")
    return SQLiteCheckpointStore(db_path=db)


def _make_mock_mission(mission_id: str, goal: str, first_task_desc: str):
    """Create a minimal mock mission with a task graph."""
    from unittest.mock import MagicMock

    task_node = MagicMock()
    task_node.description = first_task_desc

    task_graph = MagicMock()
    task_graph.nodes = [task_node]

    mission = MagicMock()
    mission.id = mission_id
    mission.goal = goal
    mission.task_graph = task_graph
    mission.result = None
    mission.task_outputs = []
    return mission


def _make_mock_squad(squad_name: str, output_text: str):
    """Create a mock squad that stores missions and 'completes' them by setting result."""

    class MockSquad:
        def __init__(self):
            self.name = squad_name
            self.missions = {}

        async def start_mission(self, mission_id: str):
            # Simulate mission execution by setting result
            if mission_id in self.missions:
                self.missions[mission_id].result = output_text

    return MockSquad()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestFederatedMissionBasic:

    def test_requires_at_least_two_stages(self):
        """FederatedMission must reject < 2 stages at construction time."""
        from agentos.core.federation import FederatedMission, FederationStage

        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            store = _make_checkpoint_store(tmp)
            squad = _make_mock_squad("SingleSquad", "output")
            mission = _make_mock_mission("m1", "Goal", "Task")
            stage = FederationStage(squad=squad, mission=mission, stage_index=0)

            with pytest.raises(ValueError, match="at least 2 stages"):
                FederatedMission(
                    federation_id="test",
                    stages=[stage],
                    checkpoint_store=store,
                )

    @pytest.mark.asyncio
    async def test_two_stage_handoff(self):
        """
        Test basic 2-stage federation: Squad A runs, then Squad B runs.
        Both stages should complete and return outputs.
        """
        from agentos.core.federation import FederatedMission, FederationStage

        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            store = _make_checkpoint_store(tmp)

            squad_a = _make_mock_squad("ResearchSquad", "Research findings: AI is advancing rapidly in 2026.")
            mission_a = _make_mock_mission("m_research", "Research AI trends", "Research AI in 2026")

            squad_b = _make_mock_squad("WritingSquad", "Final article: Based on extensive research, AI is advancing...")
            mission_b = _make_mock_mission("m_write", "Write article", "Write article from research")

            fed = FederatedMission(
                federation_id="test-two-stage",
                stages=[
                    FederationStage(squad=squad_a, mission=mission_a, stage_index=0, name="Research"),
                    FederationStage(squad=squad_b, mission=mission_b, stage_index=1, name="Writing"),
                ],
                checkpoint_store=store,
            )

            result = await fed.run()

        assert result["stages_completed"] == 2
        assert result["total_stages"] == 2
        assert len(result["outputs"]) == 2
        assert "Research findings" in result["outputs"][0]
        assert "Final article" in result["outputs"][1]
        assert result["final_output"] == result["outputs"][1]

    @pytest.mark.asyncio
    async def test_context_injection_into_next_stage(self):
        """
        Stage B's first task description should include Stage A's output as context.
        """
        from agentos.core.federation import FederatedMission, FederationStage

        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            store = _make_checkpoint_store(tmp)

            stage_a_output = "Research findings: The market grew 45% in Q2 2026."
            squad_a = _make_mock_squad("ResearchSquad", stage_a_output)
            mission_a = _make_mock_mission("m_research", "Research goal", "Research task")

            squad_b = _make_mock_squad("WritingSquad", "Article written successfully.")
            # This mission's first task should receive injected context
            mission_b = _make_mock_mission("m_write", "Writing goal", "Write the final report")

            fed = FederatedMission(
                federation_id="test-context-inject",
                stages=[
                    FederationStage(squad=squad_a, mission=mission_a, stage_index=0),
                    FederationStage(squad=squad_b, mission=mission_b, stage_index=1),
                ],
                checkpoint_store=store,
            )

            await fed.run()

        # The first task of mission_b should have been modified with context from stage A
        first_task_desc = mission_b.task_graph.nodes[0].description
        assert "[CONTEXT FROM PREVIOUS STAGE]" in first_task_desc
        assert stage_a_output in first_task_desc
        assert "Write the final report" in first_task_desc

    @pytest.mark.asyncio
    async def test_stage_checkpointing_prevents_rerun(self):
        """
        After Stage A completes, a second run() call should skip Stage A
        and only run Stage B. This tests resume behavior.
        """
        from agentos.core.federation import FederatedMission, FederationStage

        call_counts = {"a": 0, "b": 0}

        class CountingSquadA:
            name = "ResearchSquad"
            missions = {}

            async def start_mission(self, mission_id):
                call_counts["a"] += 1
                if mission_id in self.missions:
                    self.missions[mission_id].result = "Research complete."

        class CountingSquadB:
            name = "WritingSquad"
            missions = {}
            should_fail = True

            async def start_mission(self, mission_id):
                call_counts["b"] += 1
                if self.should_fail:
                    raise RuntimeError("Crash on Stage B")
                if mission_id in self.missions:
                    self.missions[mission_id].result = "Writing complete."

        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            store = _make_checkpoint_store(tmp)

            squad_a = CountingSquadA()
            mission_a = _make_mock_mission("m_research_resume", "Research", "Research task")

            squad_b = CountingSquadB()
            squad_b.should_fail = True
            mission_b = _make_mock_mission("m_write_resume", "Write", "Write task")

            stages = [
                FederationStage(squad=squad_a, mission=mission_a, stage_index=0),
                FederationStage(squad=squad_b, mission=mission_b, stage_index=1),
            ]

            # First run — A runs and checkpoints. B runs, crashes, halts federation.
            fed1 = FederatedMission(
                federation_id="test-resume",
                stages=stages,
                checkpoint_store=store,
            )
            with pytest.raises(RuntimeError, match="Federation failed at stage 1"):
                await fed1.run()
            
            assert call_counts["a"] == 1
            assert call_counts["b"] == 1

            # Create fresh squad/mission instances (simulating crash+restart)
            squad_a2 = CountingSquadA()
            mission_a2 = _make_mock_mission("m_research_resume2", "Research", "Research task")
            
            squad_b2 = CountingSquadB()
            squad_b2.should_fail = False  # Succeed on retry!
            mission_b2 = _make_mock_mission("m_write_resume2", "Write", "Write task")

            stages2 = [
                FederationStage(squad=squad_a2, mission=mission_a2, stage_index=0),
                FederationStage(squad=squad_b2, mission=mission_b2, stage_index=1),
            ]

            # Second run with SAME federation_id — Stage A should be SKIPPED, Stage B runs
            fed2 = FederatedMission(
                federation_id="test-resume",
                stages=stages2,
                checkpoint_store=store,
            )
            result = await fed2.run()

            # Stage A not called again (checkpointed); Stage B called again (new run)
            assert call_counts["a"] == 1, "Stage A should NOT run again after checkpointing"
            assert call_counts["b"] == 2, "Stage B should run again (new run)"
            assert result["stages_completed"] == 2


class TestFederatedMissionFailure:

    @pytest.mark.asyncio
    async def test_federation_fails_cleanly_on_stage_error(self):
        """
        When a stage raises, the federation raises RuntimeError with clear message.
        Completed stages are checkpointed; failed stage is not.
        """
        from agentos.core.federation import FederatedMission, FederationStage

        class FailingSquad:
            name = "FailingSquad"
            missions = {}

            async def start_mission(self, mission_id):
                raise RuntimeError("LLM provider unavailable")

        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            store = _make_checkpoint_store(tmp)

            squad_a = _make_mock_squad("GoodSquad", "Stage A succeeded.")
            mission_a = _make_mock_mission("m_a_fail", "Goal A", "Task A")

            squad_b = FailingSquad()
            mission_b = _make_mock_mission("m_b_fail", "Goal B", "Task B")

            fed = FederatedMission(
                federation_id="test-fail",
                stages=[
                    FederationStage(squad=squad_a, mission=mission_a, stage_index=0),
                    FederationStage(squad=squad_b, mission=mission_b, stage_index=1),
                ],
                checkpoint_store=store,
            )

            with pytest.raises(RuntimeError, match="Federation failed at stage 1"):
                await fed.run()

            # Stage 0 should be checkpointed even though overall run failed
            stage0_key = f"fed_test-fail_stage_0"
            checkpoint = store.load_latest_checkpoint(stage0_key)
            assert checkpoint is not None
            assert checkpoint.get("status") == "completed"


class TestFederationStageNaming:

    @pytest.mark.asyncio
    async def test_stage_name_defaults_to_squad_name(self):
        """Stage name should default to squad.name if not explicitly set."""
        from agentos.core.federation import FederatedMission, FederationStage

        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            store = _make_checkpoint_store(tmp)

            squad_a = _make_mock_squad("MyResearchCrew", "output_a")
            mission_a = _make_mock_mission("m1_name", "Goal", "Task")
            squad_b = _make_mock_squad("MyWritingCrew", "output_b")
            mission_b = _make_mock_mission("m2_name", "Goal2", "Task2")

            stage_a = FederationStage(squad=squad_a, mission=mission_a, stage_index=0)
            stage_b = FederationStage(squad=squad_b, mission=mission_b, stage_index=1)

            assert stage_a.name == "MyResearchCrew"
            assert stage_b.name == "MyWritingCrew"

    @pytest.mark.asyncio
    async def test_stage_name_explicit(self):
        """Stage name can be set explicitly and is preserved."""
        from agentos.core.federation import FederationStage

        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            squad = _make_mock_squad("AnySquad", "out")
            mission = _make_mock_mission("mx", "G", "T")
            stage = FederationStage(squad=squad, mission=mission, stage_index=0, name="Phase-One-Research")
            assert stage.name == "Phase-One-Research"
