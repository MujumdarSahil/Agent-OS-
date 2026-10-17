"""
test_characterization_v1.py - Characterization tests pinning current v1 behavior.

Sub-milestone 1.0b (Additive tests only, no source changes).
Pins existing behavior for:
  - RunManager (create_run, get, list_runs, execute)
  - SQLiteCheckpointStore (init, save_checkpoint, load_latest_checkpoint, list_runs, mark_complete)
  - UMBAdapter (silent fallback of faiss/chroma/pgvector to SimpleVectorStore)
  - Project loading & config_models (ProjectConfig, AgentYAMLConfig, CrewYAMLConfig, MissionYAMLConfig, project_ops)
  - Provider fallback ordering (router_factory priority and preferred_tags sorting)
  - CLI (new-project, validate, run)

All tests run offline with mock LLM [MOCK].
"""

import os
import sqlite3
import pytest
import yaml
from unittest.mock import patch
from pydantic import ValidationError

from typer.testing import CliRunner

from agentos.server.run_manager import RunManager, RunState
from agentos.core.checkpoint import SQLiteCheckpointStore
from agentos.core.umb_adapter import UMBAdapter, SimpleVectorStore
from agentos.core.config_models import (
    ProjectConfig,
    GovernanceConfig,
    AgentYAMLConfig,
    ToolYAMLConfig,
    CrewYAMLConfig,
    MissionYAMLConfig,
    TaskYAMLConfig,
)
from agentos.core.project_ops import (
    load_project_config,
    is_valid_project,
    write_agent,
    read_agent,
    list_agents,
    write_crew,
    read_crew,
    list_crews,
    write_mission,
    read_mission,
    list_missions,
)
from agentos.llm.provider_registry import AgentOSLLMError
from agentos.llm.router_factory import build_router
from agentos.cli.main import app


# =====================================================================
# 1. RunManager Characterization Tests [MOCK]
# =====================================================================

class TestRunManagerCharacterization:
    """Pins current RunManager in-memory tracking & async execution."""

    def test_create_and_get_run(self):
        rm = RunManager()
        run_id = rm.create_run(mission_name="test_mission")
        assert run_id is not None
        assert isinstance(run_id, str)

        state = rm.get(run_id)
        assert state is not None
        assert state.run_id == run_id
        assert state.mission_name == "test_mission"
        assert state.status == "queued"
        assert state.task_index == 0
        assert state.outputs == []
        assert state.error is None
        assert state.provider is None

    def test_get_nonexistent_run(self):
        rm = RunManager()
        assert rm.get("nonexistent-uuid") is None

    def test_list_runs(self):
        rm = RunManager()
        id1 = rm.create_run("mission_1")
        id2 = rm.create_run("mission_2")
        runs = rm.list_runs()
        assert len(runs) == 2
        run_ids = {r.run_id for r in runs}
        assert id1 in run_ids
        assert id2 in run_ids

    @pytest.mark.asyncio
    async def test_execute_unknown_run_id(self):
        rm = RunManager()
        # Should not raise exception, logs error and returns early
        await rm.execute(
            run_id="unknown-id",
            project_path="/tmp/fake",
            mission_name="fake_mission",
        )
        assert rm.get("unknown-id") is None

    @pytest.mark.asyncio
    async def test_execute_success(self, tmp_path):
        # Setup a minimal runnable project
        proj_dir = str(tmp_path / "run_manager_proj")
        runner = CliRunner()
        result = runner.invoke(app, ["new-project", proj_dir])
        assert result.exit_code == 0

        # Add crew & mission to make it executable
        crew = CrewYAMLConfig(name="DefaultCrew", agents=["GeneralAssistant"], process="sequential")
        write_crew(proj_dir, crew)
        mission = MissionYAMLConfig(
            name="demo_mission",
            goal="Test run manager goal",
            crew="DefaultCrew",
            tasks=[TaskYAMLConfig(description="Perform demo task", assigned_agent="GeneralAssistant")]
        )
        write_mission(proj_dir, mission)

        rm = RunManager()
        run_id = rm.create_run("demo_mission")

        await rm.execute(
            run_id=run_id,
            project_path=proj_dir,
            mission_name="demo_mission",
        )

        state = rm.get(run_id)
        assert state is not None
        assert state.status == "completed"
        assert len(state.outputs) > 0
        assert state.error is None

        # Check events emitted
        events = []
        while not state.event_queue.empty():
            events.append(await state.event_queue.get())
        event_types = [e.get("event") for e in events]
        assert "run_started" in event_types
        assert "run_completed" in event_types

    @pytest.mark.asyncio
    async def test_execute_failure(self, tmp_path):
        proj_dir = str(tmp_path / "fail_proj")
        runner = CliRunner()
        runner.invoke(app, ["new-project", proj_dir])

        rm = RunManager()
        run_id = rm.create_run("missing_mission")

        await rm.execute(
            run_id=run_id,
            project_path=proj_dir,
            mission_name="missing_mission",
        )

        state = rm.get(run_id)
        assert state is not None
        assert state.status == "failed"
        assert state.error is not None
        assert "not found" in state.error.lower()

        events = []
        while not state.event_queue.empty():
            events.append(await state.event_queue.get())
        event_types = [e.get("event") for e in events]
        assert "run_started" in event_types
        assert "run_failed" in event_types


# =====================================================================
# 2. SQLiteCheckpointStore Characterization Tests [MOCK]
# =====================================================================

class TestSQLiteCheckpointStoreCharacterization:
    """Pins current SQLite checkpoint schema, save, load, and query."""

    def test_init_creates_table_and_columns(self, tmp_path):
        db_file = str(tmp_path / "checkpoints.db")
        store = SQLiteCheckpointStore(db_path=db_file)
        assert os.path.exists(db_file)

        with sqlite3.connect(db_file) as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA table_info(checkpoints)")
            cols = {row[1]: row[2] for row in cursor.fetchall()}
            assert "mission_id" in cols
            assert "task_index" in cols
            assert "state" in cols
            assert "status" in cols
            assert "timestamp" in cols
            assert "provider" in cols

    def test_save_and_load_latest_checkpoint(self, tmp_path):
        db_file = str(tmp_path / "checkpoints.db")
        store = SQLiteCheckpointStore(db_path=db_file)

        # Save step 0
        state0 = {"status": "in_progress", "data": "step 0 result", "provider": "mock-llm"}
        store.save_checkpoint(mission_id="m1", task_index=0, state=state0)

        # Save step 1
        state1 = {"status": "in_progress", "data": "step 1 result", "provider": "mock-llm"}
        store.save_checkpoint(mission_id="m1", task_index=1, state=state1)

        latest = store.load_latest_checkpoint(mission_id="m1")
        assert latest is not None
        assert latest["data"] == "step 1 result"
        assert latest["status"] == "in_progress"

    def test_load_nonexistent_checkpoint(self, tmp_path):
        db_file = str(tmp_path / "checkpoints.db")
        store = SQLiteCheckpointStore(db_path=db_file)
        assert store.load_latest_checkpoint("nonexistent") is None

    def test_list_runs_all_and_filtered(self, tmp_path):
        db_file = str(tmp_path / "checkpoints.db")
        store = SQLiteCheckpointStore(db_path=db_file)

        store.save_checkpoint("mission_a", 0, {"data": "a0", "status": "in_progress"})
        store.save_checkpoint("mission_b", 0, {"data": "b0", "status": "in_progress"})

        all_runs = store.list_runs()
        assert len(all_runs) == 2
        mission_ids = {r["mission_id"] for r in all_runs}
        assert mission_ids == {"mission_a", "mission_b"}

        filtered = store.list_runs(mission_id="mission_a")
        assert len(filtered) == 1
        assert filtered[0]["mission_id"] == "mission_a"

    def test_mark_complete(self, tmp_path):
        db_file = str(tmp_path / "checkpoints.db")
        store = SQLiteCheckpointStore(db_path=db_file)

        store.save_checkpoint("mission_c", 0, {"status": "in_progress"})
        runs_before = store.list_runs(mission_id="mission_c")
        assert runs_before[0]["status"] == "in_progress"

        store.mark_complete("mission_c")
        runs_after = store.list_runs(mission_id="mission_c")
        assert runs_after[0]["status"] == "completed"


# =====================================================================
# 3. UMBAdapter Silent Fallback Characterization Tests [MOCK]
# =====================================================================

class TestUMBAdapterCharacterization:
    """
    Pins CURRENT v1 behavior:
    When backend is 'faiss', 'chroma', 'pgvector', or unknown, UMBAdapter silently falls
    back to SimpleVectorStore. It retains backend_type as requested, but store is SimpleVectorStore.
    """

    @pytest.mark.parametrize("requested_backend", ["faiss", "chroma", "pgvector", "simple", "other_backend"])
    def test_fallback_store_type_and_warning(self, requested_backend):
        if requested_backend == "simple":
            adapter = UMBAdapter(backend=requested_backend)
        else:
            with pytest.warns(UserWarning, match="falling back to SimpleVectorStore"):
                adapter = UMBAdapter(backend=requested_backend)
        assert adapter.backend_type == requested_backend
        assert isinstance(adapter.store, SimpleVectorStore)
        assert type(adapter.store) is SimpleVectorStore

    @pytest.mark.parametrize("backend", ["faiss", "chroma", "pgvector"])
    @pytest.mark.asyncio
    async def test_fallback_backend_does_not_persist_across_reinstantiation(self, backend):
        """
        Pins CURRENT v1 behavior: Because requested backends fall back to the in-memory
        SimpleVectorStore, state is volatile and does NOT persist across new instances.
        """
        with pytest.warns(UserWarning):
            adapter1 = UMBAdapter(backend=backend)
        await adapter1.upsert({
            "id": "ephemeral_doc",
            "text": "Ephemeral memory entry",
            "metadata": {"test": "reinstantiation"}
        })
        results1 = await adapter1.query("Ephemeral", top_k=5)
        assert len(results1) == 1
        assert results1[0]["id"] == "ephemeral_doc"

        # Re-instantiate adapter with the same backend
        with pytest.warns(UserWarning):
            adapter2 = UMBAdapter(backend=backend)
        results2 = await adapter2.query("Ephemeral", top_k=5)
        # Asserts data did NOT persist across re-instantiation
        assert len(results2) == 0
        assert len(adapter2.store.entries) == 0

    @pytest.mark.asyncio
    async def test_fallback_store_operations_work(self):
        # Verify store operations function normally despite fallback
        with pytest.warns(UserWarning):
            adapter = UMBAdapter(backend="faiss")
        entry_id = await adapter.upsert({
            "id": "doc1",
            "text": "Antigravity characterization test document",
            "metadata": {"source": "v1_test"},
        })
        assert entry_id == "doc1"
        results = await adapter.query("characterization", top_k=1)
        assert len(results) == 1
        assert results[0]["id"] == "doc1"
        assert results[0]["metadata"]["source"] == "v1_test"

        # Revocation
        success = await adapter.revoke("doc1")
        assert success is True
        results_after = await adapter.query("characterization", top_k=1)
        assert len(results_after) == 0


# =====================================================================
# 4. Project Config Models & project_ops Characterization Tests [MOCK]
# =====================================================================

class TestProjectConfigModelsCharacterization:
    """Pins Pydantic schema validation and project_ops file I/O."""

    def test_valid_project_config(self):
        cfg = ProjectConfig(
            preferred_tags=["fast", "cheap"],
            default_model="gpt-4o-mini",
            governance=GovernanceConfig(llm_judge_enabled=True)
        )
        assert cfg.preferred_tags == ["fast", "cheap"]
        assert cfg.default_model == "gpt-4o-mini"
        assert cfg.governance.llm_judge_enabled is True

    def test_valid_agent_config(self):
        agent = AgentYAMLConfig(
            name="WriterAgent",
            role="Technical Writer",
            goal="Write clear documentation",
            backstory="Experienced docs engineer",
            type="Agent",
            llm_tags=["reasoning"],
            tool_refs=["doc_search"],
        )
        assert agent.name == "WriterAgent"
        assert agent.type == "Agent"

    def test_agent_config_validation_error_on_missing_required(self):
        with pytest.raises(ValidationError):
            # Missing role and goal
            AgentYAMLConfig(name="IncompleteAgent")

    def test_crew_config_validation_error_on_empty_agents(self):
        with pytest.raises(ValidationError):
            # agents requires min_length=1
            CrewYAMLConfig(name="EmptyCrew", agents=[])

    def test_mission_config_validation(self):
        mission = MissionYAMLConfig(
            name="release_mission",
            goal="Ship release",
            crew="ReleaseCrew",
            tasks=[
                TaskYAMLConfig(description="Build artifacts", assigned_agent="Builder"),
                TaskYAMLConfig(description="Verify hashes")
            ]
        )
        assert mission.name == "release_mission"
        assert len(mission.tasks) == 2
        assert mission.tasks[1].assigned_agent is None

    def test_project_ops_crud_lifecycle(self, tmp_path):
        proj = str(tmp_path / "crud_proj")
        os.makedirs(proj, exist_ok=True)
        assert not is_valid_project(proj)

        # Write agentos.config.yaml
        cfg_data = {"preferred_tags": ["fast"], "default_model": "mock-model"}
        with open(os.path.join(proj, "agentos.config.yaml"), "w", encoding="utf-8") as f:
            yaml.safe_dump(cfg_data, f)
        assert is_valid_project(proj)
        loaded_cfg = load_project_config(proj)
        assert loaded_cfg.preferred_tags == ["fast"]

        # Agents CRUD
        agent = AgentYAMLConfig(name="Analyst", role="Data Analyst", goal="Analyze data")
        write_agent(proj, agent)
        agents = list_agents(proj)
        assert len(agents) == 1
        assert agents[0].name == "Analyst"
        read = read_agent(proj, "Analyst")
        assert read.role == "Data Analyst"

        # Crew CRUD
        crew = CrewYAMLConfig(name="AnalyticsCrew", agents=["Analyst"], process="sequential")
        write_crew(proj, crew)
        crews = list_crews(proj)
        assert len(crews) == 1
        assert crews[0].name == "AnalyticsCrew"
        read_c = read_crew(proj, "AnalyticsCrew")
        assert read_c.agents == ["Analyst"]

        # Mission CRUD
        mission = MissionYAMLConfig(
            name="run_analytics",
            goal="Analyze numbers",
            crew="AnalyticsCrew",
            tasks=[TaskYAMLConfig(description="Summarize metrics", assigned_agent="Analyst")]
        )
        write_mission(proj, mission)
        missions = list_missions(proj)
        assert len(missions) == 1
        assert missions[0].name == "run_analytics"
        read_m = read_mission(proj, "run_analytics")
        assert read_m.crew == "AnalyticsCrew"


# =====================================================================
# 5. Provider Fallback Ordering Characterization Tests [MOCK]
# =====================================================================

class TestProviderFallbackOrderingCharacterization:
    """Pins provider fallback ordering based on priority and preferred tags."""

    def test_build_router_with_mock_llm(self):
        # When AGENTOS_MOCK_LLM=1, build_router returns mock-provider if no keys configured
        with patch.dict(os.environ, {"AGENTOS_MOCK_LLM": "1"}):
            # Remove any real keys if set in env
            with patch("agentos.llm.router_factory.get_available_providers", return_value=[]):
                with patch("agentos.llm.router_factory.check_ollama_reachable", return_value=False):
                    router = build_router()
                    assert router is not None
                    # Model list contains mock-provider
                    assert len(router.model_list) == 1
                    assert router.model_list[0]["model_name"] == "agentos-default"
                    assert router.model_list[0]["litellm_params"]["model"] == "openai/mock-model"

    def test_build_router_raises_when_no_providers_and_mock_disabled(self):
        with patch.dict(os.environ, {"AGENTOS_MOCK_LLM": "0"}):
            with patch("agentos.llm.router_factory.get_available_providers", return_value=[]):
                with patch("agentos.llm.router_factory.check_ollama_reachable", return_value=False):
                    with pytest.raises(AgentOSLLMError) as exc_info:
                        build_router()
                    assert "No LLM providers are available" in str(exc_info.value)

    def test_build_router_preferred_tags_ordering(self):
        mock_providers = [
            {"name": "p_fast_high_priority", "litellm_model": "openai/mock-fast", "priority": 10, "tags": ["fast"], "api_key_env": "KEY1", "api_base_env": None},
            {"name": "p_reasoning_low_priority", "litellm_model": "openai/mock-reasoning", "priority": 5, "tags": ["reasoning"], "api_key_env": "KEY2", "api_base_env": None},
            {"name": "p_general", "litellm_model": "openai/mock-general", "priority": 1, "tags": ["general"], "api_key_env": "KEY3", "api_base_env": None},
        ]

        with patch("agentos.llm.router_factory.get_available_providers", return_value=mock_providers):
            with patch("agentos.llm.router_factory.check_ollama_reachable", return_value=False):
                with patch.dict(os.environ, {"KEY1": "val1", "KEY2": "val2", "KEY3": "val3"}):
                    # When preferred_tags=["reasoning"], p_reasoning should come first even if priority=5
                    router = build_router(preferred_tags=["reasoning"])
                    models = [m["litellm_params"]["model"] for m in router.model_list]
                    assert models[0] == "openai/mock-reasoning"

                    # When preferred_tags=["fast"], p_fast should come first
                    router_fast = build_router(preferred_tags=["fast"])
                    models_fast = [m["litellm_params"]["model"] for m in router_fast.model_list]
                    assert models_fast[0] == "openai/mock-fast"


# =====================================================================
# 6. CLI Characterization Tests (new-project, validate, run) [MOCK]
# =====================================================================

class TestCLICharacterization:
    """Pins CLI new-project, validate, and run behavior."""

    def test_cli_new_project_creates_structure(self, tmp_path):
        runner = CliRunner()
        proj_dir = str(tmp_path / "cli_demo_project")

        result = runner.invoke(app, ["new-project", proj_dir])
        assert result.exit_code == 0
        assert "created successfully" in result.output.lower()

        # Check expected scaffolded directories and files
        assert os.path.exists(os.path.join(proj_dir, "agentos.config.yaml"))
        assert os.path.exists(os.path.join(proj_dir, "agents", "general_assistant.yaml"))
        assert os.path.isdir(os.path.join(proj_dir, "crews"))
        assert os.path.isdir(os.path.join(proj_dir, "missions"))
        assert os.path.isdir(os.path.join(proj_dir, "tools"))

    def test_cli_new_project_fails_if_exists(self, tmp_path):
        runner = CliRunner()
        proj_dir = str(tmp_path / "existing_dir")
        os.makedirs(proj_dir, exist_ok=True)

        result = runner.invoke(app, ["new-project", proj_dir])
        assert result.exit_code == 1
        assert "already exists" in result.output.lower()

    def test_cli_validate_success(self, tmp_path):
        runner = CliRunner()
        proj_dir = str(tmp_path / "valid_cli_proj")
        runner.invoke(app, ["new-project", proj_dir])

        result = runner.invoke(app, ["validate", proj_dir])
        assert result.exit_code == 0
        assert "Config validated" in result.output
        assert "Agent validated" in result.output

    def test_cli_validate_corrupted_yaml(self, tmp_path):
        runner = CliRunner()
        proj_dir = str(tmp_path / "corrupt_proj")
        runner.invoke(app, ["new-project", proj_dir])

        # Write an invalid agent yaml (missing role and goal)
        invalid_agent_path = os.path.join(proj_dir, "agents", "bad_agent.yaml")
        with open(invalid_agent_path, "w", encoding="utf-8") as f:
            yaml.safe_dump({"name": "BadAgent"}, f)

        result = runner.invoke(app, ["validate", proj_dir])
        # validate prints error block for bad yaml
        assert "ERROR in" in result.output or "validation error" in result.output.lower()

    def test_cli_run_success(self, tmp_path):
        runner = CliRunner()
        proj_dir = str(tmp_path / "runnable_cli_proj")
        runner.invoke(app, ["new-project", proj_dir])

        # Add crew & mission to make it runnable
        crew = CrewYAMLConfig(name="GeneralCrew", agents=["GeneralAssistant"], process="sequential")
        write_crew(proj_dir, crew)
        mission = MissionYAMLConfig(
            name="cli_mission",
            goal="Test CLI mission goal",
            crew="GeneralCrew",
            tasks=[TaskYAMLConfig(description="Perform CLI demo task", assigned_agent="GeneralAssistant")]
        )
        write_mission(proj_dir, mission)

        result = runner.invoke(app, ["run", proj_dir, "--mission", "cli_mission"], env={"AGENTOS_MOCK_LLM": "1"})
        assert result.exit_code == 0
        assert "Mission executed successfully!" in result.output

    def test_cli_run_missing_mission_fails(self, tmp_path):
        runner = CliRunner()
        proj_dir = str(tmp_path / "missing_mission_cli_proj")
        runner.invoke(app, ["new-project", proj_dir])

        result = runner.invoke(app, ["run", proj_dir, "--mission", "nonexistent_mission"], env={"AGENTOS_MOCK_LLM": "1"})
        assert result.exit_code == 1
        assert "Error loading project/mission configuration" in result.output
