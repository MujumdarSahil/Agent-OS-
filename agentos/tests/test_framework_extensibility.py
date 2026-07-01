"""
test_framework_extensibility.py
Layer 1 & 2 tests for the framework extensibility feature.

Covers:
- AgentRegistry/ToolRegistry singleton behaviour
- bootstrap registers builtin types
- YAML with type="Agent" (default) uses existing hardcoded path
- YAML with type="ResearcherAgent" uses registry path
- Unknown type gives a clear, descriptive error
- list-agent-types CLI command works
- list-tool-types CLI command works
"""

import os
import shutil
import tempfile
import pytest
import yaml

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_project(tmp_path: str, agent_type: str = "Agent"):
    """
    Scaffold a minimal AgentOS project directory for testing.
    Returns the project path.
    """
    dirs = ["agents", "tools", "mcp_plugins", "crews", "missions", "checkpoints"]
    for d in dirs:
        os.makedirs(os.path.join(tmp_path, d), exist_ok=True)

    # agentos.config.yaml
    cfg = {"preferred_tags": ["mock"]}
    with open(os.path.join(tmp_path, "agentos.config.yaml"), "w") as f:
        yaml.safe_dump(cfg, f)

    # agents/testresearcher.yaml
    agent_cfg = {
        "name": "TestResearcher",
        "role": "Research Specialist",
        "goal": "Do research",
        "backstory": "A test researcher",
        "type": agent_type,
        "llm_tags": ["mock"],
        "tool_refs": [],
    }
    with open(os.path.join(tmp_path, "agents", "testresearcher.yaml"), "w") as f:
        yaml.safe_dump(agent_cfg, f)

    # crews/testcrew.yaml
    crew_cfg = {"name": "TestCrew", "agents": ["TestResearcher"], "process": "sequential"}
    with open(os.path.join(tmp_path, "crews", "testcrew.yaml"), "w") as f:
        yaml.safe_dump(crew_cfg, f)

    # missions/testmission.yaml  (read_mission slugifies: "TestMission" -> "testmission")
    mission_cfg = {
        "name": "TestMission",
        "goal": "Test mission",
        "description": "A mission for testing",
        "crew": "TestCrew",
        "tasks": [{"description": "Perform research task", "assigned_agent": "TestResearcher"}],
    }
    with open(os.path.join(tmp_path, "missions", "testmission.yaml"), "w") as f:
        yaml.safe_dump(mission_cfg, f)

    return tmp_path


# ---------------------------------------------------------------------------
# Registry singleton tests
# ---------------------------------------------------------------------------

def test_agent_registry_is_singleton():
    """Two AgentRegistry() calls must return the exact same object."""
    from agentos.core.base import AgentRegistry
    r1 = AgentRegistry()
    r2 = AgentRegistry()
    assert r1 is r2


def test_tool_registry_is_singleton():
    """Two ToolRegistry() calls must return the exact same object."""
    from agentos.core.base import ToolRegistry
    r1 = ToolRegistry()
    r2 = ToolRegistry()
    assert r1 is r2


# ---------------------------------------------------------------------------
# Bootstrap tests
# ---------------------------------------------------------------------------

def test_bootstrap_registers_builtin_agents():
    """register_builtin_components() populates AgentRegistry with core builtins."""
    from agentos.core.base import AgentRegistry
    from agentos.core.bootstrap import register_builtin_components

    register_builtin_components()
    registry = AgentRegistry()

    assert "Agent" in registry._registry
    assert "ResearcherAgent" in registry._registry
    assert "SecurityAgent" in registry._registry
    assert "ScriptAuthorAgent" in registry._registry


def test_bootstrap_is_idempotent():
    """Calling register_builtin_components() twice must not raise or duplicate entries."""
    from agentos.core.bootstrap import register_builtin_components
    from agentos.core.base import AgentRegistry

    register_builtin_components()
    first_count = len(AgentRegistry()._registry)
    register_builtin_components()
    second_count = len(AgentRegistry()._registry)
    assert first_count == second_count


# ---------------------------------------------------------------------------
# Config model tests
# ---------------------------------------------------------------------------

def test_agent_yaml_config_type_defaults_to_agent():
    """AgentYAMLConfig.type defaults to 'Agent' when not specified."""
    from agentos.core.config_models import AgentYAMLConfig
    cfg = AgentYAMLConfig(name="X", role="r", goal="g")
    assert cfg.type == "Agent"


def test_agent_yaml_config_type_custom():
    """AgentYAMLConfig accepts a custom type value."""
    from agentos.core.config_models import AgentYAMLConfig
    cfg = AgentYAMLConfig(name="X", role="r", goal="g", type="ResearcherAgent")
    assert cfg.type == "ResearcherAgent"


# ---------------------------------------------------------------------------
# build_squad_from_project  — default (type="Agent") path unchanged
# ---------------------------------------------------------------------------

def test_build_squad_default_type_unchanged():
    """
    YAML with type='Agent' must build a squad with plain Agent instances,
    not ResearcherAgent. Proves the existing hardcoded path still runs.
    """
    from agentos.core.bootstrap import register_builtin_components
    register_builtin_components()

    from agentos.core.agent import Agent
    from agentos.agents.researcher_agent import ResearcherAgent

    tmp = tempfile.mkdtemp()
    try:
        _make_project(tmp, agent_type="Agent")
        from agentos.core.project_ops import build_squad_from_project
        squad, mission = build_squad_from_project(tmp, "TestMission")

        assert len(squad.agents) == 1
        agent_instance = list(squad.agents.values())[0]
        assert isinstance(agent_instance, Agent)
        # The plain-Agent path must NOT produce a ResearcherAgent subclass
        assert not isinstance(agent_instance, ResearcherAgent)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# build_squad_from_project  — custom type path uses ResearcherAgent
# ---------------------------------------------------------------------------

def test_build_squad_custom_type_uses_registry():
    """
    YAML with type='ResearcherAgent' must instantiate the ResearcherAgent
    subclass (not plain Agent) and carry the distinctive is_researcher_subclass flag.
    """
    from agentos.core.bootstrap import register_builtin_components
    register_builtin_components()

    from agentos.core.project_ops import list_agents
    from agentos.agents.researcher_agent import ResearcherAgent

    tmp = tempfile.mkdtemp()
    try:
        _make_project(tmp, agent_type="ResearcherAgent")

        # Confirm config was parsed correctly
        agents = list_agents(tmp)
        assert len(agents) == 1
        assert agents[0].type == "ResearcherAgent"

        # Confirm build_squad produces ResearcherAgent instances
        from agentos.core.project_ops import build_squad_from_project
        squad, mission = build_squad_from_project(tmp, "TestMission")

        assert len(squad.agents) == 1
        agent_instance = list(squad.agents.values())[0]
        assert isinstance(agent_instance, ResearcherAgent), (
            f"Expected ResearcherAgent, got {type(agent_instance).__name__}"
        )
        assert agent_instance.is_researcher_subclass is True
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# build_squad_from_project  — unknown type gives clear error
# ---------------------------------------------------------------------------

def test_build_squad_unknown_type_gives_clear_error():
    """
    YAML with an unregistered type should raise ValueError with a helpful
    message naming the type and mentioning 'agentos list-agent-types'.
    """
    from agentos.core.bootstrap import register_builtin_components
    register_builtin_components()

    tmp = tempfile.mkdtemp()
    try:
        _make_project(tmp, agent_type="NonExistentAgent")
        from agentos.core.project_ops import build_squad_from_project
        with pytest.raises(ValueError) as exc_info:
            build_squad_from_project(tmp, "TestMission")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    msg = str(exc_info.value)
    assert "NonExistentAgent" in msg
    assert "list-agent-types" in msg


# ---------------------------------------------------------------------------
# CLI commands
# ---------------------------------------------------------------------------

def test_list_agent_types_cli():
    """agentos list-agent-types must exit 0 and print known builtin types."""
    from typer.testing import CliRunner
    from agentos.cli.main import app

    runner = CliRunner()
    result = runner.invoke(app, ["list-agent-types"])
    assert result.exit_code == 0, result.output
    assert "ResearcherAgent" in result.output
    assert "Agent" in result.output


def test_list_tool_types_cli():
    """agentos list-tool-types must exit 0 (even when empty)."""
    from typer.testing import CliRunner
    from agentos.cli.main import app

    runner = CliRunner()
    result = runner.invoke(app, ["list-tool-types"])
    assert result.exit_code == 0, result.output


# ---------------------------------------------------------------------------
# ResearcherAgent distinctive backstory
# ---------------------------------------------------------------------------

def test_researcher_agent_default_backstory():
    """ResearcherAgent must inject a distinctive backstory when none is given."""
    from agentos.agents.researcher_agent import ResearcherAgent
    agent = ResearcherAgent(name="R", role="Researcher", goal="Research")
    assert "research" in agent.backstory.lower()
    assert agent.is_researcher_subclass is True


# ---------------------------------------------------------------------------
# External Plugin Demo tests (Layer 2)
# ---------------------------------------------------------------------------

def test_external_agent_registered_and_instantiated():
    """DemoCustomAgent must be registered and buildable via build_squad_from_project."""
    from agentos.core.bootstrap import register_builtin_components
    register_builtin_components()

    from external_plugin_demo.agent import DemoCustomAgent
    from agentos.core.project_ops import build_squad_from_project

    tmp = tempfile.mkdtemp()
    try:
        _make_project(tmp, agent_type="DemoCustomAgent")
        squad, mission = build_squad_from_project(tmp, "TestMission")

        assert len(squad.agents) == 1
        agent_instance = list(squad.agents.values())[0]
        assert isinstance(agent_instance, DemoCustomAgent)
        assert agent_instance.is_custom_demo_agent is True
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_external_mcp_plugin_discovery_and_loading():
    """DemoMCPPlugin must be discovered and loaded via discover_plugins/load_plugin."""
    from agentos.mcp.plugin_loader import discover_plugins, load_plugin
    from agentos.core.base import ToolRegistry

    discovered = discover_plugins("dummy_project")
    # Find DemoMCPPlugin
    demo_plugin = next((m for m, p in discovered if m.name == "demo_mcp_plugin"), None)
    assert demo_plugin is not None, "DemoMCPPlugin was not discovered"

    # Get manifest path
    manifest, path = next((m, p) for m, p in discovered if m.name == "demo_mcp_plugin")
    assert path.startswith("entrypoint:DemoMCPPlugin:")

    # Load it
    tool_registry = ToolRegistry()
    registered_keys = load_plugin(manifest, path, tool_registry)
    assert "demo_mcp_plugin.demo_mcp_tool" in registered_keys
    
    # Try creating the tool
    tool = tool_registry.create("demo_mcp_plugin.demo_mcp_tool")
    assert tool is not None
    assert tool.run() == "DemoMCPTool response"


def test_entry_point_failure_isolation(caplog):
    """
    If an entry point is broken (e.g. raises on ep.load()),
    AgentOS must not crash, and must log a warning.
    """
    import logging
    from agentos.core.bootstrap import _load_entry_points
    from unittest.mock import patch, MagicMock

    mock_ep = MagicMock()
    mock_ep.name = "BrokenAgent"
    mock_ep.value = "some.nonexistent.module:Broken"
    mock_ep.load.side_effect = ImportError("Simulated import error")

    # Mock entry_points to return our broken entry point
    with patch("importlib.metadata.entry_points") as mock_entry_points:
        mock_entry_points.return_value = [mock_ep]
        
        with caplog.at_level(logging.WARNING):
            # Should not raise any exceptions
            _load_entry_points()
            
        assert any("Failed to load agent entry point 'BrokenAgent'" in record.message for record in caplog.records)
