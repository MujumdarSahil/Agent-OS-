"""
project_ops.py — Shared project file I/O and orchestration logic.

This module is the SINGLE source of truth for reading and writing AgentOS
project files (agents, tools, crews, missions).  Both agentos/cli/main.py
and agentos/server/ import from here — there is no duplicated business logic.
"""

import os
import glob
import importlib.util
import logging
import yaml
from typing import List, Optional, Dict, Any, Tuple

from agentos.core.config_models import (
    ProjectConfig,
    AgentYAMLConfig,
    CrewYAMLConfig,
    MissionYAMLConfig,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _slug(name: str) -> str:
    """Convert a name to a lowercase filename-safe slug."""
    return name.lower().replace(" ", "_")


def _agent_path(project_path: str, name: str) -> str:
    return os.path.join(project_path, "agents", f"{_slug(name)}.yaml")


def _crew_path(project_path: str, name: str) -> str:
    return os.path.join(project_path, "crews", f"{_slug(name)}.yaml")


def _mission_path(project_path: str, name: str) -> str:
    return os.path.join(project_path, "missions", f"{_slug(name)}.yaml")


def _tool_path(project_path: str, name: str) -> str:
    return os.path.join(project_path, "tools", f"{_slug(name)}.py")


# ---------------------------------------------------------------------------
# Project config
# ---------------------------------------------------------------------------

def load_project_config(project_path: str) -> ProjectConfig:
    """Load and validate agentos.config.yaml."""
    config_file = os.path.join(project_path, "agentos.config.yaml")
    if not os.path.exists(config_file):
        return ProjectConfig()
    with open(config_file, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return ProjectConfig(**data)


def is_valid_project(project_path: str) -> bool:
    """Return True if the path looks like a valid AgentOS project."""
    return os.path.exists(os.path.join(project_path, "agentos.config.yaml"))


# ---------------------------------------------------------------------------
# Agents
# ---------------------------------------------------------------------------

def list_agents(project_path: str) -> List[AgentYAMLConfig]:
    """Return all validated agent configs in the project."""
    agents_dir = os.path.join(project_path, "agents")
    results = []
    if not os.path.exists(agents_dir):
        return results
    for fpath in glob.glob(os.path.join(agents_dir, "*.yaml")):
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            results.append(AgentYAMLConfig(**data))
        except Exception as e:
            logger.warning(f"Skipping invalid agent file {fpath}: {e}")
    return results


def read_agent(project_path: str, name: str) -> AgentYAMLConfig:
    """Read a single agent config by name. Raises FileNotFoundError if missing."""
    path = _agent_path(project_path, name)
    if not os.path.exists(path):
        raise FileNotFoundError(f"Agent '{name}' not found at {path}")
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return AgentYAMLConfig(**data)


def write_agent(project_path: str, config: AgentYAMLConfig) -> str:
    """Write an agent config to disk. Returns the file path written."""
    os.makedirs(os.path.join(project_path, "agents"), exist_ok=True)
    path = _agent_path(project_path, config.name)
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(config.model_dump(), f)
    logger.info(f"Wrote agent config: {path}")
    return path


def delete_agent(project_path: str, name: str) -> bool:
    """Delete an agent config. Returns True if deleted, False if not found."""
    path = _agent_path(project_path, name)
    if not os.path.exists(path):
        return False
    os.remove(path)
    logger.info(f"Deleted agent config: {path}")
    return True


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

def list_tools(project_path: str) -> List[Dict[str, str]]:
    """Return list of tool stubs (name + file path) in the project."""
    tools_dir = os.path.join(project_path, "tools")
    results = []
    if not os.path.exists(tools_dir):
        return results
    for fpath in glob.glob(os.path.join(tools_dir, "*.py")):
        name = os.path.splitext(os.path.basename(fpath))[0]
        results.append({"name": name, "file": fpath})
    return results


def scaffold_tool(project_path: str, name: str) -> str:
    """Create a BaseTool stub file. Returns the file path."""
    os.makedirs(os.path.join(project_path, "tools"), exist_ok=True)
    class_name = "".join(x.title() for x in name.split("_"))
    tool_content = (
        f'"""\nCustom Tool: {class_name}\n"""\n\n'
        "from agentos.core.base import BaseTool\n\n"
        f"class {class_name}(BaseTool):\n"
        f'    name: str = "{name}"\n'
        f'    description: str = "TODO: Provide a description for this tool."\n\n'
        "    def run(self, **kwargs) -> str:\n"
        "        query = kwargs.get('query', '')\n"
        "        return f'Stub tool executed with query: {query}'\n"
    )
    path = _tool_path(project_path, name)
    with open(path, "w", encoding="utf-8") as f:
        f.write(tool_content)
    logger.info(f"Scaffolded tool: {path}")
    return path


# ---------------------------------------------------------------------------
# Crews
# ---------------------------------------------------------------------------

def list_crews(project_path: str) -> List[CrewYAMLConfig]:
    """Return all validated crew configs in the project."""
    crews_dir = os.path.join(project_path, "crews")
    results = []
    if not os.path.exists(crews_dir):
        return results
    for fpath in glob.glob(os.path.join(crews_dir, "*.yaml")):
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            results.append(CrewYAMLConfig(**data))
        except Exception as e:
            logger.warning(f"Skipping invalid crew file {fpath}: {e}")
    return results


def read_crew(project_path: str, name: str) -> CrewYAMLConfig:
    path = _crew_path(project_path, name)
    if not os.path.exists(path):
        raise FileNotFoundError(f"Crew '{name}' not found at {path}")
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return CrewYAMLConfig(**data)


def write_crew(project_path: str, config: CrewYAMLConfig) -> str:
    os.makedirs(os.path.join(project_path, "crews"), exist_ok=True)
    path = _crew_path(project_path, config.name)
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(config.model_dump(), f)
    logger.info(f"Wrote crew config: {path}")
    return path


# ---------------------------------------------------------------------------
# Missions
# ---------------------------------------------------------------------------

def list_missions(project_path: str) -> List[MissionYAMLConfig]:
    """Return all validated mission configs in the project."""
    missions_dir = os.path.join(project_path, "missions")
    results = []
    if not os.path.exists(missions_dir):
        return results
    for fpath in glob.glob(os.path.join(missions_dir, "*.yaml")):
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            results.append(MissionYAMLConfig(**data))
        except Exception as e:
            logger.warning(f"Skipping invalid mission file {fpath}: {e}")
    return results


def read_mission(project_path: str, name: str) -> MissionYAMLConfig:
    path = _mission_path(project_path, name)
    if not os.path.exists(path):
        # Try without slug conversion in case name already is slug
        alt = os.path.join(project_path, "missions", f"{name}.yaml")
        if os.path.exists(alt):
            path = alt
        else:
            raise FileNotFoundError(f"Mission '{name}' not found.")
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return MissionYAMLConfig(**data)


def write_mission(project_path: str, config: MissionYAMLConfig) -> str:
    os.makedirs(os.path.join(project_path, "missions"), exist_ok=True)
    path = _mission_path(project_path, config.name)
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(config.model_dump(), f)
    logger.info(f"Wrote mission config: {path}")
    return path


# ---------------------------------------------------------------------------
# Squad builder — assembles a runnable Squad+Mission from project files
# ---------------------------------------------------------------------------

def build_squad_from_project(
    project_path: str,
    mission_name: str,
    preferred_tags: Optional[List[str]] = None,
    governance: Optional[Any] = None,
) -> Tuple[Any, Any]:
    """
    Build a Squad and Mission object from project YAML configs.
    Returns (squad, mission) ready to pass to squad.run_mission().
    """
    from agentos.core.base import ToolRegistry, AgentRegistry
    from agentos.core.agent import Agent
    from agentos.core.squad import Squad, SquadRole, Mission
    from agentos.core.planner import TaskGraph, TaskNode
    from agentos.core.governance import GovernanceEngine
    from agentos.core.checkpoint import SQLiteCheckpointStore
    from agentos.llm import LLMClient
    from agentos.mcp.plugin_loader import discover_plugins, load_plugin
    from agentos.core.bootstrap import register_builtin_components

    # Ensure the registry is populated with builtin components
    register_builtin_components()

    cfg = load_project_config(project_path)
    tags = preferred_tags or cfg.preferred_tags or ["fast"]

    # Load .env if present
    dotenv_path = os.path.join(project_path, ".env")
    if os.path.exists(dotenv_path):
        from dotenv import load_dotenv
        load_dotenv(dotenv_path)

    tool_registry = ToolRegistry()

    # Load MCP plugins
    for manifest, m_path in discover_plugins(project_path):
        try:
            load_plugin(manifest, m_path, tool_registry)
        except Exception as e:
            logger.warning(f"MCP plugin '{manifest.name}' failed to load: {e}")

    # Load custom Python tools
    tools_dir = os.path.join(project_path, "tools")
    if os.path.exists(tools_dir):
        for py_file in glob.glob(os.path.join(tools_dir, "*.py")):
            try:
                spec = importlib.util.spec_from_file_location("dynamic_tool", py_file)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                from agentos.core.base import BaseTool
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if isinstance(attr, type) and issubclass(attr, BaseTool) and attr is not BaseTool:
                        tool_registry.register(attr)
            except Exception as e:
                logger.warning(f"Tool file {py_file} failed to load: {e}")

    llm_client = LLMClient(preferred_tags=tags)

    # Build agents map
    agents_map: Dict[str, Agent] = {}
    for agent_cfg in list_agents(project_path):
        agent_tools = []
        for ref in agent_cfg.tool_refs:
            try:
                agent_tools.append(tool_registry.create(ref))
            except Exception:
                try:
                    camel = "".join(x.title() for x in ref.split("_"))
                    agent_tools.append(tool_registry.create(camel))
                except Exception:
                    logger.warning(f"Tool '{ref}' not found for agent '{agent_cfg.name}'")
        agent_type = getattr(agent_cfg, "type", "Agent") or "Agent"
        if agent_type == "Agent":
            # --- EXISTING HARDCODED PATH — unchanged behavior ---
            agents_map[agent_cfg.name] = Agent(
                name=agent_cfg.name,
                role=agent_cfg.role,
                goal=agent_cfg.goal,
                backstory=agent_cfg.backstory,
                llm_client=llm_client,
                tools=agent_tools,
            )
        else:
            # --- REGISTRY PATH — custom BaseAgent subclass ---
            agent_registry = AgentRegistry()
            if agent_type not in agent_registry._registry:
                raise ValueError(
                    f"Agent type '{agent_type}' (used by agent '{agent_cfg.name}') is not registered. "
                    f"Run 'agentos list-agent-types' to see all registered types, or ensure "
                    f"the package that provides '{agent_type}' is installed and its entry point "
                    f"is correctly defined."
                )
            custom_agent = agent_registry.create(
                agent_type,
                name=agent_cfg.name,
                role=agent_cfg.role,
                goal=agent_cfg.goal,
                backstory=agent_cfg.backstory,
                llm_client=llm_client,
                tools=agent_tools,
            )
            agents_map[agent_cfg.name] = custom_agent
            logger.info(f"Instantiated '{agent_type}' (via registry) for agent '{agent_cfg.name}'")

    # Load mission + crew
    mission_cfg = read_mission(project_path, mission_name)
    crew_cfg = read_crew(project_path, mission_cfg.crew)

    checkpoint_db = os.path.join(project_path, "checkpoints", "run_history.db")
    checkpoint_store = SQLiteCheckpointStore(db_path=checkpoint_db)
    governance = GovernanceEngine()

    # Phase 4: Wire LLM judge layer if project config enables it
    if cfg.governance.llm_judge_enabled:
        governance.configure_llm_judge(enabled=True, llm_client=llm_client)
        logger.info(
            "GovernanceEngine: LLM judge layer ENABLED for this project "
            "(governance.llm_judge_enabled=true in agentos.config.yaml). "
            "This adds ~1 LLM call per task governance check."
        )

    squad = Squad(
        name=crew_cfg.name,
        checkpoint_store=checkpoint_store,
        governance=governance,
    )

    for a_name in crew_cfg.agents:
        if a_name not in agents_map:
            raise ValueError(f"Agent '{a_name}' in crew is missing from agents/ definitions.")
        role = SquadRole.WORKER
        if crew_cfg.process == "hierarchical" and a_name == crew_cfg.agents[0]:
            role = SquadRole.COMMANDER
        squad.add_agent(agents_map[a_name], role)

    task_nodes = []
    for idx, t in enumerate(mission_cfg.tasks):
        assigned_id = None
        if t.assigned_agent and t.assigned_agent in agents_map:
            assigned_id = agents_map[t.assigned_agent].id
        task_nodes.append(TaskNode(
            id=f"t_{idx}",
            description=t.description,
            assigned_agent=assigned_id,
        ))

    task_graph = TaskGraph(
        id=f"tg_{mission_name}",
        goal=mission_cfg.goal,
        nodes=task_nodes,
    )
    mission = Mission(
        id=mission_cfg.name,
        goal=mission_cfg.goal,
        description=mission_cfg.description,
        task_graph=task_graph,
    )

    return squad, mission


# ---------------------------------------------------------------------------
# MCP plugins
# ---------------------------------------------------------------------------

def list_mcp_plugins(project_path: str) -> List[Dict[str, Any]]:
    """Return discovered plugin manifests as dicts."""
    from agentos.mcp.plugin_loader import discover_plugins
    results = []
    for manifest, _ in discover_plugins(project_path):
        results.append({
            "name": manifest.name,
            "version": manifest.version,
            "author": manifest.author,
            "permissions": manifest.permissions,
            "entrypoint": manifest.entrypoint,
            "mcp_server_url": manifest.mcp_server_url,
        })
    return results


def scaffold_mcp_plugin(project_path: str, name: str) -> str:
    """Create a plugin directory stub. Returns the plugin directory path."""
    plugin_dir = os.path.join(project_path, "mcp_plugins", name)
    if os.path.exists(plugin_dir):
        raise FileExistsError(f"Plugin '{name}' already exists at {plugin_dir}")
    os.makedirs(plugin_dir, exist_ok=True)

    manifest = {
        "name": name,
        "version": "1.0.0",
        "author": "Developer",
        "permissions": [],
        "entrypoint": "plugin.MyMCPPlugin",
        "mcp_server_url": None,
    }
    with open(os.path.join(plugin_dir, "manifest.yaml"), "w", encoding="utf-8") as f:
        yaml.safe_dump(manifest, f)

    stub = (
        "from agentos.core.base import BaseMCPPlugin, BaseTool\n"
        "from typing import List\n\n"
        "class MyMCPPlugin(BaseMCPPlugin):\n"
        "    def register_tools(self) -> List[BaseTool]:\n"
        "        return []\n"
    )
    with open(os.path.join(plugin_dir, "plugin.py"), "w", encoding="utf-8") as f:
        f.write(stub)

    logger.info(f"Scaffolded MCP plugin: {plugin_dir}")
    return plugin_dir
