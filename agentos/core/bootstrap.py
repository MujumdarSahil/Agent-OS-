"""
Bootstrap - Initialize and register builtin AgentOS components,
then scan installed Python packages for third-party extensions
registered via entry points.
"""

import logging
from agentos.core.base import AgentRegistry, ToolRegistry

logger = logging.getLogger(__name__)

# Prevent double bootstrap
_bootstrapped = False


def register_builtin_components():
    """
    1. Explicitly registers AgentOS-shipped BaseAgent/BaseTool subclasses.
    2. Scans installed packages for entry points under:
         - agentos.agents      -> AgentRegistry
         - agentos.tools       -> ToolRegistry
         - agentos.mcp_plugins -> merged with project-local plugin discovery
       Each entry point load is wrapped in try/except so a broken third-party
       package never crashes AgentOS startup — only a warning is logged.
    """
    global _bootstrapped
    if _bootstrapped:
        return

    logger.info("Bootstrapping AgentOS registry...")

    # -----------------------------------------------------------------------
    # 1. Register builtin Agents
    # -----------------------------------------------------------------------
    try:
        from agentos.core.agent import Agent
        from agentos.agents.security_agent import SecurityAgent
        from agentos.agents.script_author_agent import ScriptAuthorAgent
        from agentos.agents.researcher_agent import ResearcherAgent

        agent_registry = AgentRegistry()
        agent_registry.register(Agent)
        agent_registry.register(SecurityAgent)
        agent_registry.register(ScriptAuthorAgent)
        agent_registry.register(ResearcherAgent)
        logger.info(
            "Registered builtin agents: Agent, SecurityAgent, "
            "ScriptAuthorAgent, ResearcherAgent"
        )
    except Exception as e:
        logger.error(f"Error registering builtin agents: {e}", exc_info=True)

    # -----------------------------------------------------------------------
    # 2. Scan installed packages for third-party entry points
    # -----------------------------------------------------------------------
    _load_entry_points()

    _bootstrapped = True


def _load_entry_points():
    """
    Discover and register classes from installed packages that declare
    entry points under the agentos.* groups.

    Each entry point is loaded in an isolated try/except so one broken
    third-party package does NOT prevent AgentOS from starting.
    """
    try:
        from importlib.metadata import entry_points
    except ImportError:
        logger.warning("importlib.metadata not available; skipping entry point discovery.")
        return

    agent_registry = AgentRegistry()
    tool_registry = ToolRegistry()

    # --- agentos.agents ---
    for ep in entry_points(group="agentos.agents"):
        try:
            cls = ep.load()
            agent_registry.register(cls)
            logger.info(f"[entry_points] Registered agent: {ep.name} = {cls}")
        except Exception as exc:
            logger.warning(
                f"[entry_points] Failed to load agent entry point "
                f"'{ep.name}' from '{ep.value}': {exc}"
            )

    # --- agentos.tools ---
    for ep in entry_points(group="agentos.tools"):
        try:
            cls = ep.load()
            tool_registry.register(cls)
            logger.info(f"[entry_points] Registered tool: {ep.name} = {cls}")
        except Exception as exc:
            logger.warning(
                f"[entry_points] Failed to load tool entry point "
                f"'{ep.name}' from '{ep.value}': {exc}"
            )

    # --- agentos.mcp_plugins ---
    # These are merged at discovery time — the plugin_loader already handles
    # project-local mcp_plugins/; here we just note which packages declare
    # themselves as plugins so they can be picked up via manifest scanning too.
    for ep in entry_points(group="agentos.mcp_plugins"):
        try:
            cls = ep.load()
            logger.info(
                f"[entry_points] Found MCP plugin entry point: "
                f"{ep.name} = {cls} (instantiated by plugin_loader at run time)"
            )
        except Exception as exc:
            logger.warning(
                f"[entry_points] Failed to load mcp_plugin entry point "
                f"'{ep.name}' from '{ep.value}': {exc}"
            )
