import os
import sys
import yaml
import asyncio
import logging

# Ensure project root is in Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

# Configure logging to show framework details, including LiteLLM serving provider logs
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

from agentos.mcp.plugin_loader import load_plugin, MCPPluginManifest
from agentos.core.base import ToolRegistry
from agentos.core.agent import Agent
from agentos.core.squad import Squad, Mission
from agentos.core.planner import TaskGraph, TaskNode
from agentos.core.checkpoint import SQLiteCheckpointStore
from agentos.core.governance import GovernanceEngine
from agentos.llm import LLMClient

def main():
    print("[1/4] Loading Context7 external docs MCP plugin...")
    manifest_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "manifest.yaml")
    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest_data = yaml.safe_load(f)
    manifest = MCPPluginManifest(**manifest_data)
    
    tool_registry = ToolRegistry()
    load_plugin(manifest, manifest_path, tool_registry)

    print("[2/4] Building 'Docs Helper' agent...")
    agent_config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "demo_agent.yaml")
    with open(agent_config_path, "r", encoding="utf-8") as f:
        agent_data = yaml.safe_load(f)
        
    # Check if tools are successfully registered. If MCP server was unreachable, resolution will have failed.
    for ref in agent_data["tool_refs"]:
        try:
            tool_registry.create(ref)
        except ValueError:
            raise RuntimeError(
                f"CRITICAL ERROR: MCP Server at {manifest.mcp_server_url} is unreachable or offline. "
                f"Required tool '{ref}' is not registered."
            )

    llm_client = LLMClient(preferred_tags=["fast"])
    agent_tools = [tool_registry.create(t) for t in agent_data["tool_refs"]]

    agent = Agent(
        name=agent_data["name"],
        role=agent_data["role"],
        goal=agent_data["goal"],
        backstory=agent_data.get("backstory", ""),
        llm_client=llm_client,
        tools=agent_tools,
    )

    print("[3/4] Initializing Squad and Task Graph...")
    db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "run_history.db")
    checkpoint_store = SQLiteCheckpointStore(db_path=db_path)
    squad = Squad(
        name="DocsDemoSquad",
        checkpoint_store=checkpoint_store,
        governance=GovernanceEngine(),
    )
    squad.add_agent(agent)

    task_node = TaskNode(
        id="t_docs_demo",
        description="Look up how to use React's useEffect hook and summarize it in 2 sentences.",
        assigned_agent=agent.id,
    )
    task_graph = TaskGraph(id="tg_docs_demo", goal="Look up and summarize React useEffect docs", nodes=[task_node])
    mission = Mission(
        id="m_docs_demo",
        goal="Look up and summarize React useEffect docs",
        description="Verify remote MCP tool execution and API connectivity",
        task_graph=task_graph,
    )
    squad.missions[mission.id] = mission

    print("[4/4] Executing mission...")
    result = asyncio.run(squad.start_mission(mission.id, task_graph=task_graph))

    print("\n--- DEMO 2 RUN COMPLETED ---")
    print(f"Success: {result.get('success')}")
    if result.get("success"):
        print(f"Result Output:\n{result.get('result')}")
    else:
        print(f"Error: {result.get('error')}")

    # Offline/Mock verification of direct tool query
    if os.environ.get("AGENTOS_MOCK_LLM") == "1":
        print("\n--- OFFLINE MOCK VERIFICATION ---")
        query_tool = tool_registry.create("context7_docs.query_docs")
        print("Direct call: query_docs(libraryId='/org/react', query='useEffect hook')")
        # In mock mode, we just check that the tool execution doesn't crash
        try:
            res = query_tool.run(libraryId="/org/react", query="useEffect hook")
            print(f"Tool response length: {len(res)} characters.")
            if len(res) > 10:
                print("[PASS] Direct remote tool query check PASSED!")
            else:
                print("[FAIL] Direct remote tool query returned empty or short result.")
        except Exception as e:
            print(f"[FAIL] Direct remote tool query failed: {e}")

if __name__ == "__main__":
    main()
