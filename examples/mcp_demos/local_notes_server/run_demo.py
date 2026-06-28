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
    print("[1/4] Loading local notes MCP plugin...")
    manifest_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "manifest.yaml")
    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest_data = yaml.safe_load(f)
    manifest = MCPPluginManifest(**manifest_data)
    
    tool_registry = ToolRegistry()
    load_plugin(manifest, manifest_path, tool_registry)

    print("[2/4] Building 'Notes Assistant' agent...")
    agent_config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "demo_agent.yaml")
    with open(agent_config_path, "r", encoding="utf-8") as f:
        agent_data = yaml.safe_load(f)
    
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
        name="NotesDemoSquad",
        checkpoint_store=checkpoint_store,
        governance=GovernanceEngine(),
    )
    squad.add_agent(agent)

    task_node = TaskNode(
        id="t_notes_demo",
        description="Add a note saying 'Demo note from AgentOS', then list all notes.",
        assigned_agent=agent.id,
    )
    task_graph = TaskGraph(id="tg_notes_demo", goal="Record a note and review", nodes=[task_node])
    mission = Mission(
        id="m_notes_demo",
        goal="Record a note and review",
        description="Verify custom tool execution and persistence",
        task_graph=task_graph,
    )
    squad.missions[mission.id] = mission

    print("[4/4] Executing mission...")
    result = asyncio.run(squad.start_mission(mission.id, task_graph=task_graph))

    print("\n--- DEMO 1 RUN COMPLETED ---")
    print(f"Success: {result.get('success')}")
    if result.get("success"):
        print(f"Result Output:\n{result.get('result')}")
    else:
        print(f"Error: {result.get('error')}")

    # Offline/Mock verification of notes persistence
    if os.environ.get("AGENTOS_MOCK_LLM") == "1":
        print("\n--- OFFLINE MOCK VERIFICATION ---")
        add_note_tool = tool_registry.create("local_notes.add_note")
        list_notes_tool = tool_registry.create("local_notes.list_notes")
        
        print("Direct call: add_note('Demo note from AgentOS')")
        add_note_tool.run(text="Demo note from AgentOS")
        print("Direct call: list_notes()")
        notes = list_notes_tool.run()
        print(f"Current Notes: {notes}")
        
        print("Direct call: add_note('Second note')")
        add_note_tool.run(text="Second note")
        print("Direct call: list_notes() (second run)")
        notes2 = list_notes_tool.run()
        print(f"Current Notes: {notes2}")

if __name__ == "__main__":
    main()
