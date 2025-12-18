#!/usr/bin/env python3
"""
Squad Planning Demo - AgentOS

This example shows how to:
- Create a small squad of agents (analyst + researcher)
- Use the Planner to build a task graph from a high-level goal
- Execute tasks sequentially using simple simulated logic
"""

import asyncio
from typing import Dict, Any

from agentos.core.agent import Agent
from agentos.core.squad import Squad, SquadRole
from agentos.core.planner import Planner
from agentos.core.umb_adapter import UMBAdapter


async def simulate_agent_work(agent: Agent, task: Dict[str, Any]) -> Dict[str, Any]:
    """
    Simulate an agent performing work for a planning task.
    In a real setup this would call tools and/or an LLM.
    """
    description = task.get("description", "")
    task_type = task.get("type", "generic")

    # Simple branching by role/type for nicer logs
    if task_type == "research":
        result_text = f"{agent.name} researched: {description}"
    elif task_type == "analysis":
        result_text = f"{agent.name} analyzed data for: {description}"
    else:
        result_text = f"{agent.name} completed: {description}"

    await asyncio.sleep(0.1)  # small delay to simulate work

    return {
        "success": True,
        "outputs": {"summary": result_text},
        "cost": {"tokens": 0, "api_calls": 0, "cpu_time": 0.01, "wall_time": 0.1},
    }


async def main():
    # Shared memory for the squad
    umb = UMBAdapter(backend="simple")

    # Create agents
    analyst = Agent(
        name="DataAnalyst",
        roles=["analyst"],
        skills=["analysis", "reporting"],
        memory_ref=umb,
    )
    researcher = Agent(
        name="MarketResearcher",
        roles=["researcher"],
        skills=["research", "trend_identification"],
        memory_ref=umb,
    )

    # Register a generic execution function via tools keyed by "analysis"/"research"
    analyst.register_tool("analysis", simulate_agent_work)
    researcher.register_tool("research", simulate_agent_work)

    # Build a squad
    squad = Squad(name="Market Insights Squad", shared_memory_ref=umb)
    squad.add_agent(analyst, SquadRole.WORKER)
    squad.add_agent(researcher, SquadRole.WORKER)

    print(f"\nCreated squad '{squad.name}' with {len(squad.agents)} agents.")

    # Create a high-level goal and derive a task graph using Planner
    planner = Planner()
    goal = "Understand market size and technology trends for solar energy"
    graph = planner.create_graph(goal)

    print(f"\nPlanning for goal:\n  {goal}")
    print(f"Planner created {len(graph.nodes)} tasks:")
    for node in graph.nodes:
        print(f"  - {node.id}: {node.description}")

    # Very simple assignment: research-like tasks to researcher, others to analyst
    print("\n=== Executing tasks sequentially ===")
    for node in graph.get_ready_tasks():
        # Decide which agent should handle the node
        text = node.description.lower()
        if any(word in text for word in ["research", "trend", "opportunities"]):
            agent = researcher
            task_type = "research"
        else:
            agent = analyst
            task_type = "analysis"

        task_dict = {
            "id": node.id,
            "type": task_type,
            "description": node.description,
        }

        print(f"\nRunning task {node.id} with {agent.name} ({task_type})")
        result = await agent.execute(task_dict)
        if not result.get("success"):
            print(f"  Task failed: {result.get('error')}")
        else:
            print(f"  Result: {result['outputs']['summary']}")

    print("\nSquad planning demo complete.")


if __name__ == "__main__":
    asyncio.run(main())


