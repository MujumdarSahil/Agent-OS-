"""
AgentOS Demo - Showcase key features
"""

import asyncio
from agentos.core.agent import Agent
from agentos.core.squad import Squad, SquadRole
from agentos.core.umb_adapter import UMBAdapter
from agentos.core.planner import Planner
from agentos.core.router import TaskRouter, AssignmentStrategy
from agentos.core.governance import GovernanceEngine
from agentos.dmsg.registry import MCPRegistry
from agentos.dmsg.pathfinder import Pathfinder
from agentos.mcp_connectors.base_mcp import FileMCPConnector


async def demo_basic_agent():
    """Demo: Basic agent with memory"""
    print("\n=== Demo: Basic Agent ===")
    
    # Create UMB
    umb = UMBAdapter(backend="simple")
    
    # Create agent
    agent = Agent(
        name="Alice",
        skills=["coding", "testing", "documentation"],
        memory_ref=umb,
    )
    
    print(f"Created agent: {agent.name} (ID: {agent.id})")
    print(f"Skills: {agent.skills}")
    
    # Plan a task
    task = {"id": "task1", "description": "Write a Python function to calculate factorial"}
    plan = await agent.plan(task)
    print(f"\nPlan created: {plan['task_id']}")
    
    # Execute task
    task_node = {
        "id": "task1",
        "description": "Write a Python function to calculate factorial",
        "type": "coding",
    }
    result = await agent.execute(task_node)
    print(f"Execution result: {result['success']}")
    
    # Query memory
    memories = await umb.query("Python function", scope=["agent"], agent_id=agent.id)
    print(f"Found {len(memories)} relevant memories")


async def demo_squad():
    """Demo: Squad with multiple agents"""
    print("\n=== Demo: Squad ===")
    
    # Create UMB
    umb = UMBAdapter(backend="simple")
    
    # Create squad
    squad = Squad(name="Development Squad", shared_memory_ref=umb)
    print(f"Created squad: {squad.name}")
    
    # Create agents
    commander = Agent(
        name="Commander",
        skills=["planning", "coordination"],
        memory_ref=umb,
    )
    
    developer = Agent(
        name="Developer",
        skills=["coding", "debugging"],
        memory_ref=umb,
    )
    
    tester = Agent(
        name="Tester",
        skills=["testing", "qa"],
        memory_ref=umb,
    )
    
    # Add agents to squad
    squad.add_agent(commander, SquadRole.COMMANDER)
    squad.add_agent(developer, SquadRole.WORKER)
    squad.add_agent(tester, SquadRole.WORKER)
    
    print(f"Squad has {len(squad.agents)} agents")
    print(f"Commander: {squad.get_commander().name}")
    
    # Create mission
    mission = squad.create_mission(
        goal="Build a REST API",
        description="Create a FastAPI-based REST API with authentication"
    )
    print(f"\nCreated mission: {mission.goal}")
    
    # Start mission
    result = await squad.start_mission(mission.id)
    print(f"Mission started: {result['success']}")


async def demo_planning():
    """Demo: Planning with MAGP"""
    print("\n=== Demo: Planning (MAGP) ===")
    
    # Create planner
    planner = Planner()
    
    # Create task graph
    goal = "Build and test a web scraper"
    graph = planner.create_graph(goal)
    
    print(f"Goal: {goal}")
    print(f"Created graph with {len(graph.nodes)} tasks:")
    for node in graph.nodes:
        print(f"  - {node.description} (depends on: {node.dependencies})")
    
    # Get ready tasks
    ready = graph.get_ready_tasks()
    print(f"\nReady tasks: {len(ready)}")
    
    # Optimize
    optimized = planner.optimize(graph, constraints={"minimize_latency": True})
    print(f"Optimized graph: {len(optimized.nodes)} tasks")


async def demo_routing():
    """Demo: Task routing with DMARP"""
    print("\n=== Demo: Task Routing (DMARP) ===")
    
    # Create agents
    umb = UMBAdapter(backend="simple")
    
    agents = [
        Agent(name="Python Expert", skills=["python", "api"], memory_ref=umb),
        Agent(name="Frontend Dev", skills=["javascript", "react"], memory_ref=umb),
        Agent(name="Full Stack", skills=["python", "javascript", "api"], memory_ref=umb),
    ]
    
    # Set reputation
    agents[0].identity.reputation_score = 0.9
    agents[1].identity.reputation_score = 0.8
    agents[2].identity.reputation_score = 0.85
    
    # Create task graph
    planner = Planner()
    graph = planner.create_graph("Build a Python API")
    
    # Route tasks
    router = TaskRouter(strategy=AssignmentStrategy.HYBRID)
    plan = router.assign(graph, agents)
    
    print("Assignment plan:")
    for task_id, agent_id in plan.assignments.items():
        if agent_id:
            agent = next(a for a in agents if a.id == agent_id)
            print(f"  Task {task_id} -> {agent.name}")
            print(f"    Reasoning: {plan.reasoning.get(task_id)}")
    
    print(f"\nEstimated cost: {plan.estimated_cost:.2f}")
    print(f"Estimated latency: {plan.estimated_latency:.2f}s")


async def demo_governance():
    """Demo: Governance and policies"""
    print("\n=== Demo: Governance ===")
    
    # Create governance engine
    governance = GovernanceEngine()
    
    # Create policies
    action_policy = governance.create_action_policy(
        name="Safe Actions",
        denied_actions=["delete", "format"],
        priority=10,
    )
    governance.register_policy(action_policy)
    
    resource_policy = governance.create_resource_policy(
        name="Resource Limits",
        max_tokens=10000,
        max_api_calls=100,
    )
    governance.register_policy(resource_policy)
    
    print(f"Registered {len(governance.policies)} policies")
    
    # Create agent
    umb = UMBAdapter(backend="simple")
    agent = Agent(name="TestAgent", memory_ref=umb)
    
    # Check policy
    decision = await governance.check(
        agent_id=agent.id,
        action="execute",
        context={"task": {"type": "delete"}, "agent": agent}
    )
    
    print(f"Policy check for 'delete' action: {decision.allowed}")
    print(f"Reason: {decision.reason}")


async def demo_dmsg():
    """Demo: DMSG (MCP Skill Graph)"""
    print("\n=== Demo: DMSG (MCP Skill Graph) ===")
    
    # Create registry
    registry = MCPRegistry()
    
    # Register file MCP
    file_mcp = FileMCPConnector()
    await file_mcp.connect()
    mcp_id = registry.register(file_mcp.to_mcp_metadata())
    print(f"Registered MCP: {file_mcp.name} (ID: {mcp_id})")
    
    # List skills
    skills = registry.list_all_skills()
    print(f"Available skills: {skills}")
    
    # Find path
    pathfinder = Pathfinder(registry)
    path = pathfinder.find_path(["read_file", "write_file"])
    
    if path:
        print(f"\nFound path with {len(path.steps)} steps:")
        for step in path.steps:
            print(f"  - {step['skill']} via {step['mcp_name']}")
        print(f"Total cost: {path.total_cost:.2f}")
        print(f"Total latency: {path.total_latency:.2f}s")
        print(f"Confidence: {path.confidence:.2f}")


async def demo_composite_agent():
    """Demo: Composite agents (role merging)"""
    print("\n=== Demo: Composite Agent ===")
    
    umb = UMBAdapter(backend="simple")
    
    # Create agents
    agent1 = Agent(name="Coder", skills=["python", "api"], memory_ref=umb)
    agent2 = Agent(name="Tester", skills=["testing", "qa"], memory_ref=umb)
    agent3 = Agent(name="Designer", skills=["design", "ui"], memory_ref=umb)
    
    # Merge agents
    composite = agent1.merge_with([agent2, agent3], merge_policy="union")
    
    print(f"Created composite agent: {composite.name}")
    print(f"Combined skills: {composite.skills}")
    print(f"Source agents: {len(composite.source_agents)}")
    
    # Execute with composite
    task = {
        "id": "task1",
        "description": "Build and test a feature",
        "required_skills": ["python", "testing"],
    }
    
    result = await composite.execute(task)
    print(f"Composite execution: {result['success']}")


async def main():
    """Run all demos"""
    print("=" * 60)
    print("AgentOS Framework Demo")
    print("=" * 60)
    
    await demo_basic_agent()
    await demo_squad()
    await demo_planning()
    await demo_routing()
    await demo_governance()
    await demo_dmsg()
    await demo_composite_agent()
    
    print("\n" + "=" * 60)
    print("Demo complete!")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())

