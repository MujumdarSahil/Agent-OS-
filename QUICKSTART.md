# AgentOS Quick Start Guide

## Installation

1. Clone or navigate to the AgentOS directory
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Running the Demo

```bash
python agentos/demo.py
```

Or using the CLI:

```bash
python agentos/app.py demo
```

## Basic Usage Examples

### 1. Create an Agent

```python
from agentos.core.agent import Agent
from agentos.core.umb_adapter import UMBAdapter

# Create memory bus
umb = UMBAdapter(backend="simple")

# Create agent with skills
agent = Agent(
    name="Developer",
    skills=["python", "api", "testing"],
    memory_ref=umb,
)

# Plan a task
task = {"id": "task1", "description": "Create a REST API endpoint"}
plan = await agent.plan(task)

# Execute the task
result = await agent.execute(plan["subtasks"][0])
print(result)
```

### 2. Create a Squad

```python
from agentos.core.squad import Squad, SquadRole

# Create squad
squad = Squad(name="Development Team", shared_memory_ref=umb)

# Add agents with roles
commander = Agent(name="Team Lead", skills=["planning", "coordination"])
developer = Agent(name="Backend Dev", skills=["python", "api"])
tester = Agent(name="QA Engineer", skills=["testing", "qa"])

squad.add_agent(commander, SquadRole.COMMANDER)
squad.add_agent(developer, SquadRole.WORKER)
squad.add_agent(tester, SquadRole.WORKER)

# Create and start a mission
mission = squad.create_mission(
    goal="Build a microservice",
    description="Create a FastAPI microservice with authentication"
)

await squad.start_mission(mission.id)
```

### 3. Use Planning (MAGP)

```python
from agentos.core.planner import Planner

planner = Planner()

# Create a task graph from a goal
goal = "Build and deploy a web application"
graph = planner.create_graph(goal)

print(f"Created {len(graph.nodes)} tasks:")
for node in graph.nodes:
    print(f"  - {node.description}")

# Get tasks ready to execute
ready_tasks = graph.get_ready_tasks()
print(f"\n{len(ready_tasks)} tasks ready to execute")
```

### 4. Route Tasks (DMARP)

```python
from agentos.core.router import TaskRouter, AssignmentStrategy

# Create router
router = TaskRouter(strategy=AssignmentStrategy.HYBRID)

# Assign tasks to agents
plan = router.assign(graph, [commander, developer, tester])

for task_id, agent_id in plan.assignments.items():
    agent = next(a for a in [commander, developer, tester] if a.id == agent_id)
    print(f"Task {task_id} -> {agent.name}")
```

### 5. Add Governance

```python
from agentos.core.governance import GovernanceEngine

governance = GovernanceEngine()

# Create a policy that denies dangerous actions
policy = governance.create_action_policy(
    name="Safety Policy",
    denied_actions=["delete", "format", "rm -rf"],
    priority=10,
)
governance.register_policy(policy)

# Check before execution
decision = await governance.check(
    agent_id=developer.id,
    action="execute",
    context={"task": {"type": "delete"}, "agent": developer}
)

if not decision.allowed:
    print(f"Action denied: {decision.reason}")
```

### 6. Use MCP Skills (DMSG)

```python
from agentos.dmsg.registry import MCPRegistry
from agentos.dmsg.pathfinder import Pathfinder
from agentos.mcp_connectors.base_mcp import FileMCPConnector

# Create registry
registry = MCPRegistry()

# Register an MCP connector
file_mcp = FileMCPConnector()
await file_mcp.connect()
registry.register(file_mcp.to_mcp_metadata())

# Find a path through skills
pathfinder = Pathfinder(registry)
path = pathfinder.find_path(["read_file", "write_file"])

if path:
    print(f"Found path with {len(path.steps)} steps")
    for step in path.steps:
        print(f"  - {step['skill']} via {step['mcp_name']}")
```

### 7. Merge Agents

```python
# Create composite agent from multiple agents
composite = developer.merge_with(
    [tester],
    merge_policy="union",
    temporary=True
)

print(f"Composite agent: {composite.name}")
print(f"Combined skills: {composite.skills}")

# Execute with merged capabilities
task = {
    "id": "task1",
    "description": "Code and test a feature",
    "required_skills": ["python", "testing"]
}
result = await composite.execute(task)
```

## Running Tests

```bash
pytest agentos/tests/
```

## Next Steps

- Read the full [README.md](README.md) for detailed documentation
- Explore the `agentos/demo.py` file for more examples
- Check `agentos/tests/` for usage patterns
- Customize MCP connectors in `agentos/mcp_connectors/`

## Architecture Overview

```
AgentOS
├── Core: Agents, Squads, Governance, Planning, Routing
├── Memory: UMB (Unified Memory Bus) with vector search
├── Skills: DMSG (Distributed MCP Skill Graph)
├── Communication: WebSocket for real-time collaboration
└── Resources: Monitoring and adaptive behavior
```

## Key Concepts

- **Agent**: Autonomous entity with skills, memory, and execution capabilities
- **Squad**: Hierarchical team of agents (Commander → Leader → Workers)
- **Mission**: Goal-oriented task with a task graph
- **UMB**: Unified Memory Bus for semantic memory across agents
- **MAGP**: Multi-Agent Planning Graph for task decomposition
- **DMARP**: Dynamic Multi-Agent Routing Protocol for task assignment
- **DMSG**: Distributed MCP Skill Graph for skill discovery
- **Governance**: Policy engine for safety and resource control

