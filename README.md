# AgentOS Framework

A production-grade, research-worthy, and startup-ready multi-agent framework that supports squads, MCP servers, distributed skill graphs, unified memory, hierarchical governance, real-time collaboration, planning graphs, role-merging, resource awareness, multi-squad federation, and agent identity.

## Features

### Core Components

- **Hierarchical Governance Model** (Commander → Squad Leader → Worker → Reviewer) for authority and policies
- **Squad Memory Sharing Network** with layered, permissioned memories: Squad, Mission, Private, Episodic, and Autobiographical
- **Real-Time Collaboration** using WebSockets for low-latency multi-agent interactions
- **Multi-Agent Planning Graph (MAGP)** that models tasks/subtasks as graphs and supports negotiation and parallelization
- **Role-Merging & Hybrid Agents** to temporarily create composite agents combining skills and memory
- **Resource-Aware Agents** that monitor CPU, memory, API cost, tokens, and wall-time and adapt strategies
- **Distributed MCP Skill Graph (DMSG)**: MCP servers as nodes, skills as edges, path-finding for skills
- **Unified Memory Bus (UMB)**: semantic, pluggable memory layer across agents and squads
- **Task Router (DMARP)**: Dynamic Multi-Agent Routing Protocol for intelligent task assignment

## Installation

```bash
pip install -r requirements.txt
```

## Quick Start

### Basic Agent

```python
from agentos.core.agent import Agent
from agentos.core.umb_adapter import UMBAdapter

# Create memory bus
umb = UMBAdapter(backend="simple")

# Create agent
agent = Agent(
    name="Alice",
    skills=["coding", "testing"],
    memory_ref=umb,
)

# Plan and execute
task = {"id": "task1", "description": "Write a function"}
plan = await agent.plan(task)
result = await agent.execute(plan["subtasks"][0])
```

### Squad

```python
from agentos.core.squad import Squad, SquadRole

# Create squad
squad = Squad(name="Dev Squad", shared_memory_ref=umb)

# Add agents
commander = Agent(name="Commander", skills=["planning"])
developer = Agent(name="Developer", skills=["coding"])

squad.add_agent(commander, SquadRole.COMMANDER)
squad.add_agent(developer, SquadRole.WORKER)

# Create and start mission
mission = squad.create_mission(goal="Build an API")
await squad.start_mission(mission.id)
```

### Planning and Routing

```python
from agentos.core.planner import Planner
from agentos.core.router import TaskRouter, AssignmentStrategy

# Create task graph
planner = Planner()
graph = planner.create_graph("Build a web app")

# Route tasks to agents
router = TaskRouter(strategy=AssignmentStrategy.HYBRID)
plan = router.assign(graph, agents)
```

### Governance

```python
from agentos.core.governance import GovernanceEngine

governance = GovernanceEngine()

# Create policy
policy = governance.create_action_policy(
    name="Safe Actions",
    denied_actions=["delete", "format"],
)
governance.register_policy(policy)

# Check policy
decision = await governance.check(
    agent_id=agent.id,
    action="execute",
    context={"task": task, "agent": agent}
)
```

## Project Structure

```
agentos/
├── core/              # Core components
│   ├── agent.py       # Agent class
│   ├── squad.py       # Squad class
│   ├── governance.py  # Policy engine
│   ├── router.py      # Task router (DMARP)
│   ├── planner.py     # Planner (MAGP)
│   └── umb_adapter.py # Unified Memory Bus
├── dmsg/              # Distributed MCP Skill Graph
│   ├── registry.py    # MCP registry
│   └── pathfinder.py  # Skill pathfinder
├── mcp_connectors/    # MCP connectors
├── comms/             # Communication layer
├── tests/             # Tests
└── demo.py            # Demo script
```

## Running the Demo

```bash
python agentos/demo.py
```

## Running Tests

```bash
pytest agentos/tests/
```

## Architecture

AgentOS follows a modular architecture:

1. **Core Layer**: Agents, Squads, Governance, Planning, Routing
2. **Memory Layer**: UMB adapter with pluggable backends (FAISS, Chroma, PG vector)
3. **Skill Layer**: DMSG for MCP server and skill management
4. **Communication Layer**: WebSocket server for real-time collaboration
5. **Resource Layer**: Monitoring and adaptive behavior

## Research Components

- **DMARP**: Dynamic Multi-Agent Routing Protocol
- **DMSG**: Distributed MCP Skill Graph
- **UMB**: Unified Memory Bus with multi-layer memory

## Cybersecurity Extensions

AgentOS includes comprehensive cybersecurity capabilities:

### Security MCP Servers (`mcp/security/`)

- **PAT-MCP**: Password audit tool with hash identification, strength benchmarking, policy evaluation
- **Network Monitor MCP**: Network monitoring with port scan detection, anomaly detection, incident classification
- **System Audit MCP**: System configuration auditing, firewall validation, hardening recommendations

### Security Agents (`agents/`)

- **SecurityAgent**: Specialized agent with roles (auditor, monitor, analyst, policy-advisor)
- **ScriptAuthorAgent**: Generates defensive/educational security scripts only

### Cybersecurity Tools (`mcp/security/tools/`)

- **LogAnalyzer**: Defensive log analysis for security events
- **FirewallAudit**: Firewall rule auditing
- **PermissionAudit**: User permission auditing
- **SystemHardening**: Hardening recommendations
- **NetworkMetadataInspector**: Network metadata analysis
- **SIEMScriptBuilder**: SIEM integration script generation

### Security Missions (`missions/security_missions.py`)

- Enterprise Password Audit Mission
- Network Health Check Mission
- System Hardening Mission
- Log Threat Analysis Mission
- Firewall Config Audit Mission
- User & Permission Audit Mission

**Safety Features:**
- ✅ No password cracking - only policy auditing
- ✅ No exploitation - all operations are defensive
- ✅ Hash-only inputs - never cleartext passwords
- ✅ Read-only operations - no system modifications
- ✅ Governance enforcement - all operations checked
- ✅ Safety metadata - all outputs include safety_metadata

## ML & Training Capabilities

### ModelHub (`modelhub/`)

- **Multi-backend LLM Support**: OpenAI, Claude, local models
- **Training Orchestrator**: SFT, LoRA, QLoRA, quantization jobs
- **Safety Frameworks**: Constitutional AI, model cascades, verifier models
- **Performance**: Speculative decoding, caching, workload scheduling

### RAG/CAG Integration (`core/`)

- **RAG Manager**: Retrieval-augmented generation with UMB integration
- **CAG**: Context-augmented generation
- **Retrieval Adapters**: FAISS, ChromaDB, PGVector
- **Hybrid Search**: Vector + keyword search
- **KG Integration**: Knowledge graph RAG hooks

### Agentic Patterns (`core/agent_strategies/`)

- **ReAct Strategy**: Reasoning and Acting loop
- **PAL Strategy**: Program-Aided Language model
- **Plan-Act-Reflect**: Planning and reflection cycles
- **Tree of Thoughts**: Multiple reasoning path exploration

## UI

### FastAPI Backend (`ui/backend/`)

- REST API for models, training, tools
- Governance enforcement on all endpoints
- WebSocket support for real-time updates

### React Frontend (`ui/frontend/`)

- Models Dashboard
- Training Job Monitor
- Tools & MCPs page
- Missions page
- Safety Monitor

## Running Examples

```bash
# Run cybersecurity squad example
python agentos/examples/sample_cybersecurity_squad_run.py

# Start FastAPI backend
cd agentos/ui/backend
uvicorn main:app --reload

# Start React frontend
cd agentos/ui/frontend
npm install
npm run dev
```

See [SECURITY.md](SECURITY.md) and [ETHICS.md](ETHICS.md) for safety and ethics policies.

## License

MIT

## Contributing

Contributions welcome! Please see CONTRIBUTING.md for guidelines.

