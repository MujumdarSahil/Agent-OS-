# AgentOS Framework

[![CI Build Status](https://github.com/MujumdarSahil/Agent-OS-/actions/workflows/ci.yml/badge.svg)](https://github.com/MujumdarSahil/Agent-OS-/actions)
[![Coverage Status](https://img.shields.io/badge/Coverage-98%25-green.svg)](#test-coverage)

A production-grade, research-worthy, and startup-ready multi-agent framework built on top of **CrewAI**, **LangChain/LangGraph**, and **LiteLLM**. Instead of reinventing agent execution from scratch, AgentOS integrates these powerful libraries under a clean, class-based interface, supporting squads, MCP servers, distributed skill graphs, unified memory, hierarchical governance, real-time collaboration, planning graphs, role-merging, resource awareness, multi-squad federation, and agent identity.

## Features

### Core Components

- **Two-Layer Hierarchical Governance Model** (fast keyword check + optional semantic LLM-judge) for fine-grained safety policy enforcement
- **Squad Memory Sharing Network** with layered, permissioned memories: Squad, Mission, Private, Episodic, and Autobiographical
- **Real-Time Collaboration**: WebSocket streaming endpoint (`/ws/runs/{run_id}`) for multi-agent event streaming (untested via automated suites; relies on dashboard connection)
- **Multi-Agent Planning Graph (MAGP)**: Task graph construction and dependency ordering (rule-based template decomposition; dynamic negotiation and parallel execution runners are un-implemented)
- **Role-Merging**: `Agent.merge_role()` helper for combining skill lists between agents (standalone composite `HybridAgent` classes are un-implemented)
- **Resource Monitoring**: `ResourceMonitor` process monitoring for memory, CPU, token usage, and API costs (adaptive execution strategy adjustment is un-implemented)
- **Distributed MCP Skill Graph (DMSG)**: `MCPRegistry` skill registration and NetworkX shortest-path routing (untested via automated pytest suites)
- **Unified Memory Bus (UMB)**: Semantic, pluggable memory layer across agents and squads with layered permission scopes
- **Task Router (DMARP)**: Skill-match, workload-balanced, and hybrid task assignment routing (untested via automated pytest suites)
- **Multi-Squad Federation**: Sequential multi-squad pipelines with automated context injection and stage-level checkpointing/resume
- **Pre-built Templates**: Six bundled crew templates (Research, Code Review, Triage, etc.) installable via CLI (`agentos templates`) or React UI
- **Expanded Fallback Chain**: Multi-provider registry featuring **verified integration** with OpenAI, Anthropic, Gemini, Groq, OpenRouter (including Poolside Laguna S 2.1 free tier, GLM-5.2 free tier, Gemma 4 31B free tier, and Nemotron 3 Nano Omni free tier), and local Ollama. Together AI, Fireworks, DeepSeek, and Hugging Face Inference API (experimental) entries are configured in the provider registry and supported via LiteLLM routing, pending cassette/live user API key verification.
  > **Note on Laguna S 2.1 Free Tier:** Context window is capped at **262,144 tokens** on the free endpoint (NOT full 1M). Poolside's free-tier terms state inputs/outputs may be used for training; avoid sending proprietary code.
  > **Note on Vision-Capable Models:** Models such as `google/gemma-4-31b-it:free` and `nvidia/nemotron-3-nano-omni-30b-a3b-reasoning:free` support reading and analyzing image inputs (multimodal vision input). They perform image **reading/understanding only** and do NOT support image generation.
  > **Note on Hugging Face Plugin (Experimental / Untested):** Entry pattern provided for LiteLLM HF provider (`HUGGINGFACE_API_KEY` required). Unverified via VCR cassette tests until a user supplies an HF API key. Does NOT perform local model downloads or self-hosted serving.
- **Framework Extensibility**: Load and discover custom Agents, Tools, and MCP Plugins from project-local directories or third-party package entry points. See [EXTENDING.md](docs/EXTENDING.md) for details.

## 🛡️ AgentOS-SWE Extension

AgentOS includes **AgentOS-SWE**, an enterprise autonomous software verification, security intelligence, and automated repair platform built on the AgentOS framework. It provides a complete 13-stage security engineering lifecycle — from AST code graph intake to automated repair proposal generation and release readiness scoring across a single-file 29-page Streamlit dashboard.

For complete documentation, system architecture, dashboard guide, and security lifecycle details, see **[README_SWE.md](README_SWE.md)**.

## Installation

```bash
pip install -r requirements.txt
```

## Quick Start

Activate the virtual environment first before running any `agentos` or `python` commands:

**Windows:**
```bash
venv\Scripts\activate
```

**Mac/Linux:**
```bash
source venv/bin/activate
```

Create a new project and launch the dashboard:
```bash
# Create a new project
agentos new-project demo

# Launch the platform dashboard
python main.py --project demo
```

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
│   ├── federation.py  # Multi-squad federation
│   ├── router.py      # Task router (DMARP)
│   ├── planner.py     # Planner (MAGP)
│   └── umb_adapter.py # Unified Memory Bus
├── templates/         # Pre-built crew templates (.agentpack formats)
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

### Running the Full Platform (Backend + Frontend)

AgentOS includes a unified launcher that starts both the FastAPI backend and the React frontend in a single command, auto-installing frontend dependencies.

Run python main.py from inside a project directory, or use python main.py --project <path>. The dashboard requires an open project to display agents, crews, and missions.

```bash
# Start the platform in development mode
python main.py --project demo

# Or start in production mode (single process serving both API and static frontend)
python main.py --project demo --prod
```

### Manual Execution

If you prefer to run the components in separate terminals:

```bash
# Start the FastAPI backend
python -m uvicorn agentos.server.app:create_app --factory --reload --port 8000

# Start the React frontend
cd agentos/frontend
npm install
npm run dev -- --port 5173
```

# Run cybersecurity squad example CLI script
python agentos/examples/sample_cybersecurity_squad_run.py

### MCP Demos (Teaching Examples)
AgentOS includes two minimal teaching examples to show how agents, tools, and MCP servers connect:
- [Demo 1: Custom Local notes.json MCP Server](examples/mcp_demos/local_notes_server/) — stdio subprocess transport notes manager.
- [Demo 2: External Context7 Documentation MCP Server](examples/mcp_demos/context7_docs_lookup/) — remote, read-only documentation lookups.

See [SECURITY.md](docs/SECURITY.md), [ETHICS.md](docs/ETHICS.md), and [PHASE3_LIMITATIONS.md](docs/PHASE3_LIMITATIONS.md) for safety policies, ethics guidelines, and detailed framework specifications.

## ⚠️ Known Limitations

- **Provider Verification Status**: Multi-provider fallback chain has verified VCR cassette/mock test coverage for OpenAI, Anthropic, Gemini, Groq, OpenRouter, and Ollama. Together AI, Fireworks, DeepSeek, and Hugging Face Inference API entries are defined in `provider_registry.py` and supported via LiteLLM routing, but are marked as pending live API / VCR cassette verification until a user configures their respective API keys.
- **Vector Store Database Drivers**: `UMBAdapter` supports vector memory integration via pluggable backends. Standard unit tests execute against in-memory (simple/FAISS) backends; external vector engines (ChromaDB, PGVector) require external database services and driver installation in host environments.
- **Local Ollama Probe Behavior**: Connectivity probe `check_ollama_reachable()` performs non-blocking HTTP probes (`http://localhost:11434/api/tags`) with a 1.0s timeout and non-fatal logging. When Ollama is offline, calls gracefully fall back to alternative providers in the fallback chain.
- **WebSocket Streaming**: WebSocket endpoint (`/ws/runs/{run_id}`) and `WebSocketServer` exist for execution event streaming, but lack automated unit/integration test coverage in pytest; operation relies on manual dashboard connection.
- **MAGP Planning Scope**: `Planner` builds DAG subtask graphs and dependency ordering, but LLM-based task decomposition and dynamic agent negotiation/parallelization protocols are un-implemented (uses rule-based template decomposition and static task graphs).
- **Role-Merging Scope**: Role-merging is implemented via `Agent.merge_role()` which combines skill lists between agents; standalone composite `HybridAgent` classes and memory merging are un-implemented.
- **Resource Monitoring Scope**: `ResourceMonitor` collects process memory, CPU utilization, wall-time, token usage, and API costs, but adaptive agent execution strategies (automatically modifying agent behavior when thresholds are exceeded) are un-implemented and untested.
- **DMSG Test Coverage**: `MCPRegistry` and NetworkX-based `Pathfinder` exist for registering MCP tools and finding skill paths, but lack automated pytest test suites.
- **DMARP Task Router Test Coverage**: `TaskRouter` implements skill-matching, workload-balanced, and hybrid task assignment routing algorithms, but lacks a dedicated automated pytest test suite.

## Test Coverage

We maintain a high standard of coverage across our core orchestration and LLM integration layers:

| Module / File | Coverage |
| :--- | :---: |
| `agentos/core/checkpoint.py` | 94% |
| `agentos/core/governance.py` | 91% |
| `agentos/core/squad.py` | 89% |
| `agentos/core/federation.py` | 88% |
| `agentos/core/umb_adapter.py` | 98% |
| `agentos/llm/llm_client.py` | 80% |
| `agentos/llm/router_factory.py` | 80% |
| `agentos/llm/provider_registry.py` | 100% |

To run the coverage test suite locally, use:
```bash
pytest --cov=agentos --cov-report=term-missing
```

## License

MIT

## Contributing

Contributions welcome! Please see CONTRIBUTING.md for guidelines.

