# AgentOS Framework

[![CI Build Status](https://github.com/MujumdarSahil/Agent-OS-/actions/workflows/ci.yml/badge.svg)](https://github.com/MujumdarSahil/Agent-OS-/actions)
[![Coverage Status](https://img.shields.io/badge/Coverage-48%25-yellow.svg)](#test-coverage)

AgentOS lets you build AI-agent workflows ("flows") in a visual builder and run them safely. A flow starts from a manual run, a signed webhook or a schedule; it can use CrewAI agents, HTTP calls, conditions, waits, sub-flows and human approvals; and it sends results through actions such as email. Every value carries a security label, so data from webhooks, web pages or tools cannot choose who receives an email, which URL is called or whether a destructive action runs: unsafe flows are refused at publish and blocked again at runtime. LLM calls go through **LiteLLM** with multiple providers, a fallback order and an encrypted key vault. Status of each feature (verified / experimental / planned) is in [What AgentOS can do, in plain English](#what-agentos-can-do-in-plain-english). The v1 Python API (agents, squads, governance, planner) remains available; its older extras (skill graphs, role-merging/composite agents, planning graphs with LLM decomposition, resource monitoring, multi-squad federation, LangGraph hooks) are **v1 experimental**, partly stubs, and not part of the 2.0 flow engine.

## Getting started

This walks you from a clean machine to the visual flow builder running in **MOCK mode**: no API keys,
no cost, a simulated LLM, and emails that are never actually sent.

> Verified from a fresh clone on Windows 11 / PowerShell 5.1 (see `docs/evidence/raw/2.3-cp3-readme-quickstart.txt`).
> The macOS/Linux commands are the direct equivalents but were not run on macOS/Linux in that check.

### 1. Prerequisites

| Tool | Version | Needed for |
|---|---|---|
| Python | 3.11 | backend (`requires-python >= 3.11`) |
| Node.js | 20.19+ or 22.12+ (required by Vite 8) | web UI |
| Git | any recent | cloning |
| Docker Desktop | any recent | **only** Platform mode (MongoDB/Redis) |

### 2. Get the code and install

Windows PowerShell:
```powershell
git clone https://github.com/MujumdarSahil/Agent-OS-.git agentos
cd agentos
git checkout 2.0
python -m venv venv
.\venv\Scripts\python.exe -m pip install --upgrade pip
.\venv\Scripts\python.exe -m pip install -e .
cd ui
npm install
cd ..
```

macOS / Linux:
```bash
git clone https://github.com/MujumdarSahil/Agent-OS-.git agentos
cd agentos
git checkout 2.0
python3.11 -m venv venv
./venv/bin/python -m pip install --upgrade pip
./venv/bin/python -m pip install -e .
cd ui && npm install && cd ..
```

### 3. Quick start in MOCK mode (no API keys, no cost)

Use two terminals, both starting in the `agentos` folder.

**Terminal 1: backend.** These variables turn on the mock LLM, let runs started from the UI
actually execute (in-process worker), and trust `corp.local` as an internal email domain for the
examples (no domain is trusted by default).

Windows PowerShell:
```powershell
$env:AGENTOS_MOCK_LLM = "1"
$env:AGENTOS_INPROCESS_WORKER = "1"
$env:AGENTOS_INTERNAL_DOMAINS = "corp.local"
$env:AGENTOS_PROJECT = "demo"
.\venv\Scripts\python.exe -m uvicorn agentos_server.app:create_app --factory --host 127.0.0.1 --port 8000
```

macOS / Linux:
```bash
export AGENTOS_MOCK_LLM=1 AGENTOS_INPROCESS_WORKER=1 AGENTOS_INTERNAL_DOMAINS=corp.local AGENTOS_PROJECT=demo
./venv/bin/python -m uvicorn agentos_server.app:create_app --factory --host 127.0.0.1 --port 8000
```

**Terminal 2: web UI.**
```bash
cd ui
npm run dev
```

**Open the app.** The backend prints a box with `One-Time UI Access Link: http://localhost:5173/#token=…`.
Open that link: the token is stored for the browser session and removed from the address bar. The
same token is saved in `~/.agentos/api.token` if you need to paste it into the login screen.

**First thing to try:** build and publish the use case 01 flow in the visual builder (**Flows → New
flow**). The step-by-step walkthrough is in
[examples/usecases/05-visual-builder/README.md](examples/usecases/05-visual-builder/README.md):
publish the safe version (recipient pinned), then remove the pinned recipient and watch publish refuse
the unsafe version and highlight the path.

### 4. Using a real model

1. Open **Providers & Vault** in the UI and add the API key for your provider. Keys are stored
   encrypted in the vault, and the API never returns them in plain text.
2. Stop the backend, start it again **without** `AGENTOS_MOCK_LLM` (PowerShell:
   `Remove-Item Env:AGENTOS_MOCK_LLM`; macOS/Linux: `unset AGENTOS_MOCK_LLM`).
3. Real model calls cost money with your provider. Not covered by the automated checks.

### 5. Platform mode (optional: MongoDB + Redis)

Standalone mode (above) keeps everything in files and in memory. Platform mode stores data in
MongoDB and uses Redis for the queue. Start Docker Desktop first, then:

```bash
./venv/bin/python -m pip install -e ".[platform]"     # Windows: .\venv\Scripts\python.exe -m pip install -e ".[platform]"
sh docker/mongo-init.sh                               # Windows: pwsh docker/mongo-init.ps1 ; prints AGENTOS_MONGO_URI
docker compose -f docker/compose.mongo.yml up -d --wait
sh docker/redis-init.sh                               # Windows: pwsh docker/redis-init.ps1 ; prints AGENTOS_REDIS_URI
docker compose -f docker/compose.redis.yml up -d --wait
```
Set `AGENTOS_MONGO_URI` and `AGENTOS_REDIS_URI` to the printed values (they contain generated
passwords: keep them out of files you commit), then start the backend as in step 3.

> These are the scripts and compose files the CI `mongo-live` and `redis-live` jobs use; they were not
> re-run for this README because Docker Desktop was not running.

### 6. Stopping everything

- Press **Ctrl+C** in both terminals.
- Platform mode: `docker compose -f docker/compose.mongo.yml down` and
  `docker compose -f docker/compose.redis.yml down` (data is kept in Docker volumes).

### 7. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `401 Unauthorized` / login screen keeps appearing | The token is missing or old. Open the newest one-time link from the backend output, or paste the contents of `~/.agentos/api.token`. |
| `Invalid Host header` | The API only answers on `localhost` / `127.0.0.1` (DNS-rebinding protection). Open `http://localhost:5173`, not a LAN IP or another hostname. |
| Runs stay `queued` forever | No worker is running. Start the backend with `AGENTOS_INPROCESS_WORKER=1`. |
| An email step is refused with "untrusted body … external recipient" | No internal domain is trusted by default. Set `AGENTOS_INTERNAL_DOMAINS` (or `security.internal_domains` in `agentos.config.yaml`). |
| `docker` commands fail / `--wait` never finishes | Docker Desktop is not running. Start it and check with `docker ps`. |
| `npm run dev` fails with "Cannot find native binding" | A broken `node_modules`. Delete `ui/node_modules` and run `npm install` again. |

## What AgentOS can do, in plain English

Status badges: **Works today (verified)** = covered by automated tests that run in CI in MOCK mode
(simulated LLM, fake network, no real emails); **Experimental** = present but partial or not fully
tested; **Planned** = not built yet. "Verified" never means tested against real paid providers.

**Flows and the visual builder** — *Works today (verified)*. You draw a workflow in the browser: a
trigger, agents, HTTP calls, conditions, approvals and actions such as sending an email, joined by
arrows that say which output feeds which input. Save it, then publish it as a fixed version. Use it
when you want an automation that people can read and review instead of a script.
Use cases: [05 visual builder](examples/usecases/05-visual-builder/README.md),
[06 HTTP and branching](examples/usecases/06-http-and-branching/README.md).

**Branching, waiting, sub-flows and error handling** — *Works today (verified)*. A flow can take
an if/else branch, join parallel branches, pause for a while and continue later, call another
published flow, and send a failed step to an error handler instead of failing the whole run.
Use it to model real processes ("if the page reports an incident, page on-call; otherwise do nothing").
Use case: [06 HTTP and branching](examples/usecases/06-http-and-branching/README.md).

**Calling web APIs safely** — *Works today (verified)*. The HTTP step can fetch pages and call APIs,
but it refuses internal and cloud-metadata addresses (SSRF), re-checks every redirect, caps response
size and time, and only lets outside data go to hosts an admin has allowlisted. Use it to pull data
into a flow without opening a door into your network.
Use case: [06 HTTP and branching](examples/usecases/06-http-and-branching/README.md).

**Triggers: webhooks and schedules** — *Works today (verified)*. Flows can start from a signed
webhook (with replay protection) or on a cron schedule. Use it to react to events from other systems
or to run something every morning.
Use case: [04 webhook trigger](examples/usecases/04-webhook-trigger/README.md); schedules are covered by
`agentos/tests/test_scheduler_2_2.py`.

**Agents and tools** — *Works today (verified) for agents calling built-in tools; Experimental for
MCP servers and stored custom tool code*. An agent node runs a CrewAI agent, but every tool call it
makes goes through an AgentOS proxy that checks it first. Use it when a step needs judgement, such as
summarising a ticket.
Use case: [01 email summary and exfiltration attempt](examples/usecases/01-email-summary-exfil/README.md).

**Providers, fallback and the vault** — *Works today (verified with mocked providers)*. You can
configure several LLM providers, set an order to fall back on when one fails, and pick a model per
node. API keys are stored encrypted and are never shown back. Use it to avoid depending on a single
provider. Real provider calls are not part of the automated checks.
Use case: [02 provider fallback](examples/usecases/02-provider-fallback/README.md).

**Security labels and blocked attacks** — *Works today (verified)*. Every value remembers where it
came from and whether it can be trusted. Data from webhooks, web pages, emails and tools is
untrusted, and it cannot choose who receives an email, which URL is called, or whether a destructive
action runs. Unsafe flows are refused when you publish and blocked again while running.
Use cases: [01](examples/usecases/01-email-summary-exfil/README.md),
[04](examples/usecases/04-webhook-trigger/README.md),
[06](examples/usecases/06-http-and-branching/README.md).

**Approvals** — *Works today (verified)*. A flow can stop and wait for a person to approve the exact
values that are about to be sent, with untrusted values clearly marked. Rejecting stops the run
without sending anything.
Use case: [05 visual builder](examples/usecases/05-visual-builder/README.md).

**Runs and the live view** — *Works today (verified)*. Each run shows live progress per step, a full
event history, and for anything blocked, the reason and where the data came from. The view reconnects
without losing events. Runs are queued and executed by a worker (in-process in Standalone mode).
Use cases: [03 queue and worker](examples/usecases/03-flow-queue-worker/README.md),
[05 visual builder](examples/usecases/05-visual-builder/README.md).

**Packs** — *Experimental (v1 agent/tool packaging via `agentos pack`); Planned (2.0 packs carrying
flows, prompts and policies)*. Packs will let you share a ready-made automation and install it with
one command.

## Features

### Core Components

- **Two-Layer Hierarchical Governance Model** (fast keyword check + optional semantic LLM-judge) for fine-grained safety policy enforcement
- **Squad Memory Sharing Network** with layered, permissioned memories: Squad, Mission, Private, Episodic, and Autobiographical
- **Real-Time Collaboration**: WebSocket streaming endpoint (`/ws/runs/{run_id}`) for multi-agent event streaming (untested via automated suites; relies on dashboard connection)
- **Multi-Agent Planning Graph (MAGP)**: Task graph construction and dependency ordering (rule-based template decomposition; dynamic negotiation and parallel execution runners are un-implemented)
- **Role-Merging**: `Agent.merge_role()` helper for combining skill lists between agents (standalone composite `HybridAgent` classes are un-implemented)
- **Distributed MCP Skill Graph (DMSG)**: `MCPRegistry` skill registration and NetworkX shortest-path routing (untested via automated pytest suites)
- **Unified Memory Bus (UMB)**: Semantic, pluggable memory layer across agents and squads with layered permission scopes
- **Task Router (DMARP)**: Skill-match, workload-balanced, and hybrid task assignment routing (untested via automated pytest suites)
- **Multi-Squad Federation**: Sequential multi-squad pipelines with automated context injection and stage-level checkpointing/resume
- **Pre-built Templates**: Six bundled crew templates (Research, Code Review, Triage, etc.) installable via CLI (`agentos templates`) or React UI
- **Expanded Fallback Chain**: Multi-provider registry featuring **verified integration** with OpenAI, Anthropic, Gemini, Groq, OpenRouter (including Poolside Laguna S 2.1 free tier, GLM-5.2 free tier, and Gemma 4 31B free tier), and local Ollama. Together AI, Fireworks, DeepSeek, and Hugging Face Inference API (experimental) entries are configured in the provider registry and supported via LiteLLM routing, pending cassette/live user API key verification. For **OpenRouter Nemotron 3 Nano Omni free tier**: multimodal vision input is verified via recorded VCR cassette (`test_nemotron_3_nano_omni_vision`), but text-only completion (`openrouter_nemotron_3_nano_omni_free`) is unverified (captured upstream OpenRouter 504 Gateway Timeout / 400 degraded errors during recording; skipped pending clean live recording).
  > **Note on Laguna S 2.1 Free Tier:** Context window is capped at **262,144 tokens** on the free endpoint (NOT full 1M). Poolside's free-tier terms state inputs/outputs may be used for training; avoid sending proprietary code.
  > **Note on GLM-5.2 Free Tier (OpenRouter):** Free endpoint subject to daily rate limits. OpenRouter and upstream terms specify prompts and completions may be logged or used for model training; **do not send data labeled `secret` or sensitive internal payloads**.
  > **Note on Z.ai Models (`zai_glm_4_7_flash`, `zai_glm_5_3`):** International API platform integration (`https://api.z.ai/api/paas/v4`) using LiteLLM `zai/` routing and `ZAI_API_KEY` credentials. Entries remain labeled UNVERIFIED until live recorded cassettes are captured.
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
python -m uvicorn agentos_server.app:create_app --factory --reload --port 8000

# Start the React frontend
cd ui
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

## ⚠️ Known Limitations & Claims Audit

- **Provider Verification Status**: Multi-provider fallback chain has verified VCR cassette/mock test coverage for OpenAI, Anthropic, Gemini, Groq, OpenRouter (Poolside Laguna S 2.1, GLM-5.2, Gemma 4 31B), and Ollama. Together AI, Fireworks, DeepSeek, Hugging Face Inference API, and new Z.ai entries (`zai_glm_4_7_flash`, `zai_glm_5_3`) are configured in `provider_registry.py` and supported via LiteLLM routing, but are marked as UNVERIFIED pending live API / VCR cassette verification. For **OpenRouter Nemotron 3 Nano Omni**: multimodal vision processing is verified (`test_nemotron_3_nano_omni_vision` passes via offline cassette), while text completion (`openrouter_nemotron_3_nano_omni_free`) is unverified due to upstream 504 Gateway Timeout / 400 degraded errors recorded in its cassette, and is skipped pending fresh recording.
- **UMB Vector Backends**: `UMBAdapter` requested backends `faiss`, `chroma`, and `pgvector` are un-implemented and emit explicit `UserWarning` / `logger.warning` events while safely falling back to the built-in in-memory `SimpleVectorStore`.
- **LangGraph Integration**: Agent execution is built on CrewAI and LiteLLM; LangGraph node generation (`Agent.to_langgraph_node()`) is an experimental stub raising `NotImplementedError`, scheduled for evaluation in Phase 1.5 flow engine spike.
- **Model Cascades & Safety Verifiers**: `ModelCascade` (`modelhub/safety/model_cascade.py`) is an un-tested stub returning formatted string drafts without executing real LLM calls. `VerifierModel` implements regex/keyword checks for toxicity/policy violations; hallucination verification is a hardcoded score stub.
- **Multi-Squad Federation**: `FederatedMission` implements ordered sequential handoffs (Squad A → Squad B) via context string injection with stage-level checkpointing; parallel squad execution, cross-squad shared memory, and dynamic negotiation protocols are un-implemented.
- **DMSG MCP Registry**: `MCPRegistry` (`agentos/dmsg/registry.py`) maintains an in-memory dictionary of metadata nodes and auto-registers local mock security MCP tools; it does not connect to external servers over STDIO/SSE directly.
- **Squad Memory Layers**: `Episodic` and `Autobiographical` exist solely as enum values in `MemoryPermission`; there is no episodic consolidation, reflection, or decay engine. `Squad.shared_memory_ref` is stored on the instance but is not accessed by `run_mission()`.
- **Local Ollama Probe Behavior**: Connectivity probe `check_ollama_reachable()` performs non-blocking HTTP probes (`http://localhost:11434/api/tags`) with a 1.0s timeout and non-fatal logging. When Ollama is offline, calls gracefully fall back to alternative providers in the fallback chain.
- **WebSocket Streaming**: WebSocket endpoint (`/ws/runs/{run_id}`) and `WebSocketServer` exist for execution event streaming, but lack automated unit/integration test coverage in pytest; operation relies on manual dashboard connection.
- **MAGP Planning Scope**: `Planner` builds DAG subtask graphs and dependency ordering, but LLM-based task decomposition and dynamic agent negotiation/parallelization protocols are un-implemented (uses rule-based template decomposition and static task graphs).
- **Role-Merging Scope**: Role-merging is implemented via `Agent.merge_role()` which combines skill lists between agents; standalone composite `HybridAgent` classes and memory merging are un-implemented.
- **Task Router (DMARP) Test Coverage**: `TaskRouter` implements skill-matching, workload-balanced, and hybrid task assignment routing algorithms, but lacks a dedicated automated pytest test suite.

## Test Coverage

Overall framework test coverage: **49%** (measured across 11,110 statements by `pytest --cov=agentos` offline with mock LLM across `agentos/tests`, `agentos/server/tests`, and `agentos/packaging/tests`). Core orchestration, state, and provider layers maintain high verification:

| Module / File | Statements | Missing | Coverage | Status |
| :--- | :---: | :---: | :---: | :---: |
| `agentos/core/checkpoint.py` | 70 | 4 | **94%** | Verified (Unit + Characterization) |
| `agentos/core/governance.py` | 299 | 27 | **91%** | Verified (Unit + LLM Judge) |
| `agentos/core/agent.py` | 96 | 10 | **90%** | Verified (Unit + CrewAI Mock) |
| `agentos/core/squad.py` | 210 | 23 | **89%** | Verified (Sequential Execution) |
| `agentos/core/federation.py` | 104 | 13 | **88%** | Verified (Sequential Handoff) |
| `agentos/core/umb_adapter.py` | 158 | 3 | **98%** | Verified (SimpleVectorStore + Fallback Warning) |
| `agentos/core/config_models.py` | 33 | 0 | **100%** | Verified (Pydantic Validation) |
| `agentos/llm/llm_client.py` | 184 | 8 | **96%** | Verified (Fallback & Mock Routing) |
| `agentos/llm/router_factory.py` | 62 | 12 | **81%** | Verified (Priority & Tags Ordering) |
| `agentos/llm/provider_registry.py` | 33 | 11 | **67%** | Verified (Cassette / Available Checks) |
| `agentos_server/app.py` | 76 | 9 | **88%** | Verified (FastAPI Routes) |
| `agentos_server/run_manager.py` | 66 | 6 | **91%** | Verified (Async State Tracking) |
| `agentos/packaging/signer.py` | 97 | 14 | **86%** | Verified (Ed25519 Signing) |
| `agentos/packaging/pack_format.py` | 141 | 35 | **75%** | Verified (.agentpack Archive) |

To run the coverage test suite locally, use:
```bash
pytest agentos/tests agentos_server/tests agentos/packaging/tests --cov=agentos --cov=agentos_server --cov-report=term
```

## License

MIT

## Contributing

Contributions welcome! Please see CONTRIBUTING.md for guidelines.

