# AgentOS 2.0: Product and Architecture Specification

**Document Version:** Plan v2.1  
**Date:** November 2026  
**Status:** Active Plan of Record  

---

## 1. Executive Summary & Vision

AgentOS 2.0 evolves AgentOS from an experimental agent chaining script into a production-grade multi-agent orchestration framework. The system provides a deterministic, observable flow engine with Information Flow Control (IFC) security labels, MongoDB platform persistence, React UI, granular governance, and comprehensive auditability.

Plan v2.1 incorporates key architectural and scoping decisions:
1. **ML Studio Scope Reduction:** ML Studio training, fine-tuning, and weights registry are moved to the v2.1 backlog. AgentOS 2.0 retains "model endpoint as tool" (a node that invokes an external inference endpoint such as a REST classifier, HuggingFace Inference, or vLLM instance and exposes it as a tool to agents).
2. **Security Labels as Core Engine Invariant:** Every value moving through a workflow carries integrity (`trusted` vs. `untrusted`), confidentiality (`public`, `internal`, `confidential`, `secret`), and provenance (source node run IDs and event sequence numbers).
3. **Sound Label Propagation:** LLM completions inherit the join (most restrictive) of their input labels; they are not untrusted by default. Untrusted sources are strictly delineated: webhooks, external HTTP responses, incoming emails, external files, tool outputs, and MCP server outputs. The threat model assumes the model provider is not malicious, while attackers control content.
4. **Sink Protection:** Sensitive sinks (external send like email/chat/HTTP POST, file writes/deletions, shell/code execution, payments) require trusted arguments. Furthermore, routing `secret`-labeled data to an external sink constitutes a confidentiality violation.
5. **Sound Declassification:** Validators upgrade integrity only for constrained, non-prompt-injectable outputs (enums, booleans, bounded numeric ranges, strict allowlist matches, and verified cryptographic signatures). Free-text fields remain untrusted even when passing schema validation. Quarantined extraction must strictly output constrained types.
6. **Tool Call Mediation:** All agent tool invocations (including CrewAI agents) are intercepted and mediated by an AgentOS tool proxy. Agents never invoke tools directly.
7. **Reordered Milestones:** Sub-milestone 1.5 (Flow Engine Spike + ADR 0001) precedes Sub-milestone 1.4 (React UI + Vault frontend integration).
8. **Platform Persistence:** MongoDB remains the platform persistence layer (single-node replica set `rs0`, keyfile auth, 127.0.0.1 published only, PyMongo async API).
9. **Research & Benchmarking Track:** Research track targeting AgentDojo and an in-house AgentOS workflow-injection benchmark measuring Attack Success Rate (ASR) under standard and adaptive attacks, task utility, execution overhead, and static-check false positive rates.
10. **Trimmed Phase 4:** Scoped strictly to the security evaluation harness, Ollama local model fallback, and minimal knowledge base (RAG/vector adapter).
11. **Production-Ready Phase 5:** Focuses on flow packs, one-command install, v1->2.0 migration guide, backup/restore, SBOM and signed releases, docs, a reference phishing-triage flow, and public beta.

---

## 2. Core Architecture & Security Model

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                             AgentOS Flow Engine                             │
│                                                                             │
│  ┌───────────────────────┐          ┌────────────────────────────────────┐  │
│  │ Static Flow Analyzer  │          │   Runtime Monitor & IFC Tracker    │  │
│  │ (Publish Gate Check)  │          │ (Label Join, Sink Policy, Events)  │  │
│  └──────────┬────────────┘          └─────────────────┬──────────────────┘  │
│             │                                         │                     │
│  ┌──────────▼─────────────────────────────────────────▼──────────────────┐  │
│  │                     Node Graph Execution Context                      │  │
│  │                                                                       │  │
│  │   [Ingest Node] ──> [LLM / Agent Node] ──> [Declassification Node]   │  │
│  │   (Labels Inbound)    (Label Join)          (Approval/Validator)      │  │
│  │                                                      │                │  │
│  │                                                      ▼                │  │
│  │                                                [Sink Node]            │  │
│  │                                            (Shell, Email, DB)         │  │
│  └──────────────────────────────────────────────────────┬────────────────┘  │
│                                                         │                   │
│                               ┌─────────────────────────▼──────────────┐    │
│                               │          AgentOS Tool Proxy            │    │
│                               │  (CrewAI / Agent Interception Layer)   │    │
│                               └─────────────────────────┬──────────────┘    │
│                                                         │                   │
└─────────────────────────────────────────────────────────┼───────────────────┘
                                                          │
                                       ┌──────────────────▼──────────────────┐
                                       │   MCP Servers, CLI, APIs, Vault     │
                                       └─────────────────────────────────────┘
```

### 2.1 Information Flow Control (IFC) Labels
Every value $v$ transported between flow nodes carries a metadata security label $L(v) = \langle I, C, P \rangle$:
- **Integrity ($I \in \{\text{trusted}, \text{untrusted}\}$):**
  - Inputs from webhooks, incoming emails, HTTP responses, external files, and tool/MCP outputs are tagged `untrusted`.
  - Flow static parameters, admin constants, and verified system inputs are tagged `trusted`.
  - **LLM Output Rule:** An LLM output inherits the join (most restrictive) of the labels of its inputs:
    $$I_{\text{out}} = \bigwedge_{x \in \text{inputs}} I(x)$$
    If all inputs are `trusted`, the output is `trusted`. If any prompt, context, or tool output supplied to the LLM is `untrusted`, the LLM output is `untrusted`.
- **Confidentiality ($C \in \{\text{public}, \text{internal}, \text{confidential}, \text{secret}\}$):**
  - Values default to `internal`. Secrets retrieved from the Credentials Vault carry label `secret`.
  - LLM outputs inherit the least-permissive confidentiality of all inputs.
  - Sending `secret` data to any external sink (email, external webhook, chat) is a policy violation.
- **Provenance ($P$):**
  - An append-only lineage tracking the set of source node run IDs and event sequence numbers that contributed to the generation of the value:
    $$P_{\text{out}} = \bigcup_{x \in \text{inputs}} P(x) \cup \{\text{run\_id:seq\_num}\}$$

### 2.2 Sink Nodes & Argument Contracts
A sink is any node whose execution causes external or stateful side effects:
- **External Senders:** Outgoing email (`send_email`), messaging (Slack/Teams/chat), outbound HTTP POST.
- **Data Modification:** Database record mutations, document deletion, state truncation.
- **System Execution:** Subprocess shell commands, code execution sandboxes.
- **Financial / Operational:** Payment processing, access delegation.

**Contract Invariant:** Every `NodeSpec` declaring a sink defines required argument integrity. A sink requiring trusted arguments will reject untrusted inputs at runtime and fail static validation at publish time unless an explicit declassification node intervenes.

### 2.3 Declassification Soundness
Declassification converts untrusted data into trusted data through deliberate, verifiable nodes:
1. **Approval Node (`approval`):** Suspends flow execution and requests human reviewer confirmation. If approved, reviewer-confirmed fields are labeled `trusted`.
2. **Validator Node (`validator`):** Evaluates untrusted data against strict constraints. Integrity is upgraded **only** for constrained types:
   - Enums matching closed allowlists.
   - Booleans.
   - Bounded numbers within verified ranges.
   - Strict regex allowlists (e.g., UUIDs, hash digests).
   - Cryptographic signatures verified against known public keys.
   *Soundness Rule:* Free-text strings and unstructured markdown/JSON fields **remain untrusted** even if they pass schema validation.
3. **Quarantined Extraction Node (`quarantined_extraction`):** An isolated parsing node that extracts only strictly typed, constrained fields (enums, booleans, bounded numeric IDs) from untrusted input payloads, shedding all free text.

### 2.4 Agent Tool Call Mediation via AgentOS Proxy
Agents (including CrewAI squads and individual agent executors) never invoke Python functions, external APIs, or MCP servers directly. All tool definitions provided to the model point to the **AgentOS Tool Proxy**:
- The proxy intercepts every tool invocation request.
- The proxy validates the caller's capability, checks argument integrity against the target tool's sink requirements, enforces resource quotas, and logs an immutable audit event.
- If an agent's reasoning was conditioned on untrusted text and it attempts an unauthorized tool sink call, the proxy blocks the execution before any side effect occurs.

### 2.5 Event-Sourced Execution & Provenance Graph
All workflow executions are modeled as append-only event streams. Every node start, completion, tool call, proxy check, approval, and declassification emits an immutable event. The execution state can be deterministically reconstructed from the event log, and provenance queries can trace the full lineage of every decision and data transformation.

---

## 3. Five-Phase Phased Roadmap

### Phase 1: Foundation (In Progress)
- **1.0b:** v1 Characterization test suite (Done).
- **1.1a:** Codebase cleanup, removing dead duplicates and facade layers (Done).
- **1.1b:** Package restructuring: `agentos` core library separate from `agentos_server` and `ui/` (Done).
- **1.2:** MongoDB platform persistence: repositories, replica set `rs0` with keyfile auth, live Mongo contract tests (Done).
- **1.3:** Credentials Vault with AES-256-GCM envelope encryption and migration importer/exporter (Done).
- **1.5 (NEXT):** **Flow Engine Spike & ADR 0001:** Prototype deterministic DAG engine evaluating LangGraph, Temporal, and custom async DAG options against security-label propagation and tool mediation requirements.
- **1.4:** **React UI & Vault Integration:** Visual flow canvas, node palette, settings, and vault secret management in React.

### Phase 2: Flow Engine & Security Label System
- Production deterministic Flow Engine implementation based on ADR 0001.
- In-memory and Mongo-persisted Information Flow Control (IFC) label tracking.
- `NodeSpec` sink declarations and argument contracts.
- Static flow graph verification gate at publish time.
- Runtime monitor enforcing integrity and confidentiality invariants.
- AgentOS Tool Proxy intercepting all agent/CrewAI tool invocations.
- Sound declassification nodes (`approval`, `validator`, `quarantined_extraction`).
- Event-sourced execution runner with immutable provenance recording.

### Phase 3: Governance, Observability & Access Control
- Policy Engine: fine-grained RBAC and attribute-based access control.
- Admin governance: only administrators can create declassification policies, configure allowlists, or mark tools as trusted. All policy modifications are fully audited.
- Real-time audit stream and telemetry export (OpenTelemetry / Prometheus).
- Execution visualizer displaying live node states, labels, and approval queues.

### Phase 4: Security Evaluation, Intelligence & Fallback (Trimmed)
- Security benchmark integration: **AgentDojo** evaluation harness.
- In-house AgentOS workflow-injection benchmark measuring:
  - Attack Success Rate (ASR) across standard and adaptive attacks.
  - Task utility on benign multi-agent workflows.
  - Latency and token overhead introduced by proxy interception and label validation.
  - Static-check false positive rate on valid workflows.
- Ollama local model connector for offline fallback execution.
- Minimal Knowledge Base: lightweight vector store / RAG adapter.

### Phase 5: Packaging, Enterprise Polish & Release
- `.agentpack` v2: portable bundles carrying flows, prompt templates, policies, and manifests.
- Single-command CLI installation and startup (`agentos run / agentos init`).
- v1 to 2.0 migration guide and automated schema migration tooling.
- Backup, restore, and upgrade management scripts.
- Software Bill of Materials (SBOM) and signed binary release artifacts.
- Reference end-to-end workflow: **Phishing Triage Demo Flow** (ingesting untrusted email, extracting sender metadata, quarantining payload, requiring approval for blocking/ticketing sinks).
- Complete public documentation, tutorials, and 2.0 Beta release.

---

## 4. Architectural Boundaries & Non-Functional Requirements

- **Ports and Adapters:** Core flow engine and domain logic live in `agentos` with no web framework (FastAPI) or database (PyMongo) imports. Storage and execution engines are abstracted via pure interfaces.
- **Standalone vs. Platform Modes:**
  - *Standalone:* Local file/SQLite storage, in-process queue, no external daemon dependencies.
  - *Platform:* MongoDB replica set storage, Redis message queue, multi-worker execution.
- **Determinism:** Given identical inputs and cached/mocked model responses, flow execution graph traversal is 100% deterministic and reproducible from event logs.
- **Fail-Closed Default:** Any ambiguous security classification, unparseable CVSS vector, unhandled sink argument, or expired exemption fails closed.
