# ADR 0001: Flow Engine Architecture for AgentOS 2.0

- **Status:** Proposed  
- **Date:** November 2026  
- **Deciders:** Sahil Mujumdar (owner)  
- **Target Milestone:** Sub-Milestone 1.5 (Flow Engine Spike & ADR Decision)  

---

## 1. Context and Problem Statement

AgentOS 1.x relied on unstructured agent orchestration loops (e.g. CrewAI squads, sequential routers) where data flow, tool execution, and retry semantics were implicit and difficult to audit.

For AgentOS 2.0, workflows require:
- Deterministic graph-based execution supporting branching, parallel execution, and explicit bounded loop nodes (DAG plus bounded loops; no general cycles).
- Fine-grained Information Flow Control (IFC): tracking integrity (`trusted`/`untrusted`), confidentiality, and provenance on all values.
- Comprehensive tool mediation: ensuring that agents cannot invoke external tools or sinks directly, but only through a policy-enforcing proxy.
- Publish-time static analysis and runtime monitor enforcement.
- Step-level checkpointing, idempotency, and resumability from failure and process restarts.

This ADR frames the evaluation for Sub-Milestone 1.5, which evaluates architectural options before selecting the production engine.

---

## 2. Considered Options

1. **Option 1: LangGraph**
   - *Description:* State-graph framework built on LangChain/Pregel abstraction.
   - *Pros:* Support for state schemas, branching, and bounded execution loops; active ecosystem.
   - *Cons:* Tight coupling with LangChain primitives; unclear feasibility of wrapping all intermediate edge values with custom security label metadata and intercepting non-LangChain agent tool calls.

2. **Option 2: Temporal**
   - *Description:* Distributed orchestration engine providing durable, event-sourced execution.
   - *Pros:* Exceptional durability, out-of-the-box state replay, proven resume semantics, and task queuing.
   - *Cons:* Significant operational complexity (requires external Temporal server/cluster); heavy footprint for standalone mode; harder to embed custom in-memory IFC propagation across node boundaries.

3. **Option 3: Custom Async DAG / State Machine**
   - *Description:* Lightweight, native Python async DAG engine with explicit bounded loop nodes, built with ports-and-adapters architecture specifically for AgentOS.
   - *Pros:* Tailored directly to AgentOS security requirements; native metadata label wrapping on every edge; zero external orchestration daemon dependencies in Standalone mode; trivial to embed Tool Proxy.
   - *Cons:* Requires implementing graph traversal, bounded loop guards, checkpointing, and parallel scheduling internally.

---

## 3. Methodology & Evaluation Approach

To minimize wasted engineering effort while maintaining rigorous technical validation:
1. **Desk Evaluation:** Desk-evaluate LangGraph and Temporal against the full criteria list in Section 4. Tiny proof snippets are authored in `docs/adr/spikes/` where a criterion is doubtful or requires empirical verification:
   - `docs/adr/spikes/proof_crewai_scripted_llm.py`: Proof that CrewAI 1.15.41 can be driven deterministically via a custom `BaseLLM` subclass to execute tools.
   - `docs/adr/spikes/proof_langgraph_edge_labels.py`: Analysis of the friction in wrapping LangGraph state channels and reducers with security labels.
   - `docs/adr/spikes/proof_temporal_standalone.py`: Analysis of Temporal's external cluster requirement and storage coupling.
2. **Spike Build on Leading Option:** Build the working spike prototype once, directly on the leading option that emerges from the desk evaluation.
3. **Acceptance Test Verification:** Validate the spike against all six acceptance tests (Tests A–F) and measure per-node label-tracking overhead.

---

## 4. Evaluation Criteria

Each option is evaluated against the restored core criteria from the specification:

1. **Graph Topology & Determinism:** Support for DAG plus explicit bounded loop nodes; no general cycles. Clear termination and bounded iteration semantics.
2. **Persistence Coupling (Mongo / SQLite):** Clean adapter separation supporting Standalone mode (local file/SQLite) and Platform mode (MongoDB) without leaking engine-internal storage models or forcing external daemon dependencies in Standalone.
3. **Replay & Event Sourcing:** Deterministic replay of flow execution from append-only stored event logs.
4. **Durable Waiting States:** State persisted and worker freed when awaiting external inputs (human approval, timer, incoming webhook) rather than holding active worker threads or memory.
5. **Parallel Branches & Join:** Native support for concurrent fan-out execution across branches and deterministic synchronization at join nodes.
6. **Per-Node Timeout & Cancellation:** Granular timeout configuration per node with clean cancellation propagation across downstream tasks.
7. **Blocking CrewAI Execution in Async Workers:** Ability to safely execute synchronous, blocking CrewAI agent squads inside async background workers without starving or blocking the main event loop.
8. **Security Label Propagation Feasibility:** Native ability to attach, propagate, and join $\langle \text{Integrity}, \text{Confidentiality}, \text{Provenance} \rangle$ metadata across all nodes and edges without framework interference.
9. **Tool Mediation Feasibility:** Ensuring all agent tool invocations (CrewAI, LangChain, native) route strictly through the AgentOS Tool Proxy.
10. **Publish-Time Static Verifiability:** Inspecting unexecuted flow topology to reject paths from untrusted sources to sensitive sinks without declassification.

---

## 5. Desk Evaluation Against Criteria

| Criterion | Option 1: LangGraph | Option 2: Temporal | Option 3: Custom Async DAG (Leading) |
|---|---|---|---|
| **1. Graph Topology & Determinism** | Operates on general cyclic state graphs (Pregel); building a strict DAG with explicit bounded loop nodes adds an unnecessary abstraction layer over Pregel. | Workflows are imperative code by default. While a declarative DAG interpreter could be hosted on top of Temporal, doing so adds an unnecessary orchestration layer. | **Native Support:** First-class declarative DAG representation with explicit `LoopNode` bounded iteration guards and cycle rejection at build time. |
| **2. Persistence Coupling (Mongo/SQLite)** | Dictates internal checkpoint schemas (msgpack/pickle); requires writing custom `BaseCheckpointSaver` adapters; does not map cleanly to AgentOS 1.2 ports. | Offers a single-binary SQLite dev server for local use, but production requires an external cluster DB (PostgreSQL/MySQL/Cassandra) and service daemon. Temporal's execution history duplicates the AgentOS event log. | **Direct Alignment:** Aligned with local-first architecture. Directly reuses AgentOS 1.2 storage ports for File/SQLite (Standalone) and MongoDB (Platform) with zero extra daemons. |
| **3. Replay & Event Sourcing** | State-snapshot oriented; does not natively replay from append-only domain event streams. | **Native Strength:** Industry-standard event-sourced execution with deterministic workflow replay. | **Native Support:** Append-only event stream (`run_started`, `node_started`, `sink_intent`, `sink_committed`); state reconstructible from event history. |
| **4. Durable Waiting States** | Supports `interrupt()`, but state resumption requires passing payloads back into graph invocation; state model is monolithic. | **Native Strength:** Excellent native support for signals, timers, and human approval without holding worker threads. | **Native Support:** Run enters `waiting` state, state is persisted to 1.2 checkpoint store, worker is freed. Resumed via `approve()` API call. |
| **5. Parallel Branches & Join** | Native Pregel superstep fan-out and barrier synchronization. | Supported via `asyncio.gather` across activities. | **Native Support:** `asyncio`-native scheduling of ready nodes (in-degree zero in remaining dependency graph) with barrier join synchronization. |
| **6. Per-Node Timeout & Cancellation** | No native per-node timeout configuration; requires wrapping individual node callables with `asyncio.wait_for`. | **Native Strength:** Fine-grained schedule-to-close and start-to-close timeouts per activity. | **Native Support:** `NodeSpec.timeout_seconds` enforced via `asyncio.wait_for` with cancellation tokens propagating to child tasks. |
| **7. Blocking CrewAI in Async Workers** | Feasible via `asyncio.to_thread` in node functions. | Feasible via dedicated worker activities. | **Native Support:** Wraps blocking CrewAI `execute_task` calls via `asyncio.to_thread`, keeping async engine event loop unblocked. |
| **8. Security Label Propagation** | **High Friction:** Shared state dict requires custom `Labeled[T]` wrappers on every key and custom channel reducers (`label_reducer`); see `docs/adr/spikes/proof_langgraph_edge_labels.py`. | **High Friction:** All data crossing workflow-activity boundaries requires serialization via Temporal Data Converters; cannot run non-deterministic label verification. | **Native Support:** First-class metadata labels $\langle I, C, P \rangle$ on all edge values; automatic join computation across inputs before node execution. |
| **9. Tool Mediation Feasibility** | Assumes LangChain `ToolNode`; mediating CrewAI tools requires external interception layers outside LangGraph. | Tool execution in activities, but mediating internal CrewAI execution loops still requires custom agent-level proxies. | **Native Support:** Direct integration with `AgentOSToolProxy`, wrapping tools before supplying them to CrewAI or native nodes. |
| **10. Publish-Time Static Verifiability** | Static verifiability comes from declarative definitions, which can be interpreted on any engine. However, LangGraph's native model is code-defined graphs with opaque transitions rather than declarative definitions. | While a declarative DAG could be hosted inside a Temporal workflow, Temporal's execution model and payload serialization add friction for label propagation and require an extra daemon. | **Native Support:** Declarative JSON/Pydantic flow definitions allow the Static Flow Analyzer to traverse edges and verify sink rules before execution without translation layers. |

### Leading Option Selection
**Option 3: Custom Async DAG / State Machine** is the leading option:
1. **Zero Extra Daemon (Local-First):** Unlike Temporal (which requires an extra server daemon and whose internal workflow history would duplicate our event log), it runs completely in-process in Standalone mode, fulfilling AgentOS architectural constraints.
2. **Direct Reuse of Storage Ports:** Natively connects to AgentOS 1.2 `RunRepository`, `EventStore`, and `CheckpointStore` for both local file/SQLite and MongoDB replica sets.
3. **Low-Friction Information Flow Control:** Values passed across edges natively carry $\langle \text{Integrity}, \text{Confidentiality}, \text{Provenance} \rangle$, avoiding the channel reducer friction of LangGraph and the payload serialization friction of Temporal.
4. **Native Declarative Definitions:** Declarative graph definitions permit the Static Flow Analyzer to inspect data flow paths from sources to sinks prior to execution, rejecting unsafe flows at publish time.

The Sub-Milestone 1.5 spike prototype will therefore be implemented directly using the **Custom Async DAG Engine**.

---

## 6. Spike Acceptance Criteria & Tests

All tests A–F use a scripted mock LLM (**MOCK**); an optional real-model validation run is labeled **LIVE**.

### Test A: Runtime Prompt Injection & Sink Blocking [MOCK]
- **Flow Topology:** `Webhook Ingest -> Agent (with tools) -> send_email Sink`.
- **Scenario:** Adversarial payload delivered to the webhook contains injected instructions directing the agent to exfiltrate data to an attacker email address.
- **Expected Outcome:** The agent attempts the `send_email` tool call. The Runtime Monitor and Tool Proxy detect that the destination `to` argument is untrusted; the call is blocked, the sink is not invoked, and the security violation reason is logged.

### Test B: Static Analysis Publish Gate & Declassification [MOCK]
- **Scenario:** The user attempts to publish the flow from Test A (`Webhook Ingest -> Agent -> send_email Sink`).
- **Expected Outcome:** The Static Flow Analyzer rejects the flow at publish time because an untrusted path reaches a sensitive sink. When a passing variant inserts an allowlist validator on `to`, or an approval node between the agent and the sink, the static check passes and runtime execution succeeds.

### Test C: Resumability on Failure & Process Restart [MOCK]
- **Scenario:** A multi-step flow experiences a forced runtime error (exception) and subsequent process restart, retrieving state from storage.
- **Expected Outcome:** Succeeded nodes are skipped on resume. Sinks use idempotency keys, and a crash after the sink fires must not send twice on resume.

### Test D: Strict Tool Call Mediation [MOCK]
- **Scenario:** A CrewAI agent squad configured with multiple tools is executed inside a flow node.
- **Expected Outcome:** Every tool invocation initiated by the model is routed through the AgentOS Tool Proxy. Unwrapped tool functions are never called directly.

### Test E: Provenance Query Traversal [MOCK]
- **Scenario:** Following the blocked execution in Test A, a provenance query is issued for the blocked sink event.
- **Expected Outcome:** The query returns the complete chain of append-only events and source node run IDs leading from the original webhook payload through the LLM completion to the proxy block decision.

### Test F: Utility Control (Benign Webhook Summary) [MOCK]
- **Scenario:** A benign, valid payload is delivered to the webhook; the agent summarizes the input and emails the summary to the configured, trusted recipient.
- **Expected Outcome:** The workflow completes successfully with no block, proving that security controls do not impede normal, authorized business logic.

---

## 7. Overhead & Evidence Recording

The Phase 1.5 spike evidence report (`docs/evidence/1.5.md`) will record:
- **Per-Node Label-Tracking Overhead:** Median and p95 latency (ms) per node across 100 runs of the Test F flow with label tracking ON vs. OFF.
- Raw outputs for Tests A–F labeled **MOCK** (and optionally **LIVE**).
- Completed acceptance checklist and known gaps.
