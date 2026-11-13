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
1. **Desk Evaluation:** Desk-evaluate LangGraph and Temporal against the full criteria list in Section 4. Tiny proof snippets will be authored only where a criterion is doubtful or requires empirical verification (e.g. label wrapping on LangGraph edges, running blocking CrewAI calls in Temporal activities).
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

## 5. Spike Acceptance Criteria & Tests

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

## 6. Overhead & Evidence Recording

The Phase 1.5 spike evidence report (`docs/evidence/1.5-engine-spike.md`) must record:
- **Per-Node Label-Tracking Overhead:** Latency (ms) introduced by security label propagation, join evaluation, and Tool Proxy checks per node.
- Raw outputs for Tests A–F labeled **MOCK** (and optionally **LIVE**).
- Desk-evaluation comparison matrix across LangGraph, Temporal, and Custom Async DAG against all 10 criteria.
