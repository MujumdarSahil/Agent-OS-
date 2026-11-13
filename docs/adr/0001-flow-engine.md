# ADR 0001: Flow Engine Architecture for AgentOS 2.0

- **Status:** Proposed  
- **Date:** November 2026  
- **Deciders:** AgentOS Core Team  
- **Target Milestone:** Sub-Milestone 1.5 (Flow Engine Spike & ADR Decision)  

---

## 1. Context and Problem Statement

AgentOS 1.x relied on unstructured agent orchestration loops (e.g. CrewAI squads, sequential routers) where data flow, tool execution, and retry semantics were implicit and difficult to audit. 

For AgentOS 2.0, workflows require:
- Deterministic graph-based execution supporting branching, parallel execution, and cycles.
- Fine-grained Information Flow Control (IFC): tracking integrity (`trusted`/`untrusted`), confidentiality, and provenance on all values.
- Comprehensive tool mediation: ensuring that agents cannot invoke external tools or sinks directly, but only through a policy-enforcing proxy.
- Publish-time static analysis and runtime monitor enforcement.
- Step-level checkpointing, idempotency, and resumability from failure.

This ADR frames the evaluation for Sub-Milestone 1.5, which prototypes a flow spike against three architectural options before selecting the production engine.

---

## 2. Considered Options

1. **Option 1: LangGraph**
   - *Description:* Cyclic state-graph framework built on LangChain/Pregel abstraction.
   - *Pros:* Native support for state schemas, branching, and cycles; active ecosystem.
   - *Cons:* Tight coupling with LangChain primitives; unclear feasibility of wrapping all intermediate edge values with custom security label metadata and intercepting non-LangChain agent tool calls.

2. **Option 2: Temporal**
   - *Description:* Robust distributed orchestration engine providing durable, event-sourced execution.
   - *Pros:* Exceptional durability, out-of-the-box state replay, proven resume semantics, and task queuing.
   - *Cons:* Significant operational complexity (requires external Temporal server/cluster); heavy footprint for standalone mode; harder to embed custom in-memory IFC propagation across node boundaries.

3. **Option 3: Custom Async DAG / State Machine**
   - *Description:* Lightweight, native Python async DAG engine built with ports-and-adapters architecture specifically for AgentOS.
   - *Pros:* Tailored directly to AgentOS security requirements; native metadata label wrapping on every edge; zero external orchestration daemon dependencies in Standalone mode; trivial to embed Tool Proxy.
   - *Cons:* Requires implementing graph traversal, cycle detection, checkpointing, and parallel scheduling internally.

---

## 3. Evaluation Criteria

Each option will be evaluated against the following criteria during the Phase 1.5 spike:

1. **Determinism & Graph Topology:** Support for DAG and cyclic flows with clear termination semantics.
2. **Security Label Propagation Feasibility:** Ability to carry and join $\langle \text{Integrity}, \text{Confidentiality}, \text{Provenance} \rangle$ metadata across all nodes and edges without framework interference.
3. **Tool Mediation Feasibility:** Ease of ensuring all agent tool calls (CrewAI, LangChain, native) route strictly through the AgentOS Tool Proxy.
4. **Publish-Time Static Verifiability:** Ability to inspect the unexecuted flow definition to verify that untrusted data cannot reach sensitive sinks without traversing declassification nodes.
5. **Resume & Idempotency:** Ability to resume an interrupted flow from the last successful checkpoint, skipping succeeded nodes.
6. **Footprint & Dependencies:** Usable in both lightweight Standalone mode (local file/SQLite) and scalable Platform mode (MongoDB/Redis).
7. **Developer Experience & UI Canvas Alignment:** Direct mapping to React UI node palette and flow visualizer.

---

## 4. Spike Acceptance Criteria & Tests

The Phase 1.5 spike must implement and pass the following five acceptance tests before an option is selected:

### Test A: Runtime Prompt Injection & Sink Blocking
- **Flow Topology:** `Webhook Ingest -> Agent (with tools) -> send_email Sink`.
- **Scenario:** Adversarial payload delivered to the webhook contains injected instructions directing the agent to exfiltrate data to an attacker email address.
- **Expected Outcome:** The agent attempts the `send_email` tool call; the Runtime Monitor and Tool Proxy detect that the destination address and content are derived from `untrusted` input without declassification; the call is blocked, the sink is not invoked, and the security violation is logged.

### Test B: Static Analysis Publish Gate
- **Scenario:** The user attempts to publish the flow from Test A (`Webhook Ingest -> Agent -> send_email Sink`).
- **Expected Outcome:** The Static Flow Analyzer rejects the flow at publish time because an untrusted path reaches a sensitive sink without declassification. When an `approval` (human-in-the-loop) or constrained `validator` node is inserted between the agent and the sink, the static check passes.

### Test C: Resumability on Failure
- **Scenario:** A multi-step flow executes nodes 1 and 2 successfully, then experiences a forced runtime error (simulated crash/exception) on node 3.
- **Expected Outcome:** Upon invoking flow resume from the checkpoint, nodes 1 and 2 are skipped, node 3 re-executes, and the workflow completes successfully.

### Test D: Strict Tool Call Mediation
- **Scenario:** A CrewAI agent squad configured with multiple tools is executed inside a flow node.
- **Expected Outcome:** Every tool invocation initiated by the model is routed through the AgentOS Tool Proxy. A test assertion verifies that the underlying unwrapped tool functions are never called directly.

### Test E: Provenance Query Traversal
- **Scenario:** Following the blocked execution in Test A, a provenance query is issued for the blocked sink event.
- **Expected Outcome:** The query returns the complete chain of immutable events and source node run IDs leading from the original webhook payload through the LLM completion to the proxy block decision.
