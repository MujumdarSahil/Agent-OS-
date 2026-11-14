# Use Case 02: Dynamic LLM Provider Fallback & Policy Editor

## 1. Scenario Story
In mission-critical agentic workflows, relying on a single LLM provider creates an operational single point of failure (rate limits, upstream latency spikes, service outages). AgentOS provides a persistent Fallback Policy Editor and dynamic LiteLLM router hook that cascades tool execution and reasoning across configured providers.

- **Benign Flow (Primary Active):**
  The user configures a fallback policy where `mock-primary` has order 1 and `mock-fallback` has order 2. Requests are routed to `mock-primary` and completed immediately.
- **Failover Flow (Primary Outage):**
  `mock-primary` experiences an outage or rate limit (HTTP 500 / 429). The AgentOS LiteLLM router intercepts the failure, logs the incident, and transparently cascades to `mock-fallback` without interrupting the workflow.
- **Disabled Provider Enforcement:**
  A provider marked `enabled: false` in the fallback policy is strictly excluded from the routing model list, ensuring that untrusted or deprecated endpoints are never invoked.

---

## 2. What This Demonstrates
1. **Persistent Fallback Policy Management:**
   Fallback policies (order, enabled flags, timeouts) configured via the UI/API are persisted in storage and synchronized to the in-memory router cache.
2. **Synchronous Router Hook:**
   The router factory (`build_router`) inspects policy overrides synchronously without async event-loop deadlocks or blocking storage queries.
3. **Transparent Outage Cascading:**
   When the primary provider fails, LiteLLM router handles the exception and dispatches to the secondary provider according to the user-defined order.
4. **Policy Invariants:**
   Disabled providers are pruned from the router configuration at build time (fail-closed).

---

## 3. How to Run

### Run Full Suite (Benign, Failover, and Disabled Invariant):
```bash
python examples/usecases/02-provider-fallback/run.py --mode all
```

### Run Benign Flow:
```bash
python examples/usecases/02-provider-fallback/run.py --mode benign
```

### Run Failover Flow:
```bash
python examples/usecases/02-provider-fallback/run.py --mode failover
```

---

## 4. Expected Output

```text
============================================================
=== Use Case 02: Provider Fallback & Failover ===
============================================================
[1/3] Testing Benign Execution (Primary active)...
  Router initialized with model group: agentos-default
  Primary candidate: mock-primary (order 1)
  Request succeeded via primary provider: mock-primary
  Result: "Response served by mock-primary"

[2/3] Testing Failover Execution (Primary outage -> Fallback)...
  Primary provider mock-primary failed with SimulatedServiceOutageError.
  Router cascaded to fallback candidate: mock-fallback (order 2).
  Request succeeded via fallback provider: mock-fallback
  Result: "Response served by mock-fallback"

[3/3] Testing Policy Enforcement (Disabled provider exclusion)...
  Configured mock-tertiary with enabled=False.
  Verified router model list: mock-tertiary is strictly EXCLUDED.
  Zero traffic routed to disabled provider.

Status: ALL_CHECKS_PASSED
All fallback and policy invariants verified successfully.
============================================================
```
