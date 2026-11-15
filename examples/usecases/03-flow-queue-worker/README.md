# Use Case 03: Flow Lifecycle, Worker Leasing & Fencing, and Dead-Letter Recovery

## 1. Scenario Story
In mission-critical multi-agent automation (such as incident triage, notifications, or financial dispatches), workflows must be versioned immutably, scheduled through reliable queues, and executed across worker pools with strong safety guarantees:
- **No duplicate side-effects** when worker processes stall or experience network partitions.
- **Fail-closed lease fencing** that rejects stale worker writes before touching external transports.
- **Dead-letter protection** that halts poison-pill jobs after bounded retry attempts, preventing infinite retry storms and queue blocking.

---

## 2. What This Demonstrates
1. **Flow Storage & Publish Gate:**
   Draft flows are validated against the `StaticFlowAnalyzer` security policy before being published into immutable sequential versions (`v1`, `v2`, ...). Published versions are locked and content-hashed.
2. **Worker Leasing & Heartbeat:**
   Workers lease jobs from `QueueBackend` with a lease timeout and periodic heartbeat renewals (`lease_timeout / 3`).
3. **Lease Safety & Fencing Token Defense:**
   Every event append and transport dispatch checks the worker's active `lease_id`. When a worker's lease expires and a replacement worker takes over, the stale worker's subsequent calls fail closed with `FencingTokenError`.
4. **Bounded Retries & Dead-Letter Isolation:**
   `QueueJob.attempts` increments on every lease. If a failing job exceeds `max_attempts` (default 3), the queue transitions the job to `dead_letter` and marks the run failed with `max_attempts_exceeded`.

---

## 3. How to Run

### Run Full Suite (Benign, Failover/Fencing, and Dead-Letter):
```bash
python examples/usecases/03-flow-queue-worker/run.py --mode all
```

### Run Benign Leased Execution:
```bash
python examples/usecases/03-flow-queue-worker/run.py --mode benign
```

### Run Failover & Lease Fencing Test:
```bash
python examples/usecases/03-flow-queue-worker/run.py --mode failover
```

### Run Poison-Pill Dead-Letter Recovery:
```bash
python examples/usecases/03-flow-queue-worker/run.py --mode dead_letter
```

---

## 4. Expected Output

```text
============================================================
=== Use Case 03: Flow Queue, Leasing & Fencing Safety ===
============================================================
[1/3] Benign Leased Execution...
  - Flow published: v1 (hash: e3b0c442...)
  - Job enqueued: run_benign_...
  - Worker worker_1 leased and completed job.
  - Sinks committed: 1 send recorded. PASS

[2/3] Failover & Fencing Token Defense...
  - Worker 1 leased job; lease expired.
  - Worker 2 took over and committed send.
  - Worker 1 attempted late write -> FencingTokenError caught.
  - Total transport sends: exactly 1. PASS

[3/3] Poison-Pill Dead-Letter Isolation...
  - Enqueued poison-pill job (max_attempts=3).
  - Attempt 1: Worker crash simulated.
  - Attempt 2: Worker crash simulated.
  - Attempt 3: Worker crash simulated.
  - Job transitioned to dead_letter.
  - Run marked failed with max_attempts_exceeded. PASS
============================================================
Use Case 03 PASSED in all execution modes.
============================================================
```
