# AgentOS 2.0 Architecture (one page)

Authoritative plan and security invariants: [SPEC_2.0.md](SPEC_2.0.md). Threats: [THREAT_MODEL.md](THREAT_MODEL.md).

## Folder map
| Path | What lives there |
|---|---|
| `agentos/flows/` | Flow engine (pure domain, no FastAPI/Mongo): `models` (FlowDefinition, DAG + bounded loops), `specs` (NodeSpecs, sink rules), `labels` (integrity/confidentiality/provenance), `static_analyzer` (publish gate), `engine` (event-sourced execution, runtime label monitor, approvals), `proxy` (tool mediation), `rules`, `policy` (SecurityPolicy), `worker` (FlowWorker). |
| `agentos/storage/` | Storage ports + adapters: `file/` (Standalone), `mongo/` (Platform). Append-only run events (`seq`, gap-free). |
| `agentos/queue/` | Queue ports + adapters: `in_process.py` (Standalone), `redis.py` (Platform); leases and fencing. |
| `agentos/triggers/` | Cron `scheduler.py` (croniter required), webhook `nonce_cache.py`. |
| `agentos/security/vault.py` | AES-256-GCM envelope-encrypted credential vault (master key outside the database). |
| `agentos/core/`, `agentos/llm/`, … | v1 public API (Agent, Squad, GovernanceEngine, Planner, LLMClient, …), kept stable. |
| `agentos/modelhub/` | Training/performance: NOT AVAILABLE in 2.0 (raise NotImplementedError); safety: experimental. |
| `agentos_server/` | FastAPI app: `app.py` (wiring, lifespan), `auth.py` (middleware), `routes/` (v1 `/api/*`), `routes_v2/` (`/api/v2/*`), `routes_hooks.py` (webhooks), `inprocess_worker.py` (opt-in). |
| `ui/` | React + TypeScript UI (flow builder, run panel); Playwright e2e in `ui/e2e/`. |
| `SWE/agentos_swe/` | SWE pack (packaged with AgentOS for now); legacy top-level facades are deprecated. |
| `examples/usecases/NN-*/` | Runnable use cases with benign and attack inputs (MOCK in CI). |
| `scripts/` | CI gates and tools (`check_pip_audit.py`, `check_coverage.py`, `check_wheel_install.py`, …). |
| `docs/evidence/` | Evidence reports per sub-milestone; raw logs in `raw/`. |

## Request flow
```
UI ──HTTP/WS──> API (auth middleware) ──> publish gate (static analyzer) ──> immutable flow version
UI "Run" ──> POST /api/v2/flows/{id}/runs ──> queue (enqueue job) ──> worker (lease + heartbeat)
   ──> engine (node by node, events appended) ──> tool proxy (agent tool calls) ──> sinks (send_email, …)
UI <── WS /runs/{run}/events?after_seq=N  (gap-free replay of the append-only event log)
Approval node: run waits ──> POST …/approve (exact args shown) ──> engine resumes or fails the run
```
Webhooks and cron schedules enqueue runs the same way as a manual run.

## Where security checks happen
| Check | Location | What it enforces |
|---|---|---|
| Auth middleware | `agentos_server/auth.py` | Token on every `/api/v2` route (WS: `agentos.token.<t>` subprotocol), Host/Origin checks (DNS-rebinding defence). |
| Webhook auth | `agentos_server/routes_hooks.py` | Raw-body HMAC, nonce replay protection. |
| Publish gate | `agentos/flows/static_analyzer.py` | Static label flow: untrusted data cannot reach trusted sink args; secrets cannot reach external sinks. Refusal lists `(node_id, target_arg, path, reason)`. |
| Runtime monitor | `agentos/flows/engine.py`, `rules.py` | Label joins on every value; sink contracts checked again at execution time. |
| Tool proxy | `agentos/flows/proxy.py` | All agent tool calls mediated: unknown tools rejected, pinned args cannot be overridden, sink rules applied. |
| Declassification | approval / validator nodes | Only explicit nodes upgrade integrity; validators only for constrained types. |
| Fencing | `agentos/queue/*`, storage events | Stale workers (expired lease) cannot append events or dispatch sinks. |
| Trusted domains | `SecurityPolicy.internal_domains` | Admin config only (`AGENTOS_INTERNAL_DOMAINS` or `security.internal_domains`); default empty. |

## Standalone vs Platform
| | Standalone (default) | Platform |
|---|---|---|
| Storage | File storage in the project directory | MongoDB (`AGENTOS_MONGO_URI`, replica set `rs0`, keyfile auth, 127.0.0.1) |
| Queue | In-process queue | Redis (`AGENTOS_REDIS_URI`) |
| Worker | Opt-in in-process worker (`AGENTOS_INPROCESS_WORKER=1`); otherwise runs stay queued | `FlowWorker` leasing from Redis (library class; no packaged worker command yet, see use case 03) |
| Scheduler leader | `InProcessLeaderLock` (what `app.py` wires today) | `MongoLeaderLock` exists in `agentos/triggers/scheduler.py` but is not wired by `app.py` yet |
