# AgentOS: instructions for Claude Code

## Context
AgentOS is a multi-agent framework (Python/FastAPI core, React UI). `main` is public and
used by other people: NEVER commit to or merge into `main`.
Active work is branch `2.0` (AgentOS 2.0: flow engine, security labels/IFC, MongoDB, React UI,
governance, observability). One sub-milestone = one feature branch off `2.0` = one PR into
`2.0`, merged only after the owner approves the evidence report.
Plan of record is **Plan v2.1**; refer to [docs/SPEC_2.0.md](file:///docs/SPEC_2.0.md) for the authoritative
phase plan, architecture specification, and security invariants.

### Plan v2.1 Key Owner Decisions
- **ML Studio:** Removed from 2.0 (keep "model endpoint as tool"; training goes to the 2.1 backlog).
- **Sub-Milestone Order:** 1.5 engine spike + ADR 0001 before 1.4 UI.
- **Security Labels:** Core engine requirement: every value carries integrity (`trusted`/`untrusted`),
  confidentiality, and provenance (source node run IDs and event sequence numbers).
- **Label Propagation Rule:** LLM outputs inherit the join (most restrictive) of input labels; they are
  NOT untrusted by default. Untrusted sources: webhooks, HTTP responses, email, files from outside, tool and MCP outputs.
  Threat model assumption: model provider is not malicious; attacker controls content.
- **Sound Declassification:** Validators upgrade integrity ONLY for constrained outputs (enum, bool,
  bounded number, allowlist match, verified signature). Free-text fields stay untrusted even after passing schema.
  Quarantined extraction must output only such constrained types.
- **Tool Mediation Proxy:** All agent tool calls mediated by an AgentOS proxy (CrewAI never calls tools directly).
- **Research Track:** AgentDojo harness and workflow-injection benchmark; metrics: attack success rate
  (incl. adaptive), utility, overhead, static-check false positives.
- **Phase 4 Trimmed:** Scoped strictly to eval harness, Ollama fallback, minimal knowledge base.
- **Phase 5 Focused:** Packs carrying flows/prompts/policies, one-command install, v1->2.0 migration guide,
  upgrade/backup/restore, SBOM + signed releases, docs, phishing-triage demo flow, beta.

## Environment
Windows, PowerShell. Python: `.\venv\Scripts\python.exe`. Mock LLM: `$env:AGENTOS_MOCK_LLM="1"`.
When saving raw output in Windows PowerShell, use `| Tee-Object -FilePath <f> -Encoding utf8` (PowerShell 7) or `| Out-File -Encoding utf8`.
Docker Desktop must be running for LIVE tests (check with `docker ps`).
Frontend: `ui/` (npm; moved from `agentos/frontend` in 1.1b). Server package: `agentos_server`
(`agentos.server.*` is a deprecated alias shim).

## Standing rules
1. Evidence first. Never say something works, is fixed, or passes without raw terminal
   output attached (command + full output). No verdict language without it.
2. Label every test result MOCK, CASSETTE (recorded), or LIVE. Never present MOCK as LIVE.
3. Do not break the public v1 API (Agent, Squad, GovernanceEngine, TaskRouter, Planner,
   UMBAdapter, PROVIDER_REGISTRY, LLMClient, SQLiteCheckpointStore, RunManager methods,
   CLI run/validate/new-project/pack, `/api/*` REST routes). If something must change, add
   a compatibility shim plus a deprecation warning and list it in the report.
4. No fabricated capability. Stubbed, partial or untested things are labeled as such in
   code, docs and reports. README claims must not exceed what is verified.
5. Never weaken a security check or CI gate to get green (audit levels, ignores, skips)
   without listing each item with ID, reason and expiry and asking the owner first.
6. No secrets in the repo. Credentials go through the vault. Never commit `.env`.
   Never write any part of a secret (prefix, suffix, fragment) to files, logs, commits or chat.
7. Small commits with clear messages. Do not mix deletions, features and docs in one commit.
8. Work in plan mode first. Show the plan and wait for approval before editing files.
9. At the end of each sub-milestone STOP and write an evidence report (below). Do not start
   the next sub-milestone until the owner approves.
10. If a requirement is ambiguous or has trade-offs, stop and ask with options and a
    recommendation. Do not choose silently.
11. Every user-facing feature ships with a use case under `examples/usecases/NN-name/` with
    benign and attack inputs where security-relevant, run in CI in MOCK mode.
12. Token and resource economy:
    - No background watchers, polling timers or scheduled re-checks. To wait for CI, use one
      blocking call (gh pr checks <PR> --watch --fail-fast) and report the result once.
    - Do not leave processes running after a step: stop dev servers, uvicorn, Playwright and
      test runs you started, and stop Docker containers you started unless the very next step
      needs them. Say what you stopped.
    - Do not create scratch, temp or backup files in the repo; delete any you created before
      committing. Use the system temp folder for throwaway files.
    - Read only the parts of files you need; do not re-read large files or logs repeatedly.
    - Save full raw logs to docs/evidence/raw/ and paste only the summary lines and any
      failures in chat (rule 1 is satisfied by the saved raw file plus the pasted summary).
13. Never open, list or read anything in the real AgentOS home (C:\Users\mujum\.agentos
    or ~/.agentos), not even read-only, outside the isolated test home. Any ad-hoc script or server
    that builds the app must first point the vault, master key, token and data paths at a temporary
    directory.
    Claude Code runs with AGENTOS_FORBID_REAL_HOME=1 (set in .claude/settings.json env): create_app, the CLI,
    main.py and every vault/master-key/token/storage/data-dir resolver then refuse any path inside the real
    ~/.agentos (agentos/core/home_guard.py). The pytest conftest sets it for every test session.

## Baseline (2.0 after 1.3 + audit-fail-closed)
- agentos/tests + agentos_server/tests + agentos/packaging/tests + tests/ci: 280 passed, 17 skipped with LIVE Mongo (265 passed, 32 skipped without Mongo).
- SWE/tests/swe: 671 passed.
- Requirement: no new failures, skip count must not rise without a documented reason.
- LIVE Mongo: `docker compose -f docker/compose.mongo.yml up -d --wait` (default image `mongo:8.2.12`, port 27018 if native Mongo is on 27017).

## Architecture constraints (2.0)
- Ports and adapters: domain and flow engine live in `agentos` with no FastAPI/Mongo
  imports. Storage and queue are interfaces with file/in-process (Standalone) and
  Mongo/Redis (Platform) adapters.
- CrewAI sits behind an `Executor` interface. LiteLLM stays.
- Python package for the server is `agentos_server` (never a top-level `server` or `ui`).
- Mongo: single-node replica set `rs0`, published on 127.0.0.1 only, keyfile auth,
  PyMongo async API (not Motor; confirm status in docs).
- Vault: AES-256-GCM envelope encryption, master key outside Mongo, API never returns
  plaintext secrets.
- Stored tool code is stored but NOT executed outside a sandbox. MCP stdio servers need an
  allowlist and auth.
- Flow Engine & Security:
  - Security labels: values carry integrity (`trusted`/`untrusted`), confidentiality, and provenance (source node run IDs and event sequence numbers).
  - NodeSpecs declare sinks (external send like email/chat/HTTP POST, writes, deletes, shell/code, payments) and per-argument rules (e.g. `send_email`: `to` must be trusted or allowlisted; `body` may be untrusted only if all recipients internal).
  - Sending `secret`-labeled data to any external sink is a sink violation.
  - Static flow check at publish; runtime monitor enforces label joins and sink contracts.
  - All agent/CrewAI tool calls mediated by an AgentOS tool proxy.
  - Explicit declassification nodes only (`approval`, `validator`, `quarantined_extraction`); validators upgrade integrity only for constrained types.
  - Insider editor protection: only admins can create declassification policies, allowlists, or trusted-tool flags; all changes audited (Phase 2 gap: admin config/token only until Phase 3 RBAC).
  - Event-sourced execution with an append-only provenance graph.
- Heavy dependencies (torch, chromadb, faiss, psycopg) are optional extras.
- Every flow node type has a contract test before it appears in the UI palette.

## Evidence report template (save to docs/evidence/<milestone>.md)
(a) what changed (file list + summary), (b) every command run + raw output,
(c) tests added with MOCK/CASSETTE/LIVE labels and counts vs baseline, (d) known gaps and
anything skipped, (e) how the owner can reproduce the demo, (f) PR link + CI result.

## Internal: test coverage (not public until 2.0 release)

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
