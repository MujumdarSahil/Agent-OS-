# AgentOS: instructions for Claude Code

## Context
AgentOS is a multi-agent framework (Python/FastAPI core, React UI). `main` is public and
used by other people: NEVER commit to or merge into `main`.
Active work is branch `2.0` (AgentOS 2.0: flow engine, MongoDB, React UI, governance,
observability, ML Studio). One sub-milestone = one feature branch off `2.0` = one PR into
`2.0`, merged only after the owner approves the evidence report.
Plan of record (spec "AgentOS 2.0: Product and Architecture Spec", 2 Nov 2026, five gated phases):
Phase 1 foundation (1.0b, 1.1a done; 1.1b restructure, 1.2 Mongo repos, 1.3 importer,
1.4 UI + vault, 1.5 engine spike/ADR), Phase 2 flow engine, Phase 3 security, governance +
observability, Phase 4 intelligence + model connectivity, Phase 5 ML Studio + release.

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
7. Small commits with clear messages. Do not mix deletions, features and docs in one commit.
8. Work in plan mode first. Show the plan and wait for approval before editing files.
9. At the end of each sub-milestone STOP and write an evidence report (below). Do not start
   the next sub-milestone until the owner approves.
10. If a requirement is ambiguous or has trade-offs, stop and ask with options and a
    recommendation. Do not choose silently.

## Baseline (2.0 after 1.1a)
agentos/tests + agentos/server/tests + agentos/packaging/tests: 169 passed, 17 skipped.
SWE/tests/swe: 671 passed. Requirement: no new failures, skip count must not rise without
a documented reason.
After 1.1b (server tests moved): agentos/tests + agentos_server/tests + agentos/packaging/tests:
196 passed, 17 skipped (169 + 27 restructure tests). `python check_wheel_install.py` must pass.
After 1.2: same suites 222 passed, 28 skipped without Mongo (the extra 11 are LIVE Mongo cases,
skip reason "LIVE Mongo not available"); with AGENTOS_MONGO_URI set: 233 passed, 17 skipped.
After 1.3: same suites 253 passed, 32 skipped without Mongo (the extra 15 are LIVE Mongo cases,
skip reason "LIVE Mongo not available"); with AGENTOS_MONGO_URI set: 268 passed, 17 skipped.
LIVE Mongo: `docker compose -f docker/compose.mongo.yml up -d --wait` (set AGENTOS_MONGO_PORT if
27017 is taken; this machine runs a native MongoDB service on 27017, use 27018).

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
- Heavy dependencies (torch, chromadb, faiss, psycopg) are optional extras.
- Every flow node type has a contract test before it appears in the UI palette.

## Evidence report template (save to docs/evidence/<milestone>.md)
(a) what changed (file list + summary), (b) every command run + raw output,
(c) tests added with MOCK/CASSETTE/LIVE labels and counts vs baseline, (d) known gaps and
anything skipped, (e) how the owner can reproduce the demo, (f) PR link + CI result.