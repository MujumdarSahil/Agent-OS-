# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-07-01
### Added
- Created `agentos/__version__.py` as the single source of truth for the package version.
- Added global `--version` / `-v` flag to the Typer CLI app.
- Exposed package version dynamically via the `/health` FastAPI endpoint.
- Configured CI/CD pipelines under `.github/workflows/ci.yml` (build, lint, test) and `.github/workflows/release.yml` (tagged release test builds).
- Introduced structured JSON logging format configurable via `AGENTOS_LOG_FORMAT=json`.
- Established a unified error taxonomy under `AgentOSError` base exception class.
- Added `check_coverage.py` to enforce and prevent core module code coverage from dropping below 80%.
- Documented API stability commitments in `API_STABILITY.md` and extensibility guidelines.

### Changed
- Refactored all custom exceptions to inherit from the base `AgentOSError`.
- Replaced ad-hoc `print()` statements in `agentos/core/`, `agentos/llm/`, and `agentos/server/` with proper Python logging calls.
- Updated python linter settings in `pyproject.toml` to use modern `tool.ruff` configurations.
- Upgraded the React frontend linter config from `oxlint` to modern `eslint.config.js` flat config.

### Fixed
- Boosted unit test coverage for `agentos/core/umb_adapter.py` from 72% to 98% and `agentos/llm/llm_client.py` from 79% to 96%.
- Fixed Python 3.11 syntax error in `agentos/examples/agentic_chunking_demo.py` caused by backslashes in f-strings and escaped triple-quotes.
- Fixed undefined name `os` bug in `agentos/server/routes/federation.py`.
- Fixed missing `Dict`/`Any` imports in `agentos/cybercore/squads/soc_squad.py` and missing `json` in `agentos/cli/main.py`.

---

## [0.1.0] - 2026-06-20
### Added
- **Phase 1 (Core Integration)**: Class-based `Agent` wrapping CrewAI/LangChain, pluggable `LLMClient` with a multi-provider fallback registry.
- **Phase 2 (Orchestration & Planning)**: Two-layer hierarchical safety governance model (keyword check + LLM judge). Multi-Agent Planning Graph (MAGP) and dynamic task routing (DMARP). WebSockets-based real-time squad collaboration. Resource monitoring (tokens, CPU, memory, API costs).
- **Phase 3 (MCP & Packaging)**: Distributed MCP Skill Graph (DMSG) pathfinder. Scaffolding, signing (Ed25519), verification, and installation of signed `.agentpack` bundles.
- **Phase 4 (Federation & Cyber Extension)**: sequential multi-squad federation pipeline. Six pre-built crew templates. Specialized cybersecurity agents (`SecurityAgent`, `ScriptAuthorAgent`) and MCP security tools. Multi-provider expansions including OpenRouter, DeepSeek, Together, Fireworks, and Ollama.
- **Phase 5 (Framework Registry & Extensibility)**: Entry points for third-party extensions (`agentos.agents`, `agentos.tools`, `agentos.mcp_plugins`). Proactive loading from local project directories.
