# AgentOS Versioning Policy

AgentOS follows [Semantic Versioning (SemVer)](https://semver.org/). Version numbers are formatted as `MAJOR.MINOR.PATCH` (e.g., `0.2.0`).

## Pre-1.0.0 Versioning (Current Phase)

As of version `0.2.0`, AgentOS is in active pre-release development. 
- **Minor Version Bumps (0.x.0)** may introduce breaking changes, new modules, or signature modifications.
- **Patch Version Bumps (0.x.y)** are reserved for backwards-compatible bug fixes and minor improvements.

Once the project stabilizes and reaches `1.0.0`, all breaking changes will strictly require a major version bump.

---

## What Constitutes a "Breaking Change"?

For AgentOS, any modifications to the following components are defined as breaking changes and will require a MAJOR version bump (post-1.0.0) or a MINOR version bump (pre-1.0.0):

1. **Abstract Class Signatures**:
   Changes to the abstract method signatures of any core extension base classes:
   - `BaseAgent` (in `agentos/core/base.py`)
   - `BaseTool` (in `agentos/core/base.py`)
   - `BaseMemory` (in `agentos/core/base.py`)
   - `BaseMCPPlugin` (in `agentos/core/base.py`)

2. **Entry-Point Group Names**:
   Renaming or removing the registered Phase 5 entry-point groups:
   - `agentos.agents`
   - `agentos.tools`
   - `agentos.mcp_plugins`

3. **Manifest Schema**:
   Modifying required fields or structure of the `.agentpack` manifest schema (e.g. `manifest.yaml`).

4. **CLI Contract**:
   Renaming commands, changing flags, or modifying output behavior of CLI commands (e.g. `agentos new-project`, `agentos run`, `agentos pack`).

5. **API Routes**:
   Modifying REST API endpoints under `/api/*` (e.g., `/api/health`, `/api/missions/*`, `/api/runs/*`), changing their HTTP verbs, request body formats, or response schemas.
