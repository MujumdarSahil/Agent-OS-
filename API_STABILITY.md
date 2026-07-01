# AgentOS API Stability & Interface Guarantees

This document establishes the official stability guarantees, public contracts, and internal surfaces for AgentOS. Review this page before extending the framework or building plugins to ensure forward compatibility.

---

## Stability Classifications

We classify our components and modules into three stability tiers:

| Tier | Classification | Description | Breaking Change Policy |
|---|---|---|---|
| **Stable** | Public API | Core interfaces, classes, and CLI commands intended for user and plugin developer integration. | Requires Minor version bump (pre-1.0.0) or Major version bump (post-1.0.0). |
| **Evolving** | Experimental | Newly introduced endpoints, beta features, or experimental tools. | May change or be removed in any patch release, marked clearly with warnings. |
| **Internal** | Unstable | Internal implementation details, utility modules, and private helper functions. | No stability guarantees. Subject to change or removal at any time without notice. |

---

## 1. Public Python Base Classes (Stable)

The following abstract base classes located in [base.py](file:///c:/Users/mujum/OneDrive/Desktop/Agent%20OS/agentos/core/base.py) are considered **Stable** and serve as the official extensibility points of the framework:

*   `BaseAgent`: Base class for custom agents.
*   `BaseTool`: Base class for custom tools.
*   `BaseMemory`: Base class for custom storage backends.
*   `BaseMCPPlugin`: Base class for Model Context Protocol integrations.

Any changes to their abstract method signatures (such as modifying arguments, renaming methods, or changing return types) are classified as **breaking**.

---

## 2. Extension Entry-Points (Stable)

The registered group names configured in `setup.py` and `pyproject.toml` are **Stable**:

*   `agentos.agents`: Entry-point group for third-party agents.
*   `agentos.tools`: Entry-point group for third-party tools.
*   `agentos.mcp_plugins`: Entry-point group for third-party MCP plugins.

Renaming or removing these entry-point group names is classified as a **breaking change**.

---

## 3. Package Manifest Schema (Stable)

The manifest structure of `.agentpack` bundles (e.g., `manifest.yaml`) is **Stable**. Any modification that:
*   Adds new *required* fields to the schema,
*   Removes existing fields,
*   Changes field data types or serialization behavior,
is considered a **breaking change**.

---

## 4. CLI Command Contract (Stable)

The core Command-Line Interface (CLI) commands and their flags are **Stable**:
*   `agentos run`
*   `agentos pack`
*   `agentos install`
*   `agentos new-project`

Modifying the CLI command names, removing flags, or changing the exit-code contracts constitutes a **breaking change**.

---

## 5. REST API Endpoints (Stable)

The FastAPI web backend endpoints prefixing `/api/` are **Stable**:
*   `/api/health`: Health status and framework version.
*   `/api/agents`: Agent definitions and listings.
*   `/api/tools`: Tool listings and scaffolds.
*   `/api/crews`: Crew definitions and runs.
*   `/api/missions`: Mission configurations and runs.
*   `/api/runs`: Execution runs management.

Changing HTTP verbs, request/response body schemas, or removing endpoints constitutes a **breaking change**.

---

## 6. Exception Hierarchy (Stable)

All custom exceptions raised by AgentOS are **Stable** and inherit from the base class `AgentOSError`. Applications should catch `AgentOSError` for robust error handling.

### Hierarchy
```text
Exception
 └── AgentOSError
      ├── AgentOSLLMError          (LLM client / fallback failures)
      ├── AgentOSRegistryError     (Component registration/loading failures)
      ├── AgentOSGovernanceError   (Policy violations and safety blocks)
      └── AgentOSPackagingError    (Signing, verification, pack failures)
```
Removing or renaming these exception classes, or moving them outside `AgentOSError` inheritance, is a **breaking change**.

---

## Internal / Unstable Surfaces (No Guarantees)

The following modules are considered **Internal** implementation details and are subject to refactoring:
*   `agentos.server.routes.*`: Specific route handler functions.
*   `agentos.core.project_ops`: File system structure utilities.
*   `agentos.core.retrieval_adapters`: Local vector database interfaces.
*   Any python module prefixing functions or classes with an underscore (e.g., `_my_private_func`).
