# AgentOS Phase 3 Honesty & Correctness Audit Report

This report presents the findings, severity levels, and resolution status of the full honesty/correctness audit of the AgentOS framework after Phase 3.

---

## Section 1: Mock/Stub Leak Audit

### Findings & Codebase Hits
We conducted a comprehensive search of the codebase (`agentos/`) outside tests for keywords like `"mock"`, `"stub"`, `"fake"`, `"TODO"`, `"placeholder"`, `"not implemented"`, `"hardcoded"`, and `"for now"`.

1. **Placeholder in `Planner`**
   - **File & Line**: `agentos/core/planner.py` (Line 281-282)
   - **Code**: `"""Create graph using LLM (placeholder for future implementation)"""` and `# TODO: Implement LLM-based decomposition`
   - **Severity**: Minor
   - **Reachability**: Reachable if a user attempts to call `create_graph_with_llm()`, which is documented as planned but currently falls back to a structural decomposition.
   - **Resolution**: Documented in `PHASE3_LIMITATIONS.md`.

2. **Compliance Agent Placeholder**
   - **File & Line**: `agentos/cybercore/agents/compliance_agent.py` (Line 111)
   - **Code**: `# Placeholder for compliance checking`
   - **Severity**: Minor
   - **Reachability**: Reachable when running compliance auditing checks.
   - **Resolution**: Documented.

3. **Breach Check K-Anonymity Mock Endpoint**
   - **File & Line**: `agentos/cybercore/tools/breach_check_k_anonymity.py` (Line 76) and `agentos/mcp_connectors/security_mcp.py` (Line 586)
   - **Code**: `# Placeholder: In production, this would make HTTP request to breach API`
   - **Severity**: Moderate
   - **Reachability**: Reachable if a user runs password hash audits via the security agents. The logic generates realistic responses using offline k-anonymity mock heuristics to avoid querying paid/external APIs without permission.
   - **Resolution**: Documented.

4. **FAISS & Chroma memory backends TODOs**
   - **File & Line**: `agentos/core/umb_adapter.py` (Lines 146, 149)
   - **Code**: `# TODO: Implement FAISS backend` / `# TODO: Implement Chroma backend`
   - **Severity**: Minor
   - **Reachability**: Reachable if a user initializes `UMBAdapter(backend="faiss")` or `Chroma` when executing custom agent scripts. The system currently falls back gracefully to `"simple"` in-memory backend storage.
   - **Resolution**: Documented.

5. **Tool Creation stubs**
   - **File & Line**: `agentos/cli/main.py` (Lines 176-178, 261) and `agentos/core/project_ops.py` (Line 146)
   - **Code**: `TODO: Provide detailed description of this tool's behavior.`
   - **Severity**: Minor
   - **Reachability**: Part of code scaffolding; generates TODO template code when running `agentos new-tool` or `agentos new-mcp-plugin`. This is standard scaffolding behavior.
   - **Resolution**: Expected design.

### Default Provider Registry Verification
We confirmed that `agentos/llm/provider_registry.py` does **NOT** contain `"openai/mock-model"` or any other fake model by default. The active providers are:
- `openai` (GPT-4o, GPT-3.5-Turbo)
- `anthropic` (Claude-3-Opus, Claude-3-Sonnet)
- `gemini` (Gemini-1.5-Pro, Gemini-1.5-Flash)
- `ollama_qwen` (Qwen2.5-Coder)
- `ollama_llama` (Llama3.2)
- `openai_compatible` (Custom provider)

If all API keys are unset and local Ollama is not running, calling `LLMClient()` and executing a mission via the CLI/API correctly raises a clean, user-friendly `AgentOSLLMError` explaining exactly what to configure next:
```
agentos.llm.provider_registry.AgentOSLLMError: No LLM providers available. Set an API key (e.g., OPENAI_API_KEY, ANTHROPIC_API_KEY, GEMINI_API_KEY) or ensure local Ollama is running at http://localhost:11434.
```

---

## Section 2: Fresh-Clone / Zero-Context User Simulation

### Launching Python `main.py`
We simulated a fresh-clone launcher run:
- **Dependency Auto-Install**: We found that `main.py` successfully triggers `npm install` for frontend dependencies. However, it does not auto-install Python packages (e.g. `fastapi`, `uvicorn`, `crewai`), which must be installed manually beforehand using the standard `pip install -r requirements.txt` instruction.
- **Outdated Running Instructions Fix**: The `README.md` previously instructed users to run legacy components:
  - Legacy backend: `agentos/ui/backend/main.py`
  - Legacy frontend: `agentos/ui/frontend`
  
  We corrected this in `README.md` to point users to the single-command launcher (`python main.py` / `python main.py --prod`) or the correct Phase 3 directories (`agentos/frontend`).

### local Ollama Execution (Free & Open Source Flow)
With local Ollama running and the `qwen2.5-coder` or `llama3.2` model pulled, users can build and execute squads completely offline without paid API keys. The fallback registry correctly registers these free local models and directs LiteLLM completion requests to them at zero cost.

---

## Section 3: CLI/API/UI Parity Audit

### Command & Route Parity Mapping
We audited the alignment between Typer CLI commands, FastAPI routes, and React UI controls:

| CLI Command | Equivalent FastAPI Route | Used in React UI? | Purpose / Status |
| :--- | :--- | :--- | :--- |
| `new-project` | N/A | No (Local-only scaffolding) | Local CLI project creation |
| `new-agent` | `POST /api/agents` | Yes (`Builder.tsx` & `Agents.tsx`) | Scaffold agent config |
| `new-tool` | `POST /api/tools` | Yes (`Tools.tsx`) | Scaffold tool stub |
| `new-crew` | `POST /api/crews` | Yes (`Crews.tsx`) | Assemble agents into a crew |
| `new-mcp-plugin` | `POST /api/mcp-plugins` | No (Admin/CLI only) | Create new local MCP connector |
| `validate` | N/A (Server auto-validates) | No | Check project syntax |
| `list-agents` | `GET /api/agents` | Yes (`Agents.tsx`) | List agents |
| `list-tools` | `GET /api/tools` | Yes (`Tools.tsx`) | List tools |
| `list-crews` | `GET /api/crews` | Yes (`Crews.tsx`) | List crews |
| `list-missions` | `GET /api/missions` | Yes (`Missions.tsx`) | List missions |
| `run-project` | `POST /api/missions/{id}/run` | Yes (`Missions.tsx`) | Execute mission |
| `build-agent` | `POST /api/builder/agent` | Yes (`Builder.tsx`) | AI-generated agent configs |
| `build-tool` | `POST /api/builder/tool` | Yes (`Builder.tsx`) | AI-generated tool stubs |
| `build-crew` | `POST /api/builder/crew` | Yes (`Builder.tsx`) | AI-assembled crew configs |
| `keygen` | N/A | No (Local-only developer command) | Create keypair for packaging |
| `pack-build` | `POST /api/packaging/build` | Yes (`Packaging.tsx`) | Build `.agentpack` |
| `pack-sign` | `POST /api/packaging/sign` | Yes (`Packaging.tsx`) | Sign pack with private key |
| `pack-verify` | `POST /api/packaging/verify` | Yes (`Packaging.tsx`) | Verify pack signature |
| `pack-install` | `POST /api/packaging/install` | Yes (`Packaging.tsx`) | Install pack and verify license |

- **Duplicate Logic Extraction**: In the previous session, all duplicate squad/mission loading logic in the CLI was removed, and both `cli/main.py` and `server/run_manager.py` now share the single, unified `build_squad_from_project` implementation in `agentos/core/project_ops.py`. There is **ZERO** business logic duplication between them.

---

## Section 4: Governance & Security Claims Audit

### Surface Block in UI
We verified that when a governance policy blocks a task execution, the mission is marked as `failed` in the SQLite DB, and the backend returns the error reason cleanly.
The React UI `RunDetail.tsx` renders this error inside a distinctive red banner with a warning icon:
```
Error: Task execution blocked by policy: Security policy violation: Prohibited action 'create malware' in task
```
There are no raw 500s or silent failures.

### Robustness Level and Evasions
We audited the regex/substring safety filter in `GovernanceEngine` (substring lowercase checking) and documented its limitations in `PHASE3_LIMITATIONS.md`:
- **Finding**: Substring checking is fragile. Simple variations (like `"cracking passwords"`, `"brute-force"`, `"exploits vulnerabilities"`) bypass the `"crack password"`, `"brute force"`, and `"exploit vulnerability"` filters respectively.
- **Resolution**: Appended a dedicated **Governance Filter is Easily Bypassed (Keyword-Only)** section in `PHASE3_LIMITATIONS.md` to prevent overclaiming safety guarantees.

### MCP Declarative-Only Warning
We verified that `agentos/mcp/plugin_loader.py` logs a clear runtime warning when plugins declare permissions:
```
WARNING: MCP plugin '...' requests permissions [...]. NOTE: Permission checks are declarative-only in Phase 3 and are not enforced at runtime.
```

---

## Section 5: Packaging/Licensing Correctness Audit

### Advanced File Tamper Checks
We wrote and ran extensive unit tests (`test_more_tamper_variants`) checking multiple signature/tampering variants:
1. Modifying a file inside the pack zip.
2. Replacing the signature bytes with random garbage of the correct Ed25519 signature length.
3. Swapping out the public key raw bytes.
All test cases return `False` during verification.

### Private Key Isolation
We verified that the `.gitignore` at the project root contains:
```gitignore
*.pem
*.key
*.agentpack
keys/
```
This isolates developer-generated private keys (`private.pem`) and stops them from accidentally getting committed to version control.

### Free Pack License Exemption
We verified that commercial license check prompts are skipped for packs configured with `license_required: false` (or empty license properties) by refactoring `_check_license_for_project` in `agentos/server/run_manager.py` to route through the unified `check_license_before_run` hook.

---

## Section 6: Dependency & License Compliance Audit

### License Compliance Check
We audited the license of each dependency to verify MIT/Apache-2.0 compatibility:
- **FastAPI, Pydantic, Typer, Rich, pytest**: MIT (Compatible)
- **uvicorn, python-dotenv, jinja2**: BSD-3-Clause (Compatible)
- **litellm, langchain-core, crewai, chromadb, transformers**: Apache-2.0 (Compatible)
- **psycopg2-binary**: LGPL with commercial exceptions (Compatible)

### Core Packaging & Licensing Fixes
1. **Added root `LICENSE` file**: The project declared MIT license in the README but did not ship with a `LICENSE` file. We created the MIT license file at the project root.
2. **Fixed `requirements.txt`**: Added core packages (`crewai`, `litellm`, `langchain-core`, `typer`, `rich`, `cryptography`, `requests`, `pyyaml`) which were missing from the file despite being imported by core modules.

---

## Section 7: Documentation Honesty Audit

- **Federation Claim Softening**: Softened unverified claims in `README.md` and added a section in `PHASE3_LIMITATIONS.md` explaining that **Multi-Squad Federation** is a design concept and not currently backed by code implementation.
- **Prominent Limitations Link**: Added a direct link to `PHASE3_LIMITATIONS.md` at the bottom of `README.md` alongside `SECURITY.md` and `ETHICS.md` so that users are aware of framework limitations transparently.

---

## Section 8: Observed Verification Run Logs

### 1. Caching Optimization & Event Loop Safety
We resolved issues where CrewAI kickoff deadlocked or threw `RuntimeError` due to active event loop conflicts (e.g. inside `pytest-asyncio` or FastAPI thread contexts).
- We modified `Agent.execute` to delegate `crew.kickoff()` to a thread executor using `loop.run_in_executor`.
- We overrode both `call` and `acall` in `AgentOSCrewAILLM` to ensure that CrewAI always routes LLM requests through our mock/routed client.
- We cached the Ollama reachability probe (`check_ollama_reachable`) using `@functools.lru_cache`, which dropped full test execution time from multiple minutes to under **17 seconds**.

### 2. Full Pytest Execution Output
```
============================= test session starts =============================
platform win32 -- Python 3.11.9, pytest-9.0.1, pluggy-1.6.0
rootdir: C:\Users\mujum\OneDrive\Desktop\Agent OS
plugins: anyio-4.12.0, langsmith-0.9.3, asyncio-1.3.0
asyncio: mode=Mode.STRICT, debug=False, asyncio_default_fixture_loop_scope=None, asyncio_default_test_loop_scope=function
collected 40 items

agentos\packaging\tests\test_packaging.py ......                         [ 15%]
agentos\server\tests\test_api.py ......                                  [ 30%]
agentos\tests\test_agent.py .......                                      [ 47%]
agentos\tests\test_cybersecurity.py ......                               [ 62%]
agentos\tests\test_rag.py ..                                             [ 67%]
agentos\tests\test_security_tools.py ...                                 [ 75%]
agentos\tests\test_squad.py ......                                       [ 90%]
agentos\tests\test_umb.py ....                                           [100%]

====================== 40 passed, 194 warnings in 16.73s ======================
```

---

## Section 9: Framework Extensibility Audit (Phase 5)

### Findings & Registry Gap
During a diagnostic audit, it was discovered that `AgentRegistry` and `ToolRegistry` existed as helper classes but were never wired into the actual execution pipeline of `build_squad_from_project`. Every agent was hardcoded to a plain `crewai.Agent`, making it impossible for custom agent subclasses or external packages to register and run custom Agent types.

### Phase 5 Resolution
1. **Wired Registry to Execution**: Modified `build_squad_from_project` to check `agent_cfg.type`. If it is `"Agent"` or absent, the plain CrewAI agent path is kept. If it is a custom registered type, it is resolved via the singleton `AgentRegistry` and converted via `.to_crewai_agent()`.
2. **Built-in Registrations**: Bootstrapped the registry at startup to register built-in subclasses like `ResearcherAgent`, `SecurityAgent`, and `ScriptAuthorAgent`.
3. **External Entry Points Discovery**: Integrated Python entry point scanning for `agentos.agents`, `agentos.tools`, and `agentos.mcp_plugins`. This allows third-party packages to dynamically inject custom Agents, Tools, and MCP Plugins with clean error isolation (broken packages do not crash AgentOS startup).
4. **Visibility & Diagnostics**: Added CLI commands `list-agent-types` / `list-tool-types` and equivalent HTTP endpoints to provide full runtime visibility into registered types.


---

## Section 10: Security Agent Tool Registry & Signature Fixes (Phase 6)

### Findings: Uncaught Bug in SecurityAgent Tool Registration
During a targeted diagnostic audit, two related registry and signature mismatch bugs were found:
1. **Unregistered Built-in Tools**: Built-in security tools (`FirewallAudit`, `LogAnalyzer`, `PermissionAudit`, `SystemHardening`, `NetworkMetadataInspector`, `SIEMScriptBuilder`) were implemented as plain Python classes with static methods. They did not inherit from `BaseTool` or register into `ToolRegistry`, making them invisible to the framework's registry CLI and API.
2. **Signature Mismatch**: `SecurityAgent` called `self.register_tool(name, tool_func)` (a name-callable pair), whereas the base `Agent.register_tool` method expects a single `BaseTool` instance. This mismatch was never caught because `SecurityAgent` was never instantiated or executed in any existing tests.

### Phase 6 Resolution
1. **Converted to BaseTool**: Refactored all 6 built-in security tools to inherit from `BaseTool`, implementing `run(**kwargs)` while preserving their static methods for backward compatibility.
2. **Registered in Bootstrap**: Added explicit registration for all 6 built-in security tools in `register_builtin_components()` in `agentos/core/bootstrap.py` during framework startup.
3. **Corrected Tool Registration Calls**: Updated `SecurityAgent`'s `_register_cybersecurity_tools()` to look up tool instances from `ToolRegistry` and register them using `self.register_tool(tool_instance)` matching the single-argument base signature.
4. **Wrapped Callables**: Created `SecurityWrapperTool` to wrap dynamic MCP tool async callables cleanly under the `BaseTool` interface, and updated `run_tool` on `SecurityAgent` to seamlessly support both sync and async callable/BaseTool executions.
5. **E2E Test Coverage**: Added a comprehensive E2E test file `agentos/tests/test_security_agents_e2e.py` to instantiate and execute tools via `SecurityAgent` and generate scripts via `ScriptAuthorAgent`. The test was verified to fail when the signature fix was reverted, proving it successfully exercises the corrected path.


