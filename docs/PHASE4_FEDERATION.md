# Phase 4 Federation — Scope and Limitations

## What is Implemented

Phase 4 adds **sequential multi-squad federation**: two or more `Squad` instances that
run in order, where each squad receives the prior squad's output as context for its
first task.

### Features

- **Sequential handoff**: Squad A runs fully, then Squad B runs with Squad A's output injected
- **Federation-level checkpointing**: Each stage's completion is persisted independently
  in the existing `SQLiteCheckpointStore`. If Stage B fails, a re-run skips Stage A.
- **Resume across stage boundaries**: Not just within a squad's tasks (Phase 3) but
  across the entire federation sequence
- **CLI support**: `agentos federation new` + `agentos federation run`
- **API support**: `POST /api/federation/missions`, `POST /api/federation/missions/{name}/run`
- **Config files**: Federation configs stored in `federated_missions/*.yaml`

### Context Injection Mechanism

Stage B's FIRST task description is prepended with:
```
[CONTEXT FROM PREVIOUS STAGE]
<Stage A's full output text>
[END CONTEXT]

<original task description>
```

This is **string injection into the task description** — not structured data passing.
If the output is very long, the injected context may exceed the model's context window.
No truncation is currently applied (Phase 5+).

---

## Explicitly Out of Scope

The following features were **intentionally deferred** to future phases:

| Feature | Status | Reason |
|---|---|---|
| Parallel squad execution | Not implemented | Requires distributed coordination, async locking |
| Cross-squad shared memory | Not implemented | Memory scoping model not yet resolved |
| Dynamic routing (route to different squad based on output) | Not implemented | Requires output parsing + routing logic |
| Negotiation protocols between squads | Not implemented | Protocol design needed |
| Structured data passing between stages | Not implemented | Stage B gets plain text, not JSON schema |
| Fan-out (one squad → N squads in parallel) | Not implemented | Architecture TBD |
| N→1 merge (N squads → one aggregator) | Not implemented | Architecture TBD |

---

## Known Limitations

1. **String-only context injection**: Stage B receives Stage A's output as a string
   prepended to its first task. If Stage A produces structured JSON, Stage B sees the
   raw JSON string. This works for text pipelines but is clunky for structured workflows.

2. **Context window overflow**: If Stage A's output is very long and Stage B's first task
   already has a long description, the combined prompt may exceed the model's context window.
   Current behavior: the full context is injected without truncation. Add a `max_context_chars`
   config option to truncate if needed (Phase 5).

3. **No output from intermediate tasks**: Only the final `mission.result` (the squad's
   aggregate output) is passed to the next stage — intermediate task outputs are not accessible
   by later stages.

4. **Sequential only**: Stages run in strict order A → B → C. No parallelism is supported.
   For parallel execution, run multiple `FederatedMission` instances independently.

5. **Single-machine**: All squads run in the same process. Distributed federation across
   multiple machines is not implemented.

6. **API federation state is in-memory**: The `/api/federation/runs/{run_id}/status` endpoint
   stores run state in a Python dict. It is lost on server restart. The federation-level
   checkpoints in SQLite persist, but the run metadata (status, error message) does not.

---

## Example Usage

### CLI
```bash
# Create a federated mission
agentos federation new research-and-write \
  --squads research_crew,writing_crew \
  --missions research_report,publish_report \
  ./my-project

# Run it
agentos federation run research-and-write ./my-project

# Resume after failure
agentos federation run research-and-write ./my-project --resume
```

### Python
```python
from agentos.core.federation import FederatedMission, FederationStage
from agentos.core.project_ops import build_squad_from_project
from agentos.core.checkpoint import SQLiteCheckpointStore
import asyncio

store = SQLiteCheckpointStore("./my-project/checkpoints/run_history.db")
squad_a, mission_a = build_squad_from_project("./my-project", "research_report")
squad_b, mission_b = build_squad_from_project("./my-project", "publish_report")

fed = FederatedMission(
    federation_id="my-research-pipeline",
    stages=[
        FederationStage(squad=squad_a, mission=mission_a, stage_index=0, name="Research"),
        FederationStage(squad=squad_b, mission=mission_b, stage_index=1, name="Writing"),
    ],
    checkpoint_store=store,
)

result = asyncio.run(fed.run())
print(result["final_output"])
```
