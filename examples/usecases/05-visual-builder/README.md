# Use Case 05: Visual Flow Builder and Run View (sub-milestone 2.4)

## 1. Scenario
A support lead builds the use case 01 email-summary flow in the browser instead of writing JSON:
a webhook feeds an agent that may call `send_email`. The builder must make the security model
visible: the static check refuses an unsafe flow and points at the exact node and path, runs show
live node status, and an operator approving an outgoing email sees the **exact** argument values,
with values from outside sources clearly marked **untrusted** and shown as plain text.

## 2. What this demonstrates
| Capability | Where | Test (label) |
|---|---|---|
| Palette and config forms generated from `GET /api/v2/node-specs` (no hard-coded node types) | `ui/src/pages/FlowEditor.tsx` | `builder.spec.ts` (MOCK) |
| Pinned args, edge argument mapping from schemas, bounded-loop edges drawn dashed | `FlowEditor.tsx`, `flow/canvasParts.tsx` | `builder.spec.ts` (MOCK; loop edge rendering not covered by a spec) |
| Client-side DAG/schema validation, explicit Save, server validation on save | `flow/flowGraph.ts` | `builder.spec.ts` (MOCK) |
| Publish refusal: violations listed (node, arg, path, reason) and path highlighted | `FlowEditor.tsx` | `builder.spec.ts` (MOCK) |
| Run with JSON input ("inputs are treated as untrusted"), live node status over WebSocket | `flow/RunPanel.tsx` | `builder-run.spec.ts` (MOCK) |
| Reconnect replays only missed events (`after_seq`), no gaps or duplicates | `RunPanel.tsx`, WS route | `builder-run.spec.ts` (MOCK) |
| Approval card shows exact sink args with UNTRUSTED marking (THREAT_MODEL T-14) | `RunPanel.tsx` | `builder-run.spec.ts` (MOCK) |
| Untrusted values rendered as plain text only; no remote loads (T-12) | `UntrustedText` in `RunPanel.tsx` | `builder-run.spec.ts` (MOCK) |
| Blocked call: reason and provenance chain | `flow/runModel.ts` | `builder-run.spec.ts` (MOCK-UI, synthetic event stream) |

## 3. Files
- `flows/benign.flow.json`: use case 01 flow exported from the builder (recipient pinned). Publishes.
- `flows/attack.flow.json`: exfiltration variant exported from the builder (recipient not pinned).
  Publish is refused: `agent_node` / `send_email.to` / path `webhook_in → agent_node → send_email`.
- `flows/notify.flow.json`: manual trigger → `send_email` with pinned internal recipient (runnable in MOCK).
- `flows/approval.flow.json`: webhook → approval gate → `send_email` (runnable in MOCK).

The Playwright specs live in `ui/e2e/` (`builder.spec.ts`, `builder-run.spec.ts`) because they need
the UI's Node dependencies; they read the flow files from this folder. The specs check that what the
builder exports equals `benign.flow.json` / `attack.flow.json` (ids aside).

## 4. Walkthrough (MOCK)
Start the backend with the opt-in in-process worker and a mock LLM, then the UI dev server:

```powershell
$env:AGENTOS_MOCK_LLM="1"; $env:AGENTOS_INPROCESS_WORKER="1"; $env:AGENTOS_INTERNAL_DOMAINS="corp.local"
.\venv\Scripts\python.exe -m uvicorn agentos_server.app:create_app --factory --host 127.0.0.1 --port 8000
```
```powershell
cd ui; npm run dev
```
Open the one-time link printed by the server, then:

1. **Flows → New flow** `uc05_demo`. Add node `webhook_in` (palette: `webhook_trigger`), then
   `agent_node` (`agent`). Fill role/goal/backstory, tools `send_email`.
2. Pin `send_email.to` = `support@corp.local`. Click the canvas background, add edge
   `webhook_in → agent_node`, map `payload → task`. **Save**, then **Publish** → "Published version 1".
3. Remove the pinned recipient, **Save**, **Publish** → refused; the violation table lists
   `agent_node · send_email.to · webhook_in → agent_node → send_email` and the nodes/edge turn red.
4. Create `flows/approval.flow.json` through the API (`POST /api/v2/flows`, then
   `POST /api/v2/flows/uc05_approval/publish`), open it, click **Run panel**, run with
   `{"to": "partner@corp.local", "body": "<img src=x> **hi**"}`. The approval card shows both
   values marked UNTRUSTED, as literal text. **Reject** → run `failed`, reason
   `rejected_by_operator`, sends `0`. Run again and **Approve** → `succeeded`, sends `1`.
5. While a run waits, click **Reconnect stream**: the event list stays gap-free (missing events `0`).

Stop both servers (Ctrl+C) when done.

## 5. Run the automated checks
```powershell
cd ui; npm run test:e2e:builder
```
The Playwright config starts uvicorn (temp FileStorage project, `AGENTOS_MOCK_LLM=1`,
`AGENTOS_INPROCESS_WORKER=1`) and the Vite dev server, and stops both when done. CI runs the same
command in the `ui-e2e` job.

## 6. Limits (honest scope)
- MOCK only: `send_email` goes to `MockTransport`; nothing is delivered.
- Agent nodes are not *run* in these specs (a MOCK agent needs a scripted CrewAI LLM); the agent
  flows are exercised for build/save/publish only. The blocked-call view is verified with a
  synthetic event stream, not a live runtime block.
- `AGENTOS_INPROCESS_WORKER` is opt-in and off by default; without it, runs stay `queued`.
