# AgentOS Framework

[![CI Build Status](https://github.com/MujumdarSahil/Agent-OS-/actions/workflows/ci.yml/badge.svg)](https://github.com/MujumdarSahil/Agent-OS-/actions)

AgentOS is a workflow engine for AI agents that is built to stay safe when the content it reads is hostile. You draw a flow in the browser (a webhook, schedule or manual trigger, agents, HTTP calls, conditions, approvals, and actions such as email) and AgentOS runs it. Every value carries a security label at the workflow level: data from webhooks, web pages, emails and tools is untrusted, so it can never choose who receives an email, which URL is called or whether a destructive action runs. Unsafe flows are refused when you publish them and blocked again at run time. When a person should decide, the flow stops at an approval that shows the exact call it would release. Model calls go through LiteLLM with a fallback order across free providers and an encrypted key vault, so one provider's outage or rate limit does not stop a flow. The status of each feature (verified, experimental or planned) is listed below, and the v1 Python API is documented in [docs/v1/README_v1.md](docs/v1/README_v1.md).

## Getting started

This walks you from a clean machine to the visual flow builder running in **MOCK mode**: no API keys,
no cost, a simulated LLM, and emails that are never actually sent.

> Verified from a fresh clone on Windows 11 / PowerShell 5.1 (see `docs/evidence/raw/2.3-cp3-readme-quickstart.txt`).
> The macOS/Linux commands are the direct equivalents but were not run on macOS/Linux in that check.

### 1. Prerequisites

| Tool | Version | Needed for |
|---|---|---|
| Python | 3.11 | backend (`requires-python >= 3.11`) |
| Node.js | 20.19+ or 22.12+ (required by Vite 8) | web UI |
| Git | any recent | cloning |
| Docker Desktop | any recent | **only** Platform mode (MongoDB/Redis) |

### 2. Get the code and install

Windows PowerShell:
```powershell
git clone https://github.com/MujumdarSahil/Agent-OS-.git agentos
cd agentos
git checkout 2.0
python -m venv venv
.\venv\Scripts\python.exe -m pip install --upgrade pip
.\venv\Scripts\python.exe -m pip install -e .
cd ui
npm install
cd ..
```

macOS / Linux:
```bash
git clone https://github.com/MujumdarSahil/Agent-OS-.git agentos
cd agentos
git checkout 2.0
python3.11 -m venv venv
./venv/bin/python -m pip install --upgrade pip
./venv/bin/python -m pip install -e .
cd ui && npm install && cd ..
```

### 3. Quick start in MOCK mode (no API keys, no cost)

Use two terminals, both starting in the `agentos` folder.

**Terminal 1: backend.** These variables turn on the mock LLM, let runs started from the UI
actually execute (in-process worker), and trust `corp.local` as an internal email domain for the
examples (no domain is trusted by default).

Windows PowerShell:
```powershell
$env:AGENTOS_MOCK_LLM = "1"
$env:AGENTOS_INPROCESS_WORKER = "1"
$env:AGENTOS_INTERNAL_DOMAINS = "corp.local"
$env:AGENTOS_PROJECT = "demo"
.\venv\Scripts\python.exe -m uvicorn agentos_server.app:create_app --factory --host 127.0.0.1 --port 8000
```

macOS / Linux:
```bash
export AGENTOS_MOCK_LLM=1 AGENTOS_INPROCESS_WORKER=1 AGENTOS_INTERNAL_DOMAINS=corp.local AGENTOS_PROJECT=demo
./venv/bin/python -m uvicorn agentos_server.app:create_app --factory --host 127.0.0.1 --port 8000
```

**Terminal 2: web UI.**
```bash
cd ui
npm run dev
```

**Open the app.** The backend prints a box with `One-Time UI Access Link: http://localhost:5173/#token=…`.
Open that link: the token is stored for the browser session and removed from the address bar. The
same token is saved in `~/.agentos/api.token` if you need to paste it into the login screen.

**First thing to try:** build and publish the use case 01 flow in the visual builder (**Flows → New
flow**). The step-by-step walkthrough is in
[examples/usecases/05-visual-builder/README.md](examples/usecases/05-visual-builder/README.md):
publish the safe version (recipient pinned), then remove the pinned recipient and watch publish refuse
the unsafe version and highlight the path.

### 4. Using a real model

1. Open **Providers & Vault** in the UI and add the API key for your provider. Keys are stored
   encrypted in the vault, and the API never returns them in plain text.
2. Stop the backend, start it again **without** `AGENTOS_MOCK_LLM` (PowerShell:
   `Remove-Item Env:AGENTOS_MOCK_LLM`; macOS/Linux: `unset AGENTOS_MOCK_LLM`).
3. Real model calls cost money with your provider. Not covered by the automated checks.

### 5. Platform mode (optional: MongoDB + Redis)

Standalone mode (above) keeps everything in files and in memory. Platform mode stores data in
MongoDB and uses Redis for the queue. Start Docker Desktop first, then:

```bash
./venv/bin/python -m pip install -e ".[platform]"     # Windows: .\venv\Scripts\python.exe -m pip install -e ".[platform]"
sh docker/mongo-init.sh                               # Windows: pwsh docker/mongo-init.ps1 ; prints AGENTOS_MONGO_URI
docker compose -f docker/compose.mongo.yml up -d --wait
sh docker/redis-init.sh                               # Windows: pwsh docker/redis-init.ps1 ; prints AGENTOS_REDIS_URI
docker compose -f docker/compose.redis.yml up -d --wait
```
Set `AGENTOS_MONGO_URI` and `AGENTOS_REDIS_URI` to the printed values (they contain generated
passwords: keep them out of files you commit), then start the backend as in step 3.

> These are the scripts and compose files the CI `mongo-live` and `redis-live` jobs use; they were not
> re-run for this README because Docker Desktop was not running.

### 6. Stopping everything

- Press **Ctrl+C** in both terminals.
- Platform mode: `docker compose -f docker/compose.mongo.yml down` and
  `docker compose -f docker/compose.redis.yml down` (data is kept in Docker volumes).

### 7. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `401 Unauthorized` / login screen keeps appearing | The token is missing or old. Open the newest one-time link from the backend output, or paste the contents of `~/.agentos/api.token`. |
| `Invalid Host header` | The API only answers on `localhost` / `127.0.0.1` (DNS-rebinding protection). Open `http://localhost:5173`, not a LAN IP or another hostname. |
| Runs stay `queued` forever | No worker is running. Start the backend with `AGENTOS_INPROCESS_WORKER=1`. |
| An email step is refused with "untrusted body … external recipient" | No internal domain is trusted by default. Set `AGENTOS_INTERNAL_DOMAINS` (or `security.internal_domains` in `agentos.config.yaml`). |
| `docker` commands fail / `--wait` never finishes | Docker Desktop is not running. Start it and check with `docker ps`. |
| `npm run dev` fails with "Cannot find native binding" | A broken `node_modules`. Delete `ui/node_modules` and run `npm install` again. |


## What AgentOS can do, in plain English

Status badges: **Works today (verified)** = covered by automated tests that run in CI in MOCK mode
(simulated LLM, fake network, no real emails); **Experimental** = present but partial or not fully
tested; **Planned** = not built yet. "Verified" never means tested against real paid providers.

**Flows and the visual builder** — *Works today (verified)*. You draw a workflow in the browser: a
trigger, agents, HTTP calls, conditions, approvals and actions such as sending an email, joined by
arrows that say which output feeds which input. Save it, then publish it as a fixed version. Use it
when you want an automation that people can read and review instead of a script.
Use cases: [05 visual builder](examples/usecases/05-visual-builder/README.md),
[06 HTTP and branching](examples/usecases/06-http-and-branching/README.md).

**Branching, waiting, sub-flows and error handling** — *Works today (verified)*. A flow can take
an if/else branch, join parallel branches, pause for a while and continue later, call another
published flow, and send a failed step to an error handler instead of failing the whole run.
Use it to model real processes ("if the page reports an incident, page on-call; otherwise do nothing").
Use case: [06 HTTP and branching](examples/usecases/06-http-and-branching/README.md).

**Calling web APIs safely** — *Works today (verified)*. The HTTP step can fetch pages and call APIs,
but it refuses internal and cloud-metadata addresses (SSRF), re-checks every redirect, caps response
size and time, and only lets outside data go to hosts an admin has allowlisted. Use it to pull data
into a flow without opening a door into your network.
Use case: [06 HTTP and branching](examples/usecases/06-http-and-branching/README.md).

**Triggers: webhooks and schedules** — *Works today (verified)*. Flows can start from a signed
webhook (with replay protection) or on a cron schedule. Use it to react to events from other systems
or to run something every morning.
Use case: [04 webhook trigger](examples/usecases/04-webhook-trigger/README.md); schedules are covered by
`agentos/tests/test_scheduler_2_2.py`.

**Agents and tools** — *Works today (verified) for agents calling built-in tools; Experimental for
MCP servers and stored custom tool code*. An agent node runs a CrewAI agent, but every tool call it
makes goes through an AgentOS proxy that checks it first. Use it when a step needs judgement, such as
summarising a ticket.
Use case: [01 email summary and exfiltration attempt](examples/usecases/01-email-summary-exfil/README.md).

**Providers, fallback and the vault** — *Works today (verified with mocked providers)*. You can
configure several LLM providers, set an order to fall back on when one fails, and pick a model per
node. API keys are stored encrypted and are never shown back. Use it to avoid depending on a single
provider. Real provider calls are not part of the automated checks.
Use case: [02 provider fallback](examples/usecases/02-provider-fallback/README.md).

**Security labels and blocked attacks** — *Works today (verified)*. Every value remembers where it
came from and whether it can be trusted. Data from webhooks, web pages, emails and tools is
untrusted, and it cannot choose who receives an email, which URL is called, or whether a destructive
action runs. Unsafe flows are refused when you publish and blocked again while running.
Use cases: [01](examples/usecases/01-email-summary-exfil/README.md),
[04](examples/usecases/04-webhook-trigger/README.md),
[06](examples/usecases/06-http-and-branching/README.md).

**Approvals** — *Works today (verified)*. A flow can stop and wait for a person to approve the exact
values that are about to be sent, with untrusted values clearly marked. Rejecting stops the run
without sending anything.
Use case: [05 visual builder](examples/usecases/05-visual-builder/README.md).

**Runs and the live view** — *Works today (verified)*. Each run shows live progress per step, a full
event history, and for anything blocked, the reason and where the data came from. The view reconnects
without losing events. Runs are queued and executed by a worker (in-process in Standalone mode).
Use cases: [03 queue and worker](examples/usecases/03-flow-queue-worker/README.md),
[05 visual builder](examples/usecases/05-visual-builder/README.md).

**Overview, runs and approvals** — *Works today (verified in MOCK)*. The home page (**Watch → Overview**)
shows what needs you now (waiting approvals, attacks blocked today, providers cooling down), counts of runs,
blocked attacks, waiting approvals and model calls for the last 24 hours or 7 days, recent runs with the
model that answered, approval cards with the exact call, the last blocked attacks with where their data came
from, and the provider fallback chain with its health. **Runs**, **Approvals**, **Triggers** and
**Security log** list the same data across all flows. Flows that would be too small to read left to right
open top to bottom. It shows only what AgentOS records: there is no cost or alerting yet (planned for 3.2
and 3.3), and refused publishes are not stored yet (planned for the 3.1 audit log).

**Packs** — *Experimental (v1 agent/tool packaging via `agentos pack`); Planned (2.0 packs carrying
flows, prompts and policies)*. Packs will let you share a ready-made automation and install it with
one command.

### Model providers and fallback (2.0 defaults)

- **Fallback Chain (2.4c defaults)**: A fresh workspace uses this order: **1) Groq GPT-OSS 20B** (`groq/openai/gpt-oss-20b`, fast, supports tool use), **2) Z.ai GLM-4.7 Flash** (`zai_glm_4_7_flash`), **3) OpenRouter Gemma 4 31B free**, **4) OpenRouter Nemotron 3 Nano Omni free**, **5) Groq Qwen 3.8 27B** (`groq/qwen/qwen3.8-27b`). Every other catalogue entry is disabled by default. That covers Groq GPT-OSS 120B (for heavier tasks), OpenAI, Anthropic, paid OpenRouter models, Gemini 2.0 Flash, DeepSeek Flash (`deepseek/deepseek-flash`, paid), Together, Fireworks, Z.ai GLM-5.3 and Hugging Face. It also covers the deprecated Groq Llama 3.3 70B and 3.1 8B (kept as disabled aliases), Groq Qwen 3 32B, and the OpenRouter free models that are no longer available (**GLM-5.2 free**, Laguna S 2.1 free and Mistral 7B free). Bring-your-own endpoints (`openai_compatible`, OmniRoute and local Ollama) are used only when you configure them. Enable any entry on the **Fallback** page; a saved fallback policy overrides these defaults. Keys come from the vault (or env). **LIVE-verified (owner run, 2.4c):** an agent flow end to end on `zai_glm_4_7_flash`, including fallback after an invalid first key. Other entries are routed by LiteLLM and covered only by the tests listed under Provider Verification Status. A failing provider is skipped for a cooldown (10 min for not-found, auth or no-balance errors; 60 s for transient ones), and each attempt times out after 20 s by default. For **OpenRouter Nemotron 3 Nano Omni free tier**: multimodal vision input is verified via recorded VCR cassette (`test_nemotron_3_nano_omni_vision`), but text-only completion (`openrouter_nemotron_3_nano_omni_free`) is unverified (captured upstream OpenRouter 504 Gateway Timeout / 400 degraded errors during recording; skipped pending clean live recording).
  > **Note on free tiers (OpenRouter, Z.ai):** Free endpoints have daily rate limits, and upstream terms may allow prompts and completions to be logged or used for training. **Do not send data labelled `secret` or sensitive internal payloads.** AgentOS enforces this for `secret`-labelled inputs by allowing only local providers (T-13). The Laguna S 2.1 free and GLM-5.2 free entries are kept in the registry, disabled, because OpenRouter no longer lists them.
  > **Note on Z.ai Models (`zai_glm_4_7_flash`, `zai_glm_5_3`):** International API platform integration (`https://api.z.ai/api/paas/v4`) using LiteLLM `zai/` routing and `ZAI_API_KEY` credentials. Entries remain labeled UNVERIFIED until live recorded cassettes are captured.
  > **Note on Vision-Capable Models:** Models such as `google/gemma-4-31b-it:free` and `nvidia/nemotron-3-nano-omni-30b-a3b-reasoning:free` support reading and analyzing image inputs (multimodal vision input). They perform image **reading/understanding only** and do NOT support image generation.
  > **Note on Hugging Face Plugin (Experimental / Untested):** Entry pattern provided for LiteLLM HF provider (`HUGGINGFACE_API_KEY` required). Unverified via VCR cassette tests until a user supplies an HF API key. Does NOT perform local model downloads or self-hosted serving.

## Screenshots

Taken in MOCK mode (simulated model, no keys, nothing sent) at 1440×900 by
`ui/e2e/builder-2.4e.spec.ts`, against a fresh test server with an empty vault.

![Overview](docs/images/overview.png)
*Overview: what needs you now, 24 h counts, recent runs and the model fallback chain with health.*

![Flow editor](docs/images/flow-editor.png)
*Use case 07 (support desk copilot) in the flow editor, opened top to bottom so the text stays readable.*

![Run inspect](docs/images/run-inspect.png)
*A finished run: Steps with durations, and the selected node's input with its labels (the ticket text is UNTRUSTED).*

![Approval](docs/images/approval.png)
*An approval shows the full call: `to` and `subject` are pinned in the flow; the body from the ticket is UNTRUSTED plain text.*

![Publish refused](docs/images/publish-refused.png)
*A flow that takes the email recipient from the ticket cannot be published; each refusal names the data path.*

![Security log](docs/images/security-log.png)
*Security log: a blocked request to the cloud metadata address, with its reason and provenance.*

![Models and keys](docs/images/models-and-keys.png)
*Models & keys: the provider catalogue and the encrypted vault (keys are never shown back).*

## ⚠️ Known Limitations & Claims Audit

AgentOS 2.0 (flows, labels, approvals, providers, UI):

- **Provider Verification Status**: Recorded VCR cassettes exist for the three Groq entries and for OpenRouter Gemma 4 31B, Laguna S 2.1 free, GLM-5.2 free and Nemotron (vision). The Groq, Laguna and GLM-5.2 cassettes are historical: those model IDs are deprecated or no longer listed, and the entries are disabled by default. OpenAI, Anthropic, Gemini and Ollama have no cassette; they have mock-level tests only. `zai_glm_4_7_flash` is **LIVE-verified** by the owner's 2.4c run. Together AI, Fireworks, DeepSeek (`deepseek-chat` is missing from DeepSeek's live list and awaits the owner's choice of ID), Hugging Face Inference API and `zai_glm_5_3` remain UNVERIFIED. For **OpenRouter Nemotron 3 Nano Omni**: multimodal vision processing is verified (`test_nemotron_3_nano_omni_vision` passes via offline cassette), while text completion (`openrouter_nemotron_3_nano_omni_free`) is unverified due to upstream 504 Gateway Timeout / 400 degraded errors recorded in its cassette, and is skipped pending fresh recording.
- **Local Ollama Probe Behavior**: Connectivity probe `check_ollama_reachable()` performs non-blocking HTTP probes (`http://localhost:11434/api/tags`) with a 1.0s timeout and non-fatal logging. When Ollama is offline, calls gracefully fall back to alternative providers in the fallback chain.
- **Screenshots and UI checks are MOCK**: the images above and the Playwright suites use a simulated model. Real-model behaviour (for example whether a model follows an injected instruction) can differ; the security outcome does not depend on it.
- **Overview data**: provider health comes from the server's in-memory circuit breaker (it resets on restart, and in Platform mode with separate workers it shows only the API process). Counts cover the newest 500 runs. SSRF blocks recorded before 2.4e are not counted as attacks. There is no cost, budget or alert data yet.
- **Refused publishes** are shown in the editor but not stored, so the Security log lists run-time blocks only (the 3.1 audit log will record refusals).
- **Vault startup check**: the Standalone vault file is checked at startup (it must parse and decrypt); the Platform (Mongo) vault is not.
- **Run history**: runs created before 2.4d have no stored trigger, so older webhook runs may show as `manual`.

Limitations of the v1 Python API (UMB backends, LangGraph, federation, planner, router) are listed in
[docs/v1/README_v1.md](docs/v1/README_v1.md#known-limitations-v1).

## More

- **v1 API and features** (agents, squads, governance, planner, cybersecurity extensions, ModelHub): [docs/v1/README_v1.md](docs/v1/README_v1.md).
- **AgentOS-SWE** (software verification and repair platform built on AgentOS): [README_SWE.md](README_SWE.md).

AgentOS includes two minimal teaching examples to show how agents, tools, and MCP servers connect:
- [Demo 1: Custom Local notes.json MCP Server](examples/mcp_demos/local_notes_server/) — stdio subprocess transport notes manager.
- [Demo 2: External Context7 Documentation MCP Server](examples/mcp_demos/context7_docs_lookup/) — remote, read-only documentation lookups.

See [SECURITY.md](docs/SECURITY.md), [ETHICS.md](docs/ETHICS.md), and [PHASE3_LIMITATIONS.md](docs/PHASE3_LIMITATIONS.md) for safety policies, ethics guidelines, and detailed framework specifications.

## License

MIT

## Contributing

Contributions welcome! Please see CONTRIBUTING.md for guidelines.
