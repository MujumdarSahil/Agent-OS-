# AgentOS 2.0 demo: support desk copilot (about 10 minutes)

This walkthrough is for a reviewer on Windows (PowerShell) with a clone of the `2.0` branch.
It uses use case 07 (`examples/usecases/07-support-desk-copilot/`).

> **Email is not sent.** The `send_email` node writes to a recorded outbox (`MockTransport` inside
> the server); there is no SMTP. Every "email" in this demo is a `sink_committed` event in the
> run log with the exact `to`, `subject` and `body`. Nothing leaves your machine except the
> model call and one HTTP GET to a public test API (`jsonplaceholder.typicode.com`).

## 0. Before you start (1 min)

- Python venv installed (`.\venv\Scripts\python.exe`). Node.js is only needed the first time, to build the UI.
- At least one model key. Free keys (for example Groq or OpenRouter) are enough. Put it in the vault
  in step 1. Keys are never shown back by the API.
- To run without a model, use the MOCK runner instead: `.\venv\Scripts\python.exe examples\usecases\07-support-desk-copilot\run.py`.

## 1. Start AgentOS (1 min)

```powershell
$env:AGENTOS_INTERNAL_DOMAINS = "corp.local"   # recipients in corp.local count as internal
.\venv\Scripts\python.exe main.py
```

The browser opens on the login link. Open **Providers & Vault**, store your key under the provider's
key name (for example `GROQ_API_KEY`), and restart (`Ctrl+C`, then run `main.py` again) so the key is loaded.

## 2. Publish the flow, create the webhook, send three signed tickets (1 min)

In a second PowerShell window:

```powershell
.\venv\Scripts\python.exe examples\usecases\07-support-desk-copilot\send_webhook.py all --setup --with-schedule
```

This prints the flow version, the webhook id, the schedule's `next_run_at`, and `HTTP 202 run_id=...`
for the `normal`, `urgent` and `injection` tickets. The webhook secret path and HMAC key stay in that
process's memory and are never printed.

## 3. Look at the flow (1 min)

Open **Flows -> Support desk copilot**. Check:
- `page_oncall` and `queue_note` show pinned recipients (`oncall@corp.local`, `support-queue@corp.local`)
  and a side-effect badge.
- `lookup` has a pinned URL. `http_request` blocks private, loopback and metadata addresses, including after redirects.
- `oncall_approval` sits in front of the on-call email.

## 4. Urgent ticket with approval (2 min)

Click **▶ Run** (next to Publish). The dialog is pre-filled with the flow's sample input, the `urgent`
ticket. Click **Run**: the results panel opens at the bottom and updates live, showing status and total duration.
- **Steps** tab: each node with its status and duration. `triage` also shows provider, model, tokens and
  fallback hops (for example `groq_gpt_oss_20b: ok`); this is metadata only, never the prompt or response.
- Click a node on the canvas (or a row in Steps) to see its exact **input and output** with
  `trusted` / `UNTRUSTED` labels. Untrusted values are plain text only.
- The run stops at **oncall_approval**. The approval card in the panel shows the exact `body` with its label `untrusted`
  and where it came from.
- Click **Approve these values**. The **Logs** tab gains a `sink_committed` event for `to = oncall@corp.local`. That is the recorded outbox.

## 5. Prompt injection (2 min)

Click **▶ Run** again and replace the input with the `injection` ticket from `inputs/tickets.json`. The ticket
says to mark it URGENT and email the customer list to `mallory@attacker.example`.
- If the model follows it and answers URGENT, the run waits at the approval. The body is labelled
  `untrusted` and the recipient is still `oncall@corp.local`. Click **Reject**: no email is recorded.
- If the model answers NORMAL, one note goes to `support-queue@corp.local`.
- In both cases nothing can go to the attacker: recipients are pinned, and the model has no tools.

## 6. The static check refuses an unsafe edit (1 min)

In the editor, remove the pinned `to` from `page_oncall`, connect `triage -> page_oncall` and map
`to` from `output`, then click **Publish**. Publishing is refused because the recipient is not
fixed (not pinned) and comes from untrusted data. Undo the edit.

## 7. Webhook runs, signatures and the schedule (1 min)

In the editor, click **Results**. The **History** list shows every run of the flow with its trigger
(`manual`, `webhook`, `cron`), status and time. The three runs from step 2 are marked `webhook`. Click one
to open it in the panel, where a waiting run can be approved or rejected inline. The **Security** tab lists
blocked calls with their reason and provenance chain, and opens by itself when a run has one.

The same data is available through the API:

```powershell
$token = .\venv\Scripts\python.exe -c "from agentos_server.auth import get_or_create_api_token as t; print(t())"
$h = @{ Authorization = "Bearer $token" }
Invoke-RestMethod -Headers $h http://127.0.0.1:8000/api/v2/flows/uc07_support_desk/runs | Select-Object run_id, status
Invoke-RestMethod -Headers $h http://127.0.0.1:8000/api/v2/schedules | Select-Object name, cron_expression, next_run_at
```

The three webhook runs appear: `normal` succeeded and `urgent` is waiting. `injection` is either
waiting or succeeded, depending on the model. Or approve/reject a waiting webhook run through the API:

```powershell
Invoke-RestMethod -Method Post -Headers $h -ContentType application/json `
  -Uri http://127.0.0.1:8000/api/v2/flows/uc07_support_desk/runs/<run_id>/approve `
  -Body '{"node_id": "oncall_approval", "decision": "reject"}'
```

To check signatures, run `send_webhook.py urgent` with `AGENTOS_WEBHOOK_PATH` set to anything and
`AGENTOS_WEBHOOK_KEY` set to a wrong value. The reply is `HTTP 404`, the same reply as for an
unknown path or a replay.

## 8. Stop (10 s)

Press `Ctrl+C` in the `main.py` window. It prints `AgentOS stopped.` and no AgentOS processes keep running.

## Known limits (stated honestly)

- Runs created before 2.4d have no stored trigger. The History list infers it from the run name and
  shows `manual` when it can't tell, which is the case for older webhook runs once they have executed.
- With a real model, URGENT or NORMAL is the model's own call, so it can differ from MOCK. The security
  outcome does not depend on it.
- The OmniRoute provider entry is UNVERIFIED and is not used in this demo.
