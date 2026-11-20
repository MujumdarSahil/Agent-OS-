# AgentOS 2.0 demo: support desk copilot, alerts and real (local) email (about 20 minutes)

For a presenter on Windows (PowerShell) with a clone of the `2.0` branch. It uses use case 07
(`examples/usecases/07-support-desk-copilot/`) and, at the end, use cases 08 and 09.

Email in this demo is **real SMTP to a local test server** on `127.0.0.1:1025` (window W2). Nothing leaves
your machine except the model calls and one HTTP GET per ticket to a public test API
(`jsonplaceholder.typicode.com`).

**Colours, so you can explain them once:**
- **Box colours on the canvas are node types:** teal = trigger, purple = AI (agent / LLM), blue = logic
  (condition, merge, wait, loop, subflow), orange = action (email, Slack, HTTP), yellow = human (approval),
  green = security (validator, quarantined extraction), red = error handler.
- **Labels are about the data, not the box:** `trusted` (pinned by the flow author, or approved) and
  `UNTRUSTED` (came from outside: a ticket, a webhook, a web page, a tool, or a model that read any of those).

> **Screen sharing:** the login link that W1 prints, and the browser address bar right after you open it,
> contain your API token (`#token=...`). Don't share W1 while it starts, and share the browser only after the
> page has loaded (the UI removes `#token=...` from the address bar once you are signed in). Never type
> `$token` on its own in W3: that prints it.

## Reset before the demo (5 min, do it before people join)

Skip anything that does not apply on a fresh install.
- **Approvals** (Work → Approvals): **Reject** every old waiting approval, so the Overview starts clean.
- **Alerts** (Watch → Alerts): **Acknowledge** every open alert. In **Rules**, set **Attack blocked**'s
  cooldown back to **15** and untick **demo-mail** if a previous rehearsal left it on, then **Save**.
- **Notification channels**: if **demo-mail** already exists from a rehearsal, either keep it (and in step 4
  just click **Send test**) or delete it with the bin icon so you can add it live.
- **Unsafe flow from a rehearsal**: it is a draft that was never published, so it can be deleted. In W3 (after the
  first two lines of step 8):
  `Invoke-RestMethod -Method Delete -Headers $h -Uri http://127.0.0.1:8000/api/v2/flows/uc07_support_desk_unsafe`
- **Billing plan**: set the Groq row back to **Default** if you want to show the change live in step 2.
- Every `send_webhook.py ... --setup` creates another webhook (and, with `--with-schedule`, another schedule).
  Old ones are harmless; delete them in **Build → Triggers** if the list looks cluttered.

## 0. Setup (2 min)

You need: the venv (`.\venv\Scripts\python.exe`), the built UI (`ui\dist`; `main.py` builds it if it is missing
and Node.js is installed), and one free model key (for example Groq) stored in **Connect → Models & keys** under
its key name (for example `GROQ_API_KEY`). Restart AgentOS once after storing a key so it is loaded.

Open three PowerShell windows in the repo folder (Explorer → right-click the folder → **Open in Terminal**).
Each prompt must start with `PS`. If it doesn't, you are in cmd, not PowerShell.

**W1: AgentOS**
```powershell
$env:AGENTOS_INTERNAL_DOMAINS="corp.local"
.\venv\Scripts\python.exe main.py
```
`corp.local` recipients count as internal. The browser opens on the login link (see the warning above).

**W2: local mail server** (prints every email it receives)
```powershell
.\venv\Scripts\python.exe -m pip install aiosmtpd==1.4.6   # once
.\venv\Scripts\python.exe -m aiosmtpd -n -l 127.0.0.1:1025
```

**W3: commands.** Leave it at the prompt.

*Say:* "One process is AgentOS, one is a pretend mail server on this laptop, so every email we send today
lands in that window, and one is for commands."

## 1. Overview tour (1 min)

**Watch → Overview.** Point at **Needs you now** (waiting approvals, attacks blocked today, providers cooling
down, unacknowledged alerts), the KPIs (switch **24 h / 7 d**), recent runs with the model that answered,
approval cards, blocked attacks, the provider fallback chain and the **Spend** card.

*Say:* "This page shows only what AgentOS actually recorded: no made-up numbers."

## 2. Models & keys: Groq on the free plan (1 min)

**Connect → Models & keys.** In the providers table, find the Groq row your chain uses first (for example
`groq_gpt_oss_20b`) and set **Billing plan** to **Free plan ($0)**.

*Say:* "Groq's free tier isn't tagged as free in the price tables. Setting the plan tells AgentOS these calls
cost nothing, so a dollar budget will never block them. The change is in the audit log."

## 3. Publish the flow, webhook, schedule, three tickets (1 min)

In **W3**:
```powershell
.\venv\Scripts\python.exe examples\usecases\07-support-desk-copilot\send_webhook.py all --setup --with-schedule
```
It prints `flow uc07_support_desk: saved`, `published vN`, `webhook ...: created (secret path and key kept in
memory, not shown)`, the schedule's `next_run_at`, and `HTTP 202 run_id=...` for `normal`, `urgent` and
`injection`.

*Say:* "That published the flow, created a signed webhook and a daily schedule, and sent three tickets the way a
helpdesk would. The webhook secret never leaves that process."

## 4. Notification channel: email to the local server (2 min)

**Connect → Notification channels → Email (SMTP)**. Fill in:

| Field | Value |
| --- | --- |
| name | `demo-mail` |
| SMTP host | `127.0.0.1` |
| port | `1025` |
| Security | **None (local test server only)** |
| username / password | leave empty |
| From address | `agentos@corp.local` |
| alert recipients | `admin@corp.local` |
| allowed recipient domains | `corp.local` |
| use for flows (send_email) | tick |
| allow insecure local | tick |

Click **Add email channel**, then **Send test** on the `demo-mail` row. **W2** prints the test message from
`agentos@corp.local` to `admin@corp.local`.

*Say:* "Plaintext is allowed only because the host is this laptop and I ticked 'allow insecure local'. For a real
mail server AgentOS requires TLS and checks the certificate. Passwords go to the encrypted vault and are never
shown again. The From address is fixed here; a flow can't change it."

## 5. Urgent ticket with approval (3 min)

**Build → Flows → Support desk copilot.** Click **▶ Run** (next to Publish). The dialog is pre-filled with the
`urgent` ticket. Click **Run**. The results panel opens and updates live.
- **Steps** tab: every node with status and duration; `triage` shows provider, model, tokens and fallback hops
  (metadata only, never the prompt or the answer).
- **Node inspector:** click a row in **Steps**, or click a node on the canvas, to see its exact input and output with
  `trusted` / `UNTRUSTED` labels. If you can't see it, scroll down inside the panel, or click **Results below** in
  the editor toolbar to dock the panel under the canvas.
- The run stops at **oncall_approval**. The approval card shows the exact values: `to = oncall@corp.local` marked
  pinned and `trusted`; `body` marked `UNTRUSTED` (it came from the ticket), shown as plain text.
- Click **Approve these values**. **W2** prints the email to `oncall@corp.local`.

*Say:* "The recipient was fixed by the flow author, so the model can't change it. The text came from a customer,
so it is marked untrusted, and a person approved exactly what was sent."

## 6. Prompt injection (3 min)

In the results panel's **History** list, open the runs marked `webhook` from step 3. Open the `injection` run and
inspect the `ticket` and `triage` nodes: their input is labelled `UNTRUSTED`. The ticket says to mark it URGENT
and email the customer list to `mallory@attacker.example`. A real model may or may not follow it. If the run is
waiting, the recipient on the card is still `oncall@corp.local`; click **Reject** (nothing is sent).

To show the case where the model *is* fooled, run the use case with a scripted model that obeys the injection.
In **W3**:
```powershell
$env:AGENTOS_MOCK_LLM="1"; .\venv\Scripts\python.exe examples\usecases\07-support-desk-copilot\run.py
```
Point at the two injection lines:
- `[PASS] injection: ... body_label=untrusted after_reject=failed outbox=0 to_attacker=False`
- `[PASS] injection approved anyway: card to=oncall@corp.local (pinned, trusted) outbox=['oncall@corp.local'] to_attacker=False`

Then **always** clear the variable so nothing else in W3 runs in MOCK mode:
```powershell
Remove-Item Env:AGENTOS_MOCK_LLM
```

*Say:* "Even a fooled model can only flip the branch to URGENT. Even if the approver clicks Approve, the email can
only go to the pinned on-call address. There is no path to the attacker."

## 7. Alerts: route "Attack blocked" to email (1 min)

**Watch → Alerts → Rules.** In the **Attack blocked** row tick **demo-mail**, set the cooldown to **0** (so every
attempt in the demo sends), and click **Save**.

*Say:* "Alerts exist from the first start, but nothing is sent until an admin picks a channel. The rule change is
audited."

## 8. Unsafe flow: publish refused, alert email (2 min)

In **W3**, these four lines create the shipped unsafe variant, where the email recipient comes from the ticket:
```powershell
$token = .\venv\Scripts\python.exe -c "from agentos_server.auth import get_or_create_api_token as t; print(t())"
$h = @{ Authorization = "Bearer $token" }
$flow = Get-Content -Raw examples\usecases\07-support-desk-copilot\flows\support_desk_unsafe.flow.json
Invoke-RestMethod -Method Post -Headers $h -ContentType application/json -Uri http://127.0.0.1:8000/api/v2/flows -Body $flow | Select-Object id, name
```
The first line stores the token in `$token` without printing it. Don't type `$token` on its own.
The last line prints only the flow id and name. If it says the draft already exists, see "Reset before the demo".

**Build → Flows → Support desk copilot (UNSAFE: recipient from the ticket)** → **Publish**. The editor says
**Publish refused: 3 security violation(s).** and explains each one in plain words (the recipient would be filled
from untrusted ticket data).

**W2** prints an alert email to `admin@corp.local`, subject `[AgentOS] Attack blocked (uc07_support_desk_unsafe)`.
Point out that it contains only the rule, flow, count and an AgentOS-written reason, and **no ticket text**.
Then **Watch → Alerts**: the alert shows status **sent**. Click **Acknowledge**.

*Say:* "The check runs before anything is published, so this flow can never run. The alert is written by AgentOS
from metadata only, so an attacker can't write the message the admin reads."

## 9. Audit log (1 min)

**Govern → Audit log.** The badge says **Verified · N entries**: the tamper-evident chain checks out. Filter to
today: billing plan change, channel create and test, rule update, refused publish, approval, acknowledge.

*Say:* "Every admin action is written to a hash chain before it takes effect. If the log can't be written, the
action doesn't happen."

## 10. Metrics (1 min)

**Watch → Metrics.** Groq shows today's calls and tokens at **$0** (free plan), p50 / p95 latency per provider,
and the error and fallback rate.

*Say:* "Costs are estimates from the price table, and the provider's bill is the truth. Run limits stop a runaway
run even on a free model."

## 11. Optional: two more use cases (2 min, MOCK, no keys needed)

In **W3**:
```powershell
$env:AGENTOS_MOCK_LLM="1"; .\venv\Scripts\python.exe examples\usecases\08-mcp-notes\run.py
.\venv\Scripts\python.exe examples\usecases\09-phishing-triage\run.py
Remove-Item Env:AGENTOS_MOCK_LLM
```
Each ends with `ALL PASS`. 08: tools from an MCP server are mediated and labelled; a poisoned tool can't send
email. 09: phishing triage with quarantined extraction, where only constrained fields (enum, bool, ...) come out of
the untrusted email.

## 12. Stop (10 s)

Press **Ctrl+C** in **W1** (it prints `AgentOS stopped.`; no AgentOS processes keep running) and in **W2**.

## Known limits (stated honestly)

- With a real model, URGENT or NORMAL is the model's own call, so the `injection` webhook run can differ between
  rehearsals. The security outcome doesn't depend on it; step 6's MOCK run shows the fooled case every time.
- Email here goes only to the local test server. Plaintext SMTP is allowed only to localhost with "allow insecure
  local"; a real server needs STARTTLS or TLS. Delivery to a real mail provider was not part of the verification.
- SMTP can't be exactly-once: a send that crashed after the mail server accepted it is never resent automatically
  (the run waits for review); each message carries a stable Message-ID so a receiver can de-duplicate.
- Slack (not shown) works through incoming webhooks only (`https://hooks.slack.com/...`).
- Alerts are evaluated in the AgentOS server process; a separate `agentos worker` process (Platform mode) does
  not raise alerts yet.
- Costs are estimates from price tables; the Overview counts the newest 500 runs.
- Runs created before 2.4d have no stored trigger and may show as `manual` in the History list.
- The OmniRoute provider entry is UNVERIFIED and is not used in this demo.
