# Use case 16: versions and environments (4.3)

**MOCK only.** No model is called and nothing is sent: the production email channel is a recording stand-in and a
tripwire replaces every real outbound path (SMTP, the httpx network transport, the HTTP sender, DNS). The server runs
in-process with every AgentOS path (vault, master key, token, data) in a temporary folder.

The flow `uc16_notify` is a webhook that emails a pinned recipient (`send_email`, body from the webhook payload).

| Step | What happens | Checked |
| --- | --- | --- |
| 1 | Publish v1 with a change note; promote it to production | staging v1 after publish (new flow: production not moved); promote passes the static check; the webhook is bound to production |
| 2 | Publish v2 that changes the pinned recipient | staging v2, production still v1; the diff v1 -> v2 lists `recipient_changed` (to: team@corp.local -> ops@corp.local) first |
| 3 | Run staging with an injection in the payload (benign + attack input) | the send is SIMULATED ("staging: simulated, not sent"); the production channel records nothing; the recipient stays pinned |
| 4 | Promote v2 to production with the test gate in block mode | the 4.2 suite runs against v2 (MOCK) and passes |
| 5 | A webhook run starts on v2, then production is rolled back to v1 | the started run keeps v2 (sent to ops@corp.local); the next webhook run uses v1 (sent to team@corp.local) |
| 6 | Attack: the policy is tightened after publish (corp.local no longer internal) | promoting v2 again is refused by the re-check against the current policy; promote, rollback and the refusal are audited |

Run it:

```powershell
.\venv\Scripts\python.exe examples/usecases/16-environments/run.py
```

CI runs it in MOCK mode: `tests/ci/test_usecase_16.py`.
