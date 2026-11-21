# Use case 11: users, login and roles (3.4)

**MOCK only.** The real AgentOS app runs inside the script (no network, no model; emails go to a recorded outbox).
Every AgentOS path (vault, master key, token file, data) is a fresh temp folder, never your `~/.agentos`.

```bash
python examples/usecases/11-access-roles/run.py
```

## What it shows

| Step | Who | Expected |
| --- | --- | --- |
| First admin | anyone without the local API token | 401 |
| First admin | with the local API token, no users yet | 200, admin created and logged in |
| Second setup | with the local API token, a user exists | 409 |
| Team | admin creates builder `bob`, approver `ann`, viewer `vic` | 201 each |
| Publish and run | builder | publish 200, run waits at the approval |
| Approve | builder / viewer | 403 / 403 |
| Approve | approver | 200, one email, the run records `started_by=bob`, `decided_by=ann` |
| Cross-site POST with bob's cookie | wrong Origin, or no CSRF header | 403, 403 |
| Login with an unknown user vs a wrong password | anyone | the same 401 and message |
| 6 wrong passwords | anyone | 429 with `Retry-After`; then even the right password waits |
| API token | bob, then revoked | 200, then 401 |
| Separation of duties on | the admin who published the version | 403; another approver: 200 |
| Audit log | | actor is the user (`bob`, `ann`), setup is `legacy-local-token` |

Roles: viewer (read), approver (+ approve), builder (+ build, publish, run), admin (everything). Design and the
full permission matrix: [docs/evidence/3.4.md](../../../docs/evidence/3.4.md).
