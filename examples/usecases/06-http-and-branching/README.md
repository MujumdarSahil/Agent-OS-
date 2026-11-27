# Use Case 06: HTTP requests and branching (sub-milestone 2.3)

## Scenario
An ops flow checks a public status page every morning. If the page reports an incident, it emails
the text to the internal on-call address. The same building blocks are what an attacker would try to
abuse: make the server fetch internal addresses (SSRF), send data to an attacker URL, or steer a
branch into a destructive request.

## What it demonstrates
| Scenario | Input | Expected | Where enforced |
|---|---|---|---|
| Benign | `inputs/benign.json` | `fetch` (GET, pinned public URL) -> `is_incident` (condition) -> `notify` email to pinned `ops@corp.local`; the other branch is skipped | untrusted response body may go to an internal recipient only |
| A1 SSRF, pinned URL | `flows/attack_ssrf_metadata.flow.json` | run fails, 0 requests to `169.254.169.254` | SSRF guard (`agentos/flows/net_guard.py`) |
| A1 SSRF via redirect | `flows/attack_ssrf_redirect.flow.json` | run fails at the redirect hop, 0 requests to metadata | redirect re-check |
| A2 injected URL | `inputs/attack_injected_url.json` (URL from the webhook payload) | publish refused: `url` must be trusted | shared sink rules (publish + runtime) |
| A3 attacker predicate | `inputs/attack_predicate.json` (`action: purge`) | publish refused (`(control)` violation); forced run fails with 0 requests | control-dependency rule for DESTRUCTIVE sinks (`DELETE`) |

All results are **MOCK**: a fake DNS resolver and HTTP sender replace the network, and email goes to
`MockTransport`. CI runs it through `tests/ci/test_usecase_06.py`.

## Run
```powershell
.\venv\Scripts\python.exe examples/usecases/06-http-and-branching/run.py
```
```bash
python examples/usecases/06-http-and-branching/run.py
```
Expected last line: `Use case 06: ALL PASS`.

## Notes
- Trusted internal email domains (`corp.local`) and the HTTP allowlist (`internal.corp`) are set
  explicitly in `run.py`; in a server they come from `AGENTOS_INTERNAL_DOMAINS` and
  `AGENTOS_HTTP_ALLOWLIST` (or `security.*` in `agentos.config.yaml`), both empty by default.
- To use a URL that comes from data, pass it through a `validator` node with `field_type: allowlist` and an
  admin allowlist of exact URLs (`security.allowlists` in `agentos.config.yaml`); the validator then outputs the
  admin's canonical URL, never the incoming one.
- **Changed in 2.5b:** `allowlist_name: http_allowlist` is no longer accepted by a validator. It matches by host,
  so the path and query would still come from the data; publish now refuses it, and a flow published before
  2.5b fails closed at run time (no declassification). The flows of this use case don't use a validator, so
  their behaviour is unchanged.
