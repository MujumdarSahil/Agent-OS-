# Use case 10: alerts and notifications (3.3)

**MOCK.** No model is called. "Slack" is a local plain-HTTP stand-in on 127.0.0.1, reached only through the
Slack sender's test-only constructor arguments. The configured webhook URL must still be `https://hooks.slack.com/...`
and is never contacted. Nothing leaves the machine.

```bash
python examples/usecases/10-alerts-notifications/run.py
```

| Scenario | Input | Expected |
| --- | --- | --- |
| benign | fixed deploy note to Slack channel `ops` | one post, `&` escaped, unfurling off |
| exfil (attack) | the run input names the recipient (`<canary>@attacker.example`) | sink rule blocks the send; an "Attack blocked" alert goes to `sec`, written by AgentOS from metadata; the canary is in the run events but **not** in the alert or the Slack text |
| slack-inj (attack) | untrusted text with `<!channel>`, `@here`, `<https://evil|this>` | refused at publish and at runtime for the non-internal `ops`; sent **escaped** to the internal `sec` (no ping, no link) |
| host-pin (attack) | webhook `https://evil.example/services/...` | refused |
| outbox | stand-in answers 503, then 200 | alert `retrying`, then `sent`; after a restart nothing is sent again |

CI runs it through `tests/ci/test_usecase_10.py`.

For real email in a demo, see use case 07 with `UC07_SMTP` (a local SMTP test server).
