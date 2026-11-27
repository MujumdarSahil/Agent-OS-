# Use case 15: test cases for a flow (4.2)

**MOCK only.** A scripted test model stands in for the model, email goes to fake senders, and the customer-record
HTTP call gets a fixture response. Nothing is sent, no model is called, and no key is needed.

The flow is the use case 07 support desk (`07-support-desk-copilot/flows/support_desk.flow.json`).
`suite.json` holds four hand-written cases:

| Case | Expectations |
| --- | --- |
| urgent: approval reached, only on-call paged | succeeded after approval; approval `oncall_approval` reached; exactly 1 email, to `oncall@corp.local`; the support queue is not emailed |
| urgent before approval: nothing sent yet | waiting for approval; no email |
| normal: support queue only | succeeded; exactly 1 email, to `support-queue@corp.local`; on-call not paged; at most 2 model calls |
| injection: no send to the attacker | the fooled model marks it URGENT and asks to email the attacker; nothing reaches an address outside the internal domains; only `oncall@corp.local` is emailed |

`run.py` also adds the **generated security tests**: one case for each 4.1 attack family that fits this flow (16
cases). It runs the suite twice:

1. **Against the flow:** 20/20 pass.
2. **After a careless edit** (the on-call email now goes to `oncall@outsourcer.example`): the regression summary lists
   the two newly failing cases, with readable diffs such as
   `send_email (page_oncall): expected a call with to = oncall@corp.local, got oncall@outsourcer.example`.

Finally it runs the CLI the way a CI pipeline would:
`agentos test uc07_support_desk --tags support --junit junit.xml` exits with 0.

A tripwire replaces every real outbound path (SMTP, the httpx network transport, the HTTP sender and DNS). It must
record nothing.

Run it:

```powershell
$env:AGENTOS_FORBID_REAL_HOME="1"
.\venv\Scripts\python.exe examples/usecases/15-flow-tests/run.py
```

CI: `tests/ci/test_usecase_15.py`.
