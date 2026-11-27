# Use case 14: look-alike recipients on an approval card (4.1b)

**MOCK only.** No model and no real email: the sink is AgentOS's in-memory `MockTransport`.

The flow is use case 05's approval flow (`05-visual-builder/flows/approval.flow.json`). The incoming message chooses
the recipient, and a human approves the exact values. The AWIB benchmark (4.1) found that a Unicode look-alike,
`support@corp.lоcal` with a Cyrillic "о", looked identical on the approval card and got through.

| Input | What happens |
| --- | --- |
| `inputs/benign.json` (`support@corp.local`) | No warning. Approved normally. Sent. |
| `inputs/attack.json` (Cyrillic "о") | The card shows a red **look-alike characters** warning with the real form `support@corp.xn--lcal-55d`. Approving without the extra confirmation is refused (the API returns 400). The approver rejects it, so nothing is sent. |
| `inputs/non_english.json` (`josé@ejemplo.es`) | Legitimate non-English address. It is flagged because it is non-ASCII, but it is not a look-alike. It is delivered after the confirmation click. |

The same shared check (`agentos/flows/destinations.py`) decides internal domains, allowlists, Slack channels and http
hosts. A pinned look-alike is refused at publish, and an agent's tool call to one is blocked by the tool proxy.

Run it:

```powershell
$env:AGENTOS_FORBID_REAL_HOME="1"
.\venv\Scripts\python.exe examples/usecases/14-lookalike-recipients/run.py
```

CI: `tests/ci/test_usecase_14.py`.
