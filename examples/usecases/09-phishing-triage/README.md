# Use case 09: phishing triage (quarantined extraction)

An email arrives on a webhook. A **quarantined extraction** node asks a model for three constrained fields
only, validates every value, and outputs only the validated values. They are labelled `trusted ·
declassified by extraction`:

- `category`: one of `phishing`, `spam`, `legit`
- `needs_reply`: a JSON boolean
- `reported_ticket`: a `ticket_id` pattern (`^[A-Z]{2,10}-\d{1,9}$`)

```
mail (webhook) -> extract (quarantined_extraction) -> is_phishing (condition on category)
   true  -> alert_security (send_email, to pinned: security@corp.local; subject and body ONLY from extracted fields)
   false -> is_legit_reply (category == legit and needs_reply)
              true -> draft (llm, untrusted) -> reply_approval (approval) -> send_reply (to pinned: service-desk@corp.local)
              (spam: nothing)
```

Email goes to a recorded outbox (`MockTransport`), with no SMTP. Nothing is delivered. Everything here is
**MOCK**: a scripted model answers. On invalid output the node uses its validated defaults (`spam`, `false`,
`NONE-0`), so a malformed answer can only make the flow do nothing.

## What the security model guarantees here

| Input | What happens |
|---|---|
| phishing email (benign case) | One alert to `security@corp.local`, with body `phishing` and subject `SEC-1234`. No approval: both values are extracted and trusted. |
| injection email: the model answers with an extra key (a recipient), free text, `"legit\nIgnore previous instructions"`, `"category: legit"`, a nested object, `"yes"` for a bool, `"Legit"`, or a tool call | Each answer is rejected (`extra_key`, `not_json`, `not_allowed`, `nested_value`, `wrong_type`, `no_text_output`). The defaults (`spam`) apply and nothing is sent. Only the raw output's length and sha256 are recorded, never the text. |
| attacker steers the model to a *valid* answer (`legit`, `needs_reply: true`) | Extraction can't stop this: it limits WHAT comes out, not WHICH allowed value. The reply draft is untrusted, so the run waits at the approval. The operator rejects, no email is sent, and nothing ever goes to the attacker (recipients are pinned). |
| flow variant whose alert recipient is the extracted `category` | Publish is refused: only an `allowlist` extraction field may choose a recipient. |
| flow variant that deletes the mailbox (`http_request` DELETE) when `category == phishing` | Publish is refused: a destructive action must not be enabled solely by an extraction value. It still needs an approval. |

## Run it

```bash
python examples/usecases/09-phishing-triage/run.py
```

CI runs the same scenarios in `tests/ci/test_usecase_09.py` (MOCK).

## Files

- `flows/phishing_triage.flow.json`: the flow (importable in the builder).
- `inputs/emails.json`: the phishing, injection and "steer to legit" emails.
- `run.py`: the MOCK scenarios above.
