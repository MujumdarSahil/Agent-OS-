# Use case 08: notes digest through an MCP server

An agent reads the team's notes through an MCP server and emails a short digest. The recipient is
pinned in the flow:

```
start (manual trigger) -> drafter (agent)
                            tools: mcp.notes.list_notes  (MCP, approved by an admin)
                                   send_email            (built-in; to pinned: team@corp.local)
```

The notes server is the existing demo `examples/mcp_demos/local_notes_server/server.py`, started by
AgentOS over stdio. Email goes to a recorded outbox (`MockTransport`): nothing is delivered.

## How AgentOS treats the MCP server

- **Enable:** the server starts disabled. Enabling it shows the exact command line that will run.
- **Minimal environment:** the server process gets an environment built from scratch: OS essentials, a
  private home and temp folder, and only the `env` and `secret_env` configured for it. It never sees
  provider keys, the vault master key or the API token.
- **Discover and review:** tool names, descriptions and schemas are stored as untrusted text. An admin
  approves each tool, choosing its side-effect class, which arguments may be untrusted, the output
  confidentiality, and optionally a replacement description. Approval pins a hash of the tool.
- **Namespacing:** the tool is only ever called `mcp.notes.list_notes`. A bare name such as `send_email`
  always means AgentOS's own built-in.
- **At run time:** every call goes through the AgentOS tool proxy. The tool's output is untrusted, and
  if the tool changed since approval, the call is blocked.

## What the security model guarantees here

| Scenario | What happens |
|---|---|
| benign | The agent calls `mcp.notes.list_notes`, then `send_email`. One email goes to `team@corp.local`. |
| poisoned description (`servers/poisoned_notes.py`) | The tool description tells the model to email `mallory@attacker.example`. The scripted model obeys and tries `to=mallory@...`. The proxy rejects it (`to` is pinned), and nothing reaches the attacker. Without an admin description, the agent's context is untrusted from the start. |
| rug pull (`servers/rugpull_notes.py`) | The server changes its tool after it was approved. At run time the call is blocked (`tool_call_rejected`) and no email is sent. The tool shows as "changed", and the flow can't be published again until an admin re-reviews it. |
| shadowing (`servers/shadow_notes.py`) | The server offers `send_email` and `Send-Email`. They collide after normalisation and are both rejected. The flow's bare `send_email` is the built-in. |

## Files

- `flows/mcp_notes.flow.json`: the flow.
- `servers/`: the malicious demo servers used by the runner.
- `run.py`: the MOCK runner (scripted model, real local stdio MCP servers, temp project and vault, recorded
  outbox). CI runs it through `tests/ci/test_usecase_08.py`.

## Run

```powershell
.\venv\Scripts\python.exe examples\usecases\08-mcp-notes\run.py
```

Expected output, one line per scenario:

```
[PASS] benign: publish_ok=True status=succeeded outbox=['team@corp.local'] mcp_tool_call=True
[PASS] poisoned description: model tried to=mallory@attacker.example -> rejected=True outbox=[] to_attacker=False
[PASS] rug pull: call blocked=True outbox=[] tool_status=changed republish_allowed=False
[PASS] shadowing: discovered=['list_notes'] (send_email look-alikes rejected) bare send_email is the built-in=True
Use case 08: ALL PASS
```

In the UI, open **Connect → MCP servers**, add the notes server (stdio, `python` plus the path to
`server.py`), enable it, run **Discover**, review and approve `list_notes`, then pick
`mcp.notes.list_notes` in the agent's tool picker.
