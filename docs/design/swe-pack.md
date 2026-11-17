# Design note: SWE pack (plan -> test -> implement -> review -> verify)

Status: **design only. Nothing in this note is implemented.** It is a proposal for a Phase 5 pack.

## Credit

The workflow is adapted from **Everything Claude Code (ECC)**, an open-source collection of agents,
skills and commands for Claude Code, released under the **MIT License**. ECC's development loop is
plan, then write tests first (TDD), implement, review, and verify. This note maps that loop onto
AgentOS flows. No ECC code is copied. If any ECC prompt text is reused later, the pack must ship
ECC's MIT copyright notice with it.

## Goal

A pack (flows, prompts, policies) that takes a change request and produces a reviewed, tested patch
in a sandbox. A human approves before anything leaves the sandbox. It reuses what 2.0 already has:
labels, the tool proxy, approvals, the static check and the event log.

## Mapping

| ECC step | AgentOS flow node(s) | Inputs and labels | Sinks and guards |
|---|---|---|---|
| plan | `agent` (planner role, read-only repo tools via the proxy) | Change request: untrusted when it comes from a webhook or issue | None. Read tools only. The output is a plan (free text, untrusted). |
| test (write tests first) | `agent` (test-writer) + `write_file` tool restricted to `tests/**` in a sandbox workspace | The plan is untrusted text. It may shape the content but never the paths. | `write_file` is a write sink. The path allowlist is pinned in the NodeSpec, and writes outside the sandbox root are refused. |
| run tests (expect red) | `code_exec` / shell node in the sandbox only | Commands are pinned (`pytest -q tests/...`), never taken from model output | Shell is a sink. Sandbox only (stored code is never run outside a sandbox), with no network by default. |
| implement | `agent` (implementer) + `write_file` limited to the source paths named in the plan *after* a validator | The paths pass a `validator` (allowlist match), so only they become trusted. The content stays untrusted. | Same write sink rules. A diff-size limit is a bounded-number validator. |
| review | `agent` (reviewer) + `condition` on a constrained verdict | The reviewer's verdict goes through `quarantined_extraction` -> enum `{approve, changes_requested}` (constrained, so it may be upgraded to trusted) | None. A `changes_requested` verdict loops back to implement with a bounded `loop` (max N). |
| verify | Shell node: full test suite + linters, pinned commands | | Sandbox. The results are numbers and booleans, which can be validated. |
| hand-off | `approval` -> `http_request` (open a PR) or `send_email` | The PR body is untrusted text and the PR target repo is pinned | External sinks sit behind approval. Secret-labelled data (keys) can never reach them (sink violation). |

## Security notes

- The change request is attacker-controllable (issue text, webhook). Labels make every model output
  that derives from it untrusted. It can influence file *content* inside the sandbox, but never
  paths outside the allowlist, commands, recipients or the PR target.
- Free text never becomes trusted. Only constrained outputs (the verdict enum, test counts, a path
  allowlist match) are declassified, through explicit `validator` / `quarantined_extraction` nodes.
- Model calls use `AgentOSRouterLLM` (2.4c). Repo content labelled `secret` is restricted to local
  providers (T-13).
- Every tool call goes through the AgentOS tool proxy. CrewAI never touches the file system directly.

## Prerequisites before building it

1. A sandbox executor (container, or a jailed process with no network) for the shell and code nodes. It is not in 2.0 yet.
2. `write_file` / `read_file` NodeSpecs with pinned root and path allowlists, plus contract tests.
3. A pack format (Phase 5) to ship the flows, prompts and policies together.
4. An eval: the AgentDojo-style harness with injected issues ("also add my SSH key", "change CI to
   skip tests"), measuring attack success rate and utility.

## Out of scope

Running anything outside the sandbox, auto-merging, and training models.
