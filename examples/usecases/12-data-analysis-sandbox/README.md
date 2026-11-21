# Use case 12: data analysis in the sandbox (3.5)

An agent computes statistics over a CSV by writing Python. The model is a scripted stand-in (MOCK: no keys, no
network). The code it writes really runs in the AgentOS sandbox (`agentos/sandbox`), on every backend available:

- **Docker** (strongest; the only one for `shell_exec`): `--network none`, read-only root, tmpfs workspace,
  `--cap-drop ALL`, no-new-privileges, non-root, pids/memory/cpu limits, default seccomp, no host mounts.
- **wasm** (Python only; works without Docker, also on Windows): the pinned CPython WASI build in wasmtime, only the
  workspace preopened, empty environment, no sockets, memory limit, time limit.

With no backend the code tools refuse (fail closed): the code is never run as a plain process on the host.

## Flow

`manual_trigger` -> `agent` (tools: `file_write`, `python_exec`, `file_read`). See `flows/data_analysis.flow.json`.

## Scenarios (each on every available backend)

| Scenario | What the injected code tries | Expected (fails safely) |
| --- | --- | --- |
| benign | `file_write sales.csv`, `python_exec` stats, `file_read stats.json` | mean / median / stdev; output label UNTRUSTED |
| network_exfiltration | socket + HTTP to a listener on the host | 0 connections |
| read_host_home | read a canary `~/.agentos/vault.json` on the host | canary never in any output |
| read_environment | dump `os.environ` (the host has a canary key) | empty / no secret-like names |
| write_outside_workspace | write next to the canary, `../`, `/`, `/etc` | host unchanged |
| path_traversal_names | create `..\evil.txt`, `C:evil.txt`, `nul`, `x.txt:stream` | refused on copy-out |
| symlink_escape | symlinks to `/`, `/etc/passwd`, the canary | refused on copy-out |
| fork_bomb | fork until it fails | pids limit (Docker) / no fork (wasm) |
| memory_bomb | allocate until it fails | memory limit |
| infinite_loop | `while True: pass` | time limit |
| huge_output | print forever | output capped at 100 KB |
| no backend | any `python_exec` | refused, nothing runs |

The "host" canaries live in a temporary folder created by the run (never the real home or `~/.agentos`).

## Run it

```
pip install -e .[sandbox-wasm]
agentos sandbox install-wasm          # downloads the pinned build, verifies its sha256
python examples/usecases/12-data-analysis-sandbox/run.py
```

For Docker, start Docker (Docker Desktop on Windows/macOS). CI: `tests/ci/test_usecase_12.py` (wasm in `python-ci`,
Docker in `sandbox-docker`).
