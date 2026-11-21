# Postmortem: real vault file zero-filled by a test run (2026-11-18)

Fix branch: `fix/vault-isolation-atomic`. No file contents or key names appear in this report, other
than the fake canary entry name used by tests.

## What happened

During 2.4e development, the endpoint tests in `agentos_server/tests/test_v2_overview.py` ran on the
owner's machine. The test session was cut off when the agent session ended. After that, the owner's
real Standalone vault file `C:\Users\<user>\.agentos\vault.json` was 11,049 bytes, all of them `0x00`.
Its last write time matched the interrupted run. Any keys stored in it could no longer be read.
`master.key` and `api.token` in the same folder were unchanged.

The problem showed up on the next test run, when every test that listed the vault failed with
`JSONDecodeError` on a string of NUL bytes. The agent stopped and reported it. Nothing in
`~/.agentos` was opened, moved, rewritten or deleted afterwards. The owner restored a good older
vault from their own backup.

## Cause

1. **Tests were not isolated from the real home.** With no `AGENTOS_VAULT_PATH`, the file storage uses
   `~/.agentos/vault.json`, and no test setup redirected it. Every test that wrote to the vault through
   the API wrote into the owner's real vault. That includes the existing
   `test_vault_crud_masked_values_only` and the new overview key-material test, which stored a fake
   canary entry under a real-looking provider name. The master key (`~/.agentos/master.key`) and the
   API token file defaulted to the real home in the same way.
2. **Writes were not crash-safe.** The storage helper wrote a temp file and called `os.replace`, but
   never flushed or `fsync`ed the temp file. If a process is killed right after the rename, before
   the data reaches the disk, NTFS can keep the new size with unwritten (zero) contents. That fits the
   observed file: the right size, all zeros, written at the time of the interrupted run. This is the
   most likely mechanism; it was not reproduced on the owner's disk.
3. **Startup did not fail closed.** An empty vault file was read as `{}`, and the next write would
   replace a damaged file with a new, nearly empty vault.

## Impact

- The real vault was unreadable until the owner restored it from their own backup. No secret was
  disclosed: the file held only ciphertext, and it was never printed, logged or copied anywhere.
- Before the corruption, test runs had been adding and deleting test entries in the real vault. A test
  entry with the same name as a real entry would have replaced it. Whether that happened cannot be
  told without reading the vault, and it was not read.

## Fixes (this PR)

| Area | Change |
|---|---|
| Test isolation | A new root `conftest.py`. At import time, before any `agentos` import, it points `HOME`, `USERPROFILE`, `AGENTOS_VAULT_PATH`, `AGENTOS_MASTER_KEY_FILE`, `AGENTOS_API_TOKEN_FILE` and `AGENTOS_DATA_DIR` (and on Windows `LOCALAPPDATA`/`APPDATA`) at a fresh temp folder. An autouse session fixture re-checks it. The pytest header prints the resolved paths on every run. |
| Guard | At session start the size and mtime (never contents) of the files in the real `~/.agentos` (top level and `keys/`) are recorded. At session end, any change fails the whole run with an `AGENTOS HOME GUARD` error. |
| Test data | Tests that store keys use obviously fake names (`fake_test_provider_key`, `fake_provider_a/b/c`, `fake_canary_provider`). |
| Crash-safe writes | The new `agentos/storage/atomic.py` writes a temp file in the same folder, then flush, `os.fsync`, `os.replace` (retried briefly on Windows sharing violations) and a best-effort folder fsync on POSIX. It is used for `vault.json`, a newly created `master.key`, `api.token`, and every other file-store entity write. |
| Backup | Before `vault.json` is replaced, the current file is kept as `vault.json.bak` if it is a valid vault. A damaged file is never copied over the backup. |
| Fail closed | The vault store refuses to read or write a file that exists but is not a JSON object: empty, zero-filled or truncated. At startup, `create_app` checks the vault file (it must parse, and every entry must decrypt with the current master key) and refuses to start with a message naming the file and `vault.json.bak`. A damaged `master.key` also stops startup with a message naming the path; a new key is never generated over an existing file. |

## How it is prevented

- No test can resolve an AgentOS path to the real home: the temp home is set before any module computes
  a path, and anything missed lands in the temp `HOME`/`USERPROFILE`.
- If a test still writes there, the guard fails the run (tested: a subprocess pytest run that writes to a
  fake "real home" exits 1 with the guard error; an untouched run exits 0).
- A crash at any point leaves either the old or the new file (tested: a process killed with `os._exit`
  between fsync and rename leaves the original byte-for-byte intact).
- A damaged vault or master key stops AgentOS instead of being replaced (tested: a zero-filled vault, an
  empty vault, a truncated vault, a non-object vault, a wrong master key and a zero-filled master key).

## Known limits

- The Platform (Mongo) vault is not checked at startup; this incident concerned the Standalone file.
- Folder fsync is skipped on Windows (folders can't be opened for fsync there); NTFS journals the rename.
- The guard watches `~/.agentos` top level and `keys/` only, not `~/.agentos/workspace`, which a running
  AgentOS may legitimately change during a test run.
