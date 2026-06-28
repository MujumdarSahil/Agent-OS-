# Phase 3 Limitations

This document honestly records every deliberate simplification, tradeoff, and
known limitation in Phase 3 of AgentOS. Read this before building on top of it.

---

## WebSocket vs. HTTP Polling

**What we built**: `WS /api/runs/{run_id}/stream` pushes task events in real time.
`GET /api/runs/{run_id}/status` is the polling fallback.

**Limitation**: In production behind a load balancer or reverse proxy (Nginx,
Caddy, AWS ALB), WebSocket connections require specific upgrade headers and
sticky sessions.  Without configuration, clients will silently fail to upgrade
and receive HTTP 101 errors.

**Recommended path**: Use polling (`GET /api/runs/{run_id}/status`) for all
production deployments unless you control the infrastructure and have confirmed
WebSocket passthrough.  The frontend does 2-second polling by default; switch
`src/hooks/useRunStatus.ts` to WebSocket only when confirmed working.

---

## .agentpack Signing Is Not DRM

**What we built**: Ed25519 signatures prove that the pack contents have not been
modified since signing, and identify who signed the pack.

**What it does NOT do**:
- It does NOT prevent anyone from copying the `.agentpack` file.
- It does NOT prevent anyone from extracting the zip and reading the contents.
- It does NOT phone home to any server to validate activations.
- It is NOT software DRM (Digital Rights Management).

**What this means for you as a creator**:
If you publish a commercial pack, a buyer can technically share the `.agentpack`
file with others.  The license key check in `license_check.py` also does NOT
prevent this — it is a signed blob that proves "this key was issued by the owner
of this private key", not "this key has only been used N times".

**Recommended honest stance**: Price your packs so that value comes from support,
updates, and documentation — not from technical lockout.  Use the signing to
protect your reputation (users can verify the pack is authentic and unmodified)
rather than to enforce copy protection.

---

## License Key Model Is Fully Offline

**What we built**: License keys are base64-encoded signed JSON blobs.  Verification
is a pure Ed25519 signature check with no network calls.

**Tradeoff**: Because there is no central activation server:
- A key cannot be revoked after issuance (the only revocation is expiry).
- A buyer can share their key with others and both will be granted access.
- There is no way to limit activations per key.

**Why we chose this deliberately**:
- Zero infrastructure cost for the creator.
- Works fully offline — important for ML/security environments with no internet.
- Transparent to buyers — they can read the verification code and trust it.
- No single point of failure (no server to go down).

If you need revocation or activation counting, you must add a server-side
activation API and call it from `license_check.py`. This is outside Phase 3 scope.

---

## Hierarchical Mission Resume (Carried from Phase 2)

When `process: hierarchical` is configured in a crew YAML and a mission fails
mid-run, the resume behaviour falls back to **crew-level retry** — the entire
hierarchical delegation chain is restarted from the point of failure, not from
the individual sub-task.  This is a known limitation of the CrewAI backend.

Sequential missions resume at exactly the correct task index (verified in tests).

---

## Builder AI Quality Depends on the Configured LLM

The builder routes (`POST /api/builder/*`) call `AgentBuilder`, `ToolBuilder`,
and `CrewBuilder` — which use the project's configured LLM provider to interpret
natural-language descriptions.

**Limitation**: With `AGENTOS_MOCK_LLM=1` (offline CI mode), the builder returns
a canned stub config instead of a real AI-generated one.  In production, quality
depends entirely on the model quality.  GPT-4o and Claude 3.5 Sonnet produce much
better results than smaller models.

---

## Frontend Build Requirement

`python main.py --prod` auto-runs `npm run build` if `agentos/frontend/dist/`
is missing.  This requires Node.js ≥ 18 and write access to the project directory.

**On CI/CD**: Always run `npm run build` explicitly before starting in prod mode.
Never rely on the auto-build in production pipelines.

---

## No Built-In Authentication / Authorization

The FastAPI backend has **no authentication**. Every endpoint is open to anyone
who can reach the server.

**Required for production**:
- Put the API behind a reverse proxy with basic auth or API key enforcement.
- Do NOT expose the `--backend-port` directly to the internet.

Phase 3 is designed for local developer use and private team environments.

---

## SQLite Checkpoint Store Is Single-Writer

`SQLiteCheckpointStore` uses SQLite in WAL mode by default.  It is safe for
concurrent reads but only supports one concurrent writer per database file.

Running two `agentos run` processes against the same project simultaneously will
corrupt the checkpoint database.  Use separate projects or a proper lock file for
parallel executions.

---

## Multi-Squad Federation is a Design Concept Only

**What the docs claim**: Support for multi-squad federation.

**Limitation**: In the current version of AgentOS, multi-squad federation is not implemented in code and remains a design concept described in the architecture documentation. There are no active APIs or execution paths supporting federated communication or routing between multiple isolated squads.

---

## Governance Filter is Easily Bypassed (Keyword-Only)

**What we built**: A governance policy checks task descriptions for a list of prohibited substrings (e.g. `"crack password"`, `"create malware"`, `"exploit vulnerability"`) and blocks execution if found.

**Limitation**: The safety filter relies on simple lowercase substring matching. It is extremely fragile and can be bypassed by simple rephrasings, pluralizations, or word splits. For example:
- `"exploits vulnerabilities"` or `"exploit the vulnerability"` will bypass `"exploit vulnerability"`.
- `"create a malware"` or `"write malware"` will bypass `"create malware"`.
- `"brute-force"` (with a hyphen) will bypass `"brute force"`.
- `"cracking passwords"` will bypass `"crack password"`.

**Recommended path**: For production safety, do not rely on simple keyword governance filters. Implement LLM-based verifiers or structural sandboxes to inspect and restrict actual executed code/actions at runtime.

---

*Last updated: Phase 3 implementation*
*Maintained by the AgentOS core team.*
