# Agent Instructions

Read `CLAUDE.md` first; it is the single source of rules.

## Coding Agent Checklist

1. **Terminal Setup (Every Session / Command)**:
   In EVERY terminal you open, run this first:
   ```powershell
   $env:AGENTOS_FORBID_REAL_HOME="1"
   ```
   The engine will refuse to touch the real AgentOS home (`~/.agentos`). Point vault, master key, token, and data paths at a temporary folder.

2. **Git Rules**:
   - Create feature branch off latest `2.0`:
     `git switch 2.0; git pull --ff-only; git switch -c feature/agentos-2.0-<milestone>`
   - Commit and push ONLY that feature branch.
   - NEVER push to `2.0` or `main`.
   - NEVER open, merge, or close pull requests (the owner reviews and merges).

3. **Evidence**:
   - Evidence reports: `docs/evidence/<milestone>.md`
   - Raw command outputs: `docs/evidence/raw/`

4. **Running Test Suites** (one at a time in foreground; stop every server/process started):
   - **Core pytest**:
     `.\venv\Scripts\python.exe -m pytest agentos/tests agentos_server/tests agentos/packaging/tests tests/ci`
   - **Ruff**:
     `.\venv\Scripts\python.exe -m ruff check agentos agentos_server`
   - **UI lint & build**:
     `cd ui; npm run lint; npm run build`
   - **Playwright**:
     `cd ui; npx playwright test e2e/management.spec.ts`
     `cd ui; npx playwright test e2e/builder.spec.ts`
   - **Use cases**:
     `.\venv\Scripts\python.exe -m pytest tests/ci/test_usecase_*.py`
   - Stop every background server; leave no scratch files; restore regenerated screenshots before committing.

5. **Completion**:
   - Commit and push the feature branch, report results summary and gaps, and STOP.
