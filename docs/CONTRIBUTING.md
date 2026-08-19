# Contributing to AgentOS

First — thanks for considering it. AgentOS is built on top of CrewAI, LangChain/
LangGraph, and LiteLLM rather than reinventing agent execution from scratch, so
most contributions fall into a few clear categories below. This doc tells you
where to start depending on what you want to work on.

## Before you start

Read `PHASE3_LIMITATIONS.md` (and any earlier `PHASE*_LIMITATIONS.md` files)
first. This project tries hard to document what's real, what's partial, and
what's a known gap, instead of overclaiming — that's a deliberate norm, not an
accident, and it's the standard we'd like contributions to keep up.

If you're about to add a feature that touches the LLM fallback layer, the
governance engine, or the packaging/signing code, please open an issue first to
discuss the approach. These are the parts of the project where a quiet design
mistake is expensive to unwind later.

## Setting up your dev environment

```bash
git clone https://github.com/<you>/agentos.git
cd agentos
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -r requirements.txt
cd agentos/frontend && npm install && cd ../..
cp .env.example .env
```

You do not need any paid API key to develop or test this project. Install
[Ollama](https://ollama.com), pull a small model (`ollama pull qwen3.6` or
similar), and the framework's LLM fallback chain will use it automatically with
zero configuration. If you want to test multi-provider fallback behavior, add
one real (or intentionally invalid, for testing failure paths) key to `.env`.

Run `python main.py --dev` to start both the backend and frontend. Run the test
suites before opening a PR:

```bash
pytest agentos/server/tests/ -v
pytest agentos/packaging/tests/ -v
```

## Where to start

**Good first issues** (tagged on GitHub): small, scoped, don't require deep
familiarity with CrewAI internals. Usually: a new tool subclass, a CLI UX
improvement, a frontend screen polish, a docs fix.

**Known gaps that need real design work** (see `PHASE3_LIMITATIONS.md` for the
full list, summarized here):
- The governance engine is currently a basic keyword/substring filter and is
  known to be bypassable by rephrasing. A more robust approach (semantic
  classification, an LLM-based judge, or a hybrid) is wanted, but needs design
  discussion before implementation — open an issue to propose an approach.
- MCP plugin permissions are declarative-only (a plugin author states what
  permissions it needs, but nothing enforces this at runtime). Real sandboxing
  is a meaningful undertaking — if you want to tackle this, please discuss
  scope in an issue first.
- Mission resume is fully supported for sequential CrewAI processes; resume
  mid-hierarchical-delegation is not yet implemented and currently restarts the
  whole mission. If you have ideas here, we'd love to hear them.
- The packaging/licensing system is intentionally offline and phone-home-free —
  this is a deliberate tradeoff, not a gap, but if you have ideas for stronger
  local verification without requiring a central server, that's welcome.

**New LLM providers**: if there's an OpenAI-compatible host we don't have a
`provider_registry.py` entry for, that's a very easy PR — see existing entries
for the format.

**New example agents/tools/crews**: contributions to `examples/` showing real
use cases are always welcome and don't require touching core code at all.

## PR guidelines

- One logical change per PR. A PR that touches the LLM layer AND adds a frontend
  screen is two PRs.
- If you touch `core/`, add or update tests under the matching `tests/`
  directory — we don't merge untested changes to core logic.
- If your change affects CLI behavior, confirm the equivalent API route (in
  `agentos/server/app.py`) still matches — per this project's own rule, CLI and
  API must never diverge in behavior. If you find a place where they already
  have diverged, that's worth its own PR/issue even if it's not what you set
  out to fix.
- Be honest in your PR description about what you tested versus what you
  believe should work. "Tested fallback with 2 real providers + Ollama" is a
  much more useful PR description than "should work for all providers."
- Run the full test suites locally before opening the PR. CI will also run
  them, but a green CI run on first push is appreciated.

## Code style

- Type hints on all new functions/methods.
- Pydantic models for anything that crosses a class or API boundary — don't
  hand-parse dicts or YAML without validation.
- Docstrings on all public classes explaining what to subclass/extend and why
  — this project leans on class-based extensibility (`BaseAgent`, `BaseTool`,
  `BaseMemory`, `BaseMCPPlugin`) as its core design, so a new contributor should
  be able to understand how to extend something from the docstring alone.

## Reporting issues

Please include: your OS, Python version, Node version, which LLM provider(s)
you had configured (no need to share keys, just which providers), and the
actual error output. "It doesn't work" without these is hard to act on.

## Code of conduct

Be respectful, assume good faith, keep disagreements about code, not people.
We'll add a full CODE_OF_CONDUCT.md (likely Contributor Covenant) before this
project leaves an early/quiet phase — flag in an issue if this is blocking a
contribution for you and we'll prioritize it.
