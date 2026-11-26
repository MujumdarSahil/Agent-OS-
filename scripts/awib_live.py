"""4.1 AWIB with REAL models through the AgentOS router (NOT in CI; for the paper later).

The same generated cases as `python -m benchmarks.awib`, but the model deciding is a real one (fallback chain, run
limits), not the always-obeying MOCK. Sinks are still the fake recording ones: nothing is ever sent. Only AgentOS runs
live; the naive baseline needs scripted decisions and is MOCK-only.

Keys come ONLY from environment variables (no vault, no ~/.agentos: AGENTOS_FORBID_REAL_HOME=1 and temp AgentOS paths
are set before anything is imported). Output is metadata only: counts, success rates, providers. Never prompts, model
output or keys.

Usage:
  $env:AGENTOS_FORBID_REAL_HOME="1"
  .\\venv\\Scripts\\python.exe scripts/awib_live.py [--limit 20] [--scenarios S01,S07]
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
import tempfile
from collections import Counter
from pathlib import Path

os.environ["AGENTOS_FORBID_REAL_HOME"] = "1"
_TMP = Path(tempfile.mkdtemp(prefix="agentos-awib-live-"))
for _k, _v in {"AGENTOS_DATA_DIR": _TMP / "data", "AGENTOS_VAULT_PATH": _TMP / "vault.json",
               "AGENTOS_MASTER_KEY_FILE": _TMP / "master.key", "AGENTOS_API_TOKEN_FILE": _TMP / "api.token"}.items():
    os.environ.setdefault(_k, str(_v))
os.environ.setdefault("CREWAI_TELEMETRY_OPT_OUT", "1")
if os.environ.get("AGENTOS_MOCK_LLM") == "1":
    sys.exit("AGENTOS_MOCK_LLM=1 is set: this is the LIVE run; unset it (MOCK: python -m benchmarks.awib)")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agentos.llm.router_llm import AgentOSRouterLLM  # noqa: E402
from agentos.redteam.runner import classify, run_case  # noqa: E402
from agentos.usage.guard import RunGuard, UsageContext  # noqa: E402
from agentos.usage.ledger import UsageSettings  # noqa: E402
from benchmarks.awib.run import build_cases  # noqa: E402


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0, help="at most N cases (0 = all)")
    ap.add_argument("--scenarios", default="", help="comma-separated scenario ids")
    args = ap.parse_args()
    wanted = {s.strip() for s in args.scenarios.split(",") if s.strip()}
    cases = [c for c in build_cases() if not wanted or c.scenario.id in wanted]
    cases = cases[: args.limit] if args.limit else cases
    outcomes: Counter[str] = Counter()
    providers: Counter[str] = Counter()
    errors = 0
    print("AWIB LIVE (AgentOS with real models; fake sinks; metadata only)")
    for c in cases:
        records: list[dict] = []
        guard = RunGuard(UsageContext.default(), f"awib-live-{c.id}", "awib", UsageSettings())
        model = AgentOSRouterLLM(node_id="awib", guard=guard, on_call=records.append)
        try:
            res = await run_case(c.scenario.flow, c.attack, policy=c.scenario.policy, inputs=c.scenario.inputs,
                                 model=model)
            outcomes[classify(res, c.attack)] += 1
        except Exception as err:  # provider failure, run limit: class name only
            errors += 1
            outcomes[f"error:{type(err).__name__}"] += 1
        providers.update(r.get("provider") for r in records if r.get("status") == "ok" and r.get("provider"))
    done = sum(v for k, v in outcomes.items() if not k.startswith("error"))
    print(f"cases: {len(cases)}, completed: {done}, errors: {errors}")
    for k, v in sorted(outcomes.items()):
        print(f"  {k}: {v}")
    asr = 100.0 * outcomes["succeeded"] / done if done else 0.0
    print(f"AgentOS attack success rate (live): {outcomes['succeeded']}/{done} = {asr:.1f}%")
    print("providers that answered: " + (", ".join(f"{p} x{n}" for p, n in providers.most_common()) or "-"))
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
