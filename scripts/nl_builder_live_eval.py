"""4.0 natural-language builder: LIVE eval against the real AgentOS router (NOT in CI).

Runs the 12 cases of agentos/builder/eval_cases.py (the same properties the MOCK CI eval checks) through the real
provider chain and prints the success rate. Output is metadata only: case id, status, check result, model calls,
providers that answered, failed property names. Never prompts, model output, keys or key fragments.

Provider keys are read ONLY from environment variables (no vault, no ~/.agentos: AGENTOS_FORBID_REAL_HOME=1 and temp
AgentOS paths are set here before anything is imported). Each case is one builder request with the default run limits.

Usage:
  $env:AGENTOS_FORBID_REAL_HOME="1"
  .\\venv\\Scripts\\python.exe scripts/nl_builder_live_eval.py [--cases 01-support-desk,09-injection]
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
import tempfile
from pathlib import Path

os.environ["AGENTOS_FORBID_REAL_HOME"] = "1"
_TMP = Path(tempfile.mkdtemp(prefix="agentos-nl-live-eval-"))
os.environ.setdefault("AGENTOS_DATA_DIR", str(_TMP / "data"))
os.environ.setdefault("AGENTOS_VAULT_PATH", str(_TMP / "vault.json"))
os.environ.setdefault("AGENTOS_MASTER_KEY_FILE", str(_TMP / "master.key"))
os.environ.setdefault("AGENTOS_API_TOKEN_FILE", str(_TMP / "api.token"))
if os.environ.get("AGENTOS_MOCK_LLM") == "1":
    sys.exit("AGENTOS_MOCK_LLM=1 is set: this is the LIVE eval; unset it (MOCK eval: tests/ci/test_nl_builder_eval.py)")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agentos.builder import BuilderInputError, BuilderRequest, NLFlowBuilder  # noqa: E402
from agentos.builder.eval_cases import CASES, check_case, eval_policy  # noqa: E402
from agentos.llm.router_llm import AgentOSRouterLLM  # noqa: E402
from agentos.usage.guard import RunGuard, UsageContext  # noqa: E402
from agentos.usage.ledger import UsageSettings  # noqa: E402


async def run_case(case, policy):
    records: list[dict] = []
    guard = RunGuard(UsageContext.default(), f"live-eval-{case.id}", "builder", UsageSettings())

    async def model(messages):
        llm = AgentOSRouterLLM(node_id="builder", guard=guard, on_call=records.append)
        return await asyncio.to_thread(llm.call, messages, None)

    try:
        out = await NLFlowBuilder(policy, None, model).generate(BuilderRequest(description=case.description))
    except BuilderInputError as err:
        out = {"refused_input": err.reason, "model_calls": 0}
    except Exception as err:  # provider failure, run limit: metadata only
        out = {"status": "error", "error_class": type(err).__name__, "model_calls": len(records)}
    providers = sorted({r.get("provider") for r in records if r.get("status") == "ok" and r.get("provider")})
    return out, providers


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", default="", help="comma-separated case ids (default: all 12)")
    args = ap.parse_args()
    wanted = {c.strip() for c in args.cases.split(",") if c.strip()}
    cases = [c for c in CASES if not wanted or c.id in wanted]
    policy = eval_policy()
    ok = 0
    print("LIVE natural-language builder eval (metadata only)")
    for case in cases:
        out, providers = await run_case(case, policy)
        fails = ["error"] if out.get("error_class") else check_case(case, out, policy)
        ok += not fails
        print(f"  {'PASS' if not fails else 'FAIL'}  {case.id:28s} status={out.get('status', 'refused_input')} "
              f"check={(out.get('check') or {}).get('status', '-')} calls={out.get('model_calls', 0)} "
              f"providers={','.join(providers) or '-'}"
              + (f" error={out['error_class']}" if out.get("error_class") else "")
              + (f" failed={','.join(fails)}" if fails else ""))
    rate = 100.0 * ok / len(cases) if cases else 0.0
    print(f"success rate: {ok}/{len(cases)} = {rate:.0f}%")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
