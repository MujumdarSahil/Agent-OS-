"""python -m benchmarks.awib --out docs/evidence/4.1-results.json  (MOCK only: adversarial scripted model, fake
sinks; also writes the .md summary next to the JSON)."""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

os.environ["AGENTOS_FORBID_REAL_HOME"] = "1"
os.environ["AGENTOS_MOCK_LLM"] = "1"
os.environ.setdefault("CREWAI_TELEMETRY_OPT_OUT", "1")
os.environ.setdefault("OTEL_SDK_DISABLED", "true")


def main() -> int:
    ap = argparse.ArgumentParser(prog="python -m benchmarks.awib")
    ap.add_argument("--out", default="docs/evidence/4.1-results.json")
    ap.add_argument("--subset", action="store_true", help="only the fixed CI subset")
    ap.add_argument("--reps", type=int, default=5, help="benign repetitions per scenario for the timing")
    ap.add_argument("--no-mcp", action="store_true", help="skip S08 (starts local stdio fixture servers)")
    args = ap.parse_args()
    from benchmarks.awib.run import CI_SUBSET, run_benchmark, write

    result = asyncio.run(run_benchmark(CI_SUBSET if args.subset else None, reps=args.reps, mcp=not args.no_mcp))
    write(result, Path(args.out))
    o = result["summary"]["overall"]
    print(f"AWIB: {result['summary']['cases']} cases; baseline ASR {o['baseline_asr']}%, AgentOS ASR "
          f"{o['agentos_asr']}%; wrote {args.out} and {Path(args.out).with_suffix('.md')}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
