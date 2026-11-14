"""Benchmark label tracking overhead in AgentOS 2.0 Flow Engine.

Executes Acceptance Test F flow 100 times with:
- Label tracking ON (IFC security labels, lattice joins, sink rules, and provenance)
- Label tracking OFF (benchmark baseline flag)

Reports median and p95 latency per node (ms) and total overhead.
"""

import asyncio
import json
import os
import statistics
import tempfile
import time
from pathlib import Path
from typing import Any

from crewai.llm import BaseLLM

from agentos.flows.engine import FlowEngine
from agentos.flows.models import EdgeDefinition, FlowDefinition, NodeDefinition
from agentos.flows.policy import SecurityPolicy
from agentos.flows.proxy import MockTransport
from agentos.storage import open_storage


class BenchmarkLLM(BaseLLM):
    """Deterministic scripted mock LLM for high-iteration benchmarks."""

    model: str = "mock/benchmark"

    def call(self, messages: Any, **kwargs: Any) -> str:
        # Check if already asked for tool
        msg_str = str(messages)
        if "Observation:" in msg_str or "Email successfully dispatched" in msg_str:
            return "Thought: Done\nFinal Answer: Summary email sent to team."
        return 'Thought: Summarize benign webhook and send to team\nAction: send_email\nAction Input: {"body": "Benign summary report"}'


def create_test_f_flow() -> FlowDefinition:
    """Build Acceptance Test F flow."""
    return FlowDefinition(
        id="benchmark_flow",
        entrypoint="webhook_in",
        nodes={
            "webhook_in": NodeDefinition(id="webhook_in", type="webhook_trigger"),
            "agent_node": NodeDefinition(
                id="agent_node",
                type="agent",
                config={"role": "Summarizer", "tools": ["send_email"]},
                pinned_args={"send_email.to": "team@corp.local"},
            ),
        },
        edges=[
            EdgeDefinition(source="webhook_in", target="agent_node", arg_mapping={"task": "payload"}),
        ],
    )


def percentile(data: list[float], p: float) -> float:
    """Compute p-th percentile of data."""
    if not data:
        return 0.0
    sorted_data = sorted(data)
    idx = int(len(sorted_data) * p / 100.0)
    idx = min(idx, len(sorted_data) - 1)
    return sorted_data[idx]


async def run_iterations(track_labels: bool, n: int = 100) -> dict[str, Any]:
    """Run flow N times and collect per-node and total durations."""
    policy = SecurityPolicy(internal_domains={"corp.local"})
    flow = create_test_f_flow()

    webhook_times: list[float] = []
    agent_times: list[float] = []
    total_times: list[float] = []

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
        proj_dir = Path(td) / "project"
        proj_dir.mkdir(parents=True, exist_ok=True)
        (proj_dir / "agentos.config.yaml").write_text("preferred_tags: []\n", encoding="utf-8")
        vault = Path(td) / "vault.json"

        storage = await open_storage(str(proj_dir), backend="file", vault_path=str(vault))

        for i in range(n):
            transport = MockTransport()
            llm = BenchmarkLLM(model="mock/benchmark")
            engine = FlowEngine(
                flow,
                storage,
                policy=policy,
                transport_registry={"send_email": transport},
                custom_llm=llm,
                track_labels=track_labels,
            )

            run_id = f"bench_{'on' if track_labels else 'off'}_{i}"
            t0 = time.perf_counter()
            state = await engine.run(
                run_id,
                inputs={"instruction": "Please summarize incoming report"},
            )
            total_ms = (time.perf_counter() - t0) * 1000.0

            webhook_times.append(state.node_durations_ms.get("webhook_in", 0.0))
            agent_times.append(state.node_durations_ms.get("agent_node", 0.0))
            total_times.append(total_ms)

        await storage.close()

    return {
        "webhook": {
            "median": statistics.median(webhook_times),
            "p95": percentile(webhook_times, 95),
            "raw": webhook_times,
        },
        "agent": {
            "median": statistics.median(agent_times),
            "p95": percentile(agent_times, 95),
            "raw": agent_times,
        },
        "total": {
            "median": statistics.median(total_times),
            "p95": percentile(total_times, 95),
            "raw": total_times,
        },
    }


async def main_async() -> None:
    os.environ["CREWAI_TELEMETRY_OPT_OUT"] = "1"
    os.environ["OTEL_SDK_DISABLED"] = "true"
    os.environ["AGENTOS_MOCK_LLM"] = "1"

    print("Running benchmark: 100 iterations with Label Tracking ON...")
    results_on = await run_iterations(track_labels=True, n=100)

    print("Running benchmark: 100 iterations with Label Tracking OFF (Baseline)...")
    results_off = await run_iterations(track_labels=False, n=100)

    # Compute overheads
    webhook_med_diff = results_on["webhook"]["median"] - results_off["webhook"]["median"]
    webhook_p95_diff = results_on["webhook"]["p95"] - results_off["webhook"]["p95"]

    agent_med_diff = results_on["agent"]["median"] - results_off["agent"]["median"]
    agent_p95_diff = results_on["agent"]["p95"] - results_off["agent"]["p95"]

    total_med_diff = results_on["total"]["median"] - results_off["total"]["median"]
    total_p95_diff = results_on["total"]["p95"] - results_off["total"]["p95"]
    overhead_pct = (total_med_diff / results_off["total"]["median"]) * 100.0 if results_off["total"]["median"] > 0 else 0.0

    print("\n" + "=" * 78)
    print("                 AGENTOS 2.0 FLOW ENGINE BENCHMARK (100 RUNS)")
    print("=" * 78)
    print(f"{'Metric / Node':<24} | {'Tracking ON':<20} | {'Tracking OFF':<20} | {'Overhead':<10}")
    print("-" * 78)
    print(
        f"{'webhook_in (median)':<24} | {results_on['webhook']['median']:>8.3f} ms           | "
        f"{results_off['webhook']['median']:>8.3f} ms           | {webhook_med_diff:>+7.3f} ms"
    )
    print(
        f"{'webhook_in (p95)':<24} | {results_on['webhook']['p95']:>8.3f} ms           | "
        f"{results_off['webhook']['p95']:>8.3f} ms           | {webhook_p95_diff:>+7.3f} ms"
    )
    print(
        f"{'agent_node (median)':<24} | {results_on['agent']['median']:>8.3f} ms           | "
        f"{results_off['agent']['median']:>8.3f} ms           | {agent_med_diff:>+7.3f} ms"
    )
    print(
        f"{'agent_node (p95)':<24} | {results_on['agent']['p95']:>8.3f} ms           | "
        f"{results_off['agent']['p95']:>8.3f} ms           | {agent_p95_diff:>+7.3f} ms"
    )
    print("-" * 78)
    print(
        f"{'Total Run (median)':<24} | {results_on['total']['median']:>8.3f} ms           | "
        f"{results_off['total']['median']:>8.3f} ms           | {total_med_diff:>+7.3f} ms ({overhead_pct:+.1f}%)"
    )
    print(
        f"{'Total Run (p95)':<24} | {results_on['total']['p95']:>8.3f} ms           | "
        f"{results_off['total']['p95']:>8.3f} ms           | {total_p95_diff:>+7.3f} ms"
    )
    print("=" * 78 + "\n")

    summary = {
        "iterations": 100,
        "results_on": {
            "webhook_median_ms": results_on["webhook"]["median"],
            "webhook_p95_ms": results_on["webhook"]["p95"],
            "agent_median_ms": results_on["agent"]["median"],
            "agent_p95_ms": results_on["agent"]["p95"],
            "total_median_ms": results_on["total"]["median"],
            "total_p95_ms": results_on["total"]["p95"],
        },
        "results_off": {
            "webhook_median_ms": results_off["webhook"]["median"],
            "webhook_p95_ms": results_off["webhook"]["p95"],
            "agent_median_ms": results_off["agent"]["median"],
            "agent_p95_ms": results_off["agent"]["p95"],
            "total_median_ms": results_off["total"]["median"],
            "total_p95_ms": results_off["total"]["p95"],
        },
        "overhead": {
            "webhook_median_diff_ms": webhook_med_diff,
            "agent_median_diff_ms": agent_med_diff,
            "total_median_diff_ms": total_med_diff,
            "overhead_pct": overhead_pct,
        },
    }

    out_json = Path("docs/evidence/benchmark_1.5.json")
    out_json.parent.mkdir(parents=True, exist_ok=True)
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    print(f"Benchmark summary written to {out_json}")


if __name__ == "__main__":
    asyncio.run(main_async())
