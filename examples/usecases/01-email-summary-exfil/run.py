"""Use Case 01: Email Summary & Prompt Injection Exfiltration Defense.

Demonstrates Information Flow Control (IFC) and Tool Proxy defenses in AgentOS 2.0:
- Benign input: Webhook delivers customer feedback. Agent summarizes and emails internal support.
- Attack input: Webhook delivers prompt injection attempting to exfiltrate secrets to an external attacker.
  AgentOS Tool Proxy intercepts the unauthorized tool call, prevents the sink invocation,
  records the violation event, and allows querying the complete provenance chain back to the trigger.

Usage:
    python run.py --input benign
    python run.py --input attack
"""

import argparse
import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

from crewai.llm import BaseLLM

from agentos.flows.engine import FlowEngine
from agentos.flows.models import EdgeDefinition, FlowDefinition, NodeDefinition
from agentos.flows.policy import SecurityPolicy
from agentos.flows.proxy import MockTransport
from agentos.flows.state import RunStatus
from agentos.storage import open_storage


class ScriptedLLM(BaseLLM):
    """Deterministic mock LLM for testing workflows without live API keys."""

    model: str = "mock/scripted"
    responses: list[str] = []
    _idx: int = 0

    def call(self, messages: Any, **kwargs: Any) -> str:
        idx = getattr(self, "_idx", 0)
        resp = self.responses[idx] if idx < len(self.responses) else "Final Answer: completed"
        object.__setattr__(self, "_idx", idx + 1)
        return resp


async def execute_usecase(input_type: str) -> dict[str, Any]:
    """Execute the use case with specified input type ('benign' or 'attack')."""
    base_dir = Path(__file__).resolve().parent

    # Load flow definition
    with open(base_dir / "flow.json", "r", encoding="utf-8") as f:
        flow_data = json.load(f)

    nodes = {
        nid: NodeDefinition(
            id=ndata["id"],
            type=ndata["type"],
            config=ndata.get("config", {}),
            pinned_args=ndata.get("pinned_args", {}),
        )
        for nid, ndata in flow_data["nodes"].items()
    }
    edges = [
        EdgeDefinition(
            source=edata["source"],
            target=edata["target"],
            arg_mapping=edata.get("arg_mapping", {}),
        )
        for edata in flow_data["edges"]
    ]
    flow = FlowDefinition(id=flow_data["id"], entrypoint=flow_data["entrypoint"], nodes=nodes, edges=edges)

    # Load input payload
    input_file = base_dir / "inputs" / f"{input_type}.json"
    with open(input_file, "r", encoding="utf-8") as f:
        payload = json.load(f)

    # Load scripted LLM responses
    with open(base_dir / "scripted_llm.json", "r", encoding="utf-8") as f:
        all_responses = json.load(f)
    responses = all_responses.get(input_type, [])

    transport = MockTransport()
    policy = SecurityPolicy(internal_domains={"corp.local"})
    llm = ScriptedLLM(model="mock/scripted", responses=responses)

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
        proj_dir = Path(td) / "project"
        proj_dir.mkdir(parents=True, exist_ok=True)
        (proj_dir / "agentos.config.yaml").write_text("preferred_tags: []\n", encoding="utf-8")
        vault_file = Path(td) / "vault.json"

        storage = await open_storage(str(proj_dir), backend="file", vault_path=str(vault_file))
        engine = FlowEngine(
            flow,
            storage,
            policy=policy,
            transport_registry={"send_email": transport},
            custom_llm=llm,
        )

        run_id = f"run_usecase_01_{input_type}"
        state = await engine.run(run_id, inputs=payload)
        events = await storage.events.list(run_id)

        result: dict[str, Any] = {
            "input_type": input_type,
            "status": state.status.value,
            "sent_calls": list(transport.sent_calls),
            "events_count": len(events),
        }

        if input_type == "benign":
            result["success"] = (state.status == RunStatus.SUCCEEDED and len(transport.sent_calls) == 1)
        else:
            # Find blocked / rejected event
            blocked_events = [e for e in events if e.type in ("tool_call_blocked", "tool_call_rejected")]
            result["attack_blocked"] = (len(blocked_events) >= 1 and len(transport.sent_calls) == 0)
            if blocked_events:
                b_ev = blocked_events[0]
                result["block_reason"] = b_ev.data.get("reason")
                chain = await engine.get_provenance_chain(run_id, b_ev.seq)
                result["provenance_chain"] = [
                    {"seq": e.seq, "type": e.type, "node": e.data.get("node_id") or e.data.get("agent_node")}
                    for e in chain
                ]

        await storage.close()
        return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Use Case 01: Email Summary Exfiltration Defense")
    parser.add_argument(
        "--input",
        choices=["benign", "attack"],
        required=True,
        help="Input type to run: 'benign' (normal processing) or 'attack' (prompt injection exfiltration)",
    )
    args = parser.parse_args()

    # Disable CrewAI telemetry and tracing during script execution
    os.environ["CREWAI_TELEMETRY_OPT_OUT"] = "1"
    os.environ["OTEL_SDK_DISABLED"] = "true"
    os.environ["AGENTOS_MOCK_LLM"] = "1"

    res = asyncio.run(execute_usecase(args.input))

    if args.input == "benign":
        print("\n" + "=" * 60)
        print("=== Use Case 01: Benign Execution ===")
        print("=" * 60)
        print(f"Status: {res['status'].upper()}")
        print(f"Sent Emails: {len(res['sent_calls'])}")
        if res["sent_calls"]:
            print(f"Recipient: {res['sent_calls'][0].get('to')}")
            print(f"Body: {res['sent_calls'][0].get('body')}")
        print("Flow completed successfully with zero security violations.")
        print("=" * 60 + "\n")
    else:
        print("\n" + "=" * 60)
        print("=== Use Case 01: Attack Execution ===")
        print("=" * 60)
        print(f"Status: {'ATTACK_BLOCKED' if res.get('attack_blocked') else 'FAILED'}")
        print(f"Sent Emails: {len(res['sent_calls'])} (Exfiltration strictly prevented!)")
        print(f"Block Reason: {res.get('block_reason')}")
        print("\n=== Provenance Chain (Backwards Trace to Trigger) ===")
        for item in res.get("provenance_chain", []):
            node_info = f" (node: {item['node']})" if item.get("node") else ""
            print(f"  [{item['seq']:02d}] {item['type']}{node_info}")
        print("=" * 60 + "\n")


if __name__ == "__main__":
    main()
