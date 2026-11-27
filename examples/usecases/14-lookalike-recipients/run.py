"""Use case 14 (4.1b): look-alike (homoglyph) recipients on an approval card. MOCK: MockTransport, nothing is sent.

The use case 05 approval flow lets the incoming message choose the recipient, and a human approves it. AWIB (4.1)
showed that `support@corp.lоcal` (Cyrillic "о") looked identical on the card. Now:
- benign: a plain address, no warning, approved normally, sent;
- attack: the look-alike gets a red warning with its punycode form; approving WITHOUT the extra confirmation is
  refused; the attentive approver rejects it, so nothing is sent;
- non-English: a legitimate address (josé@ejemplo.es) is flagged (non-ASCII) but deliverable after the confirmation.

Run: .\\venv\\Scripts\\python.exe examples/usecases/14-lookalike-recipients/run.py
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("AGENTOS_MOCK_LLM", "1")
os.environ["AGENTOS_FORBID_REAL_HOME"] = "1"
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT))

FLOW = ROOT / "examples" / "usecases" / "05-visual-builder" / "flows" / "approval.flow.json"


async def _scenario(payload: str) -> tuple[list[dict], object, object, object]:
    from agentos.flows.engine import FlowEngine
    from agentos.flows.models import FlowDefinition
    from agentos.flows.policy import SecurityPolicy
    from agentos.flows.proxy import MockTransport
    from agentos.storage import open_storage

    td = Path(tempfile.mkdtemp(prefix="agentos-uc14-"))
    (td / "p").mkdir()
    (td / "p" / "agentos.config.yaml").write_text("preferred_tags: []\n", encoding="utf-8")
    storage = await open_storage(str(td / "p"), backend="file", vault_path=str(td / "vault.json"))
    mt = MockTransport()
    engine = FlowEngine(FlowDefinition(**json.loads(FLOW.read_text(encoding="utf-8"))), storage,
                        policy=SecurityPolicy(internal_domains={"corp.local"}), transport_registry={"send_email": mt})
    await engine.run("uc14", inputs=payload, raise_on_error=False)
    card = [e for e in await storage.events.list("uc14") if e.type == "node_waiting"][-1].data
    return card.get("destination_warnings") or [], engine, storage, mt


async def _run_usecase_async() -> bool:
    inputs = {k: json.loads((HERE / "inputs" / f"{k}.json").read_text(encoding="utf-8"))["to"]
              for k in ("benign", "attack", "non_english")}
    ok = True

    warnings, engine, storage, mt = await _scenario(inputs["benign"])
    await engine.approve(run_id="uc14", node_id="gate", decision=True)
    await storage.close()
    benign_ok = warnings == [] and len(mt.sent_calls) == 1
    print(f"[benign] no warning, approved, sent: {benign_ok}")
    ok &= benign_ok

    warnings, engine, storage, mt = await _scenario(inputs["attack"])
    refused = False
    try:
        await engine.approve(run_id="uc14", node_id="gate", decision=True)
    except ValueError:
        refused = True
    await engine.approve(run_id="uc14", node_id="gate", decision="reject")  # the attentive approver
    await storage.close()
    attack_ok = bool(warnings) and warnings[0]["confusable"] and refused and mt.sent_calls == []
    print(f"[attack] warning {warnings[0]['ascii_form'] if warnings else '-'}, approve without confirmation "
          f"refused: {refused}, nothing sent: {mt.sent_calls == []}")
    ok &= attack_ok

    warnings, engine, storage, mt = await _scenario(inputs["non_english"])
    await engine.approve(run_id="uc14", node_id="gate", decision=True, confirm_lookalike=True)
    await storage.close()
    ne_ok = bool(warnings) and warnings[0]["confusable"] is False and len(mt.sent_calls) == 1
    print(f"[non-English] flagged (not confusable), delivered after confirmation: {ne_ok}")
    ok &= ne_ok
    print("USE CASE 14:", "PASS" if ok else "FAIL")
    return bool(ok)


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(_run_usecase_async()) else 1)
