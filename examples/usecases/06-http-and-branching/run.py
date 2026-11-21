"""
Use case 06: HTTP requests and branching (sub-milestone 2.3). MOCK only:
a fake DNS resolver and HTTP sender stand in for the network; email goes to MockTransport.

Benign: fetch a public status page, branch on it, email a summary to a pinned internal address.
Attacks:
  A1 SSRF to the cloud metadata address (pinned URL and via a redirect) -> blocked at runtime;
  A2 attacker-injected URL from the webhook payload -> publish refused (untrusted url);
  A3 attacker-controlled predicate trying to reach a destructive sink -> publish refused and
     blocked at runtime with 0 requests.

Run:  python examples/usecases/06-http-and-branching/run.py
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("AGENTOS_MOCK_LLM", "1")
ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from agentos.flows.engine import FlowEngine  # noqa: E402
from agentos.flows.models import FlowDefinition  # noqa: E402
from agentos.flows.net_guard import HttpRequestTransport, RawResponse  # noqa: E402
from agentos.flows.policy import SecurityPolicy  # noqa: E402
from agentos.flows.proxy import MockTransport  # noqa: E402
from agentos.flows.state import RunStatus  # noqa: E402
from agentos.flows.static_analyzer import StaticFlowAnalyzer  # noqa: E402
from agentos.storage import open_storage  # noqa: E402

HERE = Path(__file__).resolve().parent
POLICY = SecurityPolicy(internal_domains={"corp.local"}, http_allowlist=["internal.corp"])
DNS = {"status.example.com": ["93.184.216.34"], "attacker.example": ["203.0.113.66"], "internal.corp": ["10.20.0.5"]}
PAGES = {
    ("status.example.com", "/today"): RawResponse(200, {"content-type": "text/plain"}, b"incident: login latency is high"),
    ("status.example.com", "/redirect"): RawResponse(302, {"location": "http://169.254.169.254/latest/meta-data/"}, b""),
}


class FakeNetwork:
    def __init__(self):
        self.calls: list[dict] = []
        self.transport = HttpRequestTransport(allowlist=POLICY.http_allowlist, resolver=lambda h, p: DNS[h], sender=self.send)

    def send(self, method, target, path, headers, body, timeout_s, max_bytes):
        self.calls.append({"method": method, "host": target.host, "ip": target.ip, "path": path})
        return PAGES.get((target.host, path), RawResponse(404, {}, b"not found"))


def load_flow(name: str) -> FlowDefinition:
    return FlowDefinition(**json.loads((HERE / "flows" / f"{name}.flow.json").read_text(encoding="utf-8")))


def load_input(name: str) -> dict:
    return json.loads((HERE / "inputs" / f"{name}.json").read_text(encoding="utf-8"))


def publish_check(fd: FlowDefinition) -> list:
    return StaticFlowAnalyzer(fd, POLICY).verify().violations


async def run_flow(storage, fd, run_id, inputs, net, email):
    eng = FlowEngine(fd, storage, policy=POLICY, transport_registry={"send_email": email, "http_request": net.transport})
    return await eng.run(run_id=run_id, inputs=inputs)


async def _run_usecase_async() -> bool:
    ok = True
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        (Path(tmp) / "agentos.config.yaml").write_text("preferred_tags: []\n", encoding="utf-8")
        storage = await open_storage(tmp, backend="file", vault_path=str(Path(tmp) / "vault.json"))
        try:
            # Benign
            fd = load_flow("benign")
            violations = publish_check(fd)
            net, email = FakeNetwork(), MockTransport()
            st = await run_flow(storage, fd, "uc06_benign", load_input("benign"), net, email)
            benign_ok = (not violations and st.status == RunStatus.SUCCEEDED and len(email.sent_calls) == 1
                         and email.sent_calls[0]["to"] == "ops@corp.local" and st.node_states["skip_note"].value == "skipped")
            print(f"[{'PASS' if benign_ok else 'FAIL'}] benign: published={not violations} status={st.status.value} "
                  f"emails={len(email.sent_calls)} to={[c['to'] for c in email.sent_calls]}")
            ok &= benign_ok

            # A1: SSRF to metadata (pinned) and via redirect
            for name in ("attack_ssrf_metadata", "attack_ssrf_redirect"):
                fd = load_flow(name)
                net, email = FakeNetwork(), MockTransport()
                st = await run_flow(storage, fd, f"uc06_{name}", {}, net, email)
                hit_metadata = any(c["host"] == "169.254.169.254" for c in net.calls)
                passed = st.status == RunStatus.FAILED and "169.254.169.254" in (st.error or "") and not hit_metadata
                print(f"[{'PASS' if passed else 'FAIL'}] {name}: status={st.status.value} metadata_requests={int(hit_metadata)}")
                ok &= passed

            # A2: attacker-injected URL from the webhook payload
            fd = load_flow("attack_injected_url")
            violations = publish_check(fd)
            refused = any(v.target_arg == "url" for v in violations)
            print(f"[{'PASS' if refused else 'FAIL'}] attack_injected_url: publish refused={refused} "
                  f"reasons={[v.reason[:70] for v in violations][:1]}")
            ok &= refused

            # A3: attacker-controlled predicate -> destructive sink
            fd = load_flow("attack_predicate_destructive")
            violations = publish_check(fd)
            net, email = FakeNetwork(), MockTransport()
            st = await run_flow(storage, fd, "uc06_attack_predicate", load_input("attack_predicate"), net, email)
            refused = any(v.target_arg == "(control)" for v in violations)
            passed = refused and st.status == RunStatus.FAILED and not net.calls
            print(f"[{'PASS' if passed else 'FAIL'}] attack_predicate_destructive: publish refused={refused} "
                  f"runtime={st.status.value} requests={len(net.calls)}")
            ok &= passed
        finally:
            await storage.close()
    print("Use case 06:", "ALL PASS" if ok else "FAILURES")
    return ok


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(_run_usecase_async()) else 1)
