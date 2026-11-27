"""Use case 15 (4.2): a test suite for the use case 07 support desk. MOCK only: scripted test model, fake email
senders, a fixture for the customer-record HTTP call. Nothing is sent, no model is called, no key is needed.

1. Saves the hand-written cases (suite.json): urgent -> approval reached and only oncall@corp.local; normal -> support
   queue only; injection -> no send to the attacker.
2. Adds the generated security tests (the 4.1 attack families that fit this flow; expectation: the attack does not
   reach an outside address).
3. Runs the whole suite against the flow: every case passes.
4. Changes the flow the way a careless edit would (the on-call email now goes to an outside address) and runs the
   suite again: the regression summary lists the newly failing cases, with readable diffs.
5. Runs the CLI the way a CI pipeline would: `agentos test uc07_support_desk --tags support --junit ...` exits 0.

A tripwire replaces every real outbound path (SMTP, the httpx network transport, the HTTP sender, DNS) and must record
nothing.

Run: .\\venv\\Scripts\\python.exe examples/usecases/15-flow-tests/run.py
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
os.environ.setdefault("CREWAI_TELEMETRY_OPT_OUT", "1")
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT))

from agentos.flows.policy import SecurityPolicy  # noqa: E402
from agentos.flowtests import TestCase, TestEnv, execute_suite, flowtests_store_for  # noqa: E402
from agentos.flowtests.generate import security_cases  # noqa: E402
from agentos.storage import open_storage  # noqa: E402
from agentos.storage.models import FlowRecord  # noqa: E402

SUITE = json.loads((HERE / "suite.json").read_text(encoding="utf-8"))
FLOW = json.loads((HERE / SUITE["flow"]).read_text(encoding="utf-8"))
TICKETS = json.loads((ROOT / "examples" / "usecases" / "07-support-desk-copilot" / "inputs" / "tickets.json")
                     .read_text(encoding="utf-8"))
POLICY = SecurityPolicy(internal_domains={"corp.local"})


class _Tripwire:
    """Same idea as benchmarks/awib/tripwire.py, without pytest's monkeypatch."""

    def __init__(self) -> None:
        self.calls: list[str] = []
        self._undo: list[tuple[object, str, object]] = []

    def __enter__(self) -> "_Tripwire":
        import smtplib

        import httpx

        from agentos.flows import net_guard

        def trip(name: str):
            def _f(*_a, **_k):
                self.calls.append(name)
                raise AssertionError(f"real transport called: {name}")
            return _f

        for obj, attr, name in ((net_guard, "httpx_sender", "http sender"), (net_guard, "default_resolver", "dns"),
                                (smtplib.SMTP, "connect", "smtp"), (smtplib.SMTP_SSL, "connect", "smtp_ssl"),
                                (httpx.HTTPTransport, "handle_request", "httpx")):
            self._undo.append((obj, attr, getattr(obj, attr)))
            setattr(obj, attr, trip(name))
        return self

    def __exit__(self, *exc) -> None:
        for obj, attr, old in reversed(self._undo):
            setattr(obj, attr, old)


def hand_cases() -> list[TestCase]:
    out = []
    for c in SUITE["cases"]:
        c = dict(c)
        out.append(TestCase(flow_id=FLOW["id"], input=TICKETS[c.pop("ticket")], fixtures=SUITE["fixtures"], **c))
    return out


def report(title: str, suite) -> None:
    c = suite.counts
    print(f"\n== {title}: {c['pass']}/{c['total']} passed (model {suite.model}, target {suite.target})")
    reg = suite.regression or {}
    if not reg.get("first_run"):
        print(f"   regression: newly failing {[x['name'] for x in reg.get('newly_failing', [])]}, "
              f"newly passing {[x['name'] for x in reg.get('newly_passing', [])]}, "
              f"still failing {len(reg.get('still_failing', []))}")
    for r in suite.results:
        if r.status != "pass":
            print(f"   {r.status.upper()} {r.name} (run {r.run_id})")
            for f in r.failures[:2]:
                print(f"      {f.message}")


async def _run_usecase_async() -> bool:
    with tempfile.TemporaryDirectory(prefix="agentos-uc15-", ignore_cleanup_errors=True) as td:
        proj = Path(td) / "project"
        proj.mkdir()
        (proj / "agentos.config.yaml").write_text("preferred_tags: []\n", encoding="utf-8")
        storage = await open_storage(str(proj), backend="file", vault_path=str(Path(td) / "vault.json"))
        try:
            await storage.flows.put_draft(FlowRecord(**FLOW))
            store = flowtests_store_for(storage)
            for c in hand_cases():
                await store.put_case(c)
            sec = security_cases(FLOW)
            for c in sec:
                await store.put_case(c)
            print(f"saved {len(SUITE['cases'])} hand-written cases and {len(sec)} generated security tests "
                  f"({len({c.attack['family'] for c in sec})} attack families)")
            env = TestEnv(storage=storage, policy=POLICY)
            with _Tripwire() as wire:
                before = await execute_suite(store, env, FLOW["id"])
                report("Before the change", before)
                edited = json.loads(json.dumps(FLOW))
                edited["nodes"]["page_oncall"]["pinned_args"]["to"] = "oncall@outsourcer.example"
                await storage.flows.put_draft(FlowRecord(**edited))
                after = await execute_suite(store, env, FLOW["id"], tags=["support"])
                report("After a careless edit (on-call email goes outside)", after)
            await storage.flows.put_draft(FlowRecord(**FLOW))  # restore for the CLI step
        finally:
            await storage.close()
        assert wire.calls == [], wire.calls
        assert before.all_passed, "every case passes against the use case 07 flow"
        newly = {x["name"] for x in after.regression["newly_failing"]}
        assert "injection: no send to the attacker" in newly, newly
        assert any("oncall@outsourcer.example" in f.message for r in after.results for f in r.failures)

        # 5. the CLI, as in a CI pipeline (same storage resolution as the server: --project)
        from typer.testing import CliRunner

        from agentos.cli.main import app

        junit = Path(td) / "junit.xml"
        home = Path(td) / "home"
        # Rule 13: every AgentOS path of the CLI points into this temp folder (never the real ~/.agentos)
        env = {"AGENTOS_INTERNAL_DOMAINS": "corp.local", "AGENTOS_MONGO_URI": "",
               "AGENTOS_VAULT_PATH": str(home / "vault.json"), "AGENTOS_MASTER_KEY_FILE": str(home / "master.key"),
               "AGENTOS_API_TOKEN_FILE": str(home / "api.token"), "AGENTOS_DATA_DIR": str(home / "data")}
        saved = {k: os.environ.get(k) for k in env}
        os.environ.update(env)
        try:
            # the CLI runs its own event loop: call it from a worker thread
            res = await asyncio.to_thread(CliRunner().invoke, app, ["test", FLOW["id"], "--tags", "support",
                                                                    "--junit", str(junit), "--project", str(proj)])
        finally:
            for k, v in saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
        print(f"\n== CLI: agentos test {FLOW['id']} --tags support -> exit code {res.exit_code}")
        print("\n".join("   " + line for line in res.output.strip().splitlines()[-2:]))
        assert res.exit_code == 0, (res.output, repr(res.exception))
        assert 'failures="0"' in junit.read_text(encoding="utf-8")
    print("\nUse case 15 OK: the suite passes, the bad edit is caught as a regression, the CLI exits 0, "
          "nothing was sent.")
    return True


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(_run_usecase_async()) else 1)
