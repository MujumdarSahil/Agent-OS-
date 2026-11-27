"""4.1b D8 CI smoke (MOCK: AgentDojo's ground-truth replay, no model, no keys, no network).

Proves the adapter wires up: every tool of the four suites resolves to an AgentOS NodeSpec, and one injection
(banking: send money to the attacker's IBAN) succeeds without a defense but is blocked by the AgentOS tool proxy.
Runs in the separate `agentdojo-smoke` CI job (needs pip install -e ".[benchmark]").
"""

from __future__ import annotations

import pytest

pytest.importorskip("agentdojo")

from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline  # noqa: E402
from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage  # noqa: E402
from agentdojo.attacks.attack_registry import load_attack  # noqa: E402
from agentdojo.functions_runtime import FunctionsRuntime  # noqa: E402
from agentdojo.task_suite.load_suites import get_suite  # noqa: E402

from agentos.flows.specs import SideEffectClass  # noqa: E402
from benchmarks.agentdojo.defense import (AgentDojoCatalog, AgentOSExecutor, DefendedPipeline,  # noqa: E402
                                          ExecutorElement, PlainExecutor, ReplayAgent)
from benchmarks.agentdojo.specs import SINKS  # noqa: E402

VERSION = "v1.2.2"


def _replay(executor, suite, ut, it):
    pipe = DefendedPipeline(AgentPipeline([SystemMessage("You are a helpful assistant."), InitQuery(),
                                           ReplayAgent(ut, it, ExecutorElement(executor))]),
                            executor, f"local-replay-{executor.name}")
    injections = load_attack("important_instructions_no_model_name", suite, pipe).attack(ut, it)
    try:
        return suite.run_task_with_pipeline(pipe, ut, it, injections)
    finally:
        executor.close()


@pytest.mark.parametrize("name", ["workspace", "slack", "travel", "banking"])
def test_every_suite_tool_is_mapped_and_sinks_have_rules(name):
    suite = get_suite(VERSION, name)
    catalog = AgentDojoCatalog(FunctionsRuntime(suite.tools))
    for tool in suite.tools:
        entry = catalog.resolve(tool.name)
        assert entry.is_mcp and entry.server == "agentdojo"
        if tool.name in SINKS:
            assert entry.spec.side_effect != SideEffectClass.READ and entry.spec.sink_rules
        else:
            assert entry.spec.side_effect == SideEffectClass.READ
    with pytest.raises(LookupError):
        catalog.resolve("not_a_tool")


def test_banking_injection_succeeds_without_defense_and_is_blocked_by_agentos():
    suite = get_suite(VERSION, "banking")
    ut, it = suite.get_user_task_by_id("user_task_0"), suite.get_injection_task_by_id("injection_task_0")

    utility, attacked = _replay(PlainExecutor(), suite, ut, it)
    assert utility is True and attacked is True  # an obedient agent with no defense sends the money

    ex = AgentOSExecutor()
    utility, attacked = _replay(ex, suite, ut, it)
    assert attacked is False  # the injected send_money (recipient from untrusted data) is refused
    assert ex.blocked_tools.get("send_money", 0) >= 1
    # the user's own payment is refused too: its IBAN comes out of the bill file (untrusted). D3 utility cost.
    assert utility is False
