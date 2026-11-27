"""Planner (v1 API): llm_func is accepted but LLM decomposition is not implemented; it must say so (rule 4)."""

import logging

from agentos import Planner


def test_llm_mode_warns_and_matches_rule_based_plan(caplog):
    goal = "Research the topic, write a summary, then review it"
    rule_based = Planner().create_graph(goal)
    with caplog.at_level(logging.WARNING, logger="agentos.core.planner"):
        llm_mode = Planner(llm_func=lambda prompt: "unused").create_graph(goal)
    assert any("not implemented in AgentOS 2.0" in r.getMessage() for r in caplog.records)
    assert [n.description for n in llm_mode.nodes] == [n.description for n in rule_based.nodes]


def test_rule_based_mode_does_not_warn(caplog):
    with caplog.at_level(logging.WARNING, logger="agentos.core.planner"):
        Planner().create_graph("Write a short report")
    assert not any("not implemented" in r.getMessage() for r in caplog.records)
