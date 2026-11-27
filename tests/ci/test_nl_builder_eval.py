"""4.0 natural-language builder eval in MOCK mode (CI): the 12 cases of agentos/builder/eval_cases.py through the
real builder pipeline with the scripted builder model (via the AgentOS router's MOCK chain, as the server uses it).

MOCK measures the guard rails (schema, invented-target questions, static check, repair, one-click fixes, refusals),
not model quality: scripts/nl_builder_live_eval.py runs the same cases against real models.
"""

import asyncio
import os
import re
from pathlib import Path

import pytest

os.environ["AGENTOS_MOCK_LLM"] = "1"

from agentos.builder import BuilderInputError, BuilderRequest, NLFlowBuilder  # noqa: E402
from agentos.builder.eval_cases import CASES, check_case, eval_policy  # noqa: E402
from agentos.builder.mock_builder import EXAMPLES  # noqa: E402
from agentos.llm.router_llm import AgentOSRouterLLM  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent.parent


async def _router_model(messages):
    """The same router the server uses; in MOCK mode its chain is the offline scripted model."""
    return await asyncio.to_thread(AgentOSRouterLLM(node_id="builder").call, messages, None)


async def run_case(case, policy):
    try:
        return await NLFlowBuilder(policy, None, _router_model).generate(BuilderRequest(description=case.description))
    except BuilderInputError as err:
        return {"refused_input": err.reason, "model_calls": 0}


@pytest.mark.parametrize("case", CASES, ids=[c.id for c in CASES])
def test_eval_case(case):
    policy = eval_policy()
    outcome = asyncio.run(run_case(case, policy))
    assert check_case(case, outcome, policy) == [], outcome


def test_eval_has_twelve_cases_and_full_mock_success():
    policy = eval_policy()
    results = [(c, asyncio.run(run_case(c, policy))) for c in CASES]
    ok = sum(1 for c, o in results if not check_case(c, o, policy))
    assert len(CASES) == 12 and ok == 12


def test_ui_examples_match_the_mock_examples():
    """The three clickable UI examples must be the texts the MOCK scripted builder answers."""
    src = (ROOT / "ui" / "src" / "flow" / "describeExamples.ts").read_text(encoding="utf-8")
    ui_texts = re.findall(r"text: '([^']+)'", src)
    assert ui_texts == list(EXAMPLES.values())
