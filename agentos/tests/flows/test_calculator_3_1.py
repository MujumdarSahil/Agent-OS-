"""3.1 Part 0b (MOCK): the `calculator` tool and the agent tool picker's server list.

- safe arithmetic: normal maths works; huge exponents/numbers, names, attributes, calls, strings refused;
- NodeSpec contract; side effect NONE; output untrusted (tool output) through the agent proxy and as a flow
  node, with the input's confidentiality; publish and run time labels identical;
- GET /api/v2/agents/tool-options lists only tools the save check accepts (no file_read/file_write).
"""

from __future__ import annotations

from pathlib import Path

import jsonschema
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from agentos.flows.calculator import CalculatorError, evaluate
from agentos.flows.engine import FlowEngine
from agentos.flows.labels import Label
from agentos.flows.models import FlowDefinition
from agentos.flows.policy import SecurityPolicy
from agentos.flows.proxy import AgentOSToolProxy
from agentos.flows.specs import BUILTIN_NODE_SPECS, SideEffectClass
from agentos.flows.state import RunStatus
from agentos.flows.static_analyzer import StaticFlowAnalyzer
from agentos.flows.tool_catalog import BUILTIN_CATALOG
from agentos.storage import open_storage


@pytest.mark.parametrize("expr,expected", [
    ("1 + 2 * 3", 7), ("(1 + 2) * 3", 9), ("7 / 2", 3.5), ("7 // 2", 3), ("7 % 4", 3), ("-3 + +5", 2),
    ("2 ** 10", 1024), ("sqrt(16)", 4.0), ("abs(-2.5)", 2.5), ("round(2.567, 2)", 2.57), ("max(1, 9, 3)", 9),
    ("min(4, 2)", 2), ("floor(2.9) + ceil(2.1)", 5), ("log(1)", 0.0), ("exp(0)", 1.0), ("  12.5e2  ", 1250.0),
])
def test_normal_maths(expr, expected):
    assert evaluate(expr) == expected


@pytest.mark.parametrize("expr,needle", [
    ("10 ** 1000", "exponent too large"),
    ("9 ** 9 ** 9", "too large"),
    ("2 ** 65", "exponent too large"),
    ("10000000 ** 5", "exponent too large"),
    ("10 ** 60", "number too large"),
    ("99999999999 * 99999999999", "number too large"),
    ("1e300 * 1e300", "number too large"),
    ("10 ** 16", "too large"),
    ("1 / 0", "division by zero"),
    ("sqrt(-1)", "sqrt"),
    ("x + 1", "names are not allowed"),
    ("__import__('os')", "only these functions"),
    ("(1).__class__", "attribute access"),
    ("abs.__self__", "attribute access"),
    ("eval('1')", "only these functions"),
    ("open('f')", "only these functions"),
    ("[1, 2][0]", "not allowed"),
    ("'a' * 3", "only numbers"),
    ("True + 1", "only numbers"),
    ("lambda: 1", "not allowed"),
    ("[x for x in (1,)]", "not allowed"),
    ("max(*[1, 2])", "not allowed"),
    ("round(2.5, ndigits=1)", "keyword"),
    ("1 if 1 else 2", "not allowed"),
    ("1 < 2", "not allowed"),
    ("import os", "not a valid"),
    ("1 +", "not a valid"),
    ("1" + "+1" * 1200, "too long"),
    ("+".join(["1"] * 150), "too complex"),
])
def test_refused(expr, needle):
    with pytest.raises(CalculatorError) as err:
        evaluate(expr)
    assert needle in str(err.value)


def test_non_string_refused():
    with pytest.raises(CalculatorError):
        evaluate(42)


def test_contract_spec():
    spec = BUILTIN_NODE_SPECS["calculator"]
    for schema in (spec.config_schema, spec.input_schema, spec.output_schema):
        jsonschema.Draft202012Validator.check_schema(schema)
    assert spec.side_effect == SideEffectClass.NONE and spec.input_schema["required"] == ["expression"]
    assert BUILTIN_CATALOG.resolve("calculator").spec is spec


@pytest_asyncio.fixture
async def storage(tmp_path: Path):
    (tmp_path / "agentos.config.yaml").write_text("preferred_tags: []\n", encoding="utf-8")
    s = await open_storage(str(tmp_path), backend="file", vault_path=str(tmp_path / "vault.json"))
    yield s
    await s.close()


@pytest.mark.asyncio
async def test_proxy_path_result_and_untrusted_output(storage):
    proxy = AgentOSToolProxy(run_id="r_calc", agent_node_id="agent", storage=storage, policy=SecurityPolicy(),
                             pinned_args={}, agent_input_label=Label.trusted(sources={"cfg"}))
    assert await proxy.invoke("agent", "calculator", {"expression": "6 * 7"}) == "42"
    assert proxy.agent_context_label.integrity == "untrusted"  # tool output is untrusted
    assert (await proxy.invoke("agent", "calculator", {"expression": "__import__('os')"})).startswith(
        "Calculator error: only these functions")


@pytest.mark.asyncio
async def test_flow_node_label_untrusted_keeps_confidentiality_and_matches_publish(storage, monkeypatch):
    import agentos.flows.extraction as ex

    fd = FlowDefinition(id="calc", entrypoint="calc",
                        nodes={"calc": {"id": "calc", "type": "calculator", "config": {}}}, edges=[])
    static_labels, _, _ = StaticFlowAnalyzer(fd, SecurityPolicy())._propagate_labels_fixpoint()
    st = await FlowEngine(fd, storage, policy=SecurityPolicy()).run(run_id="r_calc_node", inputs={"expression": "2 + 3"})
    assert st.status == RunStatus.SUCCEEDED and st.node_outputs["calc"] == {"result": 5}
    assert st.node_output_labels["calc"] == static_labels["calc"]
    assert st.node_output_labels["calc"]["result"].integrity == "untrusted"
    original = ex.shared_inbound
    monkeypatch.setattr(ex, "shared_inbound", lambda *a: Label(integrity="untrusted", confidentiality="secret",
                                                                 sources=original(*a).sources))
    st2 = await FlowEngine(fd, storage, policy=SecurityPolicy()).run(run_id="r_calc_secret", inputs={"expression": "1"})
    assert st2.node_output_labels["calc"]["result"].confidentiality == "secret"


@pytest.mark.asyncio
async def test_tool_options_list_only_what_the_server_accepts(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTOS_API_TOKEN", "test-token-tool-options")
    monkeypatch.delenv("AGENTOS_MONGO_URI", raising=False)
    (tmp_path / "agentos.config.yaml").write_text("preferred_tags: []\n", encoding="utf-8")
    from agentos_server.app import create_app

    app = create_app(project_path=str(tmp_path))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://localhost",
                           headers={"Authorization": "Bearer test-token-tool-options", "Host": "localhost"}) as c:
        opts = (await c.get("/api/v2/agents/tool-options")).json()
        names = [o["name"] for o in opts]
        assert names == ["calculator", "fetch_url", "send_email"]
        assert "file_read" not in names and "file_write" not in names
        for n in names:  # every option is accepted by the save check
            r = await c.post("/api/v2/agents", json={"name": f"a_{n}", "role": "r", "goal": "g", "backstory": "b",
                                                     "tools": [n]})
            assert r.status_code == 200, r.text
        for bad in ("file_read", "file_write"):
            r = await c.post("/api/v2/agents", json={"name": "bad", "role": "r", "goal": "g", "backstory": "b",
                                                     "tools": [bad]})
            assert r.status_code == 400 and "fail closed" in r.json()["detail"]
