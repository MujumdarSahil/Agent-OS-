"""2.5b (MOCK): admin configuration for quarantined extraction.

- ``security.allowlists`` (name -> list of strings) loads into SecurityPolicy.allowlists; bad shapes are rejected.
- ``allow_extraction_for_destructive`` defaults to False; config or env (env wins) can enable it; never a flow.
- /api/v2/node-specs lists quarantined_extraction with the allowlist NAMES only (entries never exposed).
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from agentos_server.app import create_app, load_allow_extraction_for_destructive, load_allowlists

TOKEN = "test-token-extraction"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv("AGENTOS_ALLOW_EXTRACTION_FOR_DESTRUCTIVE", raising=False)
    monkeypatch.delenv("AGENTOS_ALLOW_DECLASSIFIED_FOR_DESTRUCTIVE", raising=False)
    monkeypatch.delenv("AGENTOS_MONGO_URI", raising=False)
    monkeypatch.setenv("AGENTOS_API_TOKEN", TOKEN)


def _project(tmp_path, cfg: str = "preferred_tags: []\n"):
    (tmp_path / "agentos.config.yaml").write_text(cfg, encoding="utf-8")
    return str(tmp_path)


def test_defaults_are_secure(tmp_path):
    p = _project(tmp_path)
    assert load_allowlists(p) == {}
    assert load_allow_extraction_for_destructive(p) is False
    policy = create_app(project_path=p).state.security_policy
    assert policy.allowlists == {} and policy.allow_extraction_for_destructive is False


def test_config_and_env(tmp_path, monkeypatch):
    p = _project(tmp_path, "security:\n  allowlists:\n    oncall: [security@corp.local, ' ops@corp.local ']\n"
                           "  allow_extraction_for_destructive: true\n")
    assert load_allowlists(p) == {"oncall": ["security@corp.local", "ops@corp.local"]}
    assert load_allow_extraction_for_destructive(p) is True
    monkeypatch.setenv("AGENTOS_ALLOW_EXTRACTION_FOR_DESTRUCTIVE", "0")
    assert load_allow_extraction_for_destructive(p) is False


def test_renamed_flag_covers_both_and_wins_over_the_old_name(tmp_path, monkeypatch):
    """2.5b hardening: allow_declassified_for_destructive (validator + extraction); the old name is still read."""
    from agentos_server.app import load_allow_declassified_for_destructive

    p = _project(tmp_path, "security:\n  allow_declassified_for_destructive: true\n"
                           "  allow_extraction_for_destructive: false\n")
    assert load_allow_declassified_for_destructive(p) is True
    assert create_app(project_path=p).state.security_policy.allow_declassified_for_destructive is True
    monkeypatch.setenv("AGENTOS_ALLOW_EXTRACTION_FOR_DESTRUCTIVE", "1")
    monkeypatch.setenv("AGENTOS_ALLOW_DECLASSIFIED_FOR_DESTRUCTIVE", "0")
    assert load_allow_declassified_for_destructive(p) is False  # the new env name wins


@pytest.mark.parametrize("cfg", [
    "security:\n  allowlists: [a, b]\n",
    "security:\n  allowlists:\n    oncall: security@corp.local\n",
    "security:\n  allow_extraction_for_destructive: 'yes'\n",
])
def test_bad_shapes_rejected(tmp_path, cfg):
    p = _project(tmp_path, cfg)
    with pytest.raises(ValueError):
        load_allowlists(p)
        load_allow_extraction_for_destructive(p)


def test_node_specs_lists_extraction_with_allowlist_names_only(tmp_path):
    p = _project(tmp_path, "security:\n  allowlists:\n    oncall: [security@corp.local]\n")
    client = TestClient(create_app(project_path=p), base_url="http://localhost")
    r = client.get("/api/v2/node-specs", headers={"Authorization": f"Bearer {TOKEN}", "Host": "localhost"})
    assert r.status_code == 200, r.text
    specs = r.json()
    qx = next(s for s in specs if s["type"] == "quarantined_extraction")
    assert qx["declassifies"] is True and qx["allowlist_names"] == ["oncall"]
    assert "security@corp.local" not in str(qx)
