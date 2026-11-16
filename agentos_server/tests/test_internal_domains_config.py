"""
2.0 cleanup (intentional secure-default change): trusted internal email domains come from admin
config only. Default is EMPTY (previously corp.local/internal.local were hard-coded).
Precedence: AGENTOS_INTERNAL_DOMAINS env var > security.internal_domains in agentos.config.yaml.
"""

from __future__ import annotations

import pytest

from agentos_server.app import create_app, load_internal_domains


def _project(tmp_path, cfg: str = "preferred_tags: []\n"):
    (tmp_path / "agentos.config.yaml").write_text(cfg, encoding="utf-8")
    return str(tmp_path)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv("AGENTOS_INTERNAL_DOMAINS", raising=False)
    monkeypatch.delenv("AGENTOS_MONGO_URI", raising=False)
    monkeypatch.setenv("AGENTOS_API_TOKEN", "test-token-domains")


def test_default_is_empty(tmp_path):
    assert load_internal_domains(_project(tmp_path)) == set()
    app = create_app(project_path=_project(tmp_path))
    assert app.state.security_policy.internal_domains == set()
    assert app.state.security_policy.is_internal_email("support@corp.local") is False


def test_config_file(tmp_path):
    p = _project(tmp_path, "security:\n  internal_domains: [Corp.Local, '@internal.local']\n")
    assert load_internal_domains(p) == {"corp.local", "internal.local"}
    assert create_app(project_path=p).state.security_policy.is_internal_email("a@corp.local") is True


def test_env_wins_over_config(tmp_path, monkeypatch):
    p = _project(tmp_path, "security:\n  internal_domains: [corp.local]\n")
    monkeypatch.setenv("AGENTOS_INTERNAL_DOMAINS", " example.org , ops.example.org ,")
    assert load_internal_domains(p) == {"example.org", "ops.example.org"}


def test_empty_env_overrides_config_to_none_trusted(tmp_path, monkeypatch):
    p = _project(tmp_path, "security:\n  internal_domains: [corp.local]\n")
    monkeypatch.setenv("AGENTOS_INTERNAL_DOMAINS", "")
    assert load_internal_domains(p) == set()


def test_invalid_config_type_is_rejected(tmp_path):
    p = _project(tmp_path, "security:\n  internal_domains: corp.local\n")
    with pytest.raises(ValueError, match="must be a list"):
        load_internal_domains(p)
