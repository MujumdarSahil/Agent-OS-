"""
Tests for Sub-milestone 2.2 Webhook Trigger and Anti-Oracle Security.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import tempfile
import time
import pytest
from starlette.testclient import TestClient

from agentos.storage.file import open_file_storage
from agentos.storage.models import FlowRecord, WebhookRecord
from agentos_server.app import create_app


def _compute_sig(secret_key: str, ts: int, body: str) -> str:
    payload = f"{ts}.{body}".encode("utf-8")
    hex_digest = hmac.new(secret_key.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    return f"sha256={hex_digest}"


@pytest.fixture
def webhook_env():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp_dir:
        storage = open_file_storage(tmp_dir)
        app = create_app(project_path=tmp_dir, storage=storage)
        client = TestClient(app, base_url="http://localhost")
        yield {
            "tmp_dir": tmp_dir,
            "storage": storage,
            "app": app,
            "client": client,
        }


@pytest.mark.asyncio
async def test_webhook_crud_api(webhook_env):
    """Test CRUD endpoints under /api/v2/webhooks (token authenticated)."""
    env = webhook_env
    client = env["client"]
    token = env["app"].state.api_token
    auth_headers = {"Authorization": f"Bearer {token}"}

    # 1. Create draft flow first
    flow = FlowRecord(
        id="flow_hook_crud",
        name="Hook Flow",
        entrypoint="in",
        nodes={"in": {"id": "in", "type": "webhook_trigger", "config": {}}},
        edges=[],
    )
    await env["storage"].flows.put_draft(flow)

    # 2. Create webhook: returns secret_path and secret_key ONCE
    resp = client.post(
        "/api/v2/webhooks",
        json={"name": "Alert Hook", "flow_id": "flow_hook_crud", "rate_limit_per_minute": 30},
        headers=auth_headers,
    )
    assert resp.status_code == 201, resp.text
    data = resp.json()
    webhook_id = data["webhook_id"]
    secret_path = data["secret_path"]
    secret_key = data["secret_key"]
    assert len(secret_path) >= 24
    assert len(secret_key) >= 32
    assert "secret_path_hash" in data

    # 3. List webhooks: does NOT return secret_path or secret_key
    list_resp = client.get("/api/v2/webhooks", headers=auth_headers)
    assert list_resp.status_code == 200
    hooks = list_resp.json()
    assert len(hooks) == 1
    assert hooks[0]["secret_path"] is None
    assert hooks[0]["secret_key"] is None

    # 4. Get single webhook: does NOT return secret_path or secret_key
    get_resp = client.get(f"/api/v2/webhooks/{webhook_id}", headers=auth_headers)
    assert get_resp.status_code == 200
    assert get_resp.json()["secret_path"] is None

    # 5. Rotate webhook: returns NEW secret_path and secret_key ONCE
    rot_resp = client.post(f"/api/v2/webhooks/{webhook_id}/rotate", headers=auth_headers)
    assert rot_resp.status_code == 200
    rot_data = rot_resp.json()
    assert rot_data["secret_path"] is not None and rot_data["secret_path"] != secret_path
    assert rot_data["secret_key"] is not None and rot_data["secret_key"] != secret_key

    # 6. Delete webhook
    del_resp = client.delete(f"/api/v2/webhooks/{webhook_id}", headers=auth_headers)
    assert del_resp.status_code == 204
    get_after_del = client.get(f"/api/v2/webhooks/{webhook_id}", headers=auth_headers)
    assert get_after_del.status_code == 404


@pytest.mark.asyncio
async def test_public_hosts_only_applies_to_hooks(webhook_env):
    """
    AGENTOS_PUBLIC_HOSTS applies ONLY to /hooks/* paths.
    All other paths (/api and /) keep the strict localhost-only rule.
    """
    env = webhook_env
    client = env["client"]
    token = env["app"].state.api_token

    os.environ["AGENTOS_PUBLIC_HOSTS"] = "hooks.example.com,api.public.net"
    try:
        # /hooks/* with public host -> Host accepted (passes host middleware, reaches route -> 415/404)
        resp_hook = client.post(
            "/hooks/test_path",
            headers={"Host": "hooks.example.com", "Content-Type": "application/json"},
        )
        assert resp_hook.status_code != 400, "Expected public host to be accepted on /hooks/*"

        # /api/* with public host -> Rejected with 400!
        resp_api = client.get(
            "/api/v2/agents",
            headers={"Host": "hooks.example.com", "Authorization": f"Bearer {token}"},
        )
        assert resp_api.status_code == 400
        assert "Invalid Host header" in resp_api.text

        # / (UI root) with public host -> Rejected with 400!
        resp_root = client.get("/", headers={"Host": "hooks.example.com"})
        assert resp_root.status_code == 400
        assert "Invalid Host header" in resp_root.text
    finally:
        del os.environ["AGENTOS_PUBLIC_HOSTS"]


@pytest.mark.asyncio
async def test_pre_lookup_checks_no_oracle(webhook_env):
    """
    Content-Type check (415) and Size check (413) run BEFORE path lookup.
    """
    env = webhook_env
    client = env["client"]

    # 1. Non-JSON Content-Type -> 415 on both unknown path and real path
    resp_text = client.post(
        "/hooks/nonexistent_path",
        content="plain text",
        headers={"Content-Type": "text/plain"},
    )
    assert resp_text.status_code == 415
    assert "Content-Type must be application/json" in resp_text.json()["detail"]

    # 2. Oversized body (>1 MB) -> 413 on both unknown path and real path
    huge_body = b"x" * (1024 * 1024 + 10)
    resp_huge = client.post(
        "/hooks/nonexistent_path",
        content=huge_body,
        headers={"Content-Type": "application/json"},
    )
    assert resp_huge.status_code == 413
    assert "Payload Too Large" in resp_huge.json()["detail"]


@pytest.mark.asyncio
async def test_anti_oracle_identical_404_responses(webhook_env):
    """
    After pre-lookup gates: unknown path, disabled hook, bad signature,
    stale timestamp, and replay all return the exact same 404 response.
    """
    env = webhook_env
    client = env["client"]
    storage = env["storage"]
    vault = env["app"].state.vault

    # Create published flow
    flow = FlowRecord(
        id="flow_oracle_test",
        name="Oracle Test",
        entrypoint="in",
        nodes={"in": {"id": "in", "type": "webhook_trigger", "config": {}}},
        edges=[],
    )
    await storage.flows.put_draft(flow)
    await storage.flows.publish("flow_oracle_test", "dummy_sha", "dummy_pol")

    # Create real webhook
    secret_path = "real_secret_path_1234567890"
    secret_path_hash = hashlib.sha256(secret_path.encode("utf-8")).hexdigest()
    secret_key = "secret_key_12345"
    key_ref = "wh_key_oracle"
    await vault.put(key_ref, secret_key)

    webhook = WebhookRecord(
        webhook_id="wh_oracle",
        name="Oracle Webhook",
        flow_id="flow_oracle_test",
        secret_path_hash=secret_path_hash,
        secret_key_ref=key_ref,
        enabled=True,
    )
    await storage.webhooks.put(webhook)

    body = json.dumps({"test": "data"})
    now = int(time.time())
    valid_sig = _compute_sig(secret_key, now, body)

    # 1. Unknown path
    resp_unknown = client.post(
        "/hooks/completely_unknown_path",
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-AgentOS-Signature": valid_sig,
            "X-AgentOS-Timestamp": str(now),
        },
    )

    # 2. Bad signature on real path
    resp_bad_sig = client.post(
        f"/hooks/{secret_path}",
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-AgentOS-Signature": "sha256=" + "f" * 64,
            "X-AgentOS-Timestamp": str(now),
        },
    )

    # 3. Stale timestamp (>5 min old)
    old_ts = now - 400
    stale_sig = _compute_sig(secret_key, old_ts, body)
    resp_stale = client.post(
        f"/hooks/{secret_path}",
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-AgentOS-Signature": stale_sig,
            "X-AgentOS-Timestamp": str(old_ts),
        },
    )

    # 4. Malformed signature header format
    resp_malformed_sig = client.post(
        f"/hooks/{secret_path}",
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-AgentOS-Signature": "md5=1234",
            "X-AgentOS-Timestamp": str(now),
        },
    )

    # 5. Non-integer timestamp
    resp_bad_ts = client.post(
        f"/hooks/{secret_path}",
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-AgentOS-Signature": valid_sig,
            "X-AgentOS-Timestamp": "not_an_int",
        },
    )

    # Verify all responses are IDENTICAL in status and body
    expected_body = {"detail": "Not Found"}
    for r in [resp_unknown, resp_bad_sig, resp_stale, resp_malformed_sig, resp_bad_ts]:
        assert r.status_code == 404
        assert r.json() == expected_body

    # 6. Valid request succeeds with 202
    resp_valid = client.post(
        f"/hooks/{secret_path}",
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-AgentOS-Signature": valid_sig,
            "X-AgentOS-Timestamp": str(now),
        },
    )
    assert resp_valid.status_code == 202
    assert "run_id" in resp_valid.json()

    # 7. Replayed request -> returns identical 404!
    resp_replay = client.post(
        f"/hooks/{secret_path}",
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-AgentOS-Signature": valid_sig,
            "X-AgentOS-Timestamp": str(now),
        },
    )
    assert resp_replay.status_code == 404
    assert resp_replay.json() == expected_body

    # 8. Disabled hook -> returns identical 404!
    webhook.enabled = False
    await storage.webhooks.put(webhook)
    ts2 = now + 1
    sig2 = _compute_sig(secret_key, ts2, body)
    resp_disabled = client.post(
        f"/hooks/{secret_path}",
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-AgentOS-Signature": sig2,
            "X-AgentOS-Timestamp": str(ts2),
        },
    )
    assert resp_disabled.status_code == 404
    assert resp_disabled.json() == expected_body
