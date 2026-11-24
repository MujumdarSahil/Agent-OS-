"""Milestone 3.6a: Review API endpoints, permissions matrix, and audit logging tests.

Routes tested:
- GET /api/v2/review/items (read)
- GET /api/v2/review/items/{item_id} (read)
- POST /api/v2/review/items/{item_id}/verdict (review)
- POST /api/v2/review/items/{item_id}/skip (review)
- GET /api/v2/review/sampling/{flow_id} (read)
- PUT /api/v2/review/sampling/{flow_id} (build)
- POST /api/v2/review/send-to-review (build)
- GET /api/v2/review/metrics/{flow_id} (read)
- GET /api/v2/review/export (admin)

Also verifies:
- Audit entries recorded with actor for state-changing endpoints.
- Secret redaction behavior in API export.
"""

from __future__ import annotations

import json
import pytest
from httpx import ASGITransport, AsyncClient

from agentos.access import passwords as pw
from agentos.review.models import ReviewItem
from agentos.storage.models import RunRecord
from agentos_server.app import create_app

PASSWORD = "violet-harbor-lantern-42"
UI = {"Origin": "http://localhost:5173", "Host": "localhost"}


@pytest.fixture(autouse=True)
def cheap_scrypt(monkeypatch):
    monkeypatch.setattr(pw, "LOG_N", 10)


@pytest.fixture
def project(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTOS_API_TOKEN", "test-token")
    monkeypatch.setenv("AGENTOS_MOCK_LLM", "1")
    monkeypatch.delenv("AGENTOS_MONGO_URI", raising=False)
    monkeypatch.delenv("AGENTOS_V1_NO_AUTH", raising=False)
    (tmp_path / "agentos.config.yaml").write_text("preferred_tags: []\n", encoding="utf-8")
    return tmp_path


def make_app(project):
    return create_app(str(project))


def client(app, **headers) -> AsyncClient:
    return AsyncClient(
        transport=ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://localhost",
        headers={"Host": "localhost", **headers},
    )


async def user_token(app, username: str, role: str) -> str:
    svc = app.state.access
    if await svc.find_user(username) is None:
        await svc.create_user(username, None, role, PASSWORD)
    u = await svc.find_user(username)
    raw, _ = await svc.create_token(u["id"], f"{username}-pat", 30)
    return raw


@pytest.mark.asyncio
async def test_review_api_role_permissions(project):
    app = make_app(project)
    store = app.state.review

    # Seed an item for testing
    item = ReviewItem(
        id="item-test-1",
        item_id="item-test-1",
        run_id="run-test-1",
        flow_id="test_flow",
        flow_version=1,
        node_id="llm_node",
        inputs={"prompt": "hi"},
        outputs={"answer": "hello"},
    )
    await store.put_item(item)

    # Seed a run in storage for send-to-review test
    await app.state.storage.runs.put(
        RunRecord(
            run_id="run-test-1",
            mission_name="test_flow",
            flow_id="test_flow",
            flow_version=1,
            status="succeeded",
        )
    )

    t_viewer = await user_token(app, "u_viewer", "viewer")
    t_approver = await user_token(app, "u_approver", "approver")
    t_builder = await user_token(app, "u_builder", "builder")
    t_admin = await user_token(app, "u_admin", "admin")

    # 1. Viewer Role
    async with client(app, Authorization=f"Bearer {t_viewer}") as c:
        # Allowed (read)
        r = await c.get("/api/v2/review/items")
        assert r.status_code == 200
        assert r.json()["total"] >= 1

        r = await c.get("/api/v2/review/items/item-test-1")
        assert r.status_code == 200

        r = await c.get("/api/v2/review/sampling/test_flow")
        assert r.status_code == 200

        r = await c.get("/api/v2/review/metrics/test_flow")
        assert r.status_code == 200

        # Denied (needs review)
        r = await c.post("/api/v2/review/items/item-test-1/verdict", json={"verdict": "good"})
        assert r.status_code == 403

        r = await c.post("/api/v2/review/items/item-test-1/skip", json={"note": "skip"})
        assert r.status_code == 403

        # Denied (needs build)
        r = await c.put("/api/v2/review/sampling/test_flow", json={"mode": "all"})
        assert r.status_code == 403

        r = await c.post("/api/v2/review/send-to-review", json={"run_id": "run-test-1"})
        assert r.status_code == 403

        # Denied (needs admin)
        r = await c.get("/api/v2/review/export")
        assert r.status_code == 403

    # 2. Approver Role
    async with client(app, Authorization=f"Bearer {t_approver}") as c:
        # Allowed (review)
        r = await c.post(
            "/api/v2/review/items/item-test-1/verdict",
            json={"verdict": "good", "note": "Looks solid"},
        )
        assert r.status_code == 200
        assert r.json()["verdict"] == "good"

        # Denied (needs build)
        r = await c.put("/api/v2/review/sampling/test_flow", json={"mode": "all"})
        assert r.status_code == 403

        r = await c.post("/api/v2/review/send-to-review", json={"run_id": "run-test-1"})
        assert r.status_code == 403

        # Denied (needs admin)
        r = await c.get("/api/v2/review/export")
        assert r.status_code == 403

    # 3. Builder Role
    async with client(app, Authorization=f"Bearer {t_builder}") as c:
        # Allowed (review)
        r = await c.post(
            "/api/v2/review/items/item-test-1/skip",
            json={"note": "Skipping for now"},
        )
        assert r.status_code == 200
        assert r.json()["status"] == "skipped"

        # Allowed (build)
        r = await c.put(
            "/api/v2/review/sampling/test_flow",
            json={"mode": "rules", "rules": ["failed"], "percentage": 50},
        )
        assert r.status_code == 200
        assert r.json()["mode"] == "rules"

        r = await c.post("/api/v2/review/send-to-review", json={"run_id": "run-test-1"})
        assert r.status_code == 200
        assert r.json()["run_id"] == "run-test-1"

        # Denied (needs admin)
        r = await c.get("/api/v2/review/export")
        assert r.status_code == 403

    # 4. Admin Role
    async with client(app, Authorization=f"Bearer {t_admin}") as c:
        # Allowed (admin export)
        r = await c.get("/api/v2/review/export")
        assert r.status_code == 200
        assert "ndjson" in r.headers["content-type"] or "jsonlines" in r.headers["content-type"]


@pytest.mark.asyncio
async def test_review_audit_logging(project):
    """Verify that all state-changing review endpoints write audit events with the correct actor."""
    app = make_app(project)
    store = app.state.review
    audit_repo = app.state.audit

    # Seed an item
    await store.put_item(
        ReviewItem(
            id="item-audit-1",
            item_id="item-audit-1",
            run_id="run-audit-1",
            flow_id="audit_flow",
            flow_version=1,
            node_id="gen",
            inputs={"x": 1},
            outputs={"y": 2},
        )
    )
    await app.state.storage.runs.put(
        RunRecord(
            run_id="run-audit-1",
            mission_name="audit_flow",
            flow_id="audit_flow",
            flow_version=1,
            status="succeeded",
        )
    )

    t_admin = await user_token(app, "super_admin", "admin")

    async with client(app, Authorization=f"Bearer {t_admin}") as c:
        # 1. review.verdict
        r1 = await c.post(
            "/api/v2/review/items/item-audit-1/verdict",
            json={"verdict": "bad", "reasons": ["wrong"], "corrected_output": "correct answer"},
        )
        assert r1.status_code == 200

        # 2. review.skip
        r2 = await c.post("/api/v2/review/items/item-audit-1/skip", json={"note": "audit skip"})
        assert r2.status_code == 200

        # 3. review.sampling.update
        r3 = await c.put(
            "/api/v2/review/sampling/audit_flow",
            json={"mode": "percentage", "percentage": 25},
        )
        assert r3.status_code == 200

        # 4. review.send_to_review
        r4 = await c.post("/api/v2/review/send-to-review", json={"run_id": "run-audit-1"})
        assert r4.status_code == 200

        # 5. review.export
        r5 = await c.get("/api/v2/review/export?include_secrets=true")
        assert r5.status_code == 200

    # Inspect audit trail
    events = await audit_repo.entries()
    actions = {e["action"]: e for e in events}

    assert "review.verdict" in actions
    ev_verdict = actions["review.verdict"]
    assert "super_admin" in ev_verdict["actor"]
    assert ev_verdict["target"]["id"] == "item-audit-1"

    assert "review.skip" in actions
    ev_skip = actions["review.skip"]
    assert "super_admin" in ev_skip["actor"]
    assert ev_skip["target"]["id"] == "item-audit-1"

    assert "review.sampling.update" in actions
    ev_sampling = actions["review.sampling.update"]
    assert "super_admin" in ev_sampling["actor"]
    assert ev_sampling["target"]["id"] == "audit_flow"

    assert "review.send_to_review" in actions
    ev_send = actions["review.send_to_review"]
    assert "super_admin" in ev_send["actor"]
    assert ev_send["target"]["id"] == "run-audit-1"

    assert "review.export" in actions
    ev_export = actions["review.export"]
    assert "super_admin" in ev_export["actor"]
    assert ev_export["details"].get("include_secrets") is True


@pytest.mark.asyncio
async def test_review_export_secret_redaction_api(project):
    """Verify that export endpoint redacts secrets unless include_secrets=true."""
    app = make_app(project)
    store = app.state.review

    item = ReviewItem(
        id="item-sec-1",
        item_id="item-sec-1",
        run_id="run-sec-1",
        flow_id="sec_flow",
        flow_version=1,
        node_id="auth",
        inputs={"api_key": "super-secret-123", "param": "public"},
        input_labels={"api_key": {"confidentiality": "secret"}},
        outputs={"token": "bearer-secret-token", "status": "ok"},
        output_labels={"token": {"confidentiality": "secret"}},
    )
    await store.put_item(item)
    await store.update_verdict("item-sec-1", verdict="good", reviewer_id="admin")

    t_admin = await user_token(app, "sec_admin", "admin")

    async with client(app, Authorization=f"Bearer {t_admin}") as c:
        # Default (no secrets)
        r_redacted = await c.get("/api/v2/review/export?flow_id=sec_flow")
        assert r_redacted.status_code == 200
        lines = [json.loads(line) for line in r_redacted.text.strip().split("\n") if line]
        assert len(lines) == 1
        rec = lines[0]
        assert rec["input"]["api_key"] == "[SECRET redacted]"
        assert rec["input"]["param"] == "public"
        assert rec["output"]["token"] == "[SECRET redacted]"
        assert rec["output"]["status"] == "ok"

        # Opt-in with include_secrets=true
        r_clear = await c.get("/api/v2/review/export?flow_id=sec_flow&include_secrets=true")
        assert r_clear.status_code == 200
        lines_clear = [json.loads(line) for line in r_clear.text.strip().split("\n") if line]
        assert len(lines_clear) == 1
        rec_clear = lines_clear[0]
        assert rec_clear["input"]["api_key"] == "super-secret-123"
        assert rec_clear["output"]["token"] == "bearer-secret-token"
