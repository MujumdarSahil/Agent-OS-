"""3.4 Part 0c (MOCK): the flow API says "published vN" vs "draft" (published_version / unpublished_changes)."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

TOKEN = "publish-view-test-token"
FLOW = {
    "id": "pv_flow", "name": "pv", "entrypoint": "trig",
    "nodes": {"trig": {"id": "trig", "type": "manual_trigger", "config": {}}},
    "edges": [],
}


@pytest.mark.asyncio
async def test_publish_view_fields(tmp_path, monkeypatch):
    from agentos_server.app import create_app

    monkeypatch.setenv("AGENTOS_API_TOKEN", TOKEN)
    monkeypatch.setenv("AGENTOS_MOCK_LLM", "1")
    monkeypatch.delenv("AGENTOS_MONGO_URI", raising=False)
    app = create_app(str(tmp_path))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://localhost",
                           headers={"Authorization": f"Bearer {TOKEN}", "Host": "localhost"}) as c:
        assert (await c.post("/api/v2/flows", json=FLOW)).status_code == 201
        f = (await c.get("/api/v2/flows/pv_flow")).json()
        assert (f["published_version"], f["unpublished_changes"]) == (None, True)  # never published: draft

        pub = (await c.post("/api/v2/flows/pv_flow/publish")).json()
        assert (pub["published_version"], pub["unpublished_changes"]) == (1, False)
        f = (await c.get("/api/v2/flows/pv_flow")).json()
        assert (f["published_version"], f["unpublished_changes"]) == (1, False)  # "published v1", not "draft"
        listed = {x["id"]: x for x in (await c.get("/api/v2/flows")).json()}["pv_flow"]
        assert (listed["published_version"], listed["unpublished_changes"]) == (1, False)

        edited = {**FLOW, "nodes": {**FLOW["nodes"], "n2": {"id": "n2", "type": "manual_trigger", "config": {}}}}
        saved = (await c.put("/api/v2/flows/pv_flow", json={**edited, "published_version": 99,
                                                             "unpublished_changes": False})).json()
        assert (saved["published_version"], saved["unpublished_changes"]) == (1, True)  # client values ignored
