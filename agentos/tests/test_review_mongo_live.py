"""3.6a: LIVE Mongo tests for review queue on MongoReviewDocs.

Runs in CI's mongo-live job (AGENTOS_REQUIRE_LIVE_MONGO=1 turns a skip into a failure); skipped locally without
AGENTOS_MONGO_URI. Each test uses a throwaway database that is dropped afterwards.
"""

from __future__ import annotations

import pytest
import pytest_asyncio

from agentos.review.models import ReviewItem, ReviewSamplingConfig
from agentos.review.store import review_store_for
from agentos.tests.test_storage_contract_1_2 import _live_mongo_storage

pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture
async def store():
    async for storage in _live_mongo_storage():
        yield review_store_for(storage)


async def test_mongo_review_store_is_the_mongo_backend(store):
    assert "Mongo" in type(store.items).__name__


async def test_mongo_review_crud_and_verdict(store):
    item = ReviewItem(
        id="mongo-rev-1",
        item_id="mongo-rev-1",
        run_id="run-mongo-1",
        flow_id="mongo_flow",
        flow_version=1,
        node_id="eval_step",
        inputs={"query": "test mongo"},
        outputs={"answer": "ok"},
    )
    await store.put_item(item)

    fetched = await store.get_item("mongo-rev-1")
    assert fetched is not None
    assert fetched.flow_id == "mongo_flow"
    assert fetched.status == "pending"

    # Update verdict
    updated = await store.update_verdict(
        "mongo-rev-1",
        verdict="good",
        reviewer_id="mongo_tester",
        note="Live mongo test pass",
    )
    assert updated is not None
    assert updated.status == "reviewed"
    assert updated.verdict == "good"
    assert updated.reviewer_id == "mongo_tester"

    # List items
    items, total = await store.list_items(flow_id="mongo_flow", status="reviewed")
    assert total == 1
    assert len(items) == 1
    assert items[0].id == "mongo-rev-1"


async def test_mongo_review_sampling_config_and_metrics(store):
    # Sampling config
    cfg = ReviewSamplingConfig(
        flow_id="mongo_flow_2",
        mode="percentage",
        percentage=40,
        rules=["failed"],
    )
    await store.put_sampling_config(cfg)

    fetched_cfg = await store.get_sampling_config("mongo_flow_2")
    assert fetched_cfg.flow_id == "mongo_flow_2"
    assert fetched_cfg.mode == "percentage"
    assert fetched_cfg.percentage == 40

    # Add bad review item for metrics
    item = ReviewItem(
        id="mongo-rev-bad",
        item_id="mongo-rev-bad",
        run_id="run-mongo-2",
        flow_id="mongo_flow_2",
        flow_version=1,
        node_id="step",
        inputs={"x": 1},
        outputs={"y": 2},
    )
    await store.put_item(item)
    await store.update_verdict(
        "mongo-rev-bad",
        verdict="bad",
        reasons=["wrong", "made_up"],
        reviewer_id="tester",
    )

    metrics = await store.get_metrics("mongo_flow_2", flow_version=1)
    assert metrics.reviewed_count == 1
    assert metrics.good_count == 0
    assert metrics.bad_count == 1
    assert metrics.good_percentage == 0.0
    assert len(metrics.top_bad_reasons) == 2
