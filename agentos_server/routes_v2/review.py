"""3.6a Human Review Queue endpoints (/api/v2/review).

RBAC capabilities:
- read: viewer, approver, builder, admin (items, item detail, sampling config, metrics)
- review: approver, builder, admin (verdict, skip)
- build: builder, admin (sampling config update, send-to-review)
- admin: admin (JSONL export with optional secrets)
"""

from __future__ import annotations

import json
from typing import Any, Dict, Optional, Union

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from agentos.review.models import (
    VALID_MODES,
    VALID_REASONS,
    VALID_RULES,
    ReviewSamplingConfig,
)
from agentos.review.store import enqueue_run_for_review, review_store_for
from agentos_server.audit_support import actor_of, audit

router = APIRouter(prefix="/review", tags=["v2-review"])


def _store(request: Request) -> Any:
    store = getattr(request.app.state, "review", None)
    if store is None:
        storage = getattr(request.app.state, "storage", None)
        if storage is not None:
            store = review_store_for(storage)
            request.app.state.review = store
    if store is None:
        raise HTTPException(status_code=503, detail="Review store is not available")
    return store


class ReviewVerdictRequest(BaseModel):
    verdict: str  # "good" | "bad"
    reasons: list[str] = Field(default_factory=list)
    corrected_output: Optional[str] = None
    note: Optional[str] = None


class ReviewSkipRequest(BaseModel):
    note: Optional[str] = None


class ReviewSamplingUpdateRequest(BaseModel):
    mode: str = "off"
    percentage: int = 100
    rules: list[str] = Field(default_factory=list)
    nodes: list[str] = Field(default_factory=list)


class SendToReviewRequest(BaseModel):
    run_id: str
    node_id: Optional[str] = None


@router.get("/items")
async def list_items(
    request: Request,
    flow_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    verdict: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> Dict[str, Any]:
    items, total = await _store(request).list_items(
        flow_id=flow_id, status=status, verdict=verdict, limit=limit, offset=offset
    )
    return {"items": [it.model_dump(mode="json") for it in items], "total": total}


@router.get("/items/{item_id}")
async def get_item(request: Request, item_id: str) -> Dict[str, Any]:
    item = await _store(request).get_item(item_id)
    if not item:
        raise HTTPException(status_code=404, detail=f"Review item {item_id!r} not found")
    return item.model_dump(mode="json")


@router.post("/items/{item_id}/verdict")
async def set_verdict(request: Request, item_id: str, body: ReviewVerdictRequest) -> Dict[str, Any]:
    if body.verdict not in ("good", "bad"):
        raise HTTPException(status_code=400, detail="Verdict must be 'good' or 'bad'")
    invalid = [r for r in body.reasons if r not in VALID_REASONS]
    if invalid:
        raise HTTPException(status_code=400, detail=f"Invalid review reasons: {invalid}")

    item = await _store(request).get_item(item_id)
    if not item:
        raise HTTPException(status_code=404, detail=f"Review item {item_id!r} not found")

    actor = actor_of(request)
    await audit(
        request,
        "review.verdict",
        "review_item",
        item_id,
        details={
            "flow_id": item.flow_id,
            "verdict": body.verdict,
            "reasons": body.reasons,
            "has_corrected_output": bool(body.corrected_output),
        },
    )
    updated = await _store(request).update_verdict(
        item_id=item_id,
        verdict=body.verdict,
        reasons=body.reasons,
        corrected_output=body.corrected_output,
        note=body.note,
        reviewer_id=actor,
    )
    if not updated:
        raise HTTPException(status_code=404, detail=f"Review item {item_id!r} not found")
    return updated.model_dump(mode="json")


@router.post("/items/{item_id}/skip")
async def skip_item(request: Request, item_id: str, body: ReviewSkipRequest) -> Dict[str, Any]:
    item = await _store(request).get_item(item_id)
    if not item:
        raise HTTPException(status_code=404, detail=f"Review item {item_id!r} not found")

    actor = actor_of(request)
    await audit(
        request,
        "review.skip",
        "review_item",
        item_id,
        details={"flow_id": item.flow_id, "has_note": bool(body.note)},
    )
    updated = await _store(request).skip_item(
        item_id=item_id,
        reviewer_id=actor,
        note=body.note,
    )
    if not updated:
        raise HTTPException(status_code=404, detail=f"Review item {item_id!r} not found")
    return updated.model_dump(mode="json")


@router.get("/sampling/{flow_id}")
async def get_sampling(request: Request, flow_id: str) -> Dict[str, Any]:
    config = await _store(request).get_sampling_config(flow_id)
    return config.model_dump(mode="json")


@router.put("/sampling/{flow_id}")
async def update_sampling(request: Request, flow_id: str, body: ReviewSamplingUpdateRequest) -> Dict[str, Any]:
    if body.mode not in VALID_MODES:
        raise HTTPException(status_code=400, detail=f"Invalid mode {body.mode!r}; must be one of {VALID_MODES}")
    if not (1 <= body.percentage <= 100):
        raise HTTPException(status_code=400, detail="Percentage must be between 1 and 100")
    invalid_rules = [r for r in body.rules if r not in VALID_RULES]
    if invalid_rules:
        raise HTTPException(status_code=400, detail=f"Invalid rules: {invalid_rules}; must be subset of {VALID_RULES}")

    actor = actor_of(request)
    await audit(
        request,
        "review.sampling.update",
        "flow",
        flow_id,
        details={"mode": body.mode, "percentage": body.percentage, "rules": body.rules, "nodes": body.nodes},
    )
    config = ReviewSamplingConfig(
        flow_id=flow_id,
        mode=body.mode,  # type: ignore
        percentage=body.percentage,
        rules=body.rules,
        nodes=body.nodes,
        updated_by=actor,
    )
    saved = await _store(request).put_sampling_config(config)
    return saved.model_dump(mode="json")


@router.post("/send-to-review")
async def send_to_review(request: Request, body: SendToReviewRequest) -> Dict[str, Any]:
    storage = getattr(request.app.state, "storage", None)
    if not storage:
        raise HTTPException(status_code=503, detail="Storage not available")
    try:
        item = await enqueue_run_for_review(storage, body.run_id, body.node_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

    await audit(
        request,
        "review.send_to_review",
        "run",
        body.run_id,
        details={"item_id": item.id, "flow_id": item.flow_id, "node_id": item.node_id},
    )
    return item.model_dump(mode="json")


@router.get("/metrics/{flow_id}")
async def get_metrics(
    request: Request,
    flow_id: str,
    version: Optional[Union[int, str]] = Query(None),
) -> Dict[str, Any]:
    metrics = await _store(request).get_metrics(flow_id, flow_version=version)
    return metrics.model_dump(mode="json")


@router.get("/export")
async def export_reviews(
    request: Request,
    flow_id: Optional[str] = Query(None),
    include_secrets: bool = Query(False),
) -> PlainTextResponse:
    await audit(
        request,
        "review.export",
        "flow",
        flow_id or "all",
        details={"include_secrets": include_secrets},
    )
    items = await _store(request).export_items(flow_id=flow_id, include_secrets=include_secrets)
    lines = [json.dumps(it, ensure_ascii=False) for it in items]
    body = "\n".join(lines) + ("\n" if lines else "")
    return PlainTextResponse(
        body,
        media_type="application/x-ndjson",
        headers={"Content-Disposition": 'attachment; filename="agentos-review-export.jsonl"'},
    )
