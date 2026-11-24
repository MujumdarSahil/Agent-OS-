"""Data models for 3.6a Human Review Queue."""

from __future__ import annotations

import time
import uuid
from typing import Any, Literal, Optional, Union
from pydantic import BaseModel, Field, model_validator

ReviewStatus = Literal["pending", "reviewed", "skipped"]
ReviewVerdict = Literal["good", "bad"]
ReviewReason = Literal["wrong", "incomplete", "unsafe", "made_up", "formatting", "other"]

VALID_REASONS = {"wrong", "incomplete", "unsafe", "made_up", "formatting", "other"}
VALID_RULES = {"failed", "fallback_used", "rejected_input", "approval_rejected", "sink_blocked"}
VALID_MODES = {"off", "all", "percentage", "rules"}


class ReviewItem(BaseModel):
    """An item queued for human review, capturing input/output at a given flow node."""
    id: str = Field(default_factory=lambda: f"rev_{uuid.uuid4().hex[:12]}")
    item_id: str = ""
    run_id: str
    flow_id: str
    flow_version: Union[int, str] = 1
    node_id: str
    status: ReviewStatus = "pending"
    created_at: float = Field(default_factory=time.time)
    inputs: dict[str, Any] = Field(default_factory=dict)
    input_labels: dict[str, Any] = Field(default_factory=dict)
    outputs: dict[str, Any] = Field(default_factory=dict)
    output_labels: dict[str, Any] = Field(default_factory=dict)
    input_data: Any = None
    output_data: Any = None
    labels: list[str] = Field(default_factory=list)
    verdict: Optional[ReviewVerdict] = None
    reasons: list[str] = Field(default_factory=list)
    corrected_output: Optional[str] = None
    note: Optional[str] = None
    reviewer_id: Optional[str] = None
    reviewed_at: Optional[float] = None

    @model_validator(mode="before")
    @classmethod
    def _sync_fields(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "item_id" in data and not data.get("id"):
                data["id"] = data["item_id"]
            elif "id" in data and not data.get("item_id"):
                data["item_id"] = data["id"]

            if "inputs" in data and not data.get("input_data"):
                data["input_data"] = data["inputs"]
            elif "input_data" in data and not data.get("inputs") and isinstance(data["input_data"], dict):
                data["inputs"] = data["input_data"]

            if "outputs" in data and not data.get("output_data"):
                data["output_data"] = data["outputs"]
            elif "output_data" in data and not data.get("outputs") and isinstance(data["output_data"], dict):
                data["outputs"] = data["output_data"]
        return data

    def model_post_init(self, __context: Any) -> None:
        if not self.item_id:
            self.item_id = self.id
        if not self.id:
            self.id = self.item_id
        if not self.inputs and isinstance(self.input_data, dict):
            self.inputs = self.input_data
        if not self.outputs and isinstance(self.output_data, dict):
            self.outputs = self.output_data


class ReviewSamplingConfig(BaseModel):
    """Sampling configuration per flow, controlling what gets queued for review."""
    flow_id: str
    mode: Literal["off", "all", "percentage", "rules"] = "off"
    percentage: int = 100  # 1-100
    rules: list[str] = Field(default_factory=list)
    nodes: list[str] = Field(default_factory=list)  # empty or ["*"] means final output
    node_ids: list[str] = Field(default_factory=list)
    updated_at: float = Field(default_factory=time.time)
    updated_by: str = ""

    @model_validator(mode="before")
    @classmethod
    def _sync_nodes(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "node_ids" in data and "nodes" not in data:
                data["nodes"] = data["node_ids"]
            elif "nodes" in data and "node_ids" not in data:
                data["node_ids"] = data["nodes"]
        return data

    def model_post_init(self, __context: Any) -> None:
        if not self.node_ids and self.nodes:
            self.node_ids = list(self.nodes)
        elif not self.nodes and self.node_ids:
            self.nodes = list(self.node_ids)


class ReviewReasonCount(BaseModel):
    reason: str
    count: int


class ReviewMetrics(BaseModel):
    """Quality metrics for a flow / version."""
    flow_id: str
    flow_version: Optional[Union[int, str]] = None
    reviewed_count: int = 0
    total_reviewed: int = 0
    good_count: int = 0
    bad_count: int = 0
    good_percentage: float = 0.0
    pct_good: float = 0.0
    top_bad_reasons: list[ReviewReasonCount] = Field(default_factory=list)

    def model_post_init(self, __context: Any) -> None:
        if not self.total_reviewed:
            self.total_reviewed = self.reviewed_count
        if not self.reviewed_count:
            self.reviewed_count = self.total_reviewed
        if not self.pct_good:
            self.pct_good = self.good_percentage
        if not self.good_percentage:
            self.good_percentage = self.pct_good
