"""4.2 flow test cases: data models (design: docs/evidence/4.2.md D3, D6, D10).

Domain only (no FastAPI / Mongo imports). A test case is stored per flow; expectations are typed by ``kind``.
"""

from __future__ import annotations

import re
import time
import uuid
from typing import Annotated, Any, Literal, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, field_validator

FINAL_STATUSES = ("succeeded", "waiting_for_approval", "failed")
JUDGE_REASONS_DEFAULT = ("meets_rubric", "wrong_answer", "incomplete", "unsafe_content", "off_topic", "other")
SECRET_PLACEHOLDER = "[SECRET value not stored]"


class _Exp(BaseModel):
    model_config = ConfigDict(extra="forbid")
    note: Optional[str] = None


class StatusExpectation(_Exp):
    kind: Literal["status"] = "status"
    equals: Literal["succeeded", "waiting_for_approval", "failed"]


class OutputExpectation(_Exp):
    kind: Literal["output"] = "output"
    node: str
    field: str = "output"        # dotted path ("output", "body.id") or a JSON path ("$.body.id")
    op: Literal["equals", "contains", "regex", "json_path_equals"] = "equals"
    value: Any = None


class ExtractionExpectation(_Exp):
    kind: Literal["extraction"] = "extraction"
    node: str
    field: str
    equals: Any


class SinkExpectation(_Exp):
    kind: Literal["sink"] = "sink"
    target: str                  # send_email | send_slack | http_request | fetch_url | mcp:<tool>
    node: Optional[str] = None
    op: Literal["called", "not_called", "count", "called_with"] = "called"
    n: Optional[int] = None
    arg: Optional[Literal["to", "channel", "host"]] = None
    value: Optional[str] = None


class SecurityExpectation(_Exp):
    kind: Literal["security"] = "security"
    op: Literal["blocked", "publish_refused", "no_external_send"]
    node: Optional[str] = None


class ApprovalExpectation(_Exp):
    kind: Literal["approval_reached"] = "approval_reached"
    node: Optional[str] = None


class LimitsExpectation(_Exp):
    kind: Literal["limits"] = "limits"
    max_cost_usd: Optional[float] = None
    max_duration_ms: Optional[float] = None
    max_model_calls: Optional[int] = None


class JudgeExpectation(_Exp):
    """Non-deterministic: a model grades one node output against a rubric (quarantined extraction, D9)."""
    kind: Literal["judge"] = "judge"
    node: str
    field: str = "output"
    rubric: str = Field(min_length=1, max_length=2000)
    reasons: list[str] = Field(default_factory=lambda: list(JUDGE_REASONS_DEFAULT))
    nondeterministic: bool = True

    @field_validator("reasons")
    @classmethod
    def _reasons(cls, v: list[str]) -> list[str]:
        if not 2 <= len(v) <= 20 or len(set(v)) != len(v):
            raise ValueError("judge reasons: 2-20 unique values")
        for r in v:
            if not re.fullmatch(r"[A-Za-z0-9 _.-]{1,64}", r):
                raise ValueError(f"judge reason {r!r}: letters, digits, space, _ . - only")
        return v


Expectation = Annotated[Union[StatusExpectation, OutputExpectation, ExtractionExpectation, SinkExpectation,
                              SecurityExpectation, ApprovalExpectation, LimitsExpectation, JudgeExpectation],
                        Field(discriminator="kind")]


class Fixture(BaseModel):
    """A recorded or hand-written tool response. http: by method + URL (exact, or prefix ending in ``*``);
    mcp: by tool name. ``recorded=False``: created from a run whose events hold metadata only (fill in the body)."""
    model_config = ConfigDict(extra="forbid")
    kind: Literal["http", "mcp"] = "http"
    method: str = "GET"
    url: Optional[str] = None
    tool: Optional[str] = None
    status: int = 200
    body: Any = ""
    content_type: str = "application/json"
    recorded: bool = True


class ApprovalDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")
    node: Optional[str] = None   # None: whichever approval the run waits at
    approve: bool = True


class TestCase(BaseModel):
    __test__ = False  # not a pytest class
    model_config = ConfigDict(extra="forbid")
    id: str = Field(default_factory=lambda: f"tc_{uuid.uuid4().hex[:12]}")
    flow_id: str
    name: str = Field(min_length=1, max_length=200)
    tags: list[str] = Field(default_factory=list)
    input: Any = Field(default_factory=dict)
    fixtures: list[Fixture] = Field(default_factory=list)
    mock_responses: dict[str, str] = Field(default_factory=dict)
    approvals: list[ApprovalDecision] = Field(default_factory=list)
    expectations: list[Expectation] = Field(default_factory=list)
    source: Literal["manual", "run", "review", "security"] = "manual"
    attack: Optional[dict[str, Any]] = None
    secret_values_included: bool = False
    notes: list[str] = Field(default_factory=list)
    created_by: Optional[str] = None
    created_at: float = Field(default_factory=time.time)
    updated_at: float = Field(default_factory=time.time)


class Failure(BaseModel):
    expectation: dict[str, Any]
    expected: Any = None
    actual: Any = None
    message: str


class CaseResult(BaseModel):
    case_id: str
    name: str
    tags: list[str] = Field(default_factory=list)
    status: Literal["pass", "fail", "error"]
    failures: list[Failure] = Field(default_factory=list)
    error: Optional[str] = None
    run_id: Optional[str] = None
    run_status: Optional[str] = None
    cost_usd: float = 0.0
    duration_ms: float = 0.0
    model_calls: int = 0
    latencies_ms: list[float] = Field(default_factory=list)
    models_used: list[str] = Field(default_factory=list)
    nondeterministic: bool = False


class SuiteRun(BaseModel):
    id: str = Field(default_factory=lambda: f"ts_{uuid.uuid4().hex[:12]}")
    flow_id: str
    target: Literal["draft", "published", "version"] = "draft"
    version: Optional[int] = None
    model: str = "mock"
    tags: list[str] = Field(default_factory=list)
    live_tools: bool = False
    started_at: float = Field(default_factory=time.time)
    duration_ms: float = 0.0
    counts: dict[str, int] = Field(default_factory=dict)
    results: list[CaseResult] = Field(default_factory=list)
    regression: Optional[dict[str, Any]] = None
    comparison_id: Optional[str] = None
    started_by: Optional[str] = None
    purpose: Literal["manual", "gate", "compare", "cli"] = "manual"

    @property
    def all_passed(self) -> bool:
        return bool(self.results) and all(r.status == "pass" for r in self.results)

    def pass_rate(self) -> Optional[float]:
        if not self.results:
            return None
        return round(100.0 * sum(1 for r in self.results if r.status == "pass") / len(self.results), 1)


class GateSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    flow_id: str = ""
    mode: Literal["off", "warn", "block"] = "off"
    model: str = "mock"
    updated_by: Optional[str] = None
    updated_at: Optional[float] = None


def counts_of(results: list[CaseResult]) -> dict[str, int]:
    out = {"total": len(results), "pass": 0, "fail": 0, "error": 0}
    for r in results:
        out[r.status] += 1
    return out
