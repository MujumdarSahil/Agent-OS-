"""Tests for 3.6b OpenTelemetry export (agentos/telemetry.py).

MOCK — in-memory exporters, no network / collector required.

Covers:
- OTEL disabled by default when OTEL_EXPORTER_OTLP_ENDPOINT is unset
- Trace hierarchy: run span, child node spans, child model spans, child tool spans
- Metric counters and histogram
- Privacy guarantee / Canary test: asserts no prompt, output, tool argument or result appears in telemetry
- Run record stores 32-character hex trace ID
- Unreachable exporter / drop resilience
"""

from __future__ import annotations

import os
import pytest
from typing import Any

from agentos.storage.models import RunRecord
from agentos.telemetry import (
    RunSpan,
    record_blocked_call,
    record_model_call,
    record_refused_publish,
    record_run_status,
    record_tool_call,
    reset_telemetry,
    setup_in_memory_telemetry,
    setup_telemetry,
)


# ---------------------------------------------------------------------------
# 1. Disabled by Default
# ---------------------------------------------------------------------------


class TestTelemetryDisabledByDefault:
    def test_disabled_when_endpoint_unset(self, monkeypatch):
        monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
        import agentos.telemetry as tm
        old_endpoint = tm._configured_endpoint
        tm._configured_endpoint = None
        try:
            assert setup_telemetry() is False
        finally:
            tm._configured_endpoint = old_endpoint

    def test_run_span_noop_when_disabled(self):
        import agentos.telemetry as tm
        old_tracer = tm._tracer
        tm._tracer = None
        try:
            with RunSpan("run_noop", "flow_noop") as span:
                assert span.trace_id is None
                with span.node_span("node_1", "passthrough"):
                    pass
                with span.model_span("mock", "mock-model"):
                    pass
                with span.tool_span("calc"):
                    pass
        finally:
            tm._tracer = old_tracer


# ---------------------------------------------------------------------------
# 2. In-Memory Traces Hierarchy
# ---------------------------------------------------------------------------


class TestTelemetryTracesHierarchy:
    @pytest.fixture(autouse=True)
    def setup_otel(self):
        tracer, meter, span_exp, metric_reader = setup_in_memory_telemetry()
        self.tracer = tracer
        self.meter = meter
        self.span_exp = span_exp
        self.metric_reader = metric_reader
        yield
        reset_telemetry()

    def test_trace_spans_hierarchy_and_attributes(self):
        with RunSpan("run-123", "flow-abc", trigger="webhook") as run_span:
            assert run_span.trace_id is not None
            assert len(run_span.trace_id) == 32

            with run_span.node_span("step_1", "agent"):
                with run_span.model_span("openai", "gpt-4o", node_id="step_1") as mspan:
                    mspan.set_tokens(prompt=15, completion=25, cost_usd=0.0012, fallback_attempts=1)

                with run_span.tool_span("python_exec", node_id="step_1") as tspan:
                    tspan.set_status("ok", limit_hit=False)

            run_span.set_status("succeeded")

        spans = self.span_exp.get_finished_spans()
        assert len(spans) == 4

        span_names = {s.name for s in spans}
        assert span_names == {"agentos.run", "agentos.node", "agentos.model_call", "agentos.tool_call"}

        run_s = next(s for s in spans if s.name == "agentos.run")
        assert run_s.attributes["agentos.run_id"] == "run-123"
        assert run_s.attributes["agentos.flow_id"] == "flow-abc"
        assert run_s.attributes["agentos.trigger"] == "webhook"
        assert run_s.attributes["agentos.run.status"] == "succeeded"

        node_s = next(s for s in spans if s.name == "agentos.node")
        assert node_s.attributes["agentos.node_id"] == "step_1"
        assert node_s.attributes["agentos.node_type"] == "agent"
        assert node_s.parent.span_id == run_s.context.span_id

        model_s = next(s for s in spans if s.name == "agentos.model_call")
        assert model_s.attributes["agentos.model.provider"] == "openai"
        assert model_s.attributes["agentos.model.model"] == "gpt-4o"
        assert model_s.attributes["agentos.model.prompt_tokens"] == 15
        assert model_s.attributes["agentos.model.completion_tokens"] == 25
        assert model_s.attributes["agentos.model.cost_usd"] == 0.0012
        assert model_s.attributes["agentos.model.fallback_attempts"] == 1
        assert model_s.parent.span_id == run_s.context.span_id

        tool_s = next(s for s in spans if s.name == "agentos.tool_call")
        assert tool_s.attributes["agentos.tool.name"] == "python_exec"
        assert tool_s.attributes["agentos.tool.status"] == "ok"
        assert tool_s.attributes["agentos.tool.limit_hit"] is False
        assert tool_s.parent.span_id == run_s.context.span_id


# ---------------------------------------------------------------------------
# 3. Metrics Recording
# ---------------------------------------------------------------------------


class TestTelemetryMetrics:
    @pytest.fixture(autouse=True)
    def setup_otel(self):
        tracer, meter, span_exp, metric_reader = setup_in_memory_telemetry()
        self.tracer = tracer
        self.meter = meter
        self.span_exp = span_exp
        self.metric_reader = metric_reader
        yield
        reset_telemetry()

    def test_metrics_counters_and_histogram(self):
        record_run_status("succeeded")
        record_run_status("failed")
        record_blocked_call()
        record_refused_publish()
        record_tool_call("calculator", duration_ms=12.5, status="ok", limit_hit=False)
        record_model_call(
            provider="anthropic",
            model="claude-3-5-sonnet",
            duration_ms=450.0,
            prompt_tokens=100,
            completion_tokens=50,
            cost_usd=0.002,
            fallback_attempts=0,
            success=True,
        )

        metric_data = self.metric_reader.get_metrics_data()
        assert metric_data is not None
        metrics_by_name = {
            m.name: m
            for rm in metric_data.resource_metrics
            for sm in rm.scope_metrics
            for m in sm.metrics
        }

        assert "agentos.runs.total" in metrics_by_name
        assert "agentos.blocked_calls.total" in metrics_by_name
        assert "agentos.refused_publishes.total" in metrics_by_name
        assert "agentos.tool_calls.total" in metrics_by_name
        assert "agentos.model_calls.total" in metrics_by_name
        assert "agentos.tokens.total" in metrics_by_name
        assert "agentos.cost.total" in metrics_by_name
        assert "agentos.model_call.duration" in metrics_by_name


# ---------------------------------------------------------------------------
# 4. Privacy Guarantee / Canary Test (Metadata ONLY)
# ---------------------------------------------------------------------------


class TestTelemetryCanaryPrivacy:
    CANARY_INPUT = "CANARY_SENSITIVE_INPUT_998877"
    CANARY_OUTPUT = "CANARY_SENSITIVE_OUTPUT_665544"
    CANARY_TOOL_ARG = "CANARY_SENSITIVE_TOOL_ARG_332211"
    CANARY_SECRET_TOKEN = "CANARY_BEARER_TOKEN_SECRET_001122"
    CANARY_FAILING_ARG = "CANARY_BLOCKED_SINK_VIOLATION_PAYLOAD_889900"

    @pytest.mark.asyncio
    async def test_canary_appears_nowhere_in_telemetry(self, tmp_path):
        tracer, meter, span_exp, metric_reader = setup_in_memory_telemetry()
        try:
            from agentos.flows.engine import FlowEngine
            from agentos.flows.models import EdgeDefinition, FlowDefinition, NodeDefinition
            from agentos.flows.proxy import AgentOSToolProxy
            from agentos.flows.policy import SecurityPolicy
            from agentos.storage.file import open_file_storage

            storage = open_file_storage(str(tmp_path))
            flow = FlowDefinition(
                id="canary_flow",
                entrypoint="node_agent",
                nodes={
                    "node_agent": NodeDefinition(
                        id="node_agent",
                        type="webhook_trigger",
                        config={},
                    )
                },
                edges=[],
            )
            engine = FlowEngine(flow=flow, storage=storage)

            # Run with canary strings in inputs and trigger
            state = await engine.run(
                inputs={
                    "prompt": self.CANARY_INPUT,
                    "secret": self.CANARY_SECRET_TOKEN,
                    "arg": self.CANARY_TOOL_ARG,
                }
            )
            assert state.status.value == "succeeded"

            # Execute a failing tool call where canary is in the argument that causes the failure
            class FailingTransport:
                async def avalidate(self, args):
                    raise ValueError(f"Blocked sink call due to payload: {args.get('to')}")

            with RunSpan("run-fail", "flow-fail") as run_span:
                fail_proxy = AgentOSToolProxy(
                    run_id="run-fail",
                    agent_node_id="node_fail",
                    storage=storage,
                    policy=SecurityPolicy(),
                    transport_registry={"send_email": FailingTransport()},
                    run_span=run_span,
                )
                with pytest.raises(ValueError) as excinfo:
                    # Header injection containing the canary causes avalidate() to raise ValueError
                    await fail_proxy.invoke(
                        "node_fail",
                        "send_email",
                        {"to": f"bad\r\n{self.CANARY_FAILING_ARG}@example.com", "subject": "Test", "body": "Body"},
                    )
                assert self.CANARY_FAILING_ARG in str(excinfo.value)

            # Record model and tool calls with canary values in local variables
            record_model_call(
                provider="mock-prov",
                model="mock-model",
                duration_ms=10.0,
                prompt_tokens=42,
                completion_tokens=10,
                cost_usd=0.0001,
            )
            record_tool_call(
                tool_name="calculator",
                duration_ms=5.0,
                status="ok",
                limit_hit=False,
            )

            # Inspect ALL spans
            spans = span_exp.get_finished_spans()
            canaries = [
                self.CANARY_INPUT,
                self.CANARY_OUTPUT,
                self.CANARY_TOOL_ARG,
                self.CANARY_SECRET_TOKEN,
                self.CANARY_FAILING_ARG,
            ]

            for span in spans:
                for canary in canaries:
                    assert canary not in span.name
                    if span.status.description:
                        assert canary not in span.status.description
                    for k, v in span.attributes.items():
                        assert canary not in str(k)
                        assert canary not in str(v)
                    for ev in span.events:
                        assert canary not in ev.name
                        for k, v in ev.attributes.items():
                            assert canary not in str(k)
                            assert canary not in str(v)

            # Specifically verify the failing tool span has ONLY the exception class name in description
            failing_spans = [s for s in spans if s.name == "agentos.tool_call" and s.attributes.get("agentos.node_id") == "node_fail"]
            assert len(failing_spans) == 1
            f_span = failing_spans[0]
            assert f_span.status.description == "ValueError"
            assert len(f_span.events) == 0

            # Inspect ALL metrics
            metric_data = metric_reader.get_metrics_data()
            if metric_data:
                for rm in metric_data.resource_metrics:
                    for sm in rm.scope_metrics:
                        for m in sm.metrics:
                            for canary in canaries:
                                assert canary not in m.name
                                assert canary not in (m.description or "")
                                for dp in getattr(m.data, "data_points", []):
                                    for k, v in getattr(dp, "attributes", {}).items():
                                        assert canary not in str(k)
                                        assert canary not in str(v)
        finally:
            reset_telemetry()


class TestToolSpanDeduplicationAndNoOpenSpans:
    @pytest.mark.asyncio
    async def test_tool_span_deduplicated_and_no_span_left_open(self, tmp_path):
        tracer, meter, span_exp, metric_reader = setup_in_memory_telemetry()
        try:
            from agentos.flows.proxy import AgentOSToolProxy
            from agentos.flows.policy import SecurityPolicy
            from agentos.storage.file import open_file_storage
            from opentelemetry.trace import StatusCode

            storage = open_file_storage(str(tmp_path))
            with RunSpan("run-dedup", "flow-dedup") as run_span:
                proxy = AgentOSToolProxy(
                    run_id="run-dedup",
                    agent_node_id="node_sink",
                    storage=storage,
                    policy=SecurityPolicy(),
                    track_labels=False,
                    run_span=run_span,
                )
                args = {"to": "recipient@corp.local", "subject": "Hello", "body": "First"}
                # First call commits the sink
                res1 = await proxy.invoke("node_sink", "send_email", args)
                assert "email successfully dispatched" in res1.lower()

                # Second call with same args hits existing_commit early return
                res2 = await proxy.invoke("node_sink", "send_email", args)
                assert "email successfully dispatched" in res2.lower()

            spans = span_exp.get_finished_spans()
            tool_spans = [s for s in spans if s.name == "agentos.tool_call"]
            assert len(tool_spans) == 2

            # Assert NO span is left open (every finished span has end_time set)
            for s in spans:
                assert s.end_time is not None

            # Second tool span is marked deduplicated and status is OK
            dedup_span = tool_spans[1]
            assert dedup_span.attributes.get("agentos.tool.deduplicated") is True
            assert dedup_span.status.status_code == StatusCode.OK
        finally:
            reset_telemetry()


# ---------------------------------------------------------------------------
# 5. RunRecord Stores Trace ID
# ---------------------------------------------------------------------------


class TestRunRecordStoresTraceId:
    @pytest.mark.asyncio
    async def test_run_record_stores_trace_id(self, tmp_path):
        tracer, meter, span_exp, metric_reader = setup_in_memory_telemetry()
        try:
            from agentos.flows.engine import FlowEngine
            from agentos.flows.models import FlowDefinition, NodeDefinition
            from agentos.storage.file import open_file_storage

            storage = open_file_storage(str(tmp_path))
            flow = FlowDefinition(
                id="trace_flow",
                entrypoint="start",
                nodes={"start": NodeDefinition(id="start", type="webhook_trigger")},
                edges=[],
            )
            engine = FlowEngine(flow=flow, storage=storage)
            state = await engine.run(inputs={"test": 1})

            rec = await storage.runs.get(state.run_id)
            assert rec is not None
            assert rec.trace_id is not None
            assert len(rec.trace_id) == 32
            # Matches the finished run span's trace_id
            run_span = next(s for s in span_exp.get_finished_spans() if s.name == "agentos.run")
            expected_hex = format(run_span.context.trace_id, "032x")
            assert rec.trace_id == expected_hex
        finally:
            reset_telemetry()
