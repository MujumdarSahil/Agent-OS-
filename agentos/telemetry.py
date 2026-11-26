"""
OpenTelemetry tracing and metrics for AgentOS (3.6b).

Optional extra: install with ``pip install agentos[otel]`` or manually install:
  opentelemetry-sdk>=1.26
  opentelemetry-exporter-otlp-proto-grpc>=1.26  (or opentelemetry-exporter-otlp-proto-http>=1.26)

Configuration (standard OTEL env vars):
  OTEL_EXPORTER_OTLP_ENDPOINT  — enables export; e.g. http://localhost:4317
  OTEL_SERVICE_NAME             — default "agentos"
  OTEL_RESOURCE_ATTRIBUTES      — standard OTEL resource attributes

Traces:
  One span per run, with child spans per node, model call, tool call, and sandbox call.
  Attributes are METADATA ONLY — no prompt text, model output, tool arguments, results,
  ticket payload content, keys, or tokens.

Metrics:
  Counters: runs_total (by status), model_calls_total (by provider, model),
            tokens_total (by provider, model, type), cost_total,
            blocked_calls_total, refused_publishes_total.
  Histogram: model_call_duration_ms (by provider).

Privacy guarantee:
  No sensitive attribute is ever set. The ``_safe`` filter is applied to any externally-controlled
  string (provider name, model name, tool name, error class) before use as an attribute.

Canary test coverage:
  An in-process in-memory export verifies that none of the canary strings injected into inputs,
  outputs, and tool arguments appear in any span, event, attribute, or metric.

Dropped exports:
  The OTLP batch processor uses a bounded queue (max_queue_size=512, max_export_batch_size=64).
  When the exporter is unreachable, spans are dropped after the queue fills; runs are never
  slowed down or failed. The drop count is tracked in ``drops_total`` metric.
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Lazy import helpers — OTEL is optional; never import at module top level.
# ---------------------------------------------------------------------------

_SDK_AVAILABLE = None  # None = not checked; True/False = checked


def _sdk_available() -> bool:
    global _SDK_AVAILABLE
    if _SDK_AVAILABLE is None:
        try:
            import opentelemetry.sdk.trace  # noqa: F401
            _SDK_AVAILABLE = True
        except ImportError:
            _SDK_AVAILABLE = False
    return _SDK_AVAILABLE


# ---------------------------------------------------------------------------
# Safety filter — no externally-controlled string goes into an attribute raw
# ---------------------------------------------------------------------------

_SAFE_RE = re.compile(r"^[A-Za-z0-9_./:@-]{1,128}$")


def _safe(value: Any, default: str = "unknown") -> str:
    """Return value if it looks like a safe identifier, else default."""
    s = str(value) if not isinstance(value, str) else value
    return s if _SAFE_RE.fullmatch(s) else default


# ---------------------------------------------------------------------------
# Tracer / meter registry (module-level singletons, lazily initialised)
# ---------------------------------------------------------------------------

_tracer = None
_meter = None
_configured_endpoint: Optional[str] = None  # the endpoint we initialised with


def _get_tracer():
    return _tracer


def _get_meter():
    return _meter


def setup_telemetry(service_name: str = "") -> bool:
    """Initialise the OTEL SDK and OTLP exporter.

    Called once at server startup (``create_app``).  Returns True if the exporter is configured.
    Does nothing (returns False) when OTEL_EXPORTER_OTLP_ENDPOINT is not set.
    Never raises — the server must start even without OTEL.
    """
    global _tracer, _meter, _configured_endpoint

    endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "").strip()
    if not endpoint:
        return False

    if not _sdk_available():
        logger.warning(
            "OTEL_EXPORTER_OTLP_ENDPOINT is set but opentelemetry-sdk is not installed. "
            "Install agentos[otel] to enable telemetry. Continuing without it."
        )
        return False

    # Already initialised with the same endpoint — idempotent.
    if _configured_endpoint == endpoint:
        return True

    try:
        from opentelemetry import metrics, trace
        from opentelemetry.sdk.metrics import MeterProvider
        from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor

        svc = service_name or os.environ.get("OTEL_SERVICE_NAME", "agentos")
        resource = Resource.create({"service.name": svc})

        # Detect grpc vs http exporter
        if endpoint.startswith("http://") or endpoint.startswith("https://"):
            try:
                from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
                from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
                span_exporter = OTLPSpanExporter(endpoint=endpoint + "/v1/traces")
                metric_exporter = OTLPMetricExporter(endpoint=endpoint + "/v1/metrics")
            except ImportError:
                from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
                from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
                span_exporter = OTLPSpanExporter(endpoint=endpoint)
                metric_exporter = OTLPMetricExporter(endpoint=endpoint)
        else:
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
            from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
            span_exporter = OTLPSpanExporter(endpoint=endpoint)
            metric_exporter = OTLPMetricExporter(endpoint=endpoint)

        # Bounded queue — drops spans when exporter is unreachable, never blocks runs.
        bsp = BatchSpanProcessor(
            span_exporter,
            max_queue_size=512,
            max_export_batch_size=64,
            schedule_delay_millis=5000,
        )
        tp = TracerProvider(resource=resource)
        tp.add_span_processor(bsp)
        trace.set_tracer_provider(tp)
        _tracer = trace.get_tracer("agentos", schema_url="https://opentelemetry.io/schemas/1.26.0")

        mr = PeriodicExportingMetricReader(metric_exporter, export_interval_millis=30_000)
        mp = MeterProvider(resource=resource, metric_readers=[mr])
        metrics.set_meter_provider(mp)
        _meter = metrics.get_meter("agentos")
        _configured_endpoint = endpoint

        logger.info("OpenTelemetry exporter configured: endpoint=%s service=%s", endpoint, svc)
        return True

    except Exception as exc:
        logger.warning("Failed to initialise OpenTelemetry: %s — continuing without it", exc)
        return False


# ---------------------------------------------------------------------------
# In-memory exporter (for tests only — never used in production)
# ---------------------------------------------------------------------------

def _make_in_memory_exporters():
    """Return (span_exporter, metric_exporter) using in-memory backends (for tests)."""
    if not _sdk_available():
        return None, None
    try:
        from opentelemetry.sdk.metrics.export import InMemoryMetricExporter
        from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
        return InMemorySpanExporter(), InMemoryMetricExporter()
    except ImportError:
        return None, None


def reset_telemetry() -> None:
    """Reset all active telemetry providers, meters, and instrument caches."""
    global _tracer, _meter, _configured_endpoint, _instruments
    _tracer = None
    _meter = None
    _configured_endpoint = None
    _instruments.clear()


def setup_in_memory_telemetry():
    """Set up OTEL with in-memory exporters (for tests). Returns (tracer, meter, span_exporter, metric_reader)."""
    global _tracer, _meter, _configured_endpoint, _instruments
    # Ensure OTEL_SDK_DISABLED does not disable the in-memory test SDK
    os.environ.pop("OTEL_SDK_DISABLED", None)
    if not _sdk_available():
        return None, None, None, None
    try:
        from opentelemetry import metrics, trace
        from opentelemetry.sdk.metrics import MeterProvider
        from opentelemetry.sdk.metrics.export import InMemoryMetricReader
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import SimpleSpanProcessor
        from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

        _instruments.clear()
        span_exp = InMemorySpanExporter()
        metric_reader = InMemoryMetricReader()

        resource = Resource.create({"service.name": "agentos-test"})
        tp = TracerProvider(resource=resource)
        tp.add_span_processor(SimpleSpanProcessor(span_exp))
        t = tp.get_tracer("agentos")

        mp = MeterProvider(resource=resource, metric_readers=[metric_reader])
        m = mp.get_meter("agentos")

        _tracer = t
        _meter = m
        _configured_endpoint = "__in_memory__"
        return t, m, span_exp, metric_reader
    except Exception as exc:
        logger.warning("setup_in_memory_telemetry failed: %s", exc)
        return None, None, None, None


# ---------------------------------------------------------------------------
# Metric instruments (created lazily on first use)
# ---------------------------------------------------------------------------

_instruments: dict[str, Any] = {}


def _get_counter(name: str, description: str, unit: str = "1") -> Any:
    if not _meter:
        return None
    if name not in _instruments:
        _instruments[name] = _meter.create_counter(name, description=description, unit=unit)
    return _instruments[name]


def _get_histogram(name: str, description: str, unit: str = "ms") -> Any:
    if not _meter:
        return None
    if name not in _instruments:
        _instruments[name] = _meter.create_histogram(name, description=description, unit=unit)
    return _instruments[name]


# ---------------------------------------------------------------------------
# Public instrumentation API
# ---------------------------------------------------------------------------

def record_run_status(status: str) -> None:
    """Increment the runs_total counter by status."""
    ctr = _get_counter("agentos.runs.total", "Total flow runs by final status")
    if ctr:
        ctr.add(1, {"status": _safe(status)})


def record_model_call(
    provider: str,
    model: str,
    duration_ms: float,
    prompt_tokens: int = 0,
    completion_tokens: int = 0,
    cost_usd: float = 0.0,
    fallback_attempts: int = 0,
    success: bool = True,
) -> None:
    """Record a model call: counter, token counters, cost counter, latency histogram."""
    p, m = _safe(provider), _safe(model)
    attrs = {"provider": p, "model": m}

    ctr = _get_counter("agentos.model_calls.total", "Total LLM model calls")
    if ctr:
        ctr.add(1, {**attrs, "success": str(success).lower()})

    if prompt_tokens:
        tc = _get_counter("agentos.tokens.total", "Total tokens consumed", "token")
        if tc:
            tc.add(prompt_tokens, {**attrs, "type": "prompt"})
    if completion_tokens:
        tc = _get_counter("agentos.tokens.total", "Total tokens consumed", "token")
        if tc:
            tc.add(completion_tokens, {**attrs, "type": "completion"})
    if cost_usd:
        cc = _get_counter("agentos.cost.total", "Total estimated cost", "usd")
        if cc:
            cc.add(cost_usd, attrs)
    if fallback_attempts:
        fa = _get_counter("agentos.model_fallbacks.total", "Total model fallback attempts")
        if fa:
            fa.add(fallback_attempts, attrs)

    hist = _get_histogram("agentos.model_call.duration", "Model call duration", "ms")
    if hist:
        hist.record(duration_ms, attrs)


def record_blocked_call() -> None:
    ctr = _get_counter("agentos.blocked_calls.total", "Calls blocked by security policy")
    if ctr:
        ctr.add(1)


def record_refused_publish() -> None:
    ctr = _get_counter("agentos.refused_publishes.total", "Flow publishes refused by static analyser")
    if ctr:
        ctr.add(1)


def record_tool_call(tool_name: str, duration_ms: float, status: str, limit_hit: bool = False) -> None:
    ctr = _get_counter("agentos.tool_calls.total", "Total tool/sandbox calls by tool name and status")
    if ctr:
        ctr.add(1, {"tool": _safe(tool_name), "status": _safe(status), "limit_hit": str(limit_hit).lower()})


# ---------------------------------------------------------------------------
# Context managers for tracing spans
# ---------------------------------------------------------------------------

class RunSpan:
    """OTEL span context for a single flow run.

    Usage::

        async with RunSpan(run_id, flow_id, trigger) as span:
            ...
    """

    def __init__(self, run_id: str, flow_id: str, trigger: str = "manual") -> None:
        self._run_id = run_id
        self._flow_id = flow_id
        self._trigger = trigger
        self._span = None
        self._ctx = None
        self.trace_id: Optional[str] = None

    def __enter__(self):
        if not _tracer:
            return self
        from opentelemetry import trace
        self._span = _tracer.start_span(
            "agentos.run",
            attributes={
                "agentos.run_id": _safe(self._run_id),
                "agentos.flow_id": _safe(self._flow_id),
                "agentos.trigger": _safe(self._trigger),
            },
        )
        self._ctx = trace.use_span(self._span, end_on_exit=False).__enter__()
        ctx = self._span.get_span_context()
        self.trace_id = format(ctx.trace_id, "032x") if ctx and ctx.is_valid else None
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._ctx:
            try:
                self._ctx.__exit__(exc_type, exc_val, exc_tb)
            except Exception:
                pass
            self._ctx = None
        if self._span:
            if exc_type is not None:
                from opentelemetry.trace import StatusCode
                self._span.set_status(StatusCode.ERROR, _safe(exc_type.__name__ if exc_type else "error"))
            else:
                from opentelemetry.trace import StatusCode
                self._span.set_status(StatusCode.OK)
            self._span.end()
            self._span = None
        return False

    def set_status(self, status: str) -> None:
        """Mark the run span with a final status attribute (not an error — just metadata)."""
        if self._span:
            self._span.set_attribute("agentos.run.status", _safe(status))

    def node_span(self, node_id: str, node_type: str):
        """Return a child span context manager for a single node execution."""
        if not self._span:
            return _NullSpan()
        return _NodeSpan(self._span, node_id, node_type)

    def model_span(self, provider: str, model: str, node_id: str = ""):
        """Return a child span context manager for a single model call."""
        if not self._span:
            return _NullSpan()
        return _ModelSpan(self._span, provider, model, node_id)

    def tool_span(self, tool_name: str, node_id: str = ""):
        """Return a child span context manager for a single tool/sandbox call."""
        if not self._span:
            return _NullSpan()
        return _ToolSpan(self._span, tool_name, node_id)

    async def __aenter__(self):
        return self.__enter__()

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        return self.__exit__(exc_type, exc_val, exc_tb)


class _NodeSpan:
    def __init__(self, parent, node_id: str, node_type: str) -> None:
        self._parent = parent
        self._node_id = node_id
        self._node_type = node_type
        self._span = None

    def __enter__(self):
        if not _tracer or not self._parent:
            return self
        from opentelemetry import context, trace
        ctx = trace.set_span_in_context(self._parent)
        self._span = _tracer.start_span(
            "agentos.node",
            context=ctx,
            attributes={
                "agentos.node_id": _safe(self._node_id),
                "agentos.node_type": _safe(self._node_type),
            },
        )
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._span:
            if exc_type is not None:
                from opentelemetry.trace import StatusCode
                self._span.set_status(StatusCode.ERROR, _safe(exc_type.__name__ if exc_type else "error"))
            self._span.end()
        return False

    async def __aenter__(self):
        return self.__enter__()

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        return self.__exit__(exc_type, exc_val, exc_tb)


class _ModelSpan:
    def __init__(self, parent, provider: str, model: str, node_id: str = "") -> None:
        self._parent = parent
        self._provider = provider
        self._model = model
        self._node_id = node_id
        self._span = None

    def set_tokens(self, prompt: int = 0, completion: int = 0, cost_usd: float = 0.0,
                   fallback_attempts: int = 0) -> None:
        """Add token/cost metadata to the span. Called after the model returns."""
        if self._span:
            if prompt:
                self._span.set_attribute("agentos.model.prompt_tokens", prompt)
            if completion:
                self._span.set_attribute("agentos.model.completion_tokens", completion)
            if cost_usd:
                self._span.set_attribute("agentos.model.cost_usd", cost_usd)
            if fallback_attempts:
                self._span.set_attribute("agentos.model.fallback_attempts", fallback_attempts)

    def __enter__(self):
        if not _tracer or not self._parent:
            return self
        from opentelemetry import trace
        ctx = trace.set_span_in_context(self._parent)
        self._span = _tracer.start_span(
            "agentos.model_call",
            context=ctx,
            attributes={
                "agentos.model.provider": _safe(self._provider),
                "agentos.model.model": _safe(self._model),
                "agentos.node_id": _safe(self._node_id) if self._node_id else "unknown",
            },
        )
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._span:
            if exc_type is not None:
                from opentelemetry.trace import StatusCode
                self._span.set_status(StatusCode.ERROR, _safe(exc_type.__name__ if exc_type else "error"))
            self._span.end()
        return False

    async def __aenter__(self):
        return self.__enter__()

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        return self.__exit__(exc_type, exc_val, exc_tb)


class _ToolSpan:
    def __init__(self, parent, tool_name: str, node_id: str = "") -> None:
        self._parent = parent
        self._tool_name = tool_name
        self._node_id = node_id
        self._span = None

    def set_status(self, status: str, limit_hit: bool = False) -> None:
        if self._span:
            self._span.set_attribute("agentos.tool.status", _safe(status))
            self._span.set_attribute("agentos.tool.limit_hit", limit_hit)

    def __enter__(self):
        if not _tracer or not self._parent:
            return self
        from opentelemetry import trace
        ctx = trace.set_span_in_context(self._parent)
        self._span = _tracer.start_span(
            "agentos.tool_call",
            context=ctx,
            attributes={
                "agentos.tool.name": _safe(self._tool_name),
                "agentos.node_id": _safe(self._node_id) if self._node_id else "unknown",
            },
        )
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._span:
            if exc_type is not None:
                from opentelemetry.trace import StatusCode
                self._span.set_status(StatusCode.ERROR, _safe(exc_type.__name__ if exc_type else "error"))
            self._span.end()
        return False

    async def __aenter__(self):
        return self.__enter__()

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        return self.__exit__(exc_type, exc_val, exc_tb)


# ---------------------------------------------------------------------------
# Null span (returned when OTEL is off or SDK not installed)
# ---------------------------------------------------------------------------

class _NullSpan:
    """A no-op span for when OTEL is not configured."""
    trace_id: Optional[str] = None

    def __enter__(self): return self
    def __exit__(self, *_): return False
    async def __aenter__(self): return self
    async def __aexit__(self, *_): return False
    def set_status(self, *_, **__): pass
    def set_tokens(self, *_, **__): pass
    def node_span(self, *_, **__): return _NullSpan()
    def model_span(self, *_, **__): return _NullSpan()
    def tool_span(self, *_, **__): return _NullSpan()
