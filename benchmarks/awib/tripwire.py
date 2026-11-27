"""Test helper (4.1 D5): replace every real outbound path with a function that records the attempt and fails, so a
test can assert that no real transport was ever called (SMTP, Slack/webhook HTTP, the http_request / fetch_url
sender, real DNS)."""

from __future__ import annotations

from typing import Any


class RealTransportCalled(AssertionError):
    pass


def install(monkeypatch: Any) -> list[str]:
    import smtplib

    import httpx

    from agentos.flows import net_guard

    calls: list[str] = []

    def trip(name: str):
        def _f(*_a: Any, **_k: Any) -> Any:
            calls.append(name)
            raise RealTransportCalled(f"real transport called: {name}")
        return _f

    async def atrip_send(*_a: Any, **_k: Any) -> Any:
        calls.append("httpx.AsyncHTTPTransport")
        raise RealTransportCalled("real transport called: httpx.AsyncHTTPTransport")

    monkeypatch.setattr(net_guard, "httpx_sender", trip("net_guard.httpx_sender"))
    monkeypatch.setattr(net_guard, "default_resolver", trip("net_guard.default_resolver"))
    monkeypatch.setattr(smtplib.SMTP, "connect", trip("smtplib.SMTP.connect"))
    monkeypatch.setattr(smtplib.SMTP_SSL, "connect", trip("smtplib.SMTP_SSL.connect"))
    # the real network transports of httpx (an in-process ASGITransport test client is not affected)
    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", trip("httpx.HTTPTransport"))
    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", atrip_send)
    return calls
