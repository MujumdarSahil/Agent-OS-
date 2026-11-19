"""CI test for Use Case 07: support desk copilot (MOCK: scripted LLM, fake DNS/HTTP, recorded outbox)."""

import asyncio
import hashlib
import hmac
import importlib.util
import json
import os
from pathlib import Path

os.environ["AGENTOS_MOCK_LLM"] = "1"

USECASE_DIR = Path(__file__).resolve().parent.parent.parent / "examples" / "usecases" / "07-support-desk-copilot"


def _load(name: str, file: str):
    spec = importlib.util.spec_from_file_location(name, USECASE_DIR / file)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_usecase_07_support_desk_copilot():
    """normal -> queue email; urgent -> approval then on-call email; injection -> rejected, 0 emails;
    unpinned recipient variant -> publish refused."""
    assert asyncio.run(_load("usecase_07_run", "run.py")._run_usecase_async()) is True


def test_usecase_07_with_a_local_smtp_server(monkeypatch):
    """3.3 demo path: UC07_SMTP=127.0.0.1:<port> sends the same scenarios through a real (local) SMTP channel.
    normal -> queue, urgent (approved) -> on-call, injection approved anyway -> on-call; never the attacker."""
    import socket

    from aiosmtpd.controller import Controller

    class Box:
        def __init__(self):
            self.rcpts = []

        async def handle_DATA(self, server, session, envelope):  # noqa: N802
            self.rcpts.extend(envelope.rcpt_tos)
            return "250 OK"

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    box = Box()
    ctl = Controller(box, hostname="127.0.0.1", port=port)
    ctl.start()
    try:
        monkeypatch.setenv("UC07_SMTP", f"127.0.0.1:{port}")
        assert asyncio.run(_load("usecase_07_run_smtp", "run.py")._run_usecase_async()) is True
    finally:
        ctl.stop()
    assert box.rcpts == ["support-queue@corp.local", "oncall@corp.local", "oncall@corp.local"]
    assert not any("attacker" in r for r in box.rcpts)


def test_usecase_07_daily_schedule_is_valid():
    from croniter import croniter

    from agentos_server.routes_v2.schedules import CreateScheduleRequest

    req = CreateScheduleRequest(**json.loads((USECASE_DIR / "schedule.daily.json").read_text(encoding="utf-8")))
    assert req.flow_id == "uc07_support_desk" and croniter.is_valid(req.cron_expression)


def test_usecase_07_sender_signature_format():
    sender = _load("usecase_07_sender", "send_webhook.py")
    body = json.dumps(sender.TICKETS["urgent"])
    expected = "sha256=" + hmac.new(b"k", f"1700000000.{body}".encode(), hashlib.sha256).hexdigest()
    assert sender.sign("k", 1700000000, body) == expected
    assert set(sender.TICKETS) == {"normal", "urgent", "injection"}
