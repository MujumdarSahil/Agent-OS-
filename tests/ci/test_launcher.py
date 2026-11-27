"""Smoke test for the one-command launcher (2.4c, MOCK): starts, answers /api/health, stops cleanly."""

import os
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def port_open(port: int) -> bool:
    with socket.socket() as s:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", port)) == 0


def test_launcher_starts_and_stops_cleanly(tmp_path):
    (tmp_path / "agentos.config.yaml").write_text("preferred_tags: []\n", encoding="utf-8")
    port = free_port()
    env = {**os.environ, "AGENTOS_MOCK_LLM": "1", "AGENTOS_API_TOKEN": "launcher-smoke-token"}
    flags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
    proc = subprocess.Popen(
        [sys.executable, str(ROOT / "main.py"), "--project", str(tmp_path), "--backend-port", str(port),
         "--no-browser", "--skip-ui-build"],
        cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        creationflags=flags, start_new_session=os.name != "nt",
    )
    lines: list[str] = []
    reader = threading.Thread(target=lambda: lines.extend(iter(proc.stdout.readline, "")), daemon=True)
    reader.start()
    try:
        deadline = time.time() + 120
        healthy = False
        while time.time() < deadline and proc.poll() is None:
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/health", timeout=2) as r:
                    healthy = r.status == 200
            except Exception:
                healthy = False
            if healthy and any("AgentOS is running." in ln for ln in lines):
                break
            time.sleep(0.5)
        assert healthy, "backend never answered /api/health"
        proc.send_signal(signal.CTRL_BREAK_EVENT if os.name == "nt" else signal.SIGINT)
        proc.wait(timeout=60)
        reader.join(timeout=10)
        out = "".join(lines)
    finally:
        if proc.poll() is None:
            proc.kill()
    assert proc.returncode == 0, out[-2000:]
    assert "AgentOS is running." in out and "Worker:  on (in-process)" in out
    assert "AgentOS stopped." in out
    time.sleep(1.0)
    assert not port_open(port), "backend still listening after Ctrl+C"
