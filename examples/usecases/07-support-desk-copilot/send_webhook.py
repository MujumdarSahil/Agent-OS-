"""
Send signed support tickets to a running AgentOS (use case 07 demo).

One command (recommended):
    python examples/usecases/07-support-desk-copilot/send_webhook.py all --setup [--with-schedule]
  --setup creates + publishes the flow and creates a webhook through the API (token from
  AGENTOS_API_TOKEN or the local token file, same as `python main.py`). The webhook secret path and
  HMAC key stay in memory for this process and are never printed or written.
  --with-schedule also registers schedule.daily.json (daily 08:00 UTC run of the same flow).

Existing webhook (secret path and key were returned once by POST /api/v2/webhooks):
    $env:AGENTOS_WEBHOOK_PATH = "<secret path>"; $env:AGENTOS_WEBHOOK_KEY = "<secret key>"
    python examples/usecases/07-support-desk-copilot/send_webhook.py urgent

Signature: X-AgentOS-Signature = "sha256=" + HMAC-SHA256(key, f"{timestamp}.{body}"),
X-AgentOS-Timestamp = unix seconds. A bad signature, unknown path or replay all get the same 404.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
TICKETS = json.loads((HERE / "inputs" / "tickets.json").read_text(encoding="utf-8"))


def sign(key: str, timestamp: int, body: str) -> str:
    return "sha256=" + hmac.new(key.encode(), f"{timestamp}.{body}".encode(), hashlib.sha256).hexdigest()


def api(base_url: str, token: str, method: str, path: str, payload: dict | None = None) -> tuple[int, dict]:
    req = urllib.request.Request(f"{base_url.rstrip('/')}/api/v2{path}", method=method,
                                 data=json.dumps(payload).encode() if payload is not None else None,
                                 headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def setup(base_url: str, with_schedule: bool) -> tuple[str, str]:
    token = os.environ.get("AGENTOS_API_TOKEN")
    if not token:
        sys.path.insert(0, str(HERE.parents[2]))
        from agentos_server.auth import get_or_create_api_token

        token = get_or_create_api_token()
    flow = json.loads((HERE / "flows" / "support_desk.flow.json").read_text(encoding="utf-8"))
    status, _ = api(base_url, token, "POST", "/flows", flow)
    if status == 400:
        status, _ = api(base_url, token, "PUT", f"/flows/{flow['id']}", flow)
    print(f"flow {flow['id']}: saved (HTTP {status})")
    status, body = api(base_url, token, "POST", f"/flows/{flow['id']}/publish",
                       {"note": "use case 07 setup"})
    if status != 200:
        raise SystemExit(f"publish refused (HTTP {status}): {body.get('detail')}\n"
                         "Hint: start AgentOS with $env:AGENTOS_INTERNAL_DOMAINS=\"corp.local\".")
    print(f"flow {flow['id']}: published v{body.get('version')}")
    status, hook = api(base_url, token, "POST", "/webhooks", {"name": "Support desk tickets", "flow_id": flow["id"]})
    if status != 201:
        raise SystemExit(f"webhook create failed (HTTP {status}): {hook.get('detail')}")
    print(f"webhook {hook['webhook_id']}: created (secret path and key kept in memory, not shown)")
    if with_schedule:
        sched = json.loads((HERE / "schedule.daily.json").read_text(encoding="utf-8"))
        status, s = api(base_url, token, "POST", "/schedules", sched)
        print(f"schedule: HTTP {status} {s.get('schedule_id', '')} next_run_at={s.get('next_run_at')}")
    return hook["secret_path"], hook["secret_key"]


def send(base_url: str, path: str, key: str, scenario: str) -> int:
    body = json.dumps(TICKETS[scenario])
    ts = int(time.time())
    req = urllib.request.Request(
        f"{base_url.rstrip('/')}/hooks/{path}", data=body.encode(), method="POST",
        headers={"Content-Type": "application/json", "X-AgentOS-Signature": sign(key, ts, body),
                 "X-AgentOS-Timestamp": str(ts)})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            run_id = json.loads(r.read() or b"{}").get("run_id", "?")
            print(f"{scenario}: HTTP {r.status} run_id={run_id}")
            return 0
    except urllib.error.HTTPError as e:
        print(f"{scenario}: HTTP {e.code} (404 = wrong path/key, replay, or webhook disabled)")
        return 1


def main() -> int:
    p = argparse.ArgumentParser(description="Send signed support tickets to AgentOS (use case 07).")
    p.add_argument("scenario", choices=[*TICKETS, "all"])
    p.add_argument("--base-url", default=os.environ.get("AGENTOS_BASE_URL", "http://127.0.0.1:8000"))
    p.add_argument("--setup", action="store_true", help="create + publish the flow and a webhook first")
    p.add_argument("--with-schedule", action="store_true", help="with --setup: also register the daily schedule")
    a = p.parse_args()
    if a.setup:
        path, key = setup(a.base_url, a.with_schedule)
    else:
        path, key = os.environ.get("AGENTOS_WEBHOOK_PATH"), os.environ.get("AGENTOS_WEBHOOK_KEY")
        if not path or not key:
            print("Use --setup, or set AGENTOS_WEBHOOK_PATH and AGENTOS_WEBHOOK_KEY.")
            return 2
    rc = 0
    for s in (list(TICKETS) if a.scenario == "all" else [a.scenario]):
        rc |= send(a.base_url, path, key, s)
        time.sleep(1.1)  # distinct timestamps; the replay cache rejects an identical signature
    return rc


if __name__ == "__main__":
    sys.exit(main())
