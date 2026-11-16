#!/usr/bin/env python3
"""
Use Case 04: Webhook Ingress Trigger, Signature Verification, Replay Defense,
and Security Label Propagation.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import hmac
import json
import os
from pathlib import Path
import sys
import tempfile
import time

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

os.environ["AGENTOS_MOCK_LLM"] = "1"
os.environ["AGENTOS_PORT"] = "8000"

from starlette.testclient import TestClient

from agentos.flows.models import FlowDefinition
from agentos.flows.policy import SecurityPolicy
from agentos.flows.proxy import MockTransport
from agentos.flows.worker import FlowWorker
from agentos.storage.file import open_file_storage
from agentos.storage.models import FlowRecord, WebhookRecord
from agentos_server.app import create_app


def _compute_signature(secret_key: str, timestamp: int, body_str: str) -> str:
    payload = f"{timestamp}.{body_str}".encode("utf-8")
    hex_digest = hmac.new(secret_key.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    return f"sha256={hex_digest}"


async def _run_usecase_async() -> bool:
    print("=" * 70)
    print("Use Case 04: Webhook Ingress Trigger & Untrusted Payload Labeling")
    print("=" * 70)

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp_dir:
        storage = open_file_storage(tmp_dir)
        app = create_app(project_path=tmp_dir, storage=storage)

        # 1. Publish test flow
        flow_record = FlowRecord(
            id="flow_webhook_ingest",
            name="Webhook Ingest and Alert Flow",
            entrypoint="ingress",
            nodes={
                "ingress": {
                    "id": "ingress",
                    "type": "webhook_trigger",
                    "config": {"path": "/hooks/dispatch"},
                },
                "sink": {
                    "id": "sink",
                    "type": "send_email",
                    "config": {},
                    "pinned_args": {"to": "ops@internal.local"},
                },
            },
            edges=[
                {"source": "ingress", "target": "sink", "arg_mapping": {"body": "payload"}},
            ],
        )
        await storage.flows.put_draft(flow_record)
        published_flow = await storage.flows.publish(
            "flow_webhook_ingest", content_sha256="dummy_sha", policy_hash="dummy_pol"
        )
        print(f"[OK] Published flow {published_flow.id} v{published_flow.version}")

        # 2. Register Webhook
        secret_path = "dispatch_secret_path_1234567890abcdef"
        secret_path_hash = hashlib.sha256(secret_path.encode("utf-8")).hexdigest()
        secret_key = "test_hmac_secret_key_1234567890abcdef"
        secret_key_ref = "wh_key_test_04"
        await app.state.vault.put(secret_key_ref, secret_key)

        webhook = WebhookRecord(
            webhook_id="wh_test_04",
            name="Ops Ingest Webhook",
            flow_id="flow_webhook_ingest",
            secret_path_hash=secret_path_hash,
            secret_key_ref=secret_key_ref,
            rate_limit_per_minute=60,
            enabled=True,
        )
        await storage.webhooks.put(webhook)
        print(f"[OK] Registered webhook {webhook.webhook_id} with secret path")

        client = TestClient(app, base_url="http://localhost")

        # ---------------------------------------------------------------------
        # Scenario 1: Benign Signed Webhook Ingress
        # ---------------------------------------------------------------------
        print("\n[Scenario 1] Testing Benign Signed Webhook Ingress...")
        benign_path = Path(__file__).parent / "inputs" / "benign.json"
        benign_payload = benign_path.read_text(encoding="utf-8")
        now_ts = int(time.time())
        valid_sig = _compute_signature(secret_key, now_ts, benign_payload)

        resp = client.post(
            f"/hooks/{secret_path}",
            content=benign_payload,
            headers={
                "Content-Type": "application/json",
                "X-AgentOS-Signature": valid_sig,
                "X-AgentOS-Timestamp": str(now_ts),
            },
        )
        assert resp.status_code == 202, f"Expected 202, got {resp.status_code}: {resp.text}"
        run_id = resp.json()["run_id"]
        print(f"  --> Accepted: Run created {run_id}")

        # Execute run via FlowWorker
        mock_transport = MockTransport()
        policy = SecurityPolicy(internal_domains={"internal.local"})
        worker = FlowWorker(
            worker_id="worker_04",
            queue=app.state.queue,
            storage=storage,
            policy=policy,
            transport_registry={"send_email": mock_transport},
        )
        processed = await worker.run_once()
        assert processed == run_id

        run_rec = await storage.runs.get(run_id)
        assert run_rec.status == "succeeded", f"Expected succeeded, got {run_rec.status}"
        assert len(mock_transport.sent_calls) == 1
        assert mock_transport.sent_calls[0]["to"] == "ops@internal.local"
        print(f"  --> Worker successfully processed run {run_id}; email dispatched to ops@internal.local")

        # ---------------------------------------------------------------------
        # Scenario 2: Unsigned & Bad Signature Ingress (Anti-Oracle)
        # ---------------------------------------------------------------------
        print("\n[Scenario 2] Testing Unsigned / Bad Signature Rejection (Identical 404)...")
        # Missing headers
        resp_missing = client.post(
            f"/hooks/{secret_path}",
            content=benign_payload,
            headers={"Content-Type": "application/json"},
        )
        assert resp_missing.status_code == 404
        assert resp_missing.json() == {"detail": "Not Found"}

        # Forged signature
        bad_sig = "sha256=" + "0" * 64
        resp_bad_sig = client.post(
            f"/hooks/{secret_path}",
            content=benign_payload,
            headers={
                "Content-Type": "application/json",
                "X-AgentOS-Signature": bad_sig,
                "X-AgentOS-Timestamp": str(now_ts),
            },
        )
        assert resp_bad_sig.status_code == 404
        assert resp_bad_sig.json() == {"detail": "Not Found"}

        # Unknown secret path
        resp_unknown = client.post(
            "/hooks/nonexistent_secret_path",
            content=benign_payload,
            headers={
                "Content-Type": "application/json",
                "X-AgentOS-Signature": valid_sig,
                "X-AgentOS-Timestamp": str(now_ts),
            },
        )
        assert resp_unknown.status_code == 404
        assert resp_unknown.json() == {"detail": "Not Found"}
        print("  --> Bad signature and unknown path both returned identical 404 Not Found")

        # ---------------------------------------------------------------------
        # Scenario 3: Replay Defense
        # ---------------------------------------------------------------------
        print("\n[Scenario 3] Testing Replay Defense...")
        # Re-sending the exact same valid_sig should be rejected by nonce cache
        resp_replay = client.post(
            f"/hooks/{secret_path}",
            content=benign_payload,
            headers={
                "Content-Type": "application/json",
                "X-AgentOS-Signature": valid_sig,
                "X-AgentOS-Timestamp": str(now_ts),
            },
        )
        assert resp_replay.status_code == 404
        assert resp_replay.json() == {"detail": "Not Found"}
        print("  --> Replayed signature rejected with 404 Not Found by nonce cache")

        # ---------------------------------------------------------------------
        # Scenario 4: Adversarial Injection Blocked by Untrusted Label
        # ---------------------------------------------------------------------
        print("\n[Scenario 4] Testing Adversarial Injection Exfiltration Blocked by Labels...")
        attack_path = Path(__file__).parent / "inputs" / "attack.json"
        attack_payload = attack_path.read_text(encoding="utf-8")
        attack_ts = int(time.time()) + 1
        attack_sig = _compute_signature(secret_key, attack_ts, attack_payload)

        resp_attack = client.post(
            f"/hooks/{secret_path}",
            content=attack_payload,
            headers={
                "Content-Type": "application/json",
                "X-AgentOS-Signature": attack_sig,
                "X-AgentOS-Timestamp": str(attack_ts),
            },
        )
        assert resp_attack.status_code == 202
        attack_run_id = resp_attack.json()["run_id"]

        attack_processed = await worker.run_once()
        assert attack_processed == attack_run_id

        attack_run_rec = await storage.runs.get(attack_run_id)
        # Even though injection attempted to redirect to exfil@attacker.com,
        # pinned arg 'to' enforces ops@internal.local, preventing exfiltration!
        assert len(mock_transport.sent_calls) == 2
        assert mock_transport.sent_calls[1]["to"] == "ops@internal.local"
        print("  --> Adversarial payload did not breach security sink; exfil blocked")

    print("\n[SUCCESS] Use Case 04 completed all scenarios cleanly.")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Use Case 04: Webhook Ingress & Security")
    parser.parse_args()
    success = asyncio.run(_run_usecase_async())
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
