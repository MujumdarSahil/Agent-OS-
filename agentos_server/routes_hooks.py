"""
Webhook ingress route for AgentOS: /hooks/{secret_path}.

Security Invariants:
1. Outside /api: no local API token required.
2. Protected against host rebinding via AGENTOS_PUBLIC_HOSTS.
3. No status-code oracle:
   - Rate limit (per IP) -> 429
   - Content-Type check -> 415
   - Size limit (streaming read cap 1MB) -> 413
   These run BEFORE the path lookup.
   After lookup: unknown path, disabled hook, missing/malformed signature header,
   stale timestamp (>5min), replay, and bad signature ALL return identical 404 responses.
4. Input payload is strictly tagged as Integrity.UNTRUSTED.
5. Runs the flow's latest published version via the queue backend.
6. run_id uses a full uuid4.
"""

from __future__ import annotations

import collections
import hashlib
import hmac
import json
import logging
import os
import re
import time
from typing import Deque, Dict, Optional
import uuid

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse

from agentos.flows.labels import Integrity, Label
from agentos.storage.models import RunRecord

logger = logging.getLogger(__name__)

router = APIRouter()

MAX_BODY_BYTES = 1024 * 1024  # 1 MB read cap
SIGNATURE_PATTERN = re.compile(r"^sha256=[0-9a-f]{64}$")
TIMESTAMP_PATTERN = re.compile(r"^[0-9]+$")

# In-memory IP rate limiter: ip -> deque of request timestamps
_IP_RATE_LIMITS: Dict[str, Deque[float]] = collections.defaultdict(collections.deque)
_RATE_LIMIT_WINDOW_S = 60.0
_MAX_REQUESTS_PER_IP = 120  # 120 req/min per IP pre-lookup gate


def _check_ip_rate_limit(client_ip: str) -> bool:
    now = time.monotonic()
    q = _IP_RATE_LIMITS[client_ip]
    while q and q[0] <= now - _RATE_LIMIT_WINDOW_S:
        q.popleft()
    if len(q) >= _MAX_REQUESTS_PER_IP:
        return False
    q.append(now)
    return True


def _generic_not_found() -> JSONResponse:
    """Universal 404 response to eliminate status-code and timing oracles."""
    return JSONResponse(status_code=404, content={"detail": "Not Found"})


@router.post("/hooks/{secret_path}")
async def handle_webhook(secret_path: str, request: Request) -> Response:
    # -------------------------------------------------------------------------
    # 1. Pre-lookup Gate: Rate Limit per Client IP (429)
    # -------------------------------------------------------------------------
    # 3.6b: use the resolved client IP (set by SecurityMiddleware from X-Forwarded-For when trusted).
    client_ip = getattr(request.state, "client_ip", None) or (request.client.host if request.client else "unknown")
    if not _check_ip_rate_limit(client_ip):
        logger.warning("Webhook IP rate limit exceeded for %s", client_ip)
        return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded"})

    # -------------------------------------------------------------------------
    # 2. Pre-lookup Gate: Content-Type Check (415)
    # -------------------------------------------------------------------------
    content_type = request.headers.get("content-type", "").lower()
    if not (content_type == "application/json" or content_type.startswith("application/json;")):
        logger.warning("Webhook rejected with 415: content-type %r from %s", content_type, client_ip)
        return JSONResponse(
            status_code=415,
            content={"detail": "Unsupported Media Type: Content-Type must be application/json"},
        )

    # -------------------------------------------------------------------------
    # 3. Pre-lookup Gate: Size Check with Content-Length + Read Cap (413)
    # -------------------------------------------------------------------------
    content_length_hdr = request.headers.get("content-length")
    if content_length_hdr and content_length_hdr.isdigit():
        if int(content_length_hdr) > MAX_BODY_BYTES:
            logger.warning("Webhook rejected with 413: Content-Length %s exceeds 1MB", content_length_hdr)
            return JSONResponse(
                status_code=413,
                content={"detail": "Payload Too Large: maximum allowed body size is 1MB"},
            )

    body_bytes = bytearray()
    async for chunk in request.stream():
        body_bytes.extend(chunk)
        if len(body_bytes) > MAX_BODY_BYTES:
            logger.warning("Webhook rejected with 413: streamed body exceeded 1MB")
            return JSONResponse(
                status_code=413,
                content={"detail": "Payload Too Large: maximum allowed body size is 1MB"},
            )

    raw_body = bytes(body_bytes)

    # -------------------------------------------------------------------------
    # 4. Header Validation: X-AgentOS-Signature and X-AgentOS-Timestamp
    # Any format or parsing failure returns the universal 404 response.
    # -------------------------------------------------------------------------
    sig_header = request.headers.get("x-agentos-signature", "").strip()
    ts_header = request.headers.get("x-agentos-timestamp", "").strip()

    if not sig_header or not SIGNATURE_PATTERN.match(sig_header):
        logger.warning("Webhook invalid/missing X-AgentOS-Signature format: %r", sig_header)
        return _generic_not_found()

    if not ts_header or not TIMESTAMP_PATTERN.match(ts_header):
        logger.warning("Webhook invalid/missing X-AgentOS-Timestamp format: %r", ts_header)
        return _generic_not_found()

    timestamp = int(ts_header)
    now = int(time.time())
    if abs(now - timestamp) > 300:
        logger.warning("Webhook stale/future timestamp: %s (now=%s, drift=%s)", timestamp, now, abs(now - timestamp))
        return _generic_not_found()

    # -------------------------------------------------------------------------
    # 5. Path Lookup & Hook Verification
    # -------------------------------------------------------------------------
    path_hash = hashlib.sha256(secret_path.encode("utf-8")).hexdigest()
    storage = request.app.state.storage
    if not storage.webhooks:
        logger.warning("Webhook storage repository not initialized")
        return _generic_not_found()

    webhook = await storage.webhooks.get_by_path_hash(path_hash)
    if not webhook or not webhook.enabled:
        logger.warning("Webhook lookup failed or disabled: path_hash=%s", path_hash)
        return _generic_not_found()

    # -------------------------------------------------------------------------
    # 6. HMAC-SHA256 Signature Verification over Raw Bytes
    # (Verify HMAC first; only valid signatures ever enter the nonce cache)
    # -------------------------------------------------------------------------
    vault = request.app.state.vault
    try:
        secret_key = await vault.reveal(webhook.secret_key_ref)
    except Exception:
        logger.error("Webhook secret key ref %r not found in vault", webhook.secret_key_ref)
        return _generic_not_found()

    signed_payload = ts_header.encode("utf-8") + b"." + raw_body
    expected_hex = hmac.new(secret_key.encode("utf-8"), signed_payload, hashlib.sha256).hexdigest()
    expected_sig = f"sha256={expected_hex}"

    if not hmac.compare_digest(sig_header, expected_sig):
        logger.warning("Webhook signature mismatch on hook %s", webhook.webhook_id)
        return _generic_not_found()

    # -------------------------------------------------------------------------
    # 7. Decode UTF-8 & JSON Parse (Only after HMAC Verification)
    # -------------------------------------------------------------------------
    try:
        payload_str = raw_body.decode("utf-8")
        inputs_data = json.loads(payload_str)
        if not isinstance(inputs_data, dict):
            inputs_data = {"payload": inputs_data}
    except (UnicodeDecodeError, json.JSONDecodeError, Exception) as e:
        logger.warning("Webhook UTF-8 / JSON decode error: %s", e)
        return _generic_not_found()

    # 4.3: the version the webhook's environment points to NOW (resolved once, when the run starts; a later promote
    # or rollback never changes this run). Webhooks from before 4.3 are bound to production.
    from agentos.flows.environments import environment_version

    env_name = getattr(webhook, "environment", None) or "production"
    latest_version = await environment_version(storage, webhook.flow_id, env_name)
    if latest_version is None:
        logger.warning("Webhook %s: flow %s has no version in %s", webhook.webhook_id, webhook.flow_id, env_name)
        return _generic_not_found()

    # -------------------------------------------------------------------------
    # 8. Check-and-Set Nonce Cache (Only Valid & Deliverable Signatures Consume Nonce)
    # -------------------------------------------------------------------------
    nonce_cache = getattr(request.app.state, "nonce_cache", None)
    if nonce_cache:
        nonce_key = f"{path_hash}:{sig_header}"
        is_fresh = await nonce_cache.check_and_set(nonce_key, ttl_s=300)
        if not is_fresh:
            logger.warning("Webhook replay detected for signature %r on path %s", sig_header, path_hash)
            return _generic_not_found()

    # -------------------------------------------------------------------------
    # 9. Execution Ingress: Untrusted Labeling & Queue Enqueue
    # -------------------------------------------------------------------------

    # Full uuid4 run_id
    run_id = f"run_{uuid.uuid4().hex}"

    # Tag payload with Label: Integrity.UNTRUSTED
    # Label is attached to event provenance and execution context
    untrusted_label = Label.untrusted(sources=frozenset({f"webhook:{webhook.webhook_id}"}))

    run_record = RunRecord(
        run_id=run_id,
        mission_name=f"Webhook {webhook.name}",
        flow_id=webhook.flow_id,
        flow_version=latest_version,
        status="queued",
        inputs=inputs_data,
        trigger="webhook",  # 2.4d: display metadata for run history
        environment=env_name,  # 4.3
    )
    await storage.runs.put(run_record)

    await storage.events.append(
        run_id=run_id,
        type="run_started",
        data={
            "inputs": inputs_data,
            "flow_id": webhook.flow_id,
            "version": latest_version,
            "trigger": "webhook",
            "environment": env_name,
            "webhook_id": webhook.webhook_id,
            "security_label": {
                "integrity": untrusted_label.integrity,
                "confidentiality": untrusted_label.confidentiality,
            },
        },
        lease_id=None,
    )

    queue = request.app.state.queue
    await queue.enqueue(
        run_id=run_id,
        flow_id=webhook.flow_id,
        version=latest_version,
        inputs=inputs_data,
    )

    logger.info("Webhook %s enqueued run %s for flow %s v%s", webhook.webhook_id, run_id, webhook.flow_id, latest_version)
    return JSONResponse(status_code=202, content={"run_id": run_id, "status": "queued"})
