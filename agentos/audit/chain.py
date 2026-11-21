"""Tamper-evident audit chain (3.1). Pure functions: key derivation, canonical JSON, entry hashing, the head
checkpoint MAC, the details sanitizer and chain verification. Design: docs/evidence/3.1.md.

hash = HMAC-SHA256(K, canonical_json(entry without "hash")), canonical = sorted keys, no whitespace, UTF-8.
K = HKDF-SHA256(master key, salt b"agentos-audit", info b"agentos-audit-v1"). K is never stored or logged.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from typing import Any, Iterable

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

GENESIS = "0" * 64
HKDF_SALT = b"agentos-audit"
HKDF_INFO = b"agentos-audit-v1"
SOURCES = ("ui", "api", "cli", "system", "webhook", "scheduler")
OUTCOMES = ("ok", "refused", "failed")
ACTION_RE = re.compile(r"^[a-z0-9_]+(\.[a-z0-9_]+)+$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
FIELDS = ("seq", "ts", "actor", "source", "action", "target", "outcome", "details", "prev_hash", "hash")

MAX_STR = 300
MAX_LIST = 50
_DIGEST_KEYS = ("sha256", "hash", "fingerprint", "digest")
# Anything that looks like a credential or key material is refused in details (metadata only).
_SECRET_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9_\-]{8,}"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{8,}"),
    re.compile(r"-----BEGIN [A-Z ]*(PRIVATE )?KEY-----"),
    re.compile(r"(?i)\b(password|passwd|secret|api[_-]?key|token)\s*[=:]\s*\S+"),
    re.compile(r"AGENTOS-CANARY"),
]
_LONG_OPAQUE = re.compile(r"[A-Za-z0-9+/_=\-]{40,}")


class AuditUnavailable(RuntimeError):
    """The audit entry could not be written: the audited action must not be applied (fail closed)."""


class AuditDetailsError(ValueError):
    """details contained something other than metadata (a programming error; fails closed)."""


def derive_key(master_key: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=HKDF_SALT, info=HKDF_INFO).derive(master_key)


def canonical(body: dict[str, Any]) -> bytes:
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def entry_hash(key: bytes, entry: dict[str, Any]) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    return hmac.new(key, canonical(body), hashlib.sha256).hexdigest()


def head_mac(key: bytes, seq: int, h: str) -> str:
    return hmac.new(key, f"head|{seq}|{h}".encode("ascii"), hashlib.sha256).hexdigest()


def make_head(key: bytes, entry: dict[str, Any]) -> dict[str, Any]:
    return {"seq": entry["seq"], "hash": entry["hash"], "mac": head_mac(key, entry["seq"], entry["hash"])}


def anchor_mac(key: bytes, seq: int, h: str) -> str:
    """3.2 (0a): MAC of the independent anchor (a different prefix: a head cannot be replayed as an anchor)."""
    return hmac.new(key, f"anchor|{seq}|{h}".encode("ascii"), hashlib.sha256).hexdigest()


def make_anchor(key: bytes, entry: dict[str, Any]) -> dict[str, Any]:
    return {"seq": entry["seq"], "hash": entry["hash"], "mac": anchor_mac(key, entry["seq"], entry["hash"])}


def check_anchor(result: dict[str, Any], entries: list[Any], head: dict[str, Any] | None,
                 anchor: dict[str, Any] | None, key: bytes) -> dict[str, Any]:
    """3.2 (0a): the independent anchor (kept in the main storage, not the audit folder) catches a deleted or
    rolled-back log that would otherwise verify as "empty" or as a shorter valid chain."""
    log_present = bool(entries) or head is not None
    if anchor is None:
        if log_present:
            return _broken(1, result.get("entries_checked", 0), "audit anchor missing")
        return result  # nothing anywhere: a fresh install
    if not (isinstance(anchor.get("seq"), int) and isinstance(anchor.get("hash"), str)
            and isinstance(anchor.get("mac"), str)
            and hmac.compare_digest(anchor_mac(key, anchor["seq"], anchor["hash"]), anchor["mac"])):
        return _broken(1, result.get("entries_checked", 0), "audit anchor is invalid")
    n = anchor["seq"]
    if result["status"] == "broken" and entries:
        return result  # the chain itself breaks earlier: keep that more specific seq and reason
    good = [e for e in entries if isinstance(e, dict)]
    if len(good) < n or good[n - 1].get("hash") != anchor["hash"]:
        return _broken(n, result.get("entries_checked", 0), f"audit log deleted or rolled back (anchor at seq {n})")
    return result


def _check_str(key: str, value: str) -> None:
    if len(value) > MAX_STR:
        raise AuditDetailsError(f"details[{key!r}] is longer than {MAX_STR} characters")
    for p in _SECRET_PATTERNS:
        if p.search(value):
            raise AuditDetailsError(f"details[{key!r}] looks like a secret value")
    if not key.lower().endswith(_DIGEST_KEYS) and _LONG_OPAQUE.search(value):
        raise AuditDetailsError(f"details[{key!r}] contains an opaque blob (possible key material)")


def sanitize_details(details: dict[str, Any] | None, _depth: int = 0) -> dict[str, Any]:
    """Return details unchanged if they are metadata only, else raise AuditDetailsError."""
    if details is None:
        return {}
    if not isinstance(details, dict):
        raise AuditDetailsError("details must be an object")
    out: dict[str, Any] = {}
    for k, v in details.items():
        if not isinstance(k, str) or len(k) > 64:
            raise AuditDetailsError("details keys must be short strings")
        out[k] = _sanitize_value(k, v, _depth)
    return out


def _sanitize_value(key: str, v: Any, depth: int) -> Any:
    if v is None or isinstance(v, bool) or isinstance(v, int):
        return v
    if isinstance(v, float):
        return v
    if isinstance(v, str):
        _check_str(key, v)
        return v
    if isinstance(v, (list, tuple)):
        if depth >= 2 or len(v) > MAX_LIST:
            raise AuditDetailsError(f"details[{key!r}] list is too deep or too long")
        return [_sanitize_value(key, x, depth + 1) for x in v]
    if isinstance(v, dict):
        if depth >= 2:
            raise AuditDetailsError(f"details[{key!r}] is nested too deeply")
        return sanitize_details(v, depth + 1)
    raise AuditDetailsError(f"details[{key!r}] has an unsupported type {type(v).__name__}")


def build_entry(key: bytes, prev: dict[str, Any] | None, *, ts: str, actor: str, source: str, action: str,
                target_type: str, target_id: str, outcome: str, details: dict[str, Any]) -> dict[str, Any]:
    if source not in SOURCES:
        raise AuditDetailsError(f"unknown audit source {source!r}")
    if outcome not in OUTCOMES:
        raise AuditDetailsError(f"unknown audit outcome {outcome!r}")
    if not ACTION_RE.fullmatch(action):
        raise AuditDetailsError(f"invalid audit action {action!r}")
    entry = {
        "seq": (prev["seq"] + 1) if prev else 1,
        "ts": ts,
        "actor": actor,
        "source": source,
        "action": action,
        "target": {"type": str(target_type)[:64], "id": str(target_id)[:200]},
        "outcome": outcome,
        "details": sanitize_details(details),
        "prev_hash": prev["hash"] if prev else GENESIS,
    }
    entry["hash"] = entry_hash(key, entry)
    return entry


def _schema_ok(e: Any) -> bool:
    return (
        isinstance(e, dict) and set(e) == set(FIELDS)
        and isinstance(e["seq"], int) and not isinstance(e["seq"], bool)
        and isinstance(e["target"], dict) and set(e["target"]) == {"type", "id"}
        and e["source"] in SOURCES and e["outcome"] in OUTCOMES and isinstance(e["action"], str)
        and isinstance(e["details"], dict)
        and isinstance(e["prev_hash"], str) and HEX64.fullmatch(e["prev_hash"]) is not None
        and isinstance(e["hash"], str) and HEX64.fullmatch(e["hash"]) is not None
    )


def _broken(seq: int, checked: int, reason: str) -> dict[str, Any]:
    return {"status": "broken", "entries_checked": checked, "first_broken_seq": seq, "reason": reason}


def verify_chain(entries: Iterable[Any], head: dict[str, Any] | None, key: bytes,
                 partial_tail_ignored: bool = False) -> dict[str, Any]:
    """Walk the chain. Reports the first broken seq; detects edit, delete, insert, reorder, truncation, wrong key."""
    entries = list(entries)
    expected_prev = GENESIS
    checked = 0
    for i, e in enumerate(entries, start=1):
        if not _schema_ok(e):
            return _broken(i, checked, "entry is malformed")
        if e["seq"] != i:
            return _broken(i, checked, f"expected seq {i}, found {e['seq']} (entry deleted, inserted or reordered)")
        if e["prev_hash"] != expected_prev:
            return _broken(i, checked, "prev_hash does not match the previous entry")
        if not hmac.compare_digest(entry_hash(key, e), e["hash"]):
            return _broken(i, checked, "hash mismatch (entry edited, or the wrong key)")
        expected_prev = e["hash"]
        checked = i
    n = len(entries)
    if head is None:
        if n:
            return _broken(n, checked, "head checkpoint is missing")
        return {"status": "empty", "entries_checked": 0, "first_broken_seq": None, "reason": None,
                "partial_tail_ignored": partial_tail_ignored}
    if not (isinstance(head.get("seq"), int) and isinstance(head.get("hash"), str) and isinstance(head.get("mac"), str)):
        return _broken(min(n, 1) or 1, checked, "head checkpoint is malformed")
    if not hmac.compare_digest(head_mac(key, head["seq"], head["hash"]), head["mac"]):
        return _broken(max(head["seq"], 1), checked, "head checkpoint MAC is invalid")
    if head["seq"] > n:
        return _broken(n + 1, checked, f"log truncated: head checkpoint is at seq {head['seq']}, log ends at {n}")
    if head["seq"] >= 1 and entries[head["seq"] - 1]["hash"] != head["hash"]:
        return _broken(head["seq"], checked, "entry does not match the head checkpoint")
    return {"status": "ok", "entries_checked": checked, "first_broken_seq": None, "reason": None,
            "partial_tail_ignored": partial_tail_ignored}
