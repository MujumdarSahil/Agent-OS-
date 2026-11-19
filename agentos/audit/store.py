"""Audit stores (3.1): the append-only file store (Standalone); the Mongo store is in agentos/storage/mongo. They hold entries and the head
checkpoint; they never see the key (the builder callback computes hashes). Design: docs/evidence/3.1.md.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any, Callable

from agentos.audit.chain import AuditUnavailable
from agentos.storage.atomic import atomic_write_text

Builder = Callable[[dict[str, Any] | None], tuple[dict[str, Any], dict[str, Any]]]


def _line(entry: dict[str, Any]) -> bytes:
    return (json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


class FileAuditStore:
    """``<project>/.agentos/audit/audit.jsonl`` (append-only) + ``head.json`` (atomic). One writer lock.

    Each append: one line, flush + fsync, then the head checkpoint (atomic write). A trailing line without a
    newline (or not valid JSON) is a crashed, unacknowledged append: readers ignore it and the next append cuts
    it off before writing (the audited action was never applied, because the entry is written first).
    """

    def __init__(self, project_path: str) -> None:
        self.dir = Path(project_path) / ".agentos" / "audit"
        self.path = self.dir / "audit.jsonl"
        self.head_path = self.dir / "head.json"
        self._lock = asyncio.Lock()
        self._last: dict[str, Any] | None = None
        self._loaded = False

    # ------------------------------------------------------------------ reading
    def _scan(self) -> tuple[list[Any], bool, int]:
        """(entries, partial_tail, good_bytes). A malformed line in the middle stays in the list (as None) so
        verification reports it; only an incomplete LAST line is treated as an unacknowledged append."""
        if not self.path.exists():
            return [], False, 0
        data = self.path.read_bytes()
        entries: list[Any] = []
        pos = 0
        lines = data.split(b"\n")
        for i, raw in enumerate(lines):
            last = i == len(lines) - 1
            if last:
                if raw.strip():
                    return entries, True, pos  # no trailing newline: crashed mid-append
                return entries, False, pos
            try:
                entries.append(json.loads(raw.decode("utf-8")))
            except (ValueError, UnicodeDecodeError):
                if i == len(lines) - 2 and not lines[-1]:
                    return entries, True, pos  # last complete-looking line is garbage: crashed mid-append
                entries.append(None)
            pos += len(raw) + 1
        return entries, False, pos

    async def read_all(self) -> tuple[list[Any], bool]:
        entries, partial, _ = self._scan()
        return entries, partial

    async def read_head(self) -> dict[str, Any] | None:
        if not self.head_path.exists():
            return None
        try:
            return json.loads(self.head_path.read_text(encoding="utf-8"))
        except ValueError:
            return {"seq": None, "hash": None, "mac": None}

    # ------------------------------------------------------------------ writing
    def _load(self) -> None:
        entries, partial, good = self._scan()
        if partial:
            with open(self.path, "r+b") as f:
                f.truncate(good)
                f.flush()
                os.fsync(f.fileno())
        valid = [e for e in entries if isinstance(e, dict)]
        self._last = valid[-1] if valid else None
        self._loaded = True

    async def append(self, build: Builder) -> dict[str, Any]:
        async with self._lock:
            try:
                self.dir.mkdir(parents=True, exist_ok=True)
                if not self._loaded:
                    self._load()
                entry, head = build(self._last)
                with open(self.path, "ab") as f:
                    f.write(_line(entry))
                    f.flush()
                    os.fsync(f.fileno())
                atomic_write_text(self.head_path, json.dumps(head, sort_keys=True) + "\n")
            except AuditUnavailable:
                raise
            except Exception as e:  # not writable, disk full, ...: the action must not be applied
                self._loaded = False
                raise AuditUnavailable(f"audit log not writable ({type(e).__name__})") from None
            self._last = entry
            return entry


# The Mongo store lives in agentos/storage/mongo/audit.py (only the Mongo adapter imports pymongo, and
# Standalone installs need not have it).
