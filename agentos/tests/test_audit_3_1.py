"""3.1 audit chain (MOCK; the Mongo variants are LIVE: AGENTOS_MONGO_URI, mongo-live CI job).

chain verify; tamper cases (edit, delete, insert, reorder, truncate, wrong key, head forged/removed); restart
continues the chain; 100 parallel appends -> contiguous seq + valid chain (file and Mongo); crash mid-append
leaves a valid chain; an unwritable store raises AuditUnavailable; details refuse secrets/blobs.
"""

from __future__ import annotations

import asyncio
import json
import os
import uuid

import pytest
import pytest_asyncio

from agentos.audit import AuditLog, AuditUnavailable
from agentos.audit.chain import GENESIS, AuditDetailsError, sanitize_details
from agentos.audit.store import FileAuditStore

KEY = bytes(range(32))
OTHER_KEY = bytes(range(1, 33))
MONGO_URI = os.environ.get("AGENTOS_MONGO_URI")


async def _fill(log: AuditLog, n: int) -> None:
    for i in range(n):
        await log.record("flow.save", "flow", f"f{i}", details={"version": i, "nodes": 3})


@pytest_asyncio.fixture(params=["file", "mongo"])
async def make_store(request, tmp_path):
    """Factory returning fresh stores over the same location (to simulate restarts)."""
    if request.param == "file":
        yield lambda: FileAuditStore(str(tmp_path))
        return
    if not MONGO_URI:
        if os.environ.get("AGENTOS_REQUIRE_LIVE_MONGO") == "1":
            pytest.fail("LIVE Mongo required (AGENTOS_MONGO_URI not set)")
        pytest.skip("LIVE: set AGENTOS_MONGO_URI to run the Mongo audit variant")
    from pymongo import AsyncMongoClient

    from agentos.storage.mongo.audit import MongoAuditStore

    client = AsyncMongoClient(MONGO_URI)
    db = client[f"agentos_audit_test_{uuid.uuid4().hex[:10]}"]
    yield lambda: MongoAuditStore(db.audit, db.audit_head)
    await client.drop_database(db.name)
    await client.close()


@pytest.mark.asyncio
async def test_empty_then_ok_and_restart_continues(make_store):
    log = AuditLog(make_store(), KEY)
    assert (await log.verify())["status"] == "empty"
    await _fill(log, 5)
    restarted = AuditLog(make_store(), KEY)  # new process: same store, key from the same master key
    await restarted.record("system.startup", "system", "server", actor="system", source="system",
                           details={"mode": "standalone", "version": "2.0"})
    res = await restarted.verify()
    assert res == {"status": "ok", "entries_checked": 6, "first_broken_seq": None, "reason": None,
                   "partial_tail_ignored": False}
    entries = await restarted.entries()
    assert [e["seq"] for e in entries] == [1, 2, 3, 4, 5, 6] and entries[0]["prev_hash"] == GENESIS


@pytest.mark.asyncio
async def test_wrong_key_breaks_at_seq_1(make_store):
    await _fill(AuditLog(make_store(), KEY), 3)
    res = await AuditLog(make_store(), OTHER_KEY).verify()
    assert res["status"] == "broken" and res["first_broken_seq"] == 1


@pytest.mark.asyncio
async def test_parallel_appends_are_contiguous(make_store):
    log = AuditLog(make_store(), KEY)
    await asyncio.gather(*(log.record("approval.decide", "run", f"r{i}", details={"node": "gate"}) for i in range(100)))
    entries = await log.entries()
    assert [e["seq"] for e in entries] == list(range(1, 101))
    assert (await log.verify())["status"] == "ok"
    if not isinstance(log.store, FileAuditStore):  # Mongo: two independent writers (two "processes") on one collection
        other = AuditLog(make_store(), KEY)
        await asyncio.gather(*(w.record("flow.save", "flow", f"x{i}") for i in range(30) for w in (log, other)))
        assert [e["seq"] for e in await log.entries()] == list(range(1, 161))
        assert (await log.verify())["status"] == "ok"


# ------------------------------------------------------------------ tampering (file store, edited on disk)

def _rewrite(store: FileAuditStore, entries: list[dict]) -> None:
    store.path.write_text("".join(json.dumps(e, sort_keys=True, separators=(",", ":")) + "\n" for e in entries),
                          encoding="utf-8")


async def _tamper_case(tmp_path, mutate) -> dict:
    store = FileAuditStore(str(tmp_path))
    log = AuditLog(store, KEY)
    await _fill(log, 6)
    entries = [json.loads(x) for x in store.path.read_text(encoding="utf-8").splitlines()]
    mutate(store, entries)
    return await AuditLog(FileAuditStore(str(tmp_path)), KEY).verify()


@pytest.mark.asyncio
async def test_edit_detected(tmp_path):
    def edit(store, es):
        es[2]["details"]["version"] = 99
        _rewrite(store, es)
    res = await _tamper_case(tmp_path, edit)
    assert res["status"] == "broken" and res["first_broken_seq"] == 3 and "hash" in res["reason"]


@pytest.mark.asyncio
async def test_delete_detected(tmp_path):
    res = await _tamper_case(tmp_path, lambda store, es: _rewrite(store, es[:3] + es[4:]))
    assert res["status"] == "broken" and res["first_broken_seq"] == 4


@pytest.mark.asyncio
async def test_insert_detected(tmp_path):
    def insert(store, es):
        fake = dict(es[1], details={"version": 1000})
        _rewrite(store, es[:2] + [fake] + es[2:])
    res = await _tamper_case(tmp_path, insert)
    assert res["status"] == "broken" and res["first_broken_seq"] == 3


@pytest.mark.asyncio
async def test_reorder_detected(tmp_path):
    res = await _tamper_case(tmp_path, lambda store, es: _rewrite(store, [es[0], es[2], es[1]] + es[3:]))
    assert res["status"] == "broken" and res["first_broken_seq"] == 2


@pytest.mark.asyncio
async def test_truncate_detected(tmp_path):
    res = await _tamper_case(tmp_path, lambda store, es: _rewrite(store, es[:4]))
    assert res["status"] == "broken" and res["first_broken_seq"] == 5 and "truncated" in res["reason"]


@pytest.mark.asyncio
async def test_truncate_to_empty_and_head_removal_detected(tmp_path):
    res = await _tamper_case(tmp_path, lambda store, es: _rewrite(store, []))
    assert res["status"] == "broken" and "truncated" in res["reason"]

    def drop_head(store, es):
        store.head_path.unlink()
    res2 = await _tamper_case(tmp_path / "b", drop_head)
    assert res2["status"] == "broken" and "head checkpoint is missing" in res2["reason"]


@pytest.mark.asyncio
async def test_forged_head_detected(tmp_path):
    def forge(store, es):
        _rewrite(store, es[:4])
        store.head_path.write_text(json.dumps({"seq": 4, "hash": es[3]["hash"], "mac": "0" * 64}), encoding="utf-8")
    res = await _tamper_case(tmp_path, forge)
    assert res["status"] == "broken" and "MAC" in res["reason"]


# ------------------------------------------------------------------ crash mid-append, fail closed, details

@pytest.mark.asyncio
async def test_crash_mid_append_leaves_a_valid_chain(tmp_path):
    store = FileAuditStore(str(tmp_path))
    log = AuditLog(store, KEY)
    await _fill(log, 3)
    with open(store.path, "ab") as f:  # a write cut off by a crash: half a line, no newline
        f.write(b'{"seq":4,"ts":"2026-11-19T00:00:00')
    fresh = AuditLog(FileAuditStore(str(tmp_path)), KEY)
    res = await fresh.verify()
    assert res["status"] == "ok" and res["entries_checked"] == 3 and res["partial_tail_ignored"] is True
    await fresh.record("flow.publish", "flow", "f", details={"version": 1})  # the next append repairs the tail
    res2 = await fresh.verify()
    assert res2["status"] == "ok" and res2["entries_checked"] == 4 and res2["partial_tail_ignored"] is False


@pytest.mark.asyncio
async def test_unwritable_store_raises(tmp_path):
    store = FileAuditStore(str(tmp_path))
    store.dir.mkdir(parents=True)
    store.path.mkdir()  # audit.jsonl is a directory: not writable
    with pytest.raises(AuditUnavailable):
        await AuditLog(store, KEY).record("flow.save", "flow", "f")


@pytest.mark.parametrize("details", [
    {"key": "sk-test-0123456789abcdef"},
    {"auth": "Bearer abcdefghijklmnop"},
    {"note": "password=hunter2"},
    {"blob": "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9w"},
    {"text": "x" * 301},
    {"nested": {"a": {"b": {"c": 1}}}},
    {"obj": object()},
    {"canary": "AGENTOS-CANARY-1234"},
])
def test_details_refuse_secrets_and_payloads(details):
    with pytest.raises(AuditDetailsError):
        sanitize_details(details)


def test_details_accept_metadata_and_digests():
    ok = {"version": 3, "rules": ["send_email.to"], "config_sha256": "ab" * 32, "names": ["oncall"], "count": 2}
    assert sanitize_details(ok) == ok


@pytest.mark.asyncio
async def test_bad_details_fail_closed_and_write_nothing(tmp_path):
    log = AuditLog(FileAuditStore(str(tmp_path)), KEY)
    with pytest.raises(AuditUnavailable):
        await log.record("vault.secret.set", "secret", "openai", details={"value": "sk-live-abcdefghijkl"})
    assert await log.entries() == []


def test_key_is_never_in_repr():
    log = AuditLog(FileAuditStore("."), KEY)
    assert KEY.hex() not in repr(log) and "key" not in repr(log).lower()


def test_cli_verify_and_export(tmp_path, monkeypatch):
    """`agentos audit verify|export` read the same store with the same master key as the server."""
    import base64

    from typer.testing import CliRunner

    from agentos.cli.main import app as cli_app

    master = bytes(range(32))
    monkeypatch.setenv("AGENTOS_MASTER_KEY", base64.b64encode(master).decode())
    monkeypatch.setenv("AGENTOS_STORAGE", "file")
    from agentos.audit import audit_anchor_for
    from agentos.storage.file import open_file_storage

    # like the server: with the independent anchor (3.2), which the CLI checks too
    log = AuditLog(FileAuditStore(str(tmp_path)), master, anchor=audit_anchor_for(open_file_storage(str(tmp_path))))
    asyncio.run(_fill(log, 4))
    runner = CliRunner()
    ok = runner.invoke(cli_app, ["audit", "verify", "--project", str(tmp_path)])
    assert ok.exit_code == 0 and '"status": "ok"' in ok.output and '"entries_checked": 4' in ok.output
    out = tmp_path / "export.jsonl"
    exp = runner.invoke(cli_app, ["audit", "export", "--project", str(tmp_path), "--out", str(out)])
    assert exp.exit_code == 0 and [json.loads(x)["seq"] for x in out.read_text(encoding="utf-8").splitlines()] == [1, 2, 3, 4]
    # tamper -> verify exits 1 and names the broken seq
    store = FileAuditStore(str(tmp_path))
    lines = store.path.read_text(encoding="utf-8").splitlines()
    store.path.write_text("\n".join(lines[:1] + lines[2:]) + "\n", encoding="utf-8")
    bad = runner.invoke(cli_app, ["audit", "verify", "--project", str(tmp_path)])
    assert bad.exit_code == 1 and '"first_broken_seq": 2' in bad.output
