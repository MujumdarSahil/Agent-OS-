"""3.5 wasm backend, LIVE (wasm): the real pinned CPython WASI build in wasmtime. The model is not involved.

Needs wasmtime (extra sandbox-wasm) and the pinned build: set AGENTOS_TEST_WASM_BUILD to a downloaded
python-3.12.0.wasm (its sha256 is verified before use). Skips when either is missing, unless AGENTOS_REQUIRE_WASM=1
(CI python-ci job), where it FAILS instead.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
from pathlib import Path

import pytest

from agentos.sandbox import SandboxService, SandboxSettings
from agentos.sandbox.models import SandboxLimits
from agentos.sandbox.wasm_build import WASM_SHA256, WasmBuildError, build_path, install, sha256_file

USECASE = Path(__file__).resolve().parents[2] / "examples" / "usecases" / "12-data-analysis-sandbox"
REQUIRE = os.environ.get("AGENTOS_REQUIRE_WASM") == "1"


def _attacks():
    import sys

    if "uc12_attacks" in sys.modules:
        return sys.modules["uc12_attacks"]
    spec = importlib.util.spec_from_file_location("uc12_attacks", USECASE / "attacks.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["uc12_attacks"] = mod  # dataclasses resolve annotations through sys.modules
    spec.loader.exec_module(mod)
    return mod


def _need_wasm() -> Path:
    src = os.environ.get("AGENTOS_TEST_WASM_BUILD")
    missing = None
    if importlib.util.find_spec("wasmtime") is None:
        missing = "wasmtime is not installed (pip install .[sandbox-wasm])"
    elif not src or not Path(src).is_file():
        missing = "AGENTOS_TEST_WASM_BUILD does not point at the pinned python-3.12.0.wasm"
    if missing:
        if REQUIRE:
            pytest.fail(f"LIVE wasm required (AGENTOS_REQUIRE_WASM=1): {missing}")
        pytest.skip(f"LIVE wasm: {missing}")
    return Path(src)


@pytest.fixture
def wasm_svc(tmp_path):
    src = _need_wasm()
    data = tmp_path / "data"
    install(data, fetch=lambda url, dest: shutil.copyfile(src, dest))  # the same verify-then-move path as a download
    s = SandboxService(data)
    s._settings = SandboxSettings(backend="wasm", limits=SandboxLimits(timeout_s=5))
    return s


@pytest.fixture
def host(tmp_path):
    ctx = _attacks().HostCtx(tmp_path / "host")
    yield ctx
    ctx.close()


def test_tampered_download_refused_and_deleted(tmp_path):
    data = tmp_path / "data"

    def evil_fetch(url, dest):
        Path(dest).write_bytes(b"\0asm-but-not-the-pinned-build")

    with pytest.raises(WasmBuildError, match="hash mismatch"):
        install(data, fetch=evil_fetch)
    assert not build_path(data).exists()
    assert not any((data / "sandbox" / "wasm").glob("*.part"))


def test_tampered_installed_build_is_never_used(tmp_path):
    from agentos.sandbox.models import SandboxUnavailable
    from agentos.sandbox.wasm_backend import WasmBackend

    data = tmp_path / "data"
    build_path(data).parent.mkdir(parents=True)
    build_path(data).write_bytes(b"tampered")
    wb = WasmBackend(data)
    assert wb.status()["build"] == "tampered" and not wb.available()
    with pytest.raises(SandboxUnavailable):
        wb.run("python", "print(1)", {}, SandboxLimits())


def test_benign_statistics(wasm_svc):
    csv = b"value\n3\n5\n7\n9\n"
    res = wasm_svc.run("python", (
        "import csv, statistics, json\n"
        "vals = [float(r['value']) for r in csv.DictReader(open('data.csv'))]\n"
        "out = {'mean': statistics.mean(vals), 'median': statistics.median(vals), 'stdev': statistics.stdev(vals)}\n"
        "open('stats.json', 'w').write(json.dumps(out)); print(json.dumps(out))\n"), {"data.csv": csv})
    assert res.exit_code == 0, res.stderr
    assert res.backend == "wasm" and res.runtime_id == WASM_SHA256
    assert '"mean": 6.0' in res.stdout and "stats.json" in res.files_out and res.limit_hit is None


@pytest.mark.parametrize("name", ["network_exfiltration", "read_host_home", "read_environment",
                                  "write_outside_workspace", "path_traversal_names", "symlink_escape", "fork_bomb",
                                  "memory_bomb", "infinite_loop", "huge_output"])
def test_attack_fails_safely(wasm_svc, host, name):
    kind, code, check = _attacks().scenarios(host)[name]
    res = wasm_svc.run(kind, code, {"data.csv": b"value\n1\n"})
    safe, why = check(res)
    if name == "fork_bomb":
        safe = safe or (res.exit_code not in (0, None) and host.host_unchanged())  # WASI has no fork at all
    assert safe, f"{name}: {why}"


def test_no_orphan_child_after_timeout(wasm_svc):
    psutil = pytest.importorskip("psutil")
    res = wasm_svc.run("python", "while True: pass\n")
    assert res.limit_hit == "timeout"
    me = psutil.Process()
    left = [c for c in me.children(recursive=True) if "_wasm_child" in " ".join(c.cmdline())]
    assert left == []


def test_shell_is_refused_on_wasm(wasm_svc):
    from agentos.sandbox import SandboxUnavailable

    with pytest.raises(SandboxUnavailable, match="shell"):
        wasm_svc.run("shell", "ls /")


def test_build_hash_pin(wasm_svc):
    assert sha256_file(build_path(wasm_svc.data_dir)) == WASM_SHA256
