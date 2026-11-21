"""3.5 Docker backend, LIVE (docker): real containers. The model is not involved.

Locally these skip when Docker is not running. In the CI job `sandbox-docker` AGENTOS_REQUIRE_DOCKER=1 makes them FAIL
instead of skipping when Docker is missing.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from agentos.sandbox import SandboxService, SandboxSettings
from agentos.sandbox.docker_backend import LABEL, DockerBackend
from agentos.sandbox.models import DEFAULT_IMAGE, SandboxLimits

USECASE = Path(__file__).resolve().parents[2] / "examples" / "usecases" / "12-data-analysis-sandbox"
REQUIRE = os.environ.get("AGENTOS_REQUIRE_DOCKER") == "1"


def _attacks():
    if "uc12_attacks" in sys.modules:
        return sys.modules["uc12_attacks"]
    spec = importlib.util.spec_from_file_location("uc12_attacks", USECASE / "attacks.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["uc12_attacks"] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def docker():
    d = DockerBackend()
    st = d.status(refresh=True)
    if not st["available"]:
        if REQUIRE:
            pytest.fail(f"LIVE Docker required (AGENTOS_REQUIRE_DOCKER=1): {st.get('detail')}")
        pytest.skip(f"LIVE docker: {st.get('detail')}")
    d.ensure_image(DEFAULT_IMAGE)
    return d


@pytest.fixture
def svc(docker, tmp_path):
    s = SandboxService(tmp_path / "data", docker=docker)
    s._settings = SandboxSettings(backend="docker", limits=SandboxLimits(timeout_s=8))
    return s


@pytest.fixture
def host(tmp_path):
    ctx = _attacks().HostCtx(tmp_path / "host")
    yield ctx
    ctx.close()


def _leftovers() -> list[str]:
    r = subprocess.run(["docker", "ps", "-aq", "--filter", f"label={LABEL}=1"], capture_output=True, text=True,
                       timeout=30)
    return r.stdout.split()


def test_benign_statistics_and_container_removed(svc):
    res = svc.run("python", (
        "import csv, statistics, json\n"
        "vals = [float(r['value']) for r in csv.DictReader(open('data.csv'))]\n"
        "out = {'mean': statistics.mean(vals), 'median': statistics.median(vals)}\n"
        "open('stats.json', 'w').write(json.dumps(out)); print(json.dumps(out))\n"),
        {"data.csv": b"value\n3\n5\n7\n9\n"})
    assert res.exit_code == 0, (res.stderr, res.error)
    assert res.backend == "docker" and res.runtime_id == DEFAULT_IMAGE.split("@", 1)[1]
    assert '"mean": 6.0' in res.stdout and "stats.json" in res.files_out and "data.csv" in res.files_out
    assert _leftovers() == []


def test_isolation_inside_the_container(svc):
    res = svc.run("python", (
        "import os, json\n"
        "info = {'uid': os.getuid(), 'gid': os.getgid(), 'cwd': os.getcwd(),\n"
        "        'docker_sock': os.path.exists('/var/run/docker.sock') or os.path.exists('/run/docker.sock'),\n"
        "        'env': sorted(os.environ)}\n"
        "try:\n"
        "    open('/etc/agentos-ro-test', 'w'); info['root_writable'] = True\n"
        "except OSError as e:\n"
        "    info['root_writable'] = False\n"
        "info['caps'] = [l.split()[1] for l in open('/proc/self/status') if l.startswith('CapEff')][0]\n"
        "info['nnp'] = [l.split()[1] for l in open('/proc/self/status') if l.startswith('NoNewPrivs')][0]\n"
        "info['seccomp'] = [l.split()[1] for l in open('/proc/self/status') if l.startswith('Seccomp:')][0]\n"
        "info['mounts'] = [l.split()[1] for l in open('/proc/self/mounts')]\n"
        "info['ifaces'] = sorted(os.listdir('/sys/class/net'))\n"
        "print(json.dumps(info))\n"))
    assert res.exit_code == 0, (res.stderr, res.error)
    info = json.loads(res.stdout.strip().splitlines()[-1])
    assert info["uid"] == 65534 and info["gid"] == 65534  # non-root
    assert info["root_writable"] is False  # read-only root filesystem
    assert info["docker_sock"] is False  # no Docker socket
    assert int(info["caps"], 16) == 0  # --cap-drop ALL
    assert info["nnp"] == "1"  # no-new-privileges
    assert info["seccomp"] == "2"  # default seccomp filter active
    assert info["ifaces"] == ["lo"]  # --network none
    assert info["cwd"] == "/workspace"
    assert not [k for k in info["env"] if k not in {"PATH", "HOME", "LANG", "PYTHONDONTWRITEBYTECODE", "PWD",
                                                    "LC_CTYPE"}]
    host_paths = [m for m in info["mounts"] if m.startswith(("/home", "/Users", "/mnt", "/var/run", "/root"))]
    assert host_paths == []  # no host folder is mounted (workspace and /tmp are tmpfs)


def test_container_settings_from_docker_inspect(docker, monkeypatch):
    """Run a container that sleeps, inspect it from the host, then make sure it is gone."""
    from agentos.sandbox import docker_backend as db

    seen = {}
    real_run = db._run

    def spy(args, timeout, data=None):
        if args[:2] == ["docker", "inspect"] and "--format" in args:
            name = args[-1]
            full = real_run(["docker", "inspect", name], timeout=30)
            seen.update(json.loads(full.stdout.decode("utf-8"))[0])
        return real_run(args, timeout, data)

    monkeypatch.setattr(db, "_run", spy)
    res = docker.run("python", "print('hi')", {}, SandboxLimits(timeout_s=8), run_label="inspect",
                     image=DEFAULT_IMAGE)
    assert res.exit_code == 0
    hc = seen["HostConfig"]
    assert hc["NetworkMode"] == "none" and hc["ReadonlyRootfs"] is True and hc["Privileged"] is False
    assert hc["CapDrop"] == ["ALL"] and not hc.get("CapAdd")
    assert "no-new-privileges" in (hc.get("SecurityOpt") or [])[0]
    assert not any("unconfined" in s for s in (hc.get("SecurityOpt") or []))
    assert hc["PidsLimit"] == 64 and hc["Memory"] == 512 * 1024 * 1024 and hc["MemorySwap"] == hc["Memory"]
    assert hc["NanoCpus"] == 1_000_000_000
    assert not hc.get("Binds") and not seen.get("Mounts")  # no host path, no socket
    assert seen["Config"]["User"] == "65534:65534"
    assert _leftovers() == []


@pytest.mark.parametrize("name", ["network_exfiltration", "read_host_home", "read_environment",
                                  "write_outside_workspace", "path_traversal_names", "symlink_escape", "fork_bomb",
                                  "memory_bomb", "infinite_loop", "huge_output"])
def test_attack_fails_safely(svc, host, name):
    kind, code, check = _attacks().scenarios(host)[name]
    res = svc.run(kind, code, {"data.csv": b"value\n1\n"})
    safe, why = check(res)
    assert safe, f"{name}: {why} (stdout={res.stdout[:300]!r}, error={res.error})"
    assert _leftovers() == []


def test_symlinks_are_refused_on_copy_out(svc):
    res = svc.run("python", "import os\nos.symlink('/etc/passwd', 'pw')\nopen('ok.txt','w').write('x')\n")
    assert "pw" not in res.files_out and "ok.txt" in res.files_out
    assert any("symlink refused" in r for r in res.refused_files)


def test_shell_runs_only_in_docker_and_fork_bomb_is_contained(svc):
    res = svc.run("shell", "echo $((6*7)); id -u")
    assert res.exit_code == 0 and res.stdout.split()[:2] == ["42", "65534"]
    kind, code, _ = _attacks().SHELL_ONLY["shell_fork_bomb"]
    bomb = svc.run(kind, code)
    assert bomb.limit_hit in ("pids", "timeout") or bomb.exit_code != 0
    assert _leftovers() == []


def test_limits_are_reported(svc):
    assert svc.run("python", "while True: pass\n").limit_hit == "timeout"
    assert svc.run("python", "x = bytearray(900 * 1024 * 1024)\nx[::4096] = b'1' * len(x[::4096])\n").limit_hit == "memory"
    out = svc.run("python", "print('A' * 300000)\n")
    assert out.limit_hit == "output" and out.stdout_truncated and len(out.stdout) <= 100 * 1024
    big = svc.run("python", "open('big.bin','wb').write(b'0' * (60 * 1024 * 1024))\n")
    assert big.files_out == {} and (big.limit_hit in ("workspace",) or big.exit_code != 0)
    assert _leftovers() == []
