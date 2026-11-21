"""Docker backend: the strongest isolation and the only one for shell (3.5, D4).

Docker CLI through argument lists (never a shell). Container settings: --network none, read-only root filesystem,
tmpfs /tmp and a tmpfs /workspace (size-capped; no host path is mounted at all), --cap-drop ALL,
no-new-privileges, non-root user 65534, pids / memory (= swap) / cpu limits, default seccomp, no Docker socket.
Files go in and out as a tar stream on stdin / stdout through an AgentOS-written bootstrap running as PID 1.
The container is always removed (``docker rm -f`` in ``finally``); leftovers are swept at server start.
"""

from __future__ import annotations

import base64
import json
import secrets
import shutil
import subprocess
import threading
import time
from typing import Any, Optional

from agentos.sandbox import paths
from agentos.sandbox.models import SandboxLimits, SandboxResult, SandboxUnavailable

LABEL = "agentos.sandbox"
MARKER = "AGENTOS-SANDBOX-RESULT "
MIN_DOCKER = (24, 0)
SANDBOX_UID = "65534:65534"

# Runs inside the container as PID 1 (non-root). Unpacks the workspace from stdin, runs the user's code as a child
# with an explicit minimal environment, then prints ONE result line. Its output is untrusted like any tool output;
# the limits that matter (time, memory, pids, sizes) are enforced by Docker and the host.
BOOTSTRAP = r'''
import base64, io, json, os, subprocess, sys, tarfile
spec = json.loads(sys.argv[1])
raw = sys.stdin.buffer.read(spec["in_cap"] + 1)
os.chdir("/workspace")
payload = b""
with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as tf:
    for m in tf:
        parts = m.name.split("/")
        if not m.isreg() or m.name.startswith("/") or ".." in parts:
            continue
        data = tf.extractfile(m).read()
        if m.name == ".agentos_payload":
            payload = data
            continue
        if len(parts) > 1:
            os.makedirs("/".join(parts[:-1]), exist_ok=True)
        with open(m.name, "wb") as fh:
            fh.write(data)
with open("/tmp/.p", "wb") as fh:
    fh.write(payload)
argv = ["python3", "-I", "/tmp/.p"] if spec["kind"] == "python" else ["sh", "/tmp/.p"]
env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/tmp", "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1"}
out, err = open("/tmp/.o", "wb"), open("/tmp/.e", "wb")
limit = None
try:
    p = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=out, stderr=err, cwd="/workspace", env=env)
    try:
        rc = p.wait(timeout=spec["timeout"])
    except subprocess.TimeoutExpired:
        p.kill()
        rc = p.wait()
        limit = "timeout"
except OSError as e:
    rc, limit = 127, ("pids" if getattr(e, "errno", 0) == 11 else None)
out.close(); err.close()
def cap(path, n):
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as fh:
            return fh.read(n).decode("utf-8", "replace"), size > n
    except OSError:
        return "", False
so, so_t = cap("/tmp/.o", spec["out_cap"])
se, se_t = cap("/tmp/.e", spec["err_cap"])
def events(name, key):
    try:
        for line in open("/sys/fs/cgroup/" + name):
            k, v = line.split()
            if k == key:
                return int(v)
    except Exception:
        return 0
    return 0
if limit is None and events("pids.events", "max") > 0:
    limit = "pids"
if limit is None and events("memory.events", "oom_kill") > 0:
    limit = "memory"
if limit is None and (so_t or se_t):
    limit = "output"
buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode="w:") as tf:
    for root, dirs, files in os.walk("/workspace", followlinks=False):
        for name in dirs + files:
            full = os.path.join(root, name)
            if os.path.isdir(full) and not os.path.islink(full):
                continue
            try:
                tf.add(full, arcname=os.path.relpath(full, "/workspace"), recursive=False)
            except OSError:
                pass
sys.stdout.write("AGENTOS-SANDBOX-RESULT " + json.dumps({"rc": rc, "limit": limit, "stdout": so, "stderr": se,
    "stdout_truncated": so_t, "stderr_truncated": se_t, "tar": base64.b64encode(buf.getvalue()).decode()}) + "\n")
sys.stdout.flush()
'''


def docker_cli() -> Optional[str]:
    return shutil.which("docker")


def _run(args: list[str], timeout: float, data: Optional[bytes] = None) -> subprocess.CompletedProcess:
    return subprocess.run(args, input=data, capture_output=True, timeout=timeout)


def container_args(name: str, image: str, limits: SandboxLimits, run_label: str, spec: dict[str, Any]) -> list[str]:
    """The exact `docker create` argument list (tested: no host mounts, no socket, every isolation flag)."""
    mem = f"{limits.memory_mb}m"
    return [
        "docker", "create", "-i", "--name", name,
        "--network", "none",
        "--read-only",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--user", SANDBOX_UID,
        "--pids-limit", str(limits.pids),
        "--memory", mem, "--memory-swap", mem,
        "--cpus", f"{limits.cpus:g}",
        "--ulimit", "nofile=256:256",
        "--ipc", "private",
        "--hostname", "sandbox",
        "--tmpfs", "/tmp:rw,size=16m,noexec,nosuid,nodev",
        "--tmpfs", f"/workspace:rw,size={limits.workspace_mb}m,nosuid,nodev,uid=65534,gid=65534,mode=0700",
        "--workdir", "/workspace",
        "--label", f"{LABEL}=1", "--label", f"agentos.run={run_label[:60] or 'adhoc'}",
        "--entrypoint", "python3",
        image, "-I", "-S", "-c", BOOTSTRAP, json.dumps(spec),
    ]


class DockerBackend:
    name = "docker"
    kinds = ("python", "shell")

    def __init__(self) -> None:
        self._status: Optional[dict[str, Any]] = None
        self._status_at = 0.0

    def status(self, refresh: bool = False) -> dict[str, Any]:
        if self._status is not None and not refresh and time.monotonic() - self._status_at < 30:
            return self._status
        st: dict[str, Any] = {"available": False, "client": None, "server": None, "kinds": list(self.kinds)}
        if docker_cli() is None:
            st["detail"] = "the docker CLI is not installed"
        else:
            try:
                r = _run(["docker", "version", "--format", "{{json .}}"], timeout=10)
                info = json.loads(r.stdout.decode("utf-8") or "{}") if r.stdout else {}
                st["client"] = (info.get("Client") or {}).get("Version")
                st["server"] = (info.get("Server") or {}).get("Version") if info.get("Server") else None
                if not st["server"]:
                    st["detail"] = "the Docker daemon is not running (start Docker Desktop / dockerd)"
                elif _version_tuple(st["server"]) < MIN_DOCKER:
                    st["detail"] = f"Docker {st['server']} is too old (need >= {MIN_DOCKER[0]}.{MIN_DOCKER[1]})"
                else:
                    st["available"], st["detail"] = True, "ready"
            except (subprocess.TimeoutExpired, ValueError, OSError) as e:
                st["detail"] = f"docker did not answer ({type(e).__name__})"
        self._status, self._status_at = st, time.monotonic()
        return st

    def available(self) -> bool:
        return bool(self.status()["available"])

    def ensure_image(self, image: str) -> None:
        if _run(["docker", "image", "inspect", image], timeout=30).returncode == 0:
            return
        r = _run(["docker", "pull", image], timeout=600)
        if r.returncode != 0:
            raise SandboxUnavailable(f"could not pull the allowlisted image {image} "
                                     f"({r.stderr.decode('utf-8', 'replace')[-200:].strip()})")

    def run(self, kind: str, payload: str, files_in: dict[str, bytes], limits: SandboxLimits,
            run_label: str = "", image: str = "") -> SandboxResult:
        if kind not in self.kinds:
            raise SandboxUnavailable(f"unknown sandbox kind {kind!r}")
        if not image:
            raise SandboxUnavailable("no allowlisted image configured")
        if not self.available():
            raise SandboxUnavailable(f"Docker is not available: {self.status().get('detail')}")
        self.ensure_image(image)
        tar = paths.make_tar(files_in, extra=[(".agentos_payload", payload.encode("utf-8"))])
        spec = {"kind": kind, "timeout": limits.timeout_s, "out_cap": limits.stdout_bytes,
                "err_cap": limits.stderr_bytes, "in_cap": len(tar)}
        name = f"agentos-sbx-{secrets.token_hex(8)}"
        started = time.monotonic()
        result_cap = limits.workspace_bytes * 2 + limits.stdout_bytes * 4 + limits.stderr_bytes * 4 + (1 << 20)
        killed = {"timeout": False}
        try:
            c = _run(container_args(name, image, limits, run_label, spec), timeout=120)
            if c.returncode != 0:
                raise SandboxUnavailable("docker could not create the sandbox container "
                                         f"({c.stderr.decode('utf-8', 'replace')[-200:].strip()})")
            proc = subprocess.Popen(["docker", "start", "-ai", name], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
            chunks: list[bytes] = []
            size = [0]

            def reader() -> None:
                assert proc.stdout is not None
                while True:
                    b = proc.stdout.read(1 << 16)
                    if not b:
                        return
                    if size[0] < result_cap:
                        chunks.append(b[: result_cap - size[0]])
                    size[0] += len(b)

            t = threading.Thread(target=reader, daemon=True)
            t.start()
            try:
                assert proc.stdin is not None
                proc.stdin.write(tar)
                proc.stdin.close()
            except (BrokenPipeError, OSError):
                pass

            def kill() -> None:
                killed["timeout"] = True
                _run(["docker", "kill", name], timeout=30)

            timer = threading.Timer(limits.timeout_s + 15, kill)  # backstop; the bootstrap enforces the limit first
            timer.start()
            try:
                proc.wait(timeout=limits.timeout_s + 60)
            except subprocess.TimeoutExpired:
                proc.kill()
                killed["timeout"] = True
            finally:
                timer.cancel()
            t.join(timeout=10)
            duration = (time.monotonic() - started) * 1000
            state = {}
            insp = _run(["docker", "inspect", "--format", "{{json .State}}", name], timeout=30)
            if insp.returncode == 0:
                try:
                    state = json.loads(insp.stdout.decode("utf-8"))
                except ValueError:
                    state = {}
            return self._result(b"".join(chunks), size[0] > result_cap, state, killed["timeout"], duration, image,
                                limits)
        finally:
            _run(["docker", "rm", "-f", name], timeout=60)

    def _result(self, raw: bytes, over: bool, state: dict[str, Any], timed_out: bool, duration: float, image: str,
                limits: SandboxLimits) -> SandboxResult:
        oom = bool(state.get("OOMKilled"))
        line = None
        for ln in raw.decode("utf-8", "replace").splitlines():
            if ln.startswith(MARKER):
                line = ln[len(MARKER):]
        base = dict(backend=self.name, runtime_id=image.split("@", 1)[-1], duration_ms=duration)
        if line is None:
            limit = "timeout" if timed_out else ("memory" if oom else ("output" if over else None))
            return SandboxResult(exit_code=state.get("ExitCode"), stdout="", stderr="", limit_hit=limit,
                                 error="the sandbox did not return a result", **base)
        try:
            res = json.loads(line)
            tar = base64.b64decode(res.get("tar") or "")
        except (ValueError, TypeError):
            return SandboxResult(exit_code=None, stdout="", stderr="", limit_hit=None,
                                 error="the sandbox returned a malformed result", **base)
        limit = "timeout" if timed_out else ("memory" if oom else res.get("limit"))
        files = paths.collect_tar(tar, limits.file_bytes, limits.workspace_bytes)
        if files.over_cap:
            limit, files = limit or "workspace", paths.CopyOut()
        return SandboxResult(
            exit_code=res.get("rc"), stdout=str(res.get("stdout", ""))[: limits.stdout_bytes],
            stderr=str(res.get("stderr", ""))[: limits.stderr_bytes], files_out=files.files, limit_hit=limit,
            stdout_truncated=bool(res.get("stdout_truncated")), stderr_truncated=bool(res.get("stderr_truncated")),
            refused_files=files.refused, **base,
        )


def sweep_leftovers() -> int:
    """Remove containers labelled agentos.sandbox left by a crashed server. Returns how many were removed."""
    if docker_cli() is None:
        return 0
    try:
        r = _run(["docker", "ps", "-aq", "--filter", f"label={LABEL}=1"], timeout=20)
        ids = r.stdout.decode("utf-8").split() if r.returncode == 0 else []
        if ids:
            _run(["docker", "rm", "-f", *ids], timeout=60)
        return len(ids)
    except (subprocess.TimeoutExpired, OSError):
        return 0


def _version_tuple(v: str) -> tuple[int, int]:
    try:
        a, b = v.split(".")[:2]
        return int(a), int("".join(ch for ch in b if ch.isdigit()) or 0)
    except ValueError:
        return (0, 0)
