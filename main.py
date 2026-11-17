"""
main.py — AgentOS one-command launcher (2.4c).

    python main.py                 # default workspace ~/.agentos/workspace, UI + API on one port
    python main.py --project PATH  # open a specific project
    python main.py --dev           # Vite dev server (hot reload) + backend

Default (single port): the backend serves the built UI from ui/dist. If ui/dist is missing and npm is
available it is built once; otherwise the exact commands to run are printed. The in-process flow
worker is on by default (--no-worker to disable). The browser opens on the login link
(http://localhost:<port>/#token=...), which is also printed once. Ctrl+C stops every child process.
"""

from __future__ import annotations

import argparse
import os
import shutil
import signal
import subprocess
import sys
import time
import urllib.request
import webbrowser
from pathlib import Path

ROOT = Path(__file__).parent.resolve()
FRONTEND_DIR = ROOT / "ui"
DEFAULT_WORKSPACE = Path.home() / ".agentos" / "workspace"
IS_WINDOWS = os.name == "nt"


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="Start AgentOS (backend + web UI).")
    p.add_argument("--project", help=f"Project folder (default: current folder if it has agentos.config.yaml, else {DEFAULT_WORKSPACE})")
    p.add_argument("--backend-port", type=int, default=8000)
    p.add_argument("--frontend-port", type=int, default=5173, help="Vite port (only with --dev)")
    p.add_argument("--dev", action="store_true", help="Vite dev server with hot reload + backend")
    p.add_argument("--prod", action="store_true", help="Single port (the default; kept for compatibility)")
    p.add_argument("--no-worker", action="store_true", help="Do not start the in-process flow worker")
    p.add_argument("--no-browser", action="store_true", help="Do not open a browser")
    p.add_argument("--skip-ui-build", action="store_true", help="Never build the UI (API only if ui/dist is missing)")
    return p.parse_args(argv)


def resolve_project(project_arg: str | None) -> str:
    if project_arg:
        path = os.path.abspath(project_arg)
        if not os.path.isdir(path):
            print(f"ERROR: Project path does not exist: {path}", file=sys.stderr)
            sys.exit(1)
        return path
    cwd = os.getcwd()
    if os.path.exists(os.path.join(cwd, "agentos.config.yaml")):
        return cwd
    DEFAULT_WORKSPACE.mkdir(parents=True, exist_ok=True)
    cfg = DEFAULT_WORKSPACE / "agentos.config.yaml"
    if not cfg.exists():
        cfg.write_text("preferred_tags: []\n", encoding="utf-8")
        print(f"Created default workspace: {DEFAULT_WORKSPACE}")
    return str(DEFAULT_WORKSPACE)


def npm_cmd() -> str | None:
    return shutil.which("npm.cmd" if IS_WINDOWS else "npm") or shutil.which("npm")


def ensure_ui_built(skip: bool) -> bool:
    """True if ui/dist/index.html exists (building it once when possible)."""
    if (FRONTEND_DIR / "dist" / "index.html").exists():
        return True
    npm = npm_cmd()
    if skip or npm is None:
        print("The web UI is not built, so only the API will be served. To build it, run:\n"
              f"  cd {FRONTEND_DIR}\n  npm install\n  npm run build\nthen start AgentOS again.")
        return False
    print("Building the web UI once (npm install + npm run build); this can take a few minutes...")
    if not (FRONTEND_DIR / "node_modules").exists():
        subprocess.run([npm, "install"], cwd=FRONTEND_DIR, check=True)
    subprocess.run([npm, "run", "build"], cwd=FRONTEND_DIR, check=True)
    return (FRONTEND_DIR / "dist" / "index.html").exists()


def spawn(cmd: list[str], cwd: Path, env: dict) -> subprocess.Popen:
    """Start a child in its own process group so it can be stopped as a tree."""
    if IS_WINDOWS:
        return subprocess.Popen(cmd, cwd=cwd, env=env, creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
    return subprocess.Popen(cmd, cwd=cwd, env=env, start_new_session=True)


def stop(proc: subprocess.Popen, timeout: float = 8.0) -> None:
    if proc.poll() is not None:
        return
    try:
        if IS_WINDOWS:
            proc.send_signal(signal.CTRL_BREAK_EVENT)
        else:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        proc.wait(timeout=timeout)
    except Exception:
        pass
    if proc.poll() is None:
        if IS_WINDOWS:
            subprocess.run(["taskkill", "/T", "/F", "/PID", str(proc.pid)], capture_output=True)
        else:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except ProcessLookupError:
                pass
        proc.wait(timeout=5)


def wait_for_health(port: int, procs: list[subprocess.Popen], timeout: float = 120.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if any(p.poll() is not None for p in procs):
            return False
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/health", timeout=2) as r:
                if r.status == 200:
                    return True
        except Exception:
            time.sleep(0.5)
    return False


def _interrupt(*_args) -> None:
    raise KeyboardInterrupt()


def main(argv=None) -> int:
    args = parse_args(argv)
    project = resolve_project(args.project)
    env = dict(os.environ)
    env["AGENTOS_PROJECT"] = project
    env["AGENTOS_PORT"] = str(args.backend_port)
    if not args.no_worker:
        env.setdefault("AGENTOS_INPROCESS_WORKER", "1")
    else:
        env.pop("AGENTOS_INPROCESS_WORKER", None)

    procs: list[subprocess.Popen] = []
    ui_port = args.backend_port
    if args.dev:
        env["AGENTOS_DEV"] = "1"
        ui_port = args.frontend_port
    elif ensure_ui_built(args.skip_ui_build):
        env["AGENTOS_UI_DIST"] = str(FRONTEND_DIR / "dist")

    # Ctrl+Break (Windows) and SIGTERM behave like Ctrl+C, so the children are always stopped.
    if IS_WINDOWS and hasattr(signal, "SIGBREAK"):
        signal.signal(signal.SIGBREAK, _interrupt)
    signal.signal(signal.SIGTERM, _interrupt)

    from agentos_server.auth import get_or_create_api_token

    token = get_or_create_api_token()  # same token file the server uses; read before starting children

    try:
        backend = [sys.executable, "-m", "uvicorn", "agentos_server.app:create_app", "--factory",
                   "--host", "127.0.0.1", "--port", str(args.backend_port)]
        procs.append(spawn(backend, ROOT, env))
        if args.dev:
            npm = npm_cmd()
            if npm is None:
                print("ERROR: --dev needs npm (Node.js 20.19+ or 22.12+).", file=sys.stderr)
                return 1
            procs.append(spawn([npm, "run", "dev", "--", "--port", str(args.frontend_port), "--strictPort"], FRONTEND_DIR, env))
        if not wait_for_health(args.backend_port, procs):
            print("ERROR: the backend did not start; see the output above.", file=sys.stderr)
            return 1

        url = f"http://localhost:{ui_port}/#token={token}"
        print("\nAgentOS is running.")
        print(f"  Project: {project}")
        print(f"  Worker:  {'off (--no-worker)' if args.no_worker else 'on (in-process)'}")
        print(f"  Open:    {url}")
        print("Press Ctrl+C to stop.\n", flush=True)
        if not args.no_browser:
            webbrowser.open(url)
        while all(p.poll() is None for p in procs):
            time.sleep(0.5)
        print("A server process exited; shutting down.", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nStopping AgentOS...", flush=True)
        return 0
    finally:
        for p in reversed(procs):
            stop(p)
        print("AgentOS stopped.", flush=True)


if __name__ == "__main__":
    sys.exit(main())
