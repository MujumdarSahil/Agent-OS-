"""
main.py — AgentOS single-command launcher.

DEV mode (default):
  Spawns uvicorn (FastAPI backend) + npm run dev (Vite frontend) as subprocesses.
  Opens the frontend URL in the default browser.
  Ctrl+C terminates both cleanly.

PROD mode (--prod):
  Expects the frontend already built (npm run build → agentos/frontend/dist/).
  FastAPI serves the built static files + API on one port via uvicorn.
  Auto-builds if dist/ is missing.

Usage:
  python main.py [--project PATH] [--backend-port 8000] [--frontend-port 5173] [--prod]
"""

import argparse
import os
import signal
import subprocess
import sys
import time
import webbrowser
from pathlib import Path

ROOT = Path(__file__).parent.resolve()
FRONTEND_DIR = ROOT / "agentos" / "frontend"


def parse_args():
    parser = argparse.ArgumentParser(description="AgentOS - Start the full-stack platform")
    parser.add_argument(
        "--project",
        default=None,
        help="Path to AgentOS project (default: current directory if valid project)",
    )
    parser.add_argument("--backend-port", type=int, default=8000)
    parser.add_argument("--frontend-port", type=int, default=5173)
    parser.add_argument("--prod", action="store_true", help="Production mode (single process)")
    parser.add_argument("--dev", action="store_true", help="Development mode (default)")
    return parser.parse_args()


def resolve_project(project_arg: str | None) -> str:
    if project_arg:
        p = os.path.abspath(project_arg)
        if not os.path.exists(p):
            print(f"ERROR: Project path does not exist: {p}", file=sys.stderr)
            sys.exit(1)
        return p
    # Default: current directory if it's a valid project
    cwd = os.getcwd()
    if os.path.exists(os.path.join(cwd, "agentos.config.yaml")):
        return cwd
    print(
        "ERROR: Current directory is not an AgentOS project (no agentos.config.yaml found).\n"
        "Use --project <path> to specify a project directory, or run:\n"
        "  agentos new-project my-project",
        file=sys.stderr,
    )
    sys.exit(1)


def ensure_npm_deps():
    node_modules = FRONTEND_DIR / "node_modules"
    if not node_modules.exists():
        print("First run detected — installing frontend dependencies (this may take a minute)...")
        result = subprocess.run(
            ["npm", "install"],
            cwd=str(FRONTEND_DIR),
            shell=True,
        )
        if result.returncode != 0:
            print("ERROR: npm install failed. Check that Node.js is installed.", file=sys.stderr)
            sys.exit(1)
        print("Frontend dependencies installed.")


def build_frontend():
    dist = FRONTEND_DIR / "dist"
    if not dist.exists():
        print("Building frontend (npm run build)...")
        result = subprocess.run(
            ["npm", "run", "build"],
            cwd=str(FRONTEND_DIR),
            shell=True,
        )
        if result.returncode != 0:
            print(
                "ERROR: Frontend build failed.\n"
                "Run `npm run build` in agentos/frontend/ to see the full output.",
                file=sys.stderr,
            )
            sys.exit(1)
        print("Frontend built successfully.")


def run_dev(project_path: str, backend_port: int, frontend_port: int):
    """Start uvicorn + Vite dev server as subprocesses."""
    ensure_npm_deps()

    backend_url = f"http://localhost:{backend_port}"
    frontend_url = f"http://localhost:{frontend_port}"

    print(f"\nAgentOS starting in DEV mode")
    print(f"  Project:  {project_path}")
    print(f"  Backend:  {backend_url}")
    print(f"  Frontend: {frontend_url}")
    print(f"\nPress Ctrl+C to stop both servers.\n")

    # Set AGENTOS_PROJECT env for the backend process
    env = os.environ.copy()
    env["AGENTOS_PROJECT"] = project_path

    # Spawn backend
    backend_proc = subprocess.Popen(
        [
            sys.executable, "-m", "uvicorn",
            f"agentos.server.app:create_app",
            "--host", "0.0.0.0",
            "--port", str(backend_port),
            "--factory",
            "--reload",
        ],
        env={**env, "AGENTOS_PROJECT": project_path},
        cwd=str(ROOT),
    )

    # Spawn frontend
    frontend_proc = subprocess.Popen(
        ["npm", "run", "dev", "--", "--port", str(frontend_port), "--host"],
        cwd=str(FRONTEND_DIR),
        shell=True,
    )

    # Open browser after a short delay
    def _open_browser():
        time.sleep(3)
        webbrowser.open(frontend_url)

    import threading
    threading.Thread(target=_open_browser, daemon=True).start()

    procs = [backend_proc, frontend_proc]

    def _shutdown(signum=None, frame=None):
        print("\nShutting down AgentOS servers...")
        for p in procs:
            if p.poll() is None:
                p.terminate()
        for p in procs:
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
        print("AgentOS stopped.")
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    # Wait for either process to exit
    try:
        while True:
            for p in procs:
                if p.poll() is not None:
                    print(f"A server process exited unexpectedly (code {p.returncode}). Shutting down.")
                    _shutdown()
            time.sleep(1)
    except KeyboardInterrupt:
        _shutdown()


def run_prod(project_path: str, backend_port: int):
    """Start a single uvicorn process serving both API and built frontend."""
    ensure_npm_deps()
    build_frontend()

    prod_url = f"http://localhost:{backend_port}"
    print(f"\nAgentOS starting in PROD mode")
    print(f"  Project: {project_path}")
    print(f"  URL:     {prod_url}")
    print(f"\nPress Ctrl+C to stop.\n")

    env = os.environ.copy()
    env["AGENTOS_PROJECT"] = project_path

    proc = subprocess.Popen(
        [
            sys.executable, "-m", "uvicorn",
            "agentos.server.app:create_app",
            "--host", "0.0.0.0",
            "--port", str(backend_port),
            "--factory",
        ],
        env=env,
        cwd=str(ROOT),
    )

    def _shutdown(signum=None, frame=None):
        print("\nShutting down AgentOS...")
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        print("AgentOS stopped.")
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    time.sleep(2)
    webbrowser.open(prod_url)

    try:
        proc.wait()
    except KeyboardInterrupt:
        _shutdown()


def main():
    args = parse_args()
    project_path = resolve_project(args.project)
    prod = args.prod

    if prod:
        run_prod(project_path, args.backend_port)
    else:
        run_dev(project_path, args.backend_port, args.frontend_port)


if __name__ == "__main__":
    main()
