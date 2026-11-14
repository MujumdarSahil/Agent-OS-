#!/usr/bin/env python3
"""
Build the agentos wheel and install it into a brand-new virtualenv, then check
that both packages work from the installed copy (not the source checkout):

  - agentos and agentos_server import from the venv's site-packages
  - the v1 alias agentos.server.app resolves to agentos_server.app
  - the installed `agentos new-project` console script scaffolds a project
  - create_app() on that project serves GET /api/health -> 200
  - the packaged UI (agentos_server/static/index.html) is present when
    `npm run build:package` ran before the build (reported, not required)

Usage:  python check_wheel_install.py [--keep]
Needs network access (pip installs the wheel's dependencies).
"""
import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).parent.resolve()

CHECK_CODE = r"""
import os, sys, asyncio, tempfile
import agentos, agentos_server
venv = os.path.realpath(sys.prefix)
for mod in (agentos, agentos_server):
    path = os.path.realpath(mod.__file__)
    assert path.startswith(venv), f"{mod.__name__} imported from {path}, not the venv"
    print(f"OK  {mod.__name__} -> {path}")

import agentos.server.app as old
import agentos_server.app as new
assert old is new, "agentos.server.app alias is not agentos_server.app"
print("OK  agentos.server.app is agentos_server.app")

import httpx
from agentos_server.app import create_app
app = create_app(os.environ["AGENTOS_CHECK_PROJECT"])

async def health():
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost") as c:
        return await c.get("/api/health")

resp = asyncio.run(health())
assert resp.status_code == 200, resp.text
print(f"OK  GET /api/health -> {resp.status_code}")

static_index = os.path.join(os.path.dirname(agentos_server.__file__), "static", "index.html")
print(f"{'OK ' if os.path.isfile(static_index) else 'N/A'} packaged UI at {static_index}")
"""


def run(cmd, **kwargs):
    print("$", " ".join(str(c) for c in cmd), flush=True)
    subprocess.run(cmd, check=True, **kwargs)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--keep", action="store_true", help="keep the temp directory")
    args = parser.parse_args()

    work = Path(tempfile.mkdtemp(prefix="agentos-wheel-"))
    try:
        dist = work / "dist"
        run([sys.executable, "-m", "build", "--wheel", "--outdir", str(dist), str(ROOT)])
        wheel = next(dist.glob("agentos-*.whl"))

        venv = work / "venv"
        run([sys.executable, "-m", "venv", str(venv)])
        py = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        run([str(py), "-m", "pip", "install", "--quiet", "--upgrade", "pip"])
        run([str(py), "-m", "pip", "install", "--quiet", str(wheel)])

        env = {**os.environ, "AGENTOS_MOCK_LLM": "1", "PYTHONIOENCODING": "utf-8"}
        env.pop("PYTHONPATH", None)

        # /api/health needs a valid project; scaffold one with the installed console script.
        cli = venv / ("Scripts/agentos.exe" if os.name == "nt" else "bin/agentos")
        run([str(cli), "new-project", "demo"], cwd=str(work), env=env)
        env["AGENTOS_CHECK_PROJECT"] = str(work / "demo")
        # -I: isolated mode, so neither cwd nor the source checkout is on sys.path.
        run([str(py), "-I", "-c", CHECK_CODE], cwd=str(work), env=env)
        print(f"\nWheel install check passed: {wheel.name}")
    finally:
        if args.keep:
            print(f"Kept {work}")
        else:
            shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
