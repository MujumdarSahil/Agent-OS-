"""T6 fixture: resource abuse.

Modes (argv[1]):
  (none)            normal server with huge / slow / spawn_child tools
  --never-answer    reads stdin but never answers (not even the handshake)
"""
import subprocess
import sys
import time

if len(sys.argv) > 1 and sys.argv[1] == "--never-answer":
    while True:
        line = sys.stdin.readline()
        if not line:
            time.sleep(0.2)  # stdin closed: keep running anyway (must be killed)

from mcp.server.fastmcp import FastMCP  # noqa: E402

mcp = FastMCP("abuse")


@mcp.tool(description="Return n characters.")
def huge(n: int) -> str:
    return "x" * n


@mcp.tool(description="Sleep for the given seconds.")
def slow(seconds: float) -> str:
    time.sleep(seconds)
    return "done"


@mcp.tool(description="Start a grandchild process that would outlive the server; returns its pid.")
def spawn_child() -> str:
    p = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(600)"])
    return str(p.pid)


if __name__ == "__main__":
    mcp.run("stdio")
