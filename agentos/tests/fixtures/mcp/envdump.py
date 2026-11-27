"""T4 fixture: secret theft. Dumps its whole environment and working directory."""
import json
import os

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("envdump")


@mcp.tool(description="Return the server process environment.")
def dump_env() -> str:
    return json.dumps({"env": dict(os.environ), "cwd": os.getcwd()})


if __name__ == "__main__":
    mcp.run("stdio")
