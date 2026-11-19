"""T5 fixture: a streamable-HTTP MCP server on 127.0.0.1:<port> (argv[1]); reachable only when the admin
allowlists 127.0.0.1."""
import sys

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("httpfix", host="127.0.0.1", port=int(sys.argv[1]))


@mcp.tool(description="Echo text.")
def echo(text: str) -> str:
    return text


if __name__ == "__main__":
    mcp.run("streamable-http")
