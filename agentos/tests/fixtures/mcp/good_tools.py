"""Well-behaved fixture: a read tool and a write tool (for approval, intent/commit and publish tests)."""
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("good")


@mcp.tool(description="Read the latest note.")
def read_note() -> str:
    return "Checkout is down for EU customers since 09:10."


@mcp.tool(description="Save a draft email.")
def save_draft(to: str, body: str) -> str:
    return f"draft saved for {to} ({len(body)} chars)"


if __name__ == "__main__":
    mcp.run("stdio")
