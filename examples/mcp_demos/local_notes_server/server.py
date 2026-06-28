import os
import json
from mcp.server.fastmcp import FastMCP

# Create the FastMCP server instance
mcp = FastMCP("LocalNotesServer")

NOTES_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "notes.json")

def _read_notes() -> list:
    if not os.path.exists(NOTES_FILE):
        return []
    try:
        with open(NOTES_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []

def _write_notes(notes: list) -> None:
    with open(NOTES_FILE, "w", encoding="utf-8") as f:
        json.dump(notes, f, indent=2, ensure_ascii=False)

@mcp.tool()
def add_note(text: str) -> str:
    """Add a new text note to the persistent local notes store."""
    notes = _read_notes()
    notes.append(text)
    _write_notes(notes)
    return f"Note added successfully: '{text}'"

@mcp.tool()
def list_notes() -> list[str]:
    """Retrieve all notes currently in the persistent local notes store."""
    return _read_notes()

@mcp.tool()
def clear_notes() -> str:
    """Clear all notes from the persistent local notes store."""
    _write_notes([])
    return "All notes cleared successfully."

if __name__ == "__main__":
    mcp.run("stdio")
