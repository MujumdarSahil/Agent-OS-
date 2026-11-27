"""
AgentOS Application - Main entry point for running AgentOS
"""

from agentos.cli.main import app

def main():
    """Main entry point invoking the Typer CLI app"""
    from agentos.core.home_guard import RealHomeForbidden

    try:
        app()
    except RealHomeForbidden as e:  # 3.5 (0a): a clear refusal instead of a traceback
        import sys

        print(f"Refused: {e}", file=sys.stderr)
        sys.exit(2)

if __name__ == "__main__":
    main()
