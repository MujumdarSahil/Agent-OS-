"""
AgentOS Application - Main entry point for running AgentOS
"""

import asyncio
import argparse
from agentos.demo import main as run_demo


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="AgentOS Framework")
    parser.add_argument(
        "command",
        choices=["demo", "server"],
        help="Command to run"
    )
    parser.add_argument(
        "--host",
        default="localhost",
        help="Host for server (default: localhost)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8765,
        help="Port for server (default: 8765)"
    )
    
    args = parser.parse_args()
    
    if args.command == "demo":
        asyncio.run(run_demo())
    elif args.command == "server":
        print("Server mode not yet implemented")
        # TODO: Implement server mode with WebSocket and REST API


if __name__ == "__main__":
    main()

