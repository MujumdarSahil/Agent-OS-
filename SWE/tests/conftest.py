"""
Pytest configuration for SWE test suite.
Ensures repository root and SWE directory are included in sys.path.
"""
import sys
from pathlib import Path

repo_root = Path(__file__).resolve().parent.parent.parent
swe_dir = repo_root / "SWE"

if str(swe_dir) not in sys.path:
    sys.path.insert(0, str(swe_dir))

if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))
