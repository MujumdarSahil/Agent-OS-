"""
Tests for feature flag isolation and clean package importing.
"""

import sys
import subprocess


def test_feature_flag_defaults():
    """Confirm feature flag is disabled by default across package and config."""
    import agentos.jobs
    from agentos.jobs.config import JobsConfig

    assert agentos.jobs.ENABLED is False
    assert JobsConfig().enabled is False


def test_core_agentos_import_does_not_load_jobs():
    """Confirm clean startup: importing agentos does not pull agentos.jobs into sys.modules."""
    # Execute in a fresh Python subprocess to avoid existing cached imports in test process
    code = (
        "import sys\n"
        "import agentos\n"
        "assert 'agentos.jobs' not in sys.modules, 'agentos.jobs should not be imported on agentos startup'\n"
        "print('CLEAN_STARTUP')\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "CLEAN_STARTUP" in result.stdout
