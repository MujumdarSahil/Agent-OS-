"""
Root conftest: tests never touch the real AgentOS home (vault incident 2026-11-18).

1. Isolation. At import time, BEFORE any agentos module is imported (some compute home paths at import),
   every AgentOS home path is pointed at a fresh temp folder:
   HOME / USERPROFILE (so any default we missed lands in temp too), AGENTOS_VAULT_PATH,
   AGENTOS_MASTER_KEY_FILE, AGENTOS_API_TOKEN_FILE, AGENTOS_DATA_DIR. An autouse session fixture
   re-checks this before the first test.
2. Guard. At session start the size and modification time (never the contents) of the files in the
   REAL ~/.agentos (top level and keys/) are recorded. At session end, if any changed, appeared or
   disappeared, the whole run fails with a clear error. ~/.agentos/workspace is not watched: a running
   AgentOS may legitimately write there.

The guard can be pointed at another folder with AGENTOS_TEST_GUARD_REAL_HOME (used only by the guard's
own test, which runs pytest in a subprocess against a fake "real home").
"""

from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path
from typing import Dict, Optional, Tuple

import pytest

_REAL_HOME = Path(os.environ.get("AGENTOS_TEST_GUARD_REAL_HOME") or os.path.expanduser("~"))
_TEST_HOME = Path(tempfile.mkdtemp(prefix="agentos-test-home-"))

ISOLATED_ENV: Dict[str, str] = {
    "HOME": str(_TEST_HOME),
    "USERPROFILE": str(_TEST_HOME),
    "AGENTOS_VAULT_PATH": str(_TEST_HOME / ".agentos" / "vault.json"),
    "AGENTOS_MASTER_KEY_FILE": str(_TEST_HOME / ".agentos" / "master.key"),
    "AGENTOS_API_TOKEN_FILE": str(_TEST_HOME / ".agentos" / "api.token"),
    "AGENTOS_DATA_DIR": str(_TEST_HOME / "data"),
    # 3.5 (0a): hard guard; every AgentOS resolver refuses a path inside the REAL ~/.agentos for the whole session
    "AGENTOS_FORBID_REAL_HOME": "1",
    # Part 0b (3.6b): AGENTOS_MOCK_LLM and LITELLM_LOCAL_MODEL_COST_MAP are NOT set here globally.
    # They are set only by the fixtures/tests that need them (mock_llm fixture, LLM-specific tests).
}
if os.name == "nt":
    # Windows shell-folder lookups (appdirs, used by CrewAI at import) need these to exist under the
    # profile; pointing them into the temp home also keeps third-party app data out of the real profile.
    for _sub, _var in (("AppData/Local", "LOCALAPPDATA"), ("AppData/Roaming", "APPDATA")):
        (_TEST_HOME / _sub).mkdir(parents=True, exist_ok=True)
        ISOLATED_ENV[_var] = str(_TEST_HOME / _sub)
    try:
        import appdirs
        _orig_get_win = getattr(appdirs, "_get_win_folder", None)
        def _safe_get_win(csidl_name: str) -> str:
            if "LOCAL" in csidl_name and os.environ.get("LOCALAPPDATA"):
                return os.environ["LOCALAPPDATA"]
            if os.environ.get("APPDATA"):
                return os.environ["APPDATA"]
            try:
                if _orig_get_win is not None:
                    return _orig_get_win(csidl_name)
            except Exception:
                pass
            return str(_TEST_HOME)
        appdirs._get_win_folder = _safe_get_win
    except ImportError:
        pass
os.environ.update(ISOLATED_ENV)

Snapshot = Dict[str, Optional[Tuple[int, int]]]

# Sentinel stored for a folder that existed but couldn't be scanned (Part 0a).
_SCAN_FAILED_SENTINEL = "SCAN_FAILED"


def snapshot_home(home: Path) -> Snapshot:
    """{relative path: (size, mtime_ns)} for files in home/.agentos (top level) and home/.agentos/keys.

    Only os.stat metadata is read; file contents are never opened.

    Part 0a: fail CLOSED. If a folder exists but cannot be scanned (PermissionError / OSError), we store a
    sentinel so the session-end diff can report the error rather than silently ignoring it.
    """
    base = home / ".agentos"
    out: Snapshot = {}
    for folder in (base, base / "keys"):
        folder_key = f"<folder:{folder.name}:scan_failed>"
        try:
            if not folder.is_dir():
                continue
            entries_ok = True
            for entry in os.scandir(folder):
                try:
                    if entry.is_file(follow_symlinks=False):
                        st = entry.stat(follow_symlinks=False)
                        out[str(Path(entry.path).relative_to(home))] = (st.st_size, st.st_mtime_ns)
                except (PermissionError, OSError):
                    # An individual entry stat failed — treat the whole folder as unreadable.
                    entries_ok = False
                    break
            if not entries_ok:
                # Record the scan failure so the diff sees it.
                out[folder_key] = None  # type: ignore[assignment]
        except (PermissionError, OSError):
            # The folder exists (is_dir checked above didn't throw, but scandir did), or is_dir itself
            # raised — record the failure.
            out[folder_key] = None  # type: ignore[assignment]
    return out


def diff_snapshots(before: Snapshot, after: Snapshot) -> list[str]:
    changes = []
    for name in sorted(set(before) | set(after)):
        b, a = before.get(name), after.get(name)
        if b == a:
            continue
        # Part 0a: scan-failure sentinels are stored as None under a <folder:…:scan_failed> key.
        if name.startswith("<folder:") and name.endswith(":scan_failed>"):
            folder_name = name.split(":")[1]
            if a is None and name not in before:
                # A folder that wasn't there before can now no longer be scanned — report it.
                changes.append(
                    f"scan_failed: {_REAL_HOME / '.agentos' / folder_name} could not be scanned "
                    f"(PermissionError/OSError) — guard cannot verify this folder is unchanged"
                )
            elif b is None and name not in after:
                changes.append(
                    f"scan_recovered: {_REAL_HOME / '.agentos' / folder_name} was unreadable at start but readable now"
                )
            # If it was unreadable both before and after, no change to report.
            continue
        if b is None:
            changes.append(f"created: {name}")
        elif a is None:
            changes.append(f"deleted: {name}")
        else:
            changes.append(f"modified: {name} (size {b[0]} -> {a[0]}, mtime changed: {b[1] != a[1]})")
    return changes


_BEFORE: Snapshot = {}


def pytest_configure(config: pytest.Config) -> None:
    global _BEFORE
    _BEFORE = snapshot_home(_REAL_HOME)


def pytest_report_header(config: pytest.Config) -> list[str]:
    # Resolved paths only (never contents), so every run shows where AgentOS state goes.
    if os.environ.get("AGENTOS_TEST_GUARD_REAL_HOME"):  # the guard's own subprocess test: skip agentos imports
        return [f"agentos test home: {_TEST_HOME}", f"  guard watches -> {_REAL_HOME / '.agentos'}"]
    from agentos.security.vault import default_master_key_path
    from agentos.storage.file import default_vault_path
    from agentos_server.auth import default_token_path

    return [
        f"agentos test home: {_TEST_HOME}",
        f"  Path.home()   -> {Path.home()}",
        f"  vault         -> {default_vault_path()}",
        f"  master key    -> {default_master_key_path()}",
        f"  api token     -> {default_token_path()}",
        f"  guard watches -> {_REAL_HOME / '.agentos'} (size + mtime only)",
    ]


@pytest.fixture(scope="session", autouse=True)
def agentos_isolated_home():
    """Session-wide: every AgentOS home path points inside the temp test home."""
    for key, value in ISOLATED_ENV.items():
        if os.environ.get(key) != value:
            os.environ[key] = value  # something reset it after import: put it back before tests run
    assert Path.home() == _TEST_HOME, f"Path.home() is {Path.home()}, expected the temp test home"
    yield _TEST_HOME


@pytest.fixture(autouse=True)
def agentos_per_test_vault(tmp_path_factory, monkeypatch):
    """3.2 (0c): every test gets its OWN vault file and master key file, as a pair.

    Before, the whole session shared one vault (AGENTOS_VAULT_PATH in the temp home) while some tests gave
    each test a fresh master key: a secret stored earlier with another key made create_app's startup vault
    check fail (VaultKeyMismatch), depending on test order. Tests that set their own key or vault still
    override these (their fixtures run after this one); session-scoped apps keep the vault they captured.
    """
    # inside the session temp test home, so every AgentOS path still points into it (checked by
    # test_session_isolation_points_every_path_into_the_temp_home)
    (_TEST_HOME / "per-test").mkdir(parents=True, exist_ok=True)
    d = Path(tempfile.mkdtemp(prefix="vault-", dir=_TEST_HOME / "per-test"))
    monkeypatch.setenv("AGENTOS_VAULT_PATH", str(d / "vault.json"))
    monkeypatch.setenv("AGENTOS_MASTER_KEY_FILE", str(d / "master.key"))
    yield


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    changes = diff_snapshots(_BEFORE, snapshot_home(_REAL_HOME))
    if changes:
        reporter = session.config.pluginmanager.get_plugin("terminalreporter")
        # Part 0a: scan_failed entries mean the guard could not verify the folder — still fail CLOSED.
        scan_errors = [c for c in changes if c.startswith("scan_failed:")]
        file_changes = [c for c in changes if not c.startswith("scan_failed:") and not c.startswith("scan_recovered:")]
        if scan_errors:
            header = (
                f"AGENTOS HOME GUARD: could not scan folder(s) in REAL {_REAL_HOME / '.agentos'} "
                f"(PermissionError/OSError) — guard cannot guarantee no files changed; run is marked failed:"
            )
        else:
            header = f"AGENTOS HOME GUARD: the test run changed files in the REAL {_REAL_HOME / '.agentos'}:"
        lines = [
            header,
            *[f"  {c}" for c in changes],
        ]
        if file_changes:
            lines.append("A test wrote outside the temp test home. Find it and isolate it; the run is marked failed.")
        if reporter:
            reporter.write_sep("=", "AGENTOS HOME GUARD", red=True, bold=True)
            for line in lines:
                reporter.write_line(line, red=True)
        session.exitstatus = pytest.ExitCode.TESTS_FAILED
    shutil.rmtree(_TEST_HOME, ignore_errors=True)
