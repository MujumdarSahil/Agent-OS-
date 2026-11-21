"""Real-home guard (3.5 Part 0a; CLAUDE.md rule 13).

When ``AGENTOS_FORBID_REAL_HOME=1``, every AgentOS path resolver (vault, master key, API token, project / storage,
data dir), ``create_app``, the CLI and ``main.py`` REFUSE a path inside the real user's ``~/.agentos``.

- The real home comes from the OS account, never from ``HOME`` / ``USERPROFILE`` (the pytest conftest points those
  at a temp folder): Windows ``SHGetKnownFolderPath(FOLDERID_Profile)``, POSIX ``pwd``. Tests can point the guard at
  a fake home with ``AGENTOS_GUARD_REAL_HOME``.
- A path is checked lexically first (absolute + normalized, case-insensitive on Windows), BEFORE anything is
  resolved, so a forbidden path is never opened; then its resolved real path (symlinks / junctions followed).
- The forbidden folder itself (``<home>/.agentos``) is never resolved or opened: only the home folder is resolved.
  Known gap: a ``~/.agentos`` that is itself a symlink to elsewhere is not followed.
"""

from __future__ import annotations

import os
import sys
from functools import lru_cache
from pathlib import Path
from typing import Optional, Union

ENV_FLAG = "AGENTOS_FORBID_REAL_HOME"
ENV_REAL_HOME = "AGENTOS_GUARD_REAL_HOME"  # tests only: a fake "real home"

PathLike = Union[str, "os.PathLike[str]"]


class RealHomeForbidden(RuntimeError):
    """A path inside the real AgentOS home was refused because AGENTOS_FORBID_REAL_HOME=1."""


def guard_enabled() -> bool:
    return os.environ.get(ENV_FLAG, "").strip() == "1"


def _windows_profile_dir() -> Optional[str]:
    import ctypes
    from ctypes import wintypes

    class GUID(ctypes.Structure):
        _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD), ("Data3", wintypes.WORD),
                    ("Data4", ctypes.c_ubyte * 8)]

    # FOLDERID_Profile {5E6C858F-0E22-4760-9AFE-EA3317B67173}
    fid = GUID(0x5E6C858F, 0x0E22, 0x4760, (ctypes.c_ubyte * 8)(0x9A, 0xFE, 0xEA, 0x33, 0x17, 0xB6, 0x71, 0x73))
    out = ctypes.c_wchar_p()
    shell32 = ctypes.windll.shell32  # type: ignore[attr-defined]
    ole32 = ctypes.windll.ole32  # type: ignore[attr-defined]
    hr = shell32.SHGetKnownFolderPath(ctypes.byref(fid), 0, None, ctypes.byref(out))
    try:
        return out.value if hr == 0 else None
    finally:
        ole32.CoTaskMemFree(out)


def _os_account_home() -> Optional[str]:
    if sys.platform == "win32":
        try:
            return _windows_profile_dir()
        except Exception:
            return None
    try:
        import pwd

        return pwd.getpwuid(os.getuid()).pw_dir  # type: ignore[attr-defined]
    except Exception:
        return None


def _norm(p: str) -> str:
    p = os.path.normpath(os.path.abspath(p))
    return os.path.normcase(p)


@lru_cache(maxsize=8)
def _forbidden_roots(override: Optional[str]) -> tuple[str, ...]:
    """``<home>/.agentos`` as (lexical, resolved-home) forms. Only the home folder is resolved, never .agentos."""
    home = override or _os_account_home()
    if not home:
        return ()
    roots = {_norm(os.path.join(home, ".agentos"))}
    try:
        roots.add(_norm(os.path.join(os.path.realpath(home), ".agentos")))
    except OSError:
        pass
    return tuple(sorted(roots))


def forbidden_roots() -> tuple[str, ...]:
    return _forbidden_roots(os.environ.get(ENV_REAL_HOME) or None)


def _inside(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip(os.sep) + os.sep)


def is_in_real_home(path: PathLike) -> bool:
    """True if ``path`` (lexically or once resolved) is inside the real ``~/.agentos``."""
    roots = forbidden_roots()
    if not roots:
        return False
    lexical = _norm(os.fspath(path))
    if any(_inside(lexical, r) for r in roots):
        return True  # refused before anything is resolved (never opened)
    try:
        resolved = _norm(os.path.realpath(os.fspath(path)))
    except OSError:
        return False
    return any(_inside(resolved, r) for r in roots)


def check_path(path: PathLike, what: str = "path") -> PathLike:
    """Return ``path`` unchanged, or raise ``RealHomeForbidden`` when the guard is on and it points into the real
    AgentOS home. No-op when the guard is off."""
    if guard_enabled() and is_in_real_home(path):
        raise RealHomeForbidden(
            f"{what} {os.fspath(path)!r} is inside the real AgentOS home (~/.agentos); refused because "
            f"{ENV_FLAG}=1. Point it at a temporary folder (AGENTOS_PROJECT, AGENTOS_VAULT_PATH, "
            f"AGENTOS_MASTER_KEY_FILE, AGENTOS_API_TOKEN_FILE, AGENTOS_DATA_DIR) or unset {ENV_FLAG}."
        )
    return path


def checked(path: Path, what: str) -> Path:
    check_path(path, what)
    return path
