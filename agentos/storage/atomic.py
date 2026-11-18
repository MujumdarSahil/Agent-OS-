"""
Crash-safe file writes (vault-incident fix, 2026-11-18).

``atomic_write_text`` never leaves a half-written or zero-filled target:

1. write the new content to a temp file in the SAME folder (same volume, so the rename is atomic);
2. flush and ``os.fsync`` the temp file, so its data is on disk before the rename;
3. optionally copy the current file to ``<name>.bak`` first (same steps), keeping the last good version;
4. ``os.replace`` the temp file onto the target, retrying briefly when Windows reports the file as
   locked (antivirus, indexer, another reader);
5. best-effort ``fsync`` of the folder on POSIX so the rename itself is durable.

If the process dies at any point, the target is either the old content or the new content.
Before 2026-11-18 the storage helper renamed without fsync; a process killed right after the rename
could leave a file of the right size full of zero bytes.
"""

from __future__ import annotations

import os
import tempfile
import time
from pathlib import Path
from typing import Callable, Optional, Union

REPLACE_RETRIES = 10
REPLACE_BASE_DELAY_S = 0.05

# Tests replace this to simulate a crash between steps; production code never touches it.
_replace: Callable[[str, str], None] = os.replace


def _fsync_dir(folder: Path) -> None:
    if os.name == "nt":  # directories cannot be opened for fsync on Windows; NTFS journals the rename
        return
    try:
        fd = os.open(folder, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def replace_with_retry(src: Union[str, Path], dst: Union[str, Path]) -> None:
    """``os.replace`` with a short retry loop for transient Windows sharing violations."""
    for attempt in range(REPLACE_RETRIES):
        try:
            _replace(str(src), str(dst))
            return
        except PermissionError:
            if os.name != "nt" or attempt == REPLACE_RETRIES - 1:
                raise
            time.sleep(REPLACE_BASE_DELAY_S * (attempt + 1))


def _write_temp(folder: Path, name: str, data: bytes, private: bool) -> str:
    fd, tmp = tempfile.mkstemp(dir=folder, prefix=f".{name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        if private:
            try:
                os.chmod(tmp, 0o600)  # best effort on Windows
            except OSError:
                pass
        return tmp
    except BaseException:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise


def atomic_write_bytes(
    path: Union[str, Path],
    data: bytes,
    private: bool = False,
    backup: bool = False,
    is_good: Optional[Callable[[bytes], bool]] = None,
) -> None:
    """Replace ``path`` with ``data`` atomically and durably.

    ``backup``: keep the current file as ``<path>.bak`` before replacing it, but only when it is a good
    version (``is_good(current_bytes)`` is true, or no check was given and it is not empty/zero bytes).
    """
    path = Path(path)
    folder = path.parent
    folder.mkdir(parents=True, exist_ok=True)
    if backup and path.exists():
        current = path.read_bytes()
        good = is_good(current) if is_good else bool(current.strip(b"\x00 \r\n\t"))
        if good:
            bak = path.with_name(path.name + ".bak")
            tmp_bak = _write_temp(folder, bak.name, current, private)
            try:
                replace_with_retry(tmp_bak, bak)
            except BaseException:
                if os.path.exists(tmp_bak):
                    os.remove(tmp_bak)
                raise
    tmp = _write_temp(folder, path.name, data, private)
    try:
        replace_with_retry(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise
    _fsync_dir(folder)


def atomic_write_text(
    path: Union[str, Path],
    text: str,
    private: bool = False,
    backup: bool = False,
    is_good: Optional[Callable[[bytes], bool]] = None,
    encoding: str = "utf-8",
) -> None:
    atomic_write_bytes(path, text.encode(encoding), private=private, backup=backup, is_good=is_good)
