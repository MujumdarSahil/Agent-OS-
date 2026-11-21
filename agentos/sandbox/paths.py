"""Workspace path rules and safe copy-in / copy-out (3.5, D7).

One rule for ``file_read`` / ``file_write``, the ``files`` argument of the exec tools, and every file copied OUT of
a sandbox: a relative path inside the run's workspace, nothing else. Refused: absolute paths (POSIX and Windows),
``..``, drive letters (also drive-relative ``C:x``), UNC and ``\\\\?\\`` forms, ``:`` (Windows alternate data streams),
NUL / control characters, Windows reserved device names, empty or over-long names. Backslashes count as separators.
Copy-out also refuses symlinks, hard links, devices and fifos, and enforces per-file and total size caps.
"""

from __future__ import annotations

import io
import os
import stat
import tarfile
from pathlib import Path
from typing import Iterable

MAX_PATH_CHARS = 255
MAX_FILES = 1000
_WINDOWS_RESERVED = {"con", "prn", "aux", "nul", "conin$", "conout$",
                     *(f"com{i}" for i in range(10)), *(f"lpt{i}" for i in range(10))}


class PathRefused(ValueError):
    pass


def safe_rel_path(raw: object) -> str:
    """Return the normalized POSIX relative path, or raise ``PathRefused`` (message safe to show)."""
    if not isinstance(raw, str) or not raw.strip():
        raise PathRefused("a relative file path is required")
    if len(raw) > MAX_PATH_CHARS:
        raise PathRefused(f"path longer than {MAX_PATH_CHARS} characters")
    if any(ord(c) < 32 or c == "\x7f" for c in raw):
        raise PathRefused("control characters are not allowed in a path")
    p = raw.replace("\\", "/")
    if p.startswith("/") or p.startswith("//"):
        raise PathRefused("absolute paths are not allowed (only paths inside the sandbox workspace)")
    if ":" in p:
        raise PathRefused("':' is not allowed in a path (drive letters, Windows streams)")
    parts = [s for s in p.split("/") if s not in ("", ".")]
    if not parts:
        raise PathRefused("a file path is required")
    for s in parts:
        if s == "..":
            raise PathRefused("'..' is not allowed in a path")
        base = s.split(".")[0].rstrip(" ").lower()
        if base in _WINDOWS_RESERVED:
            raise PathRefused(f"reserved device name {s!r} is not allowed")
        if s.endswith(" ") or s.endswith("."):
            raise PathRefused("names may not end with a space or a dot")
    return "/".join(parts)


def _inside(root: Path, target: Path) -> bool:
    r = os.path.normcase(os.path.realpath(root))
    t = os.path.normcase(os.path.realpath(target))
    return t == r or t.startswith(r.rstrip(os.sep) + os.sep)


def host_path(root: Path, rel: str) -> Path:
    """Host path of a workspace file. Every existing component must be a real directory (no links)."""
    rel = safe_rel_path(rel)
    cur = Path(root)
    for part in rel.split("/"):
        cur = cur / part
        if os.path.lexists(cur) and os.path.islink(cur):
            raise PathRefused("symlinks are not allowed in the workspace")
    if not _inside(root, cur):
        raise PathRefused("path escapes the workspace")
    return cur


def write_files(root: Path, files: dict[str, bytes], file_cap: int, total_cap: int) -> None:
    """Write files into a host workspace (copy-in). Caps are checked against the resulting workspace size."""
    if len(files) > MAX_FILES:
        raise PathRefused(f"more than {MAX_FILES} files")
    for rel, data in files.items():
        if len(data) > file_cap:
            raise PathRefused(f"{safe_rel_path(rel)}: file larger than {file_cap // (1024 * 1024)} MB")
    for rel, data in files.items():
        target = host_path(root, rel)
        target.parent.mkdir(parents=True, exist_ok=True)
        if not _inside(root, target.parent):
            raise PathRefused("path escapes the workspace")
        tmp = target.with_name(target.name + ".agentos-tmp")
        tmp.write_bytes(data)
        os.replace(tmp, target)
    if dir_size(root) > total_cap:
        raise PathRefused(f"workspace larger than {total_cap // (1024 * 1024)} MB")


def dir_size(root: Path) -> int:
    total = 0
    for dirpath, _dirs, names in os.walk(root, followlinks=False):
        for n in names:
            try:
                total += os.lstat(os.path.join(dirpath, n)).st_size
            except OSError:
                pass
    return total


def read_dir(root: Path) -> dict[str, bytes]:
    """All regular files of a host workspace AgentOS controls (written only by write_files / copy-out)."""
    out: dict[str, bytes] = {}
    for dirpath, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(dirpath, d))]
        for n in names:
            full = os.path.join(dirpath, n)
            st = os.lstat(full)
            if stat.S_ISREG(st.st_mode):
                out[Path(os.path.relpath(full, root)).as_posix()] = Path(full).read_bytes()
    return out


class CopyOut:
    """Result of collecting a sandbox's workspace: accepted files, refused names (with reasons), cap status."""

    def __init__(self) -> None:
        self.files: dict[str, bytes] = {}
        self.refused: list[str] = []
        self.over_cap = False

    def _refuse(self, name: str, reason: str) -> None:
        self.refused.append(f"{name[:120]!r}: {reason}")


def _accept(out: CopyOut, name: str, size: int, read, file_cap: int, total_cap: int, seen: list[int]) -> None:
    try:
        rel = safe_rel_path(name)
    except PathRefused as e:
        out._refuse(name, str(e))
        return
    if size > file_cap:
        out._refuse(rel, f"larger than {file_cap // (1024 * 1024)} MB")
        return
    if seen[0] + size > total_cap:
        out.over_cap = True
        return
    if len(out.files) >= MAX_FILES:
        out._refuse(rel, f"more than {MAX_FILES} files")
        return
    data = read()
    if len(data) != size or len(data) > file_cap:
        out._refuse(rel, "size changed while copying")
        return
    seen[0] += size
    out.files[rel] = data


def collect_dir(root: Path, file_cap: int, total_cap: int) -> CopyOut:
    """Copy-out from a host directory the sandbox wrote (wasm backend). Uses lstat only; never follows links."""
    out = CopyOut()
    seen = [0]
    for dirpath, dirs, names in os.walk(root, followlinks=False):
        keep = []
        for d in dirs:
            full = os.path.join(dirpath, d)
            if os.path.islink(full):
                out._refuse(Path(os.path.relpath(full, root)).as_posix(), "symlink refused")
            else:
                keep.append(d)
        dirs[:] = keep
        for n in names:
            full = os.path.join(dirpath, n)
            rel = Path(os.path.relpath(full, root)).as_posix()
            st = os.lstat(full)
            if stat.S_ISLNK(st.st_mode):
                out._refuse(rel, "symlink refused")
            elif not stat.S_ISREG(st.st_mode):
                out._refuse(rel, "not a regular file (device, fifo or socket) refused")
            elif st.st_nlink > 1:
                out._refuse(rel, "hard link refused")
            else:
                _accept(out, rel, st.st_size, lambda f=full: Path(f).read_bytes(), file_cap, total_cap, seen)
    return out


def collect_tar(data: bytes, file_cap: int, total_cap: int) -> CopyOut:
    """Copy-out from a tar stream the sandbox produced (docker backend). Nothing is extracted to disk."""
    out = CopyOut()
    seen = [0]
    try:
        tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:")
    except tarfile.TarError:
        out._refuse("(archive)", "unreadable workspace archive")
        return out
    with tf:
        for m in tf:
            name = m.name
            if m.isdir():
                continue
            if m.issym():
                out._refuse(name, "symlink refused")
            elif m.islnk():
                out._refuse(name, "hard link refused")
            elif not m.isreg():
                out._refuse(name, "not a regular file refused")
            else:
                def _read(member=m) -> bytes:
                    fh = tf.extractfile(member)
                    return fh.read(file_cap + 1) if fh else b""

                _accept(out, name, m.size, _read, file_cap, total_cap, seen)
    return out


def make_tar(files: dict[str, bytes], extra: Iterable[tuple[str, bytes]] = ()) -> bytes:
    """Tar of validated workspace files (copy-in for the docker backend)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:", format=tarfile.PAX_FORMAT) as tf:
        for rel, data in [*files.items(), *extra]:
            info = tarfile.TarInfo(safe_rel_path(rel))
            info.size = len(data)
            info.mode = 0o600
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()
