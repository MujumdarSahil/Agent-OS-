"""The pinned CPython WASI build for the wasm backend (3.5, D5).

Pinned by URL + sha256. Downloaded ONLY by an explicit admin action (``agentos sandbox install-wasm`` or the Settings
button), never when a run starts. The hash is verified before the file is moved into place (a mismatch is refused
and the download deleted) and again every time the build is loaded.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
import urllib.request
from pathlib import Path
from typing import Callable, Optional

from agentos.sandbox.models import SandboxError

WASM_URL = ("https://github.com/vmware-labs/webassembly-language-runtimes/releases/download/"
            "python%2F3.12.0%2B20231211-040d5a6/python-3.12.0.wasm")
WASM_SHA256 = "e5dc5a398b07b54ea8fdb503bf68fb583d533f10ec3f930963e02b9505f7a763"
WASM_SIZE = 26_267_204
WASM_FILE = "python-3.12.0.wasm"
PYTHON_VERSION = "3.12.0"
MAX_DOWNLOAD = 64 * 1024 * 1024


class WasmBuildError(SandboxError):
    pass


def wasm_dir(data_dir: Path) -> Path:
    return Path(data_dir) / "sandbox" / "wasm"


def build_path(data_dir: Path) -> Path:
    return wasm_dir(data_dir) / WASM_FILE


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def verified_build(data_dir: Path) -> Optional[Path]:
    """The installed build if present AND its sha256 matches the pin (checked on every load), else None."""
    p = build_path(data_dir)
    if not p.is_file():
        return None
    if sha256_file(p) != WASM_SHA256:
        return None
    return p


def build_state(data_dir: Path) -> str:
    """'installed' | 'missing' | 'tampered' (present but the hash does not match: never used)."""
    p = build_path(data_dir)
    if not p.is_file():
        return "missing"
    return "installed" if sha256_file(p) == WASM_SHA256 else "tampered"


def _default_fetch(url: str, dest: Path) -> None:
    req = urllib.request.Request(url, headers={"User-Agent": "agentos-sandbox-installer"})
    with urllib.request.urlopen(req, timeout=60) as resp, open(dest, "wb") as out:  # noqa: S310 (pinned https URL)
        total = 0
        while True:
            chunk = resp.read(1 << 20)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_DOWNLOAD:
                raise WasmBuildError("download larger than expected; refused")
            out.write(chunk)


def install(data_dir: Path, fetch: Optional[Callable[[str, Path], None]] = None,
            url: str = WASM_URL, expected_sha256: str = WASM_SHA256) -> Path:
    """Download the pinned build, verify its sha256, then move it into place. A mismatch is refused and the
    downloaded file deleted; an already-installed, verified build is kept."""
    target_dir = wasm_dir(data_dir)
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / WASM_FILE
    if target.is_file() and sha256_file(target) == expected_sha256:
        return target
    fd, tmp_name = tempfile.mkstemp(prefix="download-", suffix=".part", dir=target_dir)
    os.close(fd)
    tmp = Path(tmp_name)
    try:
        (fetch or _default_fetch)(url, tmp)
        got = sha256_file(tmp)
        if got != expected_sha256:
            raise WasmBuildError(f"wasm build hash mismatch (expected {expected_sha256[:12]}..., got {got[:12]}...); "
                                 f"the download was refused and deleted")
        os.replace(tmp, target)
        return target
    finally:
        if tmp.exists():
            tmp.unlink()


def wasmtime_version() -> Optional[str]:
    try:
        from importlib.metadata import version

        return version("wasmtime")
    except Exception:
        return None
