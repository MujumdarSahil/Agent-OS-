"""3.5 sandbox path rules and copy-out (MOCK: pure functions, temp dirs only)."""

from __future__ import annotations

import io
import os
import tarfile

import pytest

from agentos.sandbox import paths
from agentos.sandbox.paths import PathRefused, safe_rel_path

MB = 1024 * 1024


@pytest.mark.parametrize("ok,expected", [
    ("data.csv", "data.csv"), ("out/r.txt", "out/r.txt"), ("a\\b.txt", "a/b.txt"), ("./x/./y.txt", "x/y.txt"),
    ("dir/sub/file.json", "dir/sub/file.json"),
])
def test_relative_paths_accepted(ok, expected):
    assert safe_rel_path(ok) == expected


@pytest.mark.parametrize("bad", [
    "/etc/passwd", "//server/share/x", "\\\\server\\share\\x", "\\\\?\\C:\\x", "C:\\Windows\\x", "C:/x", "C:x",
    "../x", "a/../../b", "a\\..\\..\\b", "..", "x/..", "file.txt:stream", "nul", "CON.txt", "dir/aux", "com1",
    "a\x00b", "a\nb", "", "   ", "trailing. ", "x" * 300, None, 42,
])
def test_escapes_refused_posix_and_windows_forms(bad):
    with pytest.raises(PathRefused):
        safe_rel_path(bad)


def test_write_files_caps_and_never_escapes(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    paths.write_files(ws, {"a/b.txt": b"hi"}, 10 * MB, 50 * MB)
    assert (ws / "a" / "b.txt").read_bytes() == b"hi"
    with pytest.raises(PathRefused):
        paths.write_files(ws, {"../outside.txt": b"x"}, 10 * MB, 50 * MB)
    assert not (tmp_path / "outside.txt").exists()
    with pytest.raises(PathRefused):
        paths.write_files(ws, {"big.bin": b"0" * (2 * MB)}, 1 * MB, 50 * MB)
    with pytest.raises(PathRefused):
        paths.write_files(ws, {"x.bin": b"0" * (3 * MB)}, 10 * MB, 2 * MB)


def test_write_through_symlink_refused(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    try:
        os.symlink(outside, ws / "link", target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("creating symlinks is not permitted here")
    with pytest.raises(PathRefused):
        paths.write_files(ws, {"link/evil.txt": b"x"}, MB, MB)
    assert not (outside / "evil.txt").exists()


def _tar(members):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:") as tf:
        for m, data in members:
            tf.addfile(m, io.BytesIO(data) if data is not None else None)
    return buf.getvalue()


def _reg(name, data):
    ti = tarfile.TarInfo(name)
    ti.size = len(data)
    return ti, data


def test_collect_tar_refuses_links_traversal_devices_and_caps():
    sym = tarfile.TarInfo("escape")
    sym.type, sym.linkname = tarfile.SYMTYPE, "/etc/passwd"
    hard = tarfile.TarInfo("hard")
    hard.type, hard.linkname = tarfile.LNKTYPE, "ok.txt"
    dev = tarfile.TarInfo("dev")
    dev.type = tarfile.CHRTYPE
    data = _tar([_reg("ok.txt", b"fine"), _reg("../../evil.txt", b"x"), _reg("/abs.txt", b"x"),
                 _reg("C:/win.txt", b"x"), (sym, None), (hard, None), (dev, None), _reg("big.bin", b"0" * 2048)])
    out = paths.collect_tar(data, file_cap=1024, total_cap=10 * MB)
    assert out.files == {"ok.txt": b"fine"}
    joined = " ".join(out.refused)
    for what in ("evil.txt", "abs.txt", "win.txt", "symlink refused", "hard link refused", "not a regular file",
                 "big.bin"):
        assert what in joined, what


def test_collect_tar_total_cap_marks_over_cap():
    data = _tar([_reg(f"f{i}.bin", b"0" * 600) for i in range(5)])
    out = paths.collect_tar(data, file_cap=1024, total_cap=2000)
    assert out.over_cap


def test_collect_dir_refuses_symlinks_and_hardlinks(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "ok.txt").write_text("fine")
    secret = tmp_path / "host-secret.txt"
    secret.write_text("HOST")
    made_link = True
    try:
        os.symlink(secret, ws / "sym.txt")
    except (OSError, NotImplementedError):
        made_link = False
    os.link(ws / "ok.txt", ws / "hard.txt")
    out = paths.collect_dir(ws, file_cap=MB, total_cap=10 * MB)
    assert "HOST" not in str(out.files.values())
    assert set(out.files) == set()  # ok.txt and hard.txt share an inode: both refused
    joined = " ".join(out.refused)
    assert "hard link refused" in joined
    if made_link:
        assert "symlink refused" in joined
