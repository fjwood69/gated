"""Increment 2.3 (chunk 1) — safe tarball extraction + the canonicalisation corpus.

Run from the gated/ root:  python3 -m unittest discover -s tests

Two ship-gates:
  * ADVERSARIAL extraction — malicious tarballs (tar-slip, symlink-escape, special
    files, bombs) MUST be rejected (fail-closed). The tarball is the untrusted PR head.
  * CANONICALISATION CORPUS — the App's ArtifactSpec hash == the SHARED core.tree_hash
    the sandbox verifies with, and that hash is deterministic + well-defined across the
    trap cases (unicode, symlinks, empty dirs, line endings, permission bits).
"""
from __future__ import annotations

import io
import os
import tarfile
import tempfile
import unittest
from pathlib import Path

from core import tree_hash
from gate.artifact import (
    ExtractLimits,
    SafeExtractError,
    build_artifact_spec,
    extraction_workspace,
    safe_extract_tarball,
)

_PREFIX = "acme-widgets-deadbeef"  # GitHub's {owner}-{repo}-{sha} top-level dir


def _tar(path: Path, build) -> None:  # type: ignore[no-untyped-def]
    with tarfile.open(path, "w") as tar:
        build(tar)


def _add_file(tar: tarfile.TarFile, name: str, data: bytes) -> None:
    ti = tarfile.TarInfo(name)
    ti.type = tarfile.REGTYPE
    ti.size = len(data)
    tar.addfile(ti, io.BytesIO(data))


def _add_dir(tar: tarfile.TarFile, name: str) -> None:
    ti = tarfile.TarInfo(name.rstrip("/") + "/")
    ti.type = tarfile.DIRTYPE
    ti.mode = 0o755
    tar.addfile(ti)


def _add_symlink(tar: tarfile.TarFile, name: str, target: str) -> None:
    ti = tarfile.TarInfo(name)
    ti.type = tarfile.SYMTYPE
    ti.linkname = target
    tar.addfile(ti)


def _add_dev(tar: tarfile.TarFile, name: str) -> None:
    ti = tarfile.TarInfo(name)
    ti.type = tarfile.CHRTYPE
    tar.addfile(ti)


class SafeExtractAdversarialTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="mv-extract-"))
        self.tar = self.tmp / "a.tar"
        self.dest = self.tmp / "out"

    def _expect_reject(self) -> None:
        with self.assertRaises(SafeExtractError):
            safe_extract_tarball(self.tar, self.dest)

    def test_path_traversal_rejected(self) -> None:
        _tar(self.tar, lambda t: _add_file(t, f"{_PREFIX}/../evil", b"x"))
        self._expect_reject()

    def test_absolute_path_rejected(self) -> None:
        _tar(self.tar, lambda t: _add_file(t, "/etc/evil", b"x"))
        self._expect_reject()

    def test_symlink_escape_rejected(self) -> None:
        _tar(self.tar, lambda t: _add_symlink(t, f"{_PREFIX}/link", "../../../../etc/passwd"))
        self._expect_reject()

    def test_absolute_symlink_rejected(self) -> None:
        _tar(self.tar, lambda t: _add_symlink(t, f"{_PREFIX}/link", "/etc/passwd"))
        self._expect_reject()

    def test_device_file_rejected(self) -> None:
        _tar(self.tar, lambda t: _add_dev(t, f"{_PREFIX}/null"))
        self._expect_reject()

    def test_file_count_cap_rejected(self) -> None:
        def build(t: tarfile.TarFile) -> None:
            for i in range(5):
                _add_file(t, f"{_PREFIX}/f{i}", b"x")
        _tar(self.tar, build)
        with self.assertRaises(SafeExtractError):
            safe_extract_tarball(self.tar, self.dest, ExtractLimits(max_files=3))

    def test_total_size_cap_rejected(self) -> None:
        _tar(self.tar, lambda t: _add_file(t, f"{_PREFIX}/big", b"x" * 5000))
        with self.assertRaises(SafeExtractError):
            safe_extract_tarball(self.tar, self.dest, ExtractLimits(max_total_bytes=1000))


class SafeExtractHappyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="mv-extract-ok-"))
        self.tar = self.tmp / "a.tar"
        self.dest = self.tmp / "out"

    def test_extracts_and_strips_prefix(self) -> None:
        def build(t: tarfile.TarFile) -> None:
            _add_dir(t, _PREFIX)
            _add_file(t, f"{_PREFIX}/main.py", b"print('hi')\n")
            _add_dir(t, f"{_PREFIX}/pkg")
            _add_file(t, f"{_PREFIX}/pkg/mod.py", b"x = 1\n")
        _tar(self.tar, build)
        safe_extract_tarball(self.tar, self.dest)
        self.assertTrue((self.dest / "main.py").is_file())
        self.assertTrue((self.dest / "pkg" / "mod.py").is_file())
        self.assertFalse((self.dest / _PREFIX).exists())  # prefix stripped

    def test_any_symlink_rejected_mvp(self) -> None:
        # MVP hardening: even a within-tree symlink is rejected (eliminates the whole
        # symlink-chain / traverse-through-a-symlink class).
        def build(t: tarfile.TarFile) -> None:
            _add_file(t, f"{_PREFIX}/real.txt", b"data\n")
            _add_symlink(t, f"{_PREFIX}/link.txt", "real.txt")
        _tar(self.tar, build)
        with self.assertRaises(SafeExtractError):
            safe_extract_tarball(self.tar, self.dest)


class CanonicalisationCorpusTests(unittest.TestCase):
    """App hash == the shared core.tree_hash, deterministic across the trap cases."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="mv-canon-"))

    def _tree(self, name: str) -> Path:
        d = self.tmp / name
        d.mkdir()
        return d

    def test_app_spec_uses_shared_hash(self) -> None:
        d = self._tree("t")
        (d / "a.py").write_bytes(b"x = 1\n")
        spec = build_artifact_spec(d)
        self.assertEqual(spec.tree_hash, tree_hash(d))  # App == sandbox canon
        self.assertEqual(spec.path, d)

    def test_deterministic(self) -> None:
        d = self._tree("t")
        (d / "a.py").write_bytes(b"content\n")
        (d / "b.py").write_bytes(b"more\n")
        self.assertEqual(tree_hash(d), tree_hash(d))

    def test_permission_bits_ignored(self) -> None:
        d = self._tree("t")
        f = d / "a.py"
        f.write_bytes(b"x = 1\n")
        h1 = tree_hash(d)
        os.chmod(f, 0o777)
        self.assertEqual(tree_hash(d), h1)  # perms excluded from the canon

    def test_line_endings_are_content(self) -> None:
        crlf = self._tree("crlf")
        (crlf / "a.py").write_bytes(b"x = 1\r\n")
        lf = self._tree("lf")
        (lf / "a.py").write_bytes(b"x = 1\n")
        self.assertNotEqual(tree_hash(crlf), tree_hash(lf))  # CRLF != LF (content differs)

    def test_empty_dirs_excluded(self) -> None:
        with_empty = self._tree("we")
        (with_empty / "a.py").write_bytes(b"x\n")
        (with_empty / "emptydir").mkdir()
        (with_empty / "nested" / "deep").mkdir(parents=True)
        without = self._tree("wo")
        (without / "a.py").write_bytes(b"x\n")
        self.assertEqual(tree_hash(with_empty), tree_hash(without))  # empty dirs contribute nothing

    def test_unicode_name_roundtrips_and_is_deterministic(self) -> None:
        d = self._tree("u")
        (d / "café.py").write_bytes(b"x\n")  # non-ASCII
        h1 = tree_hash(d)
        self.assertEqual(tree_hash(d), h1)
        self.assertEqual(build_artifact_spec(d).tree_hash, h1)

    def test_dangling_symlink_recorded_not_read(self) -> None:
        d = self._tree("d")
        os.symlink("does_not_exist", d / "link")
        # hashes deterministically as L:target without reading the (missing) target
        self.assertEqual(tree_hash(d), tree_hash(d))

    def test_extract_then_hash_matches_direct_hash(self) -> None:
        # round-trip: a tree tar'd -> safe-extracted -> hashed == the original tree hash
        src = self._tree("src")
        (src / "a.py").write_bytes(b"alpha\n")
        (src / "pkg").mkdir()
        (src / "pkg" / "b.py").write_bytes(b"beta\n")
        direct = tree_hash(src)

        tarp = self.tmp / "rt.tar"
        with tarfile.open(tarp, "w") as tar:
            for name in ["a.py", "pkg/b.py"]:
                _add_file(tar, f"{_PREFIX}/{name}", (src / name).read_bytes())
        dest = self.tmp / "rt-out"
        safe_extract_tarball(tarp, dest)
        self.assertEqual(tree_hash(dest), direct)  # extraction preserves the canon

    def test_extraction_workspace_purges_on_exception(self) -> None:
        # RAII: the host-side scratch dir is rm -rf'd even when the job raises mid-flight
        captured: Path | None = None
        with self.assertRaises(RuntimeError):
            with extraction_workspace() as ws:
                captured = ws
                (ws / "extracted.py").write_bytes(b"x\n")
                self.assertTrue(ws.exists())
                raise RuntimeError("job died mid-check")
        assert captured is not None
        self.assertFalse(captured.exists())  # purged despite the exception


if __name__ == "__main__":
    unittest.main()
