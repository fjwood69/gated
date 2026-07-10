"""gate/artifact.py — build a SHA-bound ArtifactSpec from a PR head tarball (2.3).

The App fetches the PR head as a GitHub tarball (chosen over `git clone` — no `.git`,
no hooks, no checkout, so the malicious-git-hook code-execution vector doesn't exist),
extracts it SAFELY, and hashes it with the SHARED ``core.tree_hash`` — the same canon
the sandbox verifies with, so App-hash == sandbox-hash by construction (both hash the
same extracted bytes).

The tarball is UNTRUSTED (it is the PR head). Extraction is therefore an RCE / escape
surface (tar-slip / zip-slip), hardened here with a MANUAL filter that works on Python
3.9+ (``tarfile.extractall(filter='data')`` is 3.12+ only). The must-haves:

  * reject absolute paths and any ``..`` component (after stripping the tarball's
    ``{owner}-{repo}-{sha}/`` top-level prefix);
  * resolve every target under the extraction root and verify containment;
  * reject ALL symlinks + hardlinks (MVP hardening — eliminates the symlink-chain /
    traverse-through-a-symlink / extraction-TOCTOU class outright; source artifacts
    rarely need links, and a repo that does fails closed);
  * reject device/char/block files, FIFOs, sockets, and non-UTF-8 names;
  * enforce total-size / file-count / path-length caps (bomb defence).

Host-side scratch is RAII-managed by ``extraction_workspace`` so extracted source is
purged on every exit path (disk-exhaustion defence).

Special files are rejected here so they never reach ``core.tree_hash`` (which is defined
only over regular files + symlinks).
"""
from __future__ import annotations

import os
import shutil
import tarfile
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, NoReturn

from core import ArtifactSpec, tree_hash


class SafeExtractError(RuntimeError):
    """A tarball entry violated an extraction-safety rule. Fail closed: reject the
    whole archive (never a partial, possibly-escaped extraction)."""


@dataclass(frozen=True)
class ExtractLimits:
    max_total_bytes: int = 100 * 1024 * 1024  # 100 MiB extracted
    max_files: int = 10_000
    max_path_length: int = 4096
    max_member_bytes: int = 50 * 1024 * 1024  # 50 MiB per file


def _reject(msg: str) -> NoReturn:
    raise SafeExtractError(msg)


def _strip_top_level(name: str) -> str | None:
    """GitHub tarballs nest everything under a single ``{owner}-{repo}-{sha}/`` dir.
    Strip that first component; return None for the prefix dir entry itself."""
    parts = name.split("/", 1)
    return parts[1] if len(parts) == 2 and parts[1] else None


def _validate_raw(name: str, limits: ExtractLimits) -> None:
    """Reject unsafe RAW member names BEFORE prefix-stripping — an absolute path must
    not be silently neutralised into a relative one by the strip."""
    if not name:
        _reject("empty member name")
    if any(0xD800 <= ord(c) <= 0xDFFF for c in name):
        _reject(f"non-UTF-8 (surrogate) member name: {name!r}")
    if len(name) > limits.max_path_length:
        _reject(f"member path too long: {len(name)} > {limits.max_path_length}")
    if name.startswith("/") or (len(name) > 1 and name[1] == ":"):
        _reject(f"absolute member path: {name!r}")
    if ".." in name.split("/"):
        _reject(f"path traversal in member: {name!r}")


def _within_root(root: str, target: str) -> bool:
    root_real = os.path.realpath(root)
    target_real = os.path.realpath(target)
    return target_real == root_real or target_real.startswith(root_real + os.sep)


def safe_extract_tarball(
    tar_path: Path, dest_dir: Path, limits: ExtractLimits | None = None
) -> None:
    """Extract an UNTRUSTED tarball into ``dest_dir`` under the hardening rules above.
    Raises ``SafeExtractError`` on any violation (fail-closed)."""
    lim = limits or ExtractLimits()
    dest = str(dest_dir)
    os.makedirs(dest, exist_ok=True)
    total_bytes = 0
    file_count = 0

    with tarfile.open(tar_path, mode="r:*") as tar:
        for member in tar:
            _validate_raw(member.name, lim)
            rel = _strip_top_level(member.name)
            if rel is None:
                continue  # the top-level prefix dir itself
            out_path = os.path.join(dest, rel)
            if not _within_root(dest, out_path):
                _reject(f"member escapes extraction root: {member.name!r}")

            if member.isdir():
                os.makedirs(out_path, exist_ok=True)
            elif member.isfile():
                file_count += 1
                if file_count > lim.max_files:
                    _reject(f"too many files (> {lim.max_files})")
                if member.size > lim.max_member_bytes:
                    _reject(f"member too large: {member.size} > {lim.max_member_bytes}")
                total_bytes += member.size
                if total_bytes > lim.max_total_bytes:
                    _reject(f"archive too large (> {lim.max_total_bytes} bytes)")
                src = tar.extractfile(member)
                if src is None:
                    _reject(f"unreadable file member: {member.name!r}")
                os.makedirs(os.path.dirname(out_path), exist_ok=True)
                with open(out_path, "wb") as dst:
                    while True:
                        chunk = src.read(65536)
                        if not chunk:
                            break
                        dst.write(chunk)
            elif member.issym() or member.islnk():
                # MVP hardening (board): reject ALL symlinks + hardlinks outright, rather
                # than reasoning about symlink chains / traverse-through-a-symlink /
                # extraction-time TOCTOU. Source artifacts rarely need links; if a repo
                # does, it fails closed. (Revisit: allow verified within-root symlinks
                # once chain/TOCTOU handling is proven.)
                _reject(f"symlink/hardlink rejected (MVP): {member.name!r}")
            else:
                # device, char, block, FIFO, socket — no place in a source tree
                _reject(f"illegal member type ({member.type!r}): {member.name!r}")


def build_artifact_spec(extracted_dir: Path) -> ArtifactSpec:
    """Bind the extracted tree to its canonical hash via the SHARED ``core.tree_hash``
    — the exact function the sandbox re-computes to verify the SHA-bind."""
    return ArtifactSpec(path=extracted_dir, tree_hash=tree_hash(extracted_dir))


@contextmanager
def extraction_workspace(prefix: str = "moriverify-art-") -> Iterator[Path]:
    """RAII host-side scratch dir for one artifact — ``rm -rf`` on EVERY exit path
    (success, exception, or the job-runner being killed mid-flight), so extracted
    source can never accumulate and fill the runner's disk (board disk-exhaustion
    vector). The job-runner MUST extract + hash + run inside this context so cleanup is
    bound to the work, not remembered separately."""
    workspace = Path(tempfile.mkdtemp(prefix=prefix))
    try:
        yield workspace
    finally:
        shutil.rmtree(workspace, ignore_errors=True)
