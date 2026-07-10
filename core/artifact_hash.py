"""Canonical artifact-tree hashing — the shared definition of ``ArtifactSpec.tree_hash``.

This is THE single canonicalisation spec that the engine and every sandbox backend
MUST use, so a hash computed on one side equals the other. Reimplementing it
elsewhere is a bug (board rider to the 1.2 SHA-bind ruling: write the canon once,
in core/, shared — else a Windows path separator produces a maddening hash-mismatch
at 1.3).

Canonicalisation — deterministic and cross-platform:
  * Walk regular files recursively; each path is made relative to the tree root and
    normalised to ``/`` separators (Windows ``\\`` -> ``/``).
  * Entries are sorted lexicographically by their normalised relative path (UTF-8).
  * Each regular file contributes ``F:`` + a streamed content hash.
  * Symlinks are NOT followed — a symlinked file contributes ``L:`` + its target
    string, never the pointed-at bytes (prevents escaping the tree to hash host
    files). Symlinked directories are not traversed (documented limitation; revisit
    for HERMETIC).
  * Empty directories and file permissions are EXCLUDED (avoid cross-platform churn;
    a verdict binds to content + structure).
  * The per-entry (relpath, digest) pairs are concatenated in sorted order and hashed
    once more -> a single Merkle-style root.

Returns ``"sha256:<hex>"``.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

_ALGO = "sha256"
_CHUNK = 65536


class ArtifactHashMismatchError(Exception):
    """Raised when a staged tree's canonical hash does not equal the claimed
    ``ArtifactSpec.tree_hash``. The SHA-bind refuses to certify unverified bytes:
    on mismatch, no ``SandboxHandle`` is returned and execution never starts."""


def _hash_file(path: Path) -> str:
    h = hashlib.new(_ALGO)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def tree_hash(root: Path) -> str:
    """Canonical hash of an artifact tree (see module docstring). Deterministic
    and cross-platform. Raises FileNotFoundError if ``root`` does not exist."""
    root = Path(root)
    if not root.exists():
        raise FileNotFoundError(root)

    entries: list[tuple[str, str]] = []
    if root.is_file():
        entries.append(("", "F:" + _hash_file(root)))
    else:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames.sort()  # stable traversal (order doesn't affect the sorted hash)
            for name in filenames:
                full = Path(dirpath) / name
                rel = full.relative_to(root).as_posix()  # '/' separators, cross-OS
                if full.is_symlink():
                    entries.append((rel, "L:" + os.readlink(full)))
                else:
                    entries.append((rel, "F:" + _hash_file(full)))

    entries.sort(key=lambda e: e[0].encode("utf-8"))
    root_h = hashlib.new(_ALGO)
    for rel, digest in entries:
        root_h.update(rel.encode("utf-8"))
        root_h.update(b"\0")
        root_h.update(digest.encode("utf-8"))
        root_h.update(b"\0")
    return f"{_ALGO}:{root_h.hexdigest()}"
