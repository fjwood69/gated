"""core/chain.py — the append-only tamper-evident hash-chain primitive.

Pure, stdlib-only (hashlib + json). The shared low-level building block for every append-only
tamper-evident ledger in gated — the gate's override ledger (C3) and the calibration-set
store (3.2) — so BOTH consume the same proven chain math WITHOUT importing each other. `core`
imports neither `engine` nor `gate`, so the extractability + engine⊥gate invariants hold by
construction (verified by gitnexus + an import-linter rule).

A chain is a sequence of records; each carries a ``content_digest`` (a canonical hash of its own
semantic fields) and a ``record_hash = chain_hash(prev_record_hash, content_digest)``. Editing,
removing, or reordering any record breaks every subsequent ``record_hash`` — the tamper-evidence
property. The first record chains from ``GENESIS_HASH``.

FROZEN WIRE FORMAT (the load-bearing constraint). The canonicalisation — ``sort_keys`` + compact
separators + utf-8 + sha256 — IS the on-disk format. It MUST NOT drift: a change to key ordering,
separators, or encoding re-hashes every historical record and silently invalidates live ledger
data (C3 has real HUMAN_OVERRIDE records on disk). Byte-level golden tests pin the exact output;
if the algorithm must ever change it is a new ``CHAIN_VERSION`` with a migration, never a silent
edit. (This module was extracted hash-preserving from ``gate/ledger.py`` — the golden tests +
the unchanged C3 ledger suite prove the bytes did not move.)
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping

# The chain format version. Bump ONLY with a migration — never re-hash live ledgers silently.
CHAIN_VERSION = 1

# The chain root — the prev_hash of the first record. A fixed, public constant.
GENESIS_HASH = "0" * 64


def content_digest(fields: Mapping[str, Any]) -> str:
    """Canonical content hash of a record's semantic fields. Canonicalisation is FROZEN
    (sort_keys + compact separators + utf-8 + sha256) — see the module docstring."""
    canonical = json.dumps(dict(fields), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def chain_hash(prev_hash: str, digest: str) -> str:
    """Link a record into the chain: ``sha256(prev_record_hash + content_digest)``."""
    return hashlib.sha256((prev_hash + digest).encode("utf-8")).hexdigest()


__all__ = ["CHAIN_VERSION", "GENESIS_HASH", "content_digest", "chain_hash"]
