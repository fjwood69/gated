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
import unicodedata
from typing import Any, Mapping

# The chain format version. Bump ONLY with a migration — never re-hash live ledgers silently.
CHAIN_VERSION = 1

# The canonical-digest format version (3.5-close identity/receipt binder — see ``canonical_digest``).
# INDEPENDENT of CHAIN_VERSION: bumping it re-derives 3.5-close identity digests, never the ledgers.
CANONICAL_DIGEST_VERSION = 1

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


class NonCanonicalValueError(ValueError):
    """A value in a canonical-digest payload cannot be canonically + deterministically serialized —
    3.5-close: identity/receipt digests SCHEMA-VALIDATE before hashing. Floats are rejected (their
    representation is ambiguous — use integer units, e.g. ``threshold_milli``); only str / int / bool /
    None / list / dict of the same are permitted. ``None`` (explicit null) is a valid, distinct value —
    it is NOT the same as an absent key."""


def _normalise_canonical(value: object, path: str = "$") -> Any:
    """Validate + normalise a value for ``canonical_digest``: reject floats + unknown types, and
    NFC-normalise every string (so NFC/NFD forms of the same text hash identically). ``bool`` is checked
    before ``int`` (bool is an int subclass)."""
    if isinstance(value, bool):
        return value
    if value is None or isinstance(value, int):
        return value
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, float):
        raise NonCanonicalValueError(
            f"{path}: float values are not canonical (representation is ambiguous — use integer units); "
            f"got {value!r}"
        )
    if isinstance(value, Mapping):
        out: dict[str, Any] = {}
        for k, v in value.items():
            if not isinstance(k, str):
                raise NonCanonicalValueError(f"{path}: map keys must be str, got {type(k).__name__}")
            out[unicodedata.normalize("NFC", k)] = _normalise_canonical(v, f"{path}.{k}")
        return out
    if isinstance(value, (list, tuple)):
        return [_normalise_canonical(v, f"{path}[{i}]") for i, v in enumerate(value)]
    raise NonCanonicalValueError(f"{path}: unsupported type {type(value).__name__} for canonical digest")


def canonical_bytes(domain: str, payload: Mapping[str, Any], *, version: int = CANONICAL_DIGEST_VERSION) -> bytes:
    """The public, versioned CANONICAL BYTE ENCODING (``gated.canonical.v1``) that underlies every 3.5-close
    identity/receipt digest. Extracted VERBATIM from ``canonical_digest`` (behaviour-preserving, A2a): the
    payload is schema-validated + NFC-normalised, wrapped in a ``{domain, version, payload}`` envelope, and
    serialised with FROZEN JSON settings (``sort_keys`` + compact separators + ``ensure_ascii=False`` +
    utf-8). Exposing the BYTES (not only their hash) lets ``canonical_digest`` be defined as
    ``sha256(canonical_bytes(...))`` and lets a companion repo pin the exact byte vectors (cross-repo
    contract). Rejects the SAME non-canonical inputs (floats, non-str keys, unknown types) at the SAME
    point via ``_normalise_canonical`` — so error timing/types are unchanged. Do NOT alter the JSON settings
    or the envelope shape without a version bump: the bytes ARE the contract."""
    normalised = _normalise_canonical(dict(payload))
    envelope = {"domain": domain, "version": version, "payload": normalised}
    return json.dumps(envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def canonical_digest(domain: str, payload: Mapping[str, Any], *, version: int = CANONICAL_DIGEST_VERSION) -> str:
    """A CANONICAL + DETERMINISTIC identity digest (3.5-close) = ``sha256(canonical_bytes(...))`` —
    domain-separated + versioned, with the payload schema-validated + NFC-normalised BEFORE hashing. NOT
    "non-malleable" (a digest is only as strong as the schema it validates); it is *canonical and
    deterministic*: reordered maps hash identically, ``None`` differs from an absent key, floats are
    rejected, and NFC/NFD forms coincide. DISTINCT from ``content_digest`` (the FROZEN ledger wire format):
    this binder may version independently. Domain separation means a profile digest can never be confused
    with an envelope or a trust-policy digest (each passes a distinct ``domain``). A2a: this is now a thin
    wrapper over ``canonical_bytes`` — byte-for-byte identical output to before the extraction."""
    return hashlib.sha256(canonical_bytes(domain, payload, version=version)).hexdigest()


__all__ = [
    "CHAIN_VERSION",
    "CANONICAL_DIGEST_VERSION",
    "GENESIS_HASH",
    "content_digest",
    "chain_hash",
    "canonical_bytes",
    "canonical_digest",
    "NonCanonicalValueError",
]
