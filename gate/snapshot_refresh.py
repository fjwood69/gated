"""gate/snapshot_refresh.py — 3.4 close-4: the generation-locked snapshot refresh.

Mints the signed fallback snapshot atomically and durably, and completes close-3's fallback
guarantee (only head-CURRENT enabled policies are attested, each carrying its per-set oracle_head,
so a drifted set invalidates the fallback exactly as the live path). Two coupled jobs:

  * PAIRED-EPOCH compare-and-swap. The epoch = (policy-store tier head, calibration-store head). It
    changes on ANY tier transition (enable/disable) OR fixture append. The refresh reads the epoch,
    mints from the enabled-set, and commits (atomic swap) ONLY if the epoch is unchanged across the
    read+mint — an EXACT-set guarantee (a policy disabled mid-mint moves the tier head -> retry). It
    NEVER blocks the store write path (optimistic CAS, bounded retry + backoff); on repeated
    contention it fails LOUD and leaves the prior snapshot in place (never swaps a stale one).

  * POSIX durability. Write to a temp file, fsync it, ``os.replace`` (atomic), then FSYNC THE PARENT
    DIRECTORY — else a crash after the rename can lose the directory-entry update and revert the
    file. Only after the swap is the mint committed.

Dependency-inverted for testability + layering (engine⊥gate holds — this is pure gate-side
orchestration): the epoch reader and the enabled-attestations builder are INJECTED; production wires
them to the policy + calibration stores, tests inject fakes.
"""
from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Callable, Mapping, TypeVar

from gate.snapshot import (
    AttestationRecord,
    CalibrationSnapshot,
    from_json,
    issue_snapshot,
    prune_and_resign,
    to_json,
)

_T = TypeVar("_T")

# read_epoch() -> an opaque, comparable epoch (e.g. (tier_head, calibration_head)). Changes on any
# tier transition or fixture append.
EpochReader = Callable[[], object]
# enabled_attestations() -> {policy_id: AttestationRecord} for the currently-ENABLED, head-CURRENT
# policies ONLY (a policy whose set drifted is EXCLUDED, so the fallback fails closed for it).
AttestationBuilder = Callable[[], Mapping[str, AttestationRecord]]


class RefreshContention(RuntimeError):
    """The refresh could not mint a snapshot under a stable epoch within the retry budget. Fails
    LOUD; the prior snapshot is left in place (never swapped) and rides its freshness horizon."""


def _atomic_write(path: str, data: str) -> None:
    """Durable atomic replace: temp -> fsync(temp) -> os.replace -> fsync(parent dir). The parent
    fsync is the load-bearing POSIX detail — without it a crash after the rename can lose the
    directory-entry update and revert to the old file."""
    directory = os.path.dirname(os.path.abspath(path))
    tmp = f"{path}.tmp.{os.getpid()}"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)  # atomic on POSIX
    dir_fd = os.open(directory, os.O_DIRECTORY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def refresh_snapshot(
    *,
    read_epoch: EpochReader,
    enabled_attestations: AttestationBuilder,
    key: bytes,
    now: float,
    path: str,
    valid_for_seconds: float = 300.0,
    max_retries: int = 3,
    backoff: Callable[[int], None] = lambda attempt: time.sleep(min(0.05 * (2 ** attempt), 1.0)),
) -> CalibrationSnapshot:
    """Mint + atomically swap the fallback snapshot under a paired-epoch CAS. Commits ONLY if the
    epoch is stable across the read+mint (exact-set); otherwise retries with backoff, and after
    ``max_retries`` raises ``RefreshContention`` WITHOUT swapping (prior snapshot intact). Returns
    the committed snapshot."""
    for attempt in range(max_retries + 1):
        epoch = read_epoch()
        records = dict(enabled_attestations())  # only head-CURRENT enabled policies
        if read_epoch() != epoch:
            # a tier transition or fixture append landed during the read/mint -> the mint may be
            # stale (exact-set violated). Back off and retry; do NOT swap.
            backoff(attempt)
            continue
        snapshot = issue_snapshot(records, key=key, now=now, valid_for_seconds=valid_for_seconds)
        _atomic_write(path, to_json(snapshot))  # commit — epoch was stable through the mint
        return snapshot
    raise RefreshContention(
        f"snapshot refresh did not converge under a stable epoch in {max_retries + 1} attempts — "
        "prior snapshot left in place (rides its freshness horizon)"
    )


def invalidate_fallback_for_set(snapshot_path: str, *, set_id: str, key: bytes) -> None:
    """SYNCHRONOUSLY revoke the fallback attestations for ``set_id`` — durably, in place. Called
    BEFORE an oracle append commits (via ``commit_fixture_append``): after this returns, the
    persisted snapshot no longer attests any policy bound to ``set_id``, so during a TOTAL outage
    (both stores down) a drifted policy is absent -> fails closed, instead of stale-enforcing the
    pre-append head. Optimistic refresh cannot provide this — only synchronous invalidation closes
    the both-stores-down window. Raises (propagating) on any I/O failure so the caller ABORTS the
    append. No-op if no snapshot exists yet."""
    if not os.path.exists(snapshot_path):
        return
    snapshot = from_json(Path(snapshot_path).read_text(encoding="utf-8"))
    pruned = prune_and_resign(snapshot, drop_set_id=set_id, key=key)
    _atomic_write(snapshot_path, to_json(pruned))  # temp -> fsync -> os.replace -> fsync parent dir


def commit_fixture_append(*, invalidate: Callable[[], None], append: Callable[[], _T]) -> _T:
    """Enforce the ordering the fallback correctness depends on: durably REVOKE the affected fallback
    attestations FIRST, and only then commit the oracle append. If ``invalidate`` raises, ``append``
    NEVER runs — the oracle change is aborted rather than committed while a stale fallback
    attestation for its set still stands. (invalidate-then-append; failure aborts.)"""
    invalidate()
    return append()


__all__ = [
    "RefreshContention",
    "refresh_snapshot",
    "invalidate_fallback_for_set",
    "commit_fixture_append",
    "EpochReader",
    "AttestationBuilder",
]
