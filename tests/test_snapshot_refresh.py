"""3.4 close-4 — the generation-locked snapshot refresh. Run: python3 -m unittest discover -s tests

Load-bearing: paired-epoch CAS commits ONLY under a stable epoch (an exact-set guarantee — a tier
transition or fixture append mid-mint forces a retry); repeated contention fails LOUD (RefreshContention)
and leaves the prior snapshot in place (never swaps a stale one); the write is atomic + durable
(temp -> os.replace -> parent-dir fsync), leaving no temp residue.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from gate.snapshot import AttestationRecord, from_json, issue_snapshot, to_json, verify_snapshot
from gate.snapshot_refresh import (
    RefreshContention,
    commit_fixture_append,
    invalidate_fallback_for_set,
    refresh_snapshot,
)

_KEY = b"gate-governance-key"


def _rec(pid: str) -> AttestationRecord:
    return AttestationRecord(
        policy_id=pid, detector_identity="det-1", calibration_result_ref="cal-1",
        fixture_set_version="fx", tier_chain_head="th", backend="podman",
        set_id="X", oracle_head="h1",
    )


class _Epoch:
    """Yields a scripted sequence of epoch values (repeating the last) — each refresh attempt reads
    twice (before + after mint), so [A, A] commits and [A, B, ...] retries."""

    def __init__(self, seq: list[str]) -> None:
        self._seq = seq
        self._i = 0

    def read(self) -> object:
        v = self._seq[min(self._i, len(self._seq) - 1)]
        self._i += 1
        return v


def _no_backoff(_attempt: int) -> None:
    return None


class RefreshTests(unittest.TestCase):
    def test_stable_epoch_commits_atomic_signed_snapshot(self) -> None:
        d = Path(tempfile.mkdtemp(prefix="mv-refresh-"))
        path = str(d / "snapshot.json")
        snap = refresh_snapshot(
            read_epoch=_Epoch(["A", "A"]).read,
            enabled_attestations=lambda: {"p1": _rec("p1")},
            key=_KEY, now=1000.0, path=path, backoff=_no_backoff,
        )
        # written, loadable, and HMAC-valid.
        loaded = from_json(Path(path).read_text())
        verify_snapshot(loaded, key=_KEY, now=1100.0)
        self.assertEqual(loaded.records["p1"].oracle_head, "h1")
        self.assertEqual(snap.records["p1"].set_id, "X")
        self.assertFalse(list(d.glob("*.tmp*")), "no temp residue")

    def test_paired_epoch_cas_retries_then_commits(self) -> None:
        # attempt 0: reads A then B (differ) -> retry; attempt 1: reads C then C -> commit.
        d = Path(tempfile.mkdtemp(prefix="mv-refresh2-"))
        path = str(d / "s.json")
        snap = refresh_snapshot(
            read_epoch=_Epoch(["A", "B", "C", "C"]).read,
            enabled_attestations=lambda: {"p1": _rec("p1")},
            key=_KEY, now=1000.0, path=path, backoff=_no_backoff,
        )
        self.assertIn("p1", snap.records)
        self.assertTrue(Path(path).exists())

    def test_exact_set_change_during_mint_forces_retry(self) -> None:
        # a policy disabled mid-mint moves the epoch -> the first attempt must NOT commit.
        d = Path(tempfile.mkdtemp(prefix="mv-refresh3-"))
        path = str(d / "s.json")
        mint_calls: list[int] = []

        def builder():  # type: ignore[no-untyped-def]
            mint_calls.append(1)
            return {"p1": _rec("p1")}

        refresh_snapshot(
            read_epoch=_Epoch(["A", "B", "C", "C"]).read, enabled_attestations=builder,
            key=_KEY, now=1000.0, path=path, backoff=_no_backoff,
        )
        self.assertGreaterEqual(len(mint_calls), 2)  # re-minted after the mid-mint change

    def test_repeated_contention_fails_loud_leaving_prior_snapshot(self) -> None:
        d = Path(tempfile.mkdtemp(prefix="mv-refresh4-"))
        path = str(d / "s.json")
        Path(path).write_text("PRIOR")  # a prior snapshot on disk
        with self.assertRaises(RefreshContention):
            refresh_snapshot(
                read_epoch=_Epoch(["A", "B", "C", "D", "E", "F", "G", "H"]).read,  # always changes
                enabled_attestations=lambda: {"p1": _rec("p1")},
                key=_KEY, now=1000.0, path=path, max_retries=3, backoff=_no_backoff,
            )
        self.assertEqual(Path(path).read_text(), "PRIOR")  # never swapped a stale one

    def test_empty_enabled_set_commits_empty_snapshot(self) -> None:
        d = Path(tempfile.mkdtemp(prefix="mv-refresh5-"))
        path = str(d / "s.json")
        snap = refresh_snapshot(
            read_epoch=_Epoch(["A", "A"]).read, enabled_attestations=lambda: {},
            key=_KEY, now=1000.0, path=path, backoff=_no_backoff,
        )
        self.assertEqual(dict(snap.records), {})
        verify_snapshot(from_json(Path(path).read_text()), key=_KEY, now=1100.0)


class SynchronousInvalidationTests(unittest.TestCase):
    """close-4 completion — the both-stores-down counterexample. Optimistic refresh cannot fix it;
    the append must SYNCHRONOUSLY revoke the affected fallback attestations BEFORE it commits."""

    def _persist(self, path: str, records: dict[str, AttestationRecord]) -> None:
        snap = issue_snapshot(records, key=_KEY, now=1000.0, valid_for_seconds=300)
        Path(path).write_text(to_json(snap))

    def test_append_synchronously_removes_fallback_attestation_before_commit(self) -> None:
        # 1. snapshot S attests P (set X @ h0) and Q (set Y), fresh + persisted.
        d = Path(tempfile.mkdtemp(prefix="mv-inval-"))
        path = str(d / "snapshot.json")
        self._persist(path, {"P": _rec("P"), "Q": _rec_set("Q", "Y", "hy")})
        appended: list[str] = []
        # 2. commit an oracle append to set X: invalidate-then-append. The append runs ONLY after
        #    the fallback attestation for X is durably revoked.
        commit_fixture_append(
            invalidate=lambda: invalidate_fallback_for_set(path, set_id="X", key=_KEY),
            append=lambda: appended.append("bx2"),
        )
        self.assertEqual(appended, ["bx2"])  # append happened (after invalidation)
        # 3. reload the persisted snapshot -> P (set X) is GONE; Q (set Y) remains; still HMAC-valid.
        reloaded = from_json(Path(path).read_text())
        self.assertNotIn("P", reloaded.records)   # the both-down window is now fail-closed for P
        self.assertIn("Q", reloaded.records)       # scoped: set Y untouched
        verify_snapshot(reloaded, key=_KEY, now=1100.0)

    def test_invalidation_failure_aborts_the_append(self) -> None:
        # if the durable revocation fails, the append MUST NOT commit.
        appended: list[str] = []

        def boom() -> None:
            raise OSError("disk full — cannot revoke fallback attestation")

        with self.assertRaises(OSError):
            commit_fixture_append(invalidate=boom, append=lambda: appended.append("x"))
        self.assertEqual(appended, [])  # aborted — never committed the oracle change

    def test_invalidate_is_noop_when_no_snapshot_yet(self) -> None:
        d = Path(tempfile.mkdtemp(prefix="mv-inval2-"))
        invalidate_fallback_for_set(str(d / "absent.json"), set_id="X", key=_KEY)  # no raise


def _rec_set(pid: str, set_id: str, oracle_head: str) -> AttestationRecord:
    return AttestationRecord(
        policy_id=pid, detector_identity="det-1", calibration_result_ref="cal-1",
        fixture_set_version="fx", tier_chain_head="th", backend="podman",
        set_id=set_id, oracle_head=oracle_head,
    )


if __name__ == "__main__":
    unittest.main()
