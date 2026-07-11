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

from gate.snapshot import AttestationRecord, from_json, verify_snapshot
from gate.snapshot_refresh import RefreshContention, refresh_snapshot

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


if __name__ == "__main__":
    unittest.main()
