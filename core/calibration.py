"""core/calibration.py — the CalibrationSet value types (pure data, immutable, BYTES-not-paths).

The Oracle invariant's data layer. Defined in ``core/`` so BOTH the gate-side loader (constructs
the set from the protected ref) and the engine-side calibrator (consumes it) share the types
without importing each other — the engine⊥gate invariant holds by construction.

**The pure-bytes injection seam (board mandate).** A ``Fixture`` carries its code as opaque
``payload: bytes`` — NEVER a filesystem ``Path`` or file descriptor. The gate hands the engine
*values*; the engine materialises them itself, under a randomised handle, into a read-only mount.
So the detector-under-calibration cannot (a) be handed a predictable path to traverse or race
(TOCTOU), nor (b) fingerprint *which* fixture it is seeing by name/inode. Content-addressed by the
payload hash for reproducibility (NFR6).

**The label lives HERE, outside the sandbox (1a).** A fixture's ground-truth label
(known_good/known_bad) is on this value object, never materialised with the payload — so a fixture
executing in the sandbox cannot read whether it is *expected* to PASS or FAIL and behave-to-pass.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum


class FixtureLabel(Enum):
    KNOWN_GOOD = "known_good"  # a genuine non-violation — the detector MUST pass it
    KNOWN_BAD = "known_bad"    # a genuine violation — the detector MUST catch (fail) it


@dataclass(frozen=True)
class Fixture:
    """One calibration sample: opaque ``payload`` bytes + ground-truth ``label`` (kept off the
    payload — 1a). The slice's payload is a single ``main.py``'s bytes; multi-file trees = [SPEC].
    ``evasion_class`` tags the adversary category (env-keying / input-keying / logic-bug …)."""

    fixture_id: str
    label: FixtureLabel
    payload: bytes
    evasion_class: str | None = None

    @property
    def content_hash(self) -> str:
        """Content-address of the payload (NFR6 pinning)."""
        return hashlib.sha256(self.payload).hexdigest()


@dataclass(frozen=True)
class CalibrationSet:
    """The fixtures a detector is calibrated against — an immutable value the gate loader builds
    (from the protected chain, applying supersession/deprecation) and injects into the engine."""

    known_good: tuple[Fixture, ...]
    known_bad: tuple[Fixture, ...]

    @property
    def is_adequate(self) -> bool:
        """Vacuity floor (P5): at least one fixture on EACH side — else the detector passes
        vacuously (no known-bad to miss / no known-good to false-positive)."""
        return len(self.known_bad) >= 1 and len(self.known_good) >= 1


__all__ = ["FixtureLabel", "Fixture", "CalibrationSet"]
