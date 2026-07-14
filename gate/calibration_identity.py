"""gate/calibration_identity.py — the LOGICAL identity of a calibration PASS.

Extracted (3.5 S3-completion CP4 Slice B) from ``gatekeeper._result_ref`` so both the synchronous
enable path (``run_calibration``) and the shared measurement spine (``produce_candidate_measurement``)
derive the SAME handle from the SAME inputs. This module is PURE — it depends only on the content
digest and takes primitive coordinates, NOT a ``CalibrationResult``, ``PolicyStore``, intent, CAS, or
clock. It computes a deterministic, content-derived reference; it decides nothing about state.

The handle ties a PASS to the exact calibration context (policy, fixture-set version, the
measurement-derived detector identity, and the pass shape). Reproducible (NFR6) and not guessable
without the actual result.
"""
from __future__ import annotations

from collections.abc import Sequence

from core.chain import content_digest


def calibration_result_ref(
    policy_id: str,
    pinned_set_version: str,
    detector_identity: str,
    *,
    passed: bool,
    n_bad: int,
    fixture_ids: Sequence[str],
) -> str:
    """A deterministic, content-derived handle for a PASS. The field shape is FROZEN — a golden pins
    it — so callers pass ``n_bad`` = the outcome count and ``fixture_ids`` = the outcome fixture ids,
    exactly as the pre-extraction ``_result_ref`` derived them from the ``CalibrationResult``."""
    return content_digest({
        "policy_id": policy_id, "pinned_set_version": pinned_set_version,
        "detector_identity": detector_identity, "passed": passed,
        "n_bad": n_bad, "fixtures": sorted(fixture_ids),
    })


__all__ = ["calibration_result_ref"]
