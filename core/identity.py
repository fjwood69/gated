"""core/identity.py — 3.4 close-2: the 4-tuple execution identity binding.

The transitive-dependency spoof (verified against ``engine/runner.py``): ``assert_invariant`` runs
on the TRUSTED HOST, after the artifact ran in the sandbox. So content-addressing the detector's own
source, or the artifact IMAGE alone, does NOT close the detector's dependencies — a shared helper the
detector imports (host-side) can change behaviour with the artifact image unchanged, replaying a
stale calibration. The verdict is a function of FOUR execution coordinates; the identity must bind
all four, and enforcement must exact-match all four (a change in any one -> new identity -> the
existing calibration_pass / snapshot identity-match blocks, un-calibrated).

The four coordinates:
  * detector_build_digest       — the detector's exact BUILD ARTIFACT (bytes), via a declarative
                                   manifest, NOT a canonical AST. AST "semantic equivalence" is an
                                   unsafe claim (a canonicaliser bug is a silent identity collision);
                                   hash WHAT ACTUALLY RUNS.
  * host_closure_digest         — the host engine + observer execution closure (pinned lockfile /
                                   hashed site-packages) — where ``assert_invariant`` actually runs.
  * artifact_image_digest       — the hermetic OCI image (already content-addressed) the artifact
                                   runs in; shapes the observation the detector judges.
  * eval_profile_digest         — trials, budget, fault-injection spec + seeds, entrypoint — the
                                   behavioural configuration.

Pure + stdlib-only (reuses ``core.chain.content_digest``); ``core`` imports neither engine nor gate,
so this is usable both engine-side (compute a detector's identity) and gate-side (bind + check it).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping

from core.chain import content_digest

# The identity scheme version — bump (with migration) if the composition changes, so old
# calibration records are invalidated rather than silently re-interpreted.
IDENTITY_VERSION = 1


@dataclass(frozen=True)
class DetectorManifest:
    """A versioned, declarative description of a detector's BUILD — the thing hashed for
    ``detector_build_digest``. Declarative (not AST): ``impl_digest`` is a digest of the exact build
    artifact bytes; the manifest pins the intent (check_type, entrypoint) and behavioural config."""

    check_type: str
    entrypoint: tuple[str, ...]
    impl_digest: str                       # sha256 of the detector's exact build-artifact bytes
    eval_profile: Mapping[str, object] = field(default_factory=dict)  # trials/budget/faults/seeds

    def build_digest(self) -> str:
        return content_digest({
            "check_type": self.check_type, "entrypoint": list(self.entrypoint),
            "impl_digest": self.impl_digest,
        })

    def eval_profile_digest(self) -> str:
        return content_digest({"eval_profile": dict(sorted(self.eval_profile.items()))})


def bind_identity(
    *,
    detector_build_digest: str,
    host_closure_digest: str,
    artifact_image_digest: str,
    eval_profile_digest: str,
) -> str:
    """Compose the 4-tuple into a single execution identity. A change in ANY coordinate yields a new
    identity — so the existing exact-match (snapshot identity-binding + the gap-1 calibration_pass
    match) refuses a detector whose build, host closure, image, or eval profile has drifted since
    calibration. This is the transitive-spoof close made structural, not asserted."""
    return content_digest({
        "identity_version": IDENTITY_VERSION,
        "detector_build_digest": detector_build_digest,
        "host_closure_digest": host_closure_digest,
        "artifact_image_digest": artifact_image_digest,
        "eval_profile_digest": eval_profile_digest,
    })


def identity_for(
    manifest: DetectorManifest,
    *,
    host_closure_digest: str,
    artifact_image_digest: str,
) -> str:
    """Convenience: derive the execution identity from a manifest + the host/image digests. The
    manifest supplies detector_build_digest + eval_profile_digest; the caller supplies the host
    closure (pinned lockfile) and the content-addressed image."""
    return bind_identity(
        detector_build_digest=manifest.build_digest(),
        host_closure_digest=host_closure_digest,
        artifact_image_digest=artifact_image_digest,
        eval_profile_digest=manifest.eval_profile_digest(),
    )


__all__ = ["IDENTITY_VERSION", "DetectorManifest", "bind_identity", "identity_for"]
