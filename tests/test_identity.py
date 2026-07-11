"""3.4 close-2 — the 4-tuple execution identity. Run: python3 -m unittest discover -s tests

Load-bearing: the identity binds FOUR coordinates (detector build, host closure, artifact image,
eval profile); a change in ANY one yields a new identity (so the existing exact-match refuses a
drifted detector — the transitive-spoof close made structural). Reproducible from the same inputs.
"""
from __future__ import annotations

import unittest

from core.identity import DetectorManifest, bind_identity, identity_for


def _id(**over: str) -> str:
    base = dict(detector_build_digest="db", host_closure_digest="hc",
               artifact_image_digest="img", eval_profile_digest="ep")
    base.update(over)
    return bind_identity(**base)  # type: ignore[arg-type]


class BindIdentityTests(unittest.TestCase):
    def test_reproducible(self) -> None:
        self.assertEqual(_id(), _id())

    def test_each_coordinate_changes_the_identity(self) -> None:
        base = _id()
        self.assertNotEqual(base, _id(detector_build_digest="db2"))
        self.assertNotEqual(base, _id(host_closure_digest="hc2"))  # the transitive-dep coordinate
        self.assertNotEqual(base, _id(artifact_image_digest="img2"))
        self.assertNotEqual(base, _id(eval_profile_digest="ep2"))

    def test_host_closure_is_a_real_coordinate(self) -> None:
        # the whole point of the 4-tuple: a helper the DETECTOR imports (host-side) changing must
        # change the identity even if the detector's own build + the artifact image are identical.
        same_detector_same_image = dict(detector_build_digest="db", artifact_image_digest="img",
                                        eval_profile_digest="ep")
        a = bind_identity(host_closure_digest="closure-v1", **same_detector_same_image)  # type: ignore[arg-type]
        b = bind_identity(host_closure_digest="closure-v2", **same_detector_same_image)  # type: ignore[arg-type]
        self.assertNotEqual(a, b)


class ManifestTests(unittest.TestCase):
    def test_manifest_digests_deterministic_and_field_sensitive(self) -> None:
        m1 = DetectorManifest(check_type="egress", entrypoint=("python3", "main.py"),
                              impl_digest="abc", eval_profile={"trials": 3, "budget": 1.0})
        m2 = DetectorManifest(check_type="egress", entrypoint=("python3", "main.py"),
                              impl_digest="abc", eval_profile={"budget": 1.0, "trials": 3})
        self.assertEqual(m1.build_digest(), m2.build_digest())
        self.assertEqual(m1.eval_profile_digest(), m2.eval_profile_digest())  # order-independent
        m3 = DetectorManifest(check_type="egress", entrypoint=("python3", "main.py"),
                              impl_digest="DIFFERENT", eval_profile={"trials": 3, "budget": 1.0})
        self.assertNotEqual(m1.build_digest(), m3.build_digest())
        # a trial-count change (behavioural) changes the eval-profile digest -> a new identity.
        m4 = DetectorManifest(check_type="egress", entrypoint=("python3", "main.py"),
                              impl_digest="abc", eval_profile={"trials": 5, "budget": 1.0})
        self.assertNotEqual(m1.eval_profile_digest(), m4.eval_profile_digest())

    def test_identity_for_composes_from_manifest(self) -> None:
        m = DetectorManifest("egress", ("python3", "main.py"), "abc", {"trials": 3})
        i1 = identity_for(m, host_closure_digest="hc", artifact_image_digest="img")
        i2 = bind_identity(detector_build_digest=m.build_digest(), host_closure_digest="hc",
                           artifact_image_digest="img", eval_profile_digest=m.eval_profile_digest())
        self.assertEqual(i1, i2)


if __name__ == "__main__":
    unittest.main()
