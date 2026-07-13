"""B3 (D1) execution-identity GOLDEN regression. Run: python3 -m unittest discover -s tests

The packaging increment (S2) must be execution-identity-NEUTRAL: relocating modules must not change
``ExecutionIdentity``. That holds because ``engine/runner._raw_identity`` composes the identity from the
BARE class name (``type(sandbox).__name__``), the immutable image digest, the isolation-level enum value,
and a CONTENT hash of the observer config — no import path anywhere. But the bare class names ARE the
identity, so a class RENAME (or a change to the identity formula) would change it SILENTLY. This golden
pins the identity BYTE-FOR-BYTE against checked-in constants so any such change breaks the build loudly.

Board D1 (amended): pin the TUPLE and the DIGEST, and cover OCI + Observed, not merely NoOp/fake
(confound #5). The observer-config hash is pinned too (confound #7): it is ``sha256`` over
``observe/proxy.py`` bytes + the escape-probe script + the sealed-network flags, so this also anchors that
the proxy source shipped unchanged — the clean-wheel test re-checks the SAME constant post-install.
"""
from __future__ import annotations

import unittest

from engine.runner import ExecutionIdentity
from sandbox.noop import NoOpSandbox
from sandbox.observed import ObservedOCISandbox, _OBSERVER_CONFIG_HASH
from sandbox.oci import OCISandbox

# The identity-load-bearing class names — a rename here CHANGES execution_identity and must ride S3's
# identity-plane bump, never land silently in a packaging step.
_GOLDEN_BACKEND_NAMES = {
    "oci": "OCISandbox",
    "observed": "ObservedOCISandbox",
    "noop": "NoOpSandbox",
}
# The proxy-bytes golden: sha256 over observe/proxy.py bytes + escape probe + sealed-network flags
# (confound #7 — the proxy source is part of identity; pin it and re-verify after a wheel install).
_GOLDEN_OBSERVER_CONFIG_HASH = "cb587495998cdde73b2b7a44c5dcfda315e69142ae1c3b812f7a9492c0e38b72"
# A representative FULL Observed identity (image_ref a fixed sentinel) and its digest — the tuple AND the
# digest are pinned so neither a coordinate change nor a digest-formula change slips through.
_GOLDEN_OBSERVED_IMAGE_REF = "sha256:GOLDEN"
_GOLDEN_OBSERVED_DIGEST = "dd2e8270feb8c0335f00e94310ad476537ef40e12357867e1b07d0c8726cc970"


class ExecutionIdentityGoldenTests(unittest.TestCase):
    def test_backend_class_names_are_pinned(self) -> None:
        # the load-bearing identity constants — the whole point of the golden.
        self.assertEqual(OCISandbox.__name__, _GOLDEN_BACKEND_NAMES["oci"])
        self.assertEqual(ObservedOCISandbox.__name__, _GOLDEN_BACKEND_NAMES["observed"])
        self.assertEqual(NoOpSandbox.__name__, _GOLDEN_BACKEND_NAMES["noop"])

    def test_observer_config_hash_is_pinned(self) -> None:
        # confound #7: the observed-proxy source bytes are part of the identity — pin them.
        self.assertEqual(_OBSERVER_CONFIG_HASH, _GOLDEN_OBSERVER_CONFIG_HASH)

    def test_observed_execution_identity_tuple_and_digest_are_pinned(self) -> None:
        ei = ExecutionIdentity(
            backend=_GOLDEN_BACKEND_NAMES["observed"], image_ref=_GOLDEN_OBSERVED_IMAGE_REF,
            isolation_level="hermetic", observer_config_hash=_OBSERVER_CONFIG_HASH,
        )
        # the TUPLE (board: pin the tuple, not merely backend == "ObservedOCISandbox")
        self.assertEqual(
            (ei.backend, ei.image_ref, ei.isolation_level, ei.observer_config_hash),
            (_GOLDEN_BACKEND_NAMES["observed"], _GOLDEN_OBSERVED_IMAGE_REF, "hermetic",
             _GOLDEN_OBSERVER_CONFIG_HASH),
        )
        # AND the digest — catches any change to the identity digest formula.
        self.assertEqual(ei.digest(), _GOLDEN_OBSERVED_DIGEST)


if __name__ == "__main__":
    unittest.main()
