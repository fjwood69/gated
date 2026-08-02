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
# rebaked when observe/proxy.py moved the egress count to accept-time (3.5 security dissent, count-at-accept);
# the proxy source bytes are part of the observer identity, so a legitimate proxy change re-pins this golden.
# RE-PINNED AGAIN — P3 step 0, 2026-08-02: write_count now publishes the countfile by ATOMIC RENAME
# (sibling temp + os.replace) instead of truncate-then-write. The old shape truncated the file before the
# value landed, so the executor's out-of-process ``cat`` could read it EMPTY and parse it to None —
# measured at 2687 of 4000 reads under a hammering writer, 0 of 4000 after. This is a deliberate,
# behaviour-changing proxy edit, so the re-pin is the identity working as designed rather than noise.
_GOLDEN_OBSERVER_CONFIG_HASH = "6605652a4c75592c1678aca75e547a6276e4c8cce10c57ff6651cca58ad7e8b0"
# A representative FULL Observed identity (image_ref a fixed sentinel) and its digest — the tuple AND the
# digest are pinned so neither a coordinate change nor a digest-formula change slips through.
_GOLDEN_OBSERVED_IMAGE_REF = "sha256:GOLDEN"
_GOLDEN_OBSERVED_DIGEST = "91b9f6fbb788e7bd4ce4224997fcd235ecf8847eb41ffb1ee3113b0e7d9503ed"


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
