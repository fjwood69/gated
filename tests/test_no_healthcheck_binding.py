"""P3 step 1 item 3 — engine healthchecks are disabled on EVERY container gated creates, the flag is
SINGLE-SOURCED, and the value is ATTESTED.

THE DEFECT THIS CLOSES. A HEALTHCHECK makes the ENGINE open periodic connections. The proxy counts
CONNECTIONS at accept, so engine traffic enters the verdict input as though the artifact had produced
it — and ``fail_once`` is a GLOBAL counter, so one stray connection consumes attempt 1 and silently
upgrades the artifact's first retry from 503 to 200. That changes what the artifact DOES, changes the
number, and nothing notices. Clause M exactly: a value outside the identity altering what the instrument
reports on a run that STILL SUCCEEDS.

MEASURED 2026-08-02: the configured image has ``Config.Healthcheck = null``, so it was not firing. THAT
IS THE FINDING, NOT THE REASSURANCE — the safety rested on the configured image happening to lack one,
and nothing checked it. Accidental protection is not structural protection, and an image swap is an
ordinary act.

THREE ASSERTIONS, because this control has three distinct silent deaths:

  1. a builder loses the flag              -> engine connections resume, uncounted-by-the-artifact
  2. a builder RESTATES the literal        -> the attested value and the applied value can diverge,
                                              which is the ``_SEALED_NETWORK_FLAGS`` defect verbatim
  3. the value leaves the identity hash    -> the control becomes a FOSSIL: live, effective, and
                                              invisible to every receipt

(3) is the one the brief for this increment had to be corrected about. Builder-SOURCE hashing would also
have covered these sites, but that mechanism is NOT BUILT — the NARROW ruling kept its design, not a
live implementation — so the value is pinned as a value. An unattested flag addition is out of bounds.

The artifact builder is the surface that matters most: it holds ``--add-host health-proxy`` on the
sealed network, so its healthcheck reaches the proxy DIRECTLY.

Assertions parse the AST rather than scanning prose — tests in this tree have three times matched a
comment describing the code they were checking had been removed.
"""
from __future__ import annotations

import ast
import unittest
from pathlib import Path

from sandbox.oci import NO_HEALTHCHECK_FLAGS, artifact_run_argv
from sandbox.observed import _OBSERVER_CONFIG_HASH, escape_probe_argv, proxy_run_argv

_PKG = Path(__file__).resolve().parent.parent / "sandbox"

# Every builder that constructs a `<runtime> run` argv. If a fourth is ever added it belongs here; the
# totality assertion below is what makes that obligation visible rather than optional.
_RUN_BUILDERS = {
    "oci.py": ("artifact_run_argv",),
    "observed.py": ("proxy_run_argv", "escape_probe_argv"),
}


def _fn(module: str, name: str) -> ast.FunctionDef:
    tree = ast.parse((_PKG / module).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError(f"sandbox/{module} no longer defines {name} — this guard is now blind")


class EveryRunBuilderDisablesHealthchecks(unittest.TestCase):
    def test_each_builder_expands_the_shared_constant(self) -> None:
        """EXPANDED, never restated. A builder spelling ``"--no-healthcheck"`` inline would be
        byte-identical today and free to drift tomorrow, and the identity would not move with it —
        the exact shape ``network_create_argv`` documents for the sealed-network flags."""
        for module, names in _RUN_BUILDERS.items():
            for name in names:
                fn = _fn(module, name)
                starred = {
                    n.value.id for n in ast.walk(fn)
                    if isinstance(n, ast.Starred) and isinstance(n.value, ast.Name)
                }
                self.assertIn(
                    "NO_HEALTHCHECK_FLAGS", starred,
                    f"sandbox/{module}::{name} does not expand NO_HEALTHCHECK_FLAGS. A HEALTHCHECK on "
                    "this container puts ENGINE connections into the verdict input, and on a fail_once "
                    "run it consumes attempt 1 and upgrades the artifact's first retry to 200",
                )
                restated = [
                    n for n in ast.walk(fn)
                    if isinstance(n, ast.Constant) and n.value in NO_HEALTHCHECK_FLAGS
                ]
                self.assertEqual(
                    restated, [],
                    f"sandbox/{module}::{name} RESTATES a healthcheck flag literal instead of expanding "
                    "the constant — the attested value and the applied value could then diverge",
                )

    def test_the_flag_actually_reaches_the_built_argv(self) -> None:
        """The AST says the constant is expanded; this says the OUTPUT carries it. Both, because a
        builder could expand the constant into a position the runtime ignores."""
        built = {
            "artifact_run_argv": artifact_run_argv(
                "/usr/bin/podman", container="c", network=["--network", "n"],
                snapshot=Path("/tmp"), image_id="sha256:x", entrypoint=["true"]),
            "proxy_run_argv": proxy_run_argv(
                "/usr/bin/podman", network="n", name="p", image_id="sha256:x", mode="fail_always"),
            "escape_probe_argv": escape_probe_argv(
                "/usr/bin/podman", network="n", proxy_ip="10.0.0.2", image_id="sha256:x"),
        }
        for name, argv in built.items():
            for flag in NO_HEALTHCHECK_FLAGS:
                self.assertIn(flag, argv, f"{name} output is missing {flag}")
            # Before the image and the entrypoint, or the runtime treats it as an argument TO the image.
            self.assertLess(
                argv.index(NO_HEALTHCHECK_FLAGS[0]), argv.index("sha256:x"),
                f"{name} places the flag after the image ref, where it is an argument to the "
                "container rather than a flag to the runtime",
            )

    def test_the_flag_is_a_member_of_the_attested_identity(self) -> None:
        """THE FOSSIL GUARD. A Clause-M control that is live but unattested is invisible to every
        receipt — which is precisely how the ``ObservedHandle.baseline`` field came to exist and survive
        long after the design that justified it (now deleted). Recomputing the
        digest WITHOUT this member must produce a DIFFERENT hash; if it does not, the member is
        decorative and the control is a fossil."""
        import hashlib

        from core.chain import content_digest
        from sandbox.observed import (
            _ESCAPE_SCRIPT, _PROXY_SRC, _SEALED_NETWORK_FLAGS, PROXY_HOST, PROXY_PORT,
        )

        without = content_digest({
            "proxy_src_sha256": hashlib.sha256(_PROXY_SRC.read_bytes()).hexdigest(),
            "escape_probe_sha256": hashlib.sha256(_ESCAPE_SCRIPT.encode("utf-8")).hexdigest(),
            "sealed_network_flags": list(_SEALED_NETWORK_FLAGS),
            "proxy_port": PROXY_PORT,
            "proxy_host": PROXY_HOST,
        })
        self.assertNotEqual(
            _OBSERVER_CONFIG_HASH, without,
            "the observer identity is UNCHANGED by the healthcheck member — the flag is live but "
            "unattested, so a receipt cannot distinguish an instrument that disables engine "
            "healthchecks from one that does not",
        )


if __name__ == "__main__":
    unittest.main()
