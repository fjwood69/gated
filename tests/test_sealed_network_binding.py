"""P1 binding tests — the attested sealed-network flags and the APPLIED ones cannot diverge.

These are BINDING tests, not value tests. They deliberately do NOT assert that the flags are
``--internal`` and ``--disable-dns``: a value test passes happily after someone edits both the
constant and the create site, which is the case nobody needs help with. What these assert is that
the create argv is DERIVED from ``_SEALED_NETWORK_FLAGS`` — so expanding the constant without
touching the create site (or the reverse) fails here rather than silently producing an identity that
attests a network posture the container does not have.

They also do NOT replace the escape probe. The probe asserts the RUNTIME property (external TCP
fails, public DNS fails, the proxy positively answers) against the network that was actually created,
and it is the stronger control. It cannot, however, see the failure this file exists for: if the
constant and the literals both still describe a sealed posture but differ FROM EACH OTHER, the probe
passes and the identity lies quietly. Two layers, different jobs.

No runtime required — these are argv-shape assertions.
"""
from __future__ import annotations

import subprocess
import unittest
from unittest import mock

from sandbox.observed import (
    _PREFIX,
    _SEALED_NETWORK_FLAGS,
    ObservedOCISandbox,
    network_create_argv,
)


class SealedNetworkArgvBinding(unittest.TestCase):
    """``network_create_argv`` is the single application site for the attested flags."""

    def test_argv_contains_every_attested_flag(self) -> None:
        argv = network_create_argv("podman", "net-x")
        for flag in _SEALED_NETWORK_FLAGS:
            self.assertIn(flag, argv, f"attested flag {flag!r} is not applied by the create argv")

    def test_argv_flags_are_exactly_the_attested_set(self) -> None:
        """No dashed option may appear in the SEAM's output that is not in the attested tuple.

        Scope, stated precisely because an earlier version of this docstring misattributed it: this
        inspects ``network_create_argv``'s output — the seam — not what ``_create_network`` executes.
        A create-site-only addition is caught by the equality test below, not by this one.

        KNOWN LIMIT — operand blindness. ``argv_options`` keeps only dashed tokens, so a
        value-taking flag has its VALUE discarded: an applied ``--subnet 0.0.0.0/0`` against an
        attested ``--subnet 10.0.0.0/24`` would pass. Latent today (both sealed flags are boolean),
        and ``_OBSERVER_CONFIG_HASH`` shares the blindness exactly — it hashes the flag tuple, so an
        operand living outside that tuple is unattested by BOTH layers. Adding a value-taking flag to
        the sealed set requires fixing both, together. The ``--opt=value`` form is unaffected: it is
        one token and any change to it flips the comparison.
        """
        applied = [a for a in argv_options(network_create_argv("podman", "net-x"))]
        self.assertEqual(
            sorted(applied), sorted(_SEALED_NETWORK_FLAGS),
            "create argv options differ from the attested _SEALED_NETWORK_FLAGS",
        )

    def test_argv_is_derived_not_restated(self) -> None:
        """Mutating the constant must move the argv. If the create site restated the flags as
        literals, this fails — which is precisely the defect P1 closes."""
        fake = ("--internal", "--disable-dns", "--sentinel-not-a-real-flag")
        with mock.patch("sandbox.observed._SEALED_NETWORK_FLAGS", fake):
            argv = network_create_argv("podman", "net-x")
        self.assertIn(
            "--sentinel-not-a-real-flag", argv,
            "create argv did not follow _SEALED_NETWORK_FLAGS — the flags are restated, not derived",
        )

    def test_argv_shape(self) -> None:
        argv = network_create_argv("podman", "net-x")
        self.assertEqual(argv[:3], ["podman", "network", "create"])
        self.assertEqual(argv[-1], "net-x", "the network name must be the final positional")


class CreateNetworkUsesTheSeam(unittest.TestCase):
    """``_create_network``'s executed argv must follow the attested constant.

    BOTH tests below are load-bearing and NEITHER subsumes the other. Do not delete one as
    "tautological" — that framing is wrong and deleting either re-opens a distinct hole:

    * The **equality** test (unpatched) is the sole catcher of *create-site post-processing*: calling
      the seam and then mutating its output — ``argv.insert(-1, "--dns=1.1.1.1")`` — leaves the
      sentinel *present*, so the sentinel test stays green while the posture moves.
    * The **sentinel** test is the sole catcher of *restated literals*: re-listing the flags inline
      produces a byte-identical argv, so the equality test stays green while the coupling is gone.
      Verified by reintroducing that defect and watching only the sentinel test red.

    What neither asserts: that this is the ONLY expansion site. A second site re-expanding
    ``*_SEALED_NETWORK_FLAGS`` satisfies both.
    """

    def test_create_network_invokes_the_seam_argv(self) -> None:
        sbx = ObservedOCISandbox.__new__(ObservedOCISandbox)  # no runtime detection
        sbx._runtime = "podman"
        with mock.patch.object(subprocess, "run") as run:
            run.return_value = subprocess.CompletedProcess([], 0, b"", b"")
            sbx._create_network("net-x")
        self.assertTrue(run.called, "_create_network did not invoke subprocess.run")
        self.assertEqual(
            list(run.call_args.args[0]), network_create_argv("podman", "net-x"),
            "_create_network built its own argv instead of using network_create_argv",
        )

    def test_create_network_is_bound_to_the_constant_not_merely_equal_to_it(self) -> None:
        """The one that has teeth.

        Comparing ``_create_network``'s argv to ``network_create_argv``'s output is TAUTOLOGICAL
        while the two happen to agree: restating the flags as literals at the create site produces a
        byte-identical argv and the comparison above passes. Verified by reintroducing the defect —
        that test stayed green.

        So bind through the constant instead: swap in a sentinel flag and require it to reach the
        argv ``_create_network`` actually executes. A restated literal cannot follow it.
        """
        fake = (*_SEALED_NETWORK_FLAGS, "--sentinel-not-a-real-flag")
        sbx = ObservedOCISandbox.__new__(ObservedOCISandbox)
        sbx._runtime = "podman"
        with mock.patch("sandbox.observed._SEALED_NETWORK_FLAGS", fake):
            with mock.patch.object(subprocess, "run") as run:
                run.return_value = subprocess.CompletedProcess([], 0, b"", b"")
                sbx._create_network("net-x")
        self.assertIn(
            "--sentinel-not-a-real-flag", list(run.call_args.args[0]),
            "_create_network does not follow _SEALED_NETWORK_FLAGS — the flags are restated at the "
            "create site, not derived from the attested constant",
        )


class PrefixIsTheSingleSource(unittest.TestCase):
    """Every reap-visible name must derive from ``_PREFIX``.

    ``reap_orphans`` selects by ``--filter name={_PREFIX}``; a name that does not derive from it is a
    resource the reaper cannot see. Before P1 the names were hardcoded, so changing ``_PREFIX`` left
    the reaper filtering for a prefix nothing used.
    """

    def test_prefix_is_used_by_prepare_not_hardcoded(self) -> None:
        """Source-level guard: NO name in ``prepare()`` may restate the literal prefix.

        Asserted against source text because the alternative — running ``prepare()`` — needs a real
        runtime. A hardcoded name passes every behavioural test while silently making itself
        invisible to the reaper, which filters on ``_PREFIX``.

        Checks EVERY generated name, not just the network. An earlier version grepped only for
        ``net-`` and would have passed a ``prepare()`` that derived the network name but hardcoded
        the proxy and sandbox ones. It also included the snapshot tempdir, which was still hardcoded
        two lines above the comment claiming ``_PREFIX`` was the single source.
        """
        import inspect

        import sandbox.observed as obs

        src = inspect.getsource(obs.ObservedOCISandbox.prepare)
        for suffix in ("net-", "proxy-", "sbx-", "obs-"):
            self.assertNotIn(
                f'"{_PREFIX}{suffix}', src,
                f"prepare() hardcodes the prefix for {suffix!r} instead of deriving from _PREFIX",
            )

    def test_prefix_is_referenced_by_code_not_only_by_a_comment(self) -> None:
        """``assertIn("_PREFIX", src)`` alone is satisfied by a COMMENT mentioning it.

        So strip comments first and assert against what remains. Two properties, both on the
        comment-free text: ``_PREFIX`` is referenced, and the literal value appears NOWHERE.

        Deliberately NOT a token COUNT. An earlier version asserted
        ``names.count("_PREFIX") >= 4`` over NAME tokens, which was wrong three ways: it went RED on
        correct refactors (``p = _PREFIX`` used four times is one reference; extracting name-building
        into a helper is zero, since ``getsource`` sees only ``prepare``), it stayed GREEN on a
        single-quoted hardcode plus one spurious reference, and — worst — it depended on PEP 701
        f-string tokenisation, so it would have counted ZERO and failed on CPython 3.9/3.10/3.11,
        which are three of the five versions in the CI matrix. Text-after-comment-stripping behaves
        identically on every version because a pre-3.12 f-string is one STRING token whose text still
        contains the name.
        """
        import inspect
        import io
        import tokenize

        import sandbox.observed as obs

        src = inspect.getsource(obs.ObservedOCISandbox.prepare)
        code_only = "".join(
            tok.string
            for tok in tokenize.generate_tokens(io.StringIO(src).readline)
            if tok.type != tokenize.COMMENT
        )
        self.assertIn(
            "_PREFIX", code_only,
            "prepare() references _PREFIX only in a comment, or not at all",
        )
        self.assertNotIn(
            _PREFIX, code_only,
            f"prepare() restates the literal {_PREFIX!r} instead of deriving from _PREFIX "
            "(any quote style) — such a name is invisible to the reaper's --filter",
        )


def argv_options(argv: list[str]) -> list[str]:
    """The dashed options in an argv, ignoring the runtime, subcommand and positionals."""
    return [a for a in argv if a.startswith("-")]


if __name__ == "__main__":
    unittest.main()
