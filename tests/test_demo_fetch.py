"""The first consumption path, tested — including the PIN ITSELF.

Every constraint here is easier to relax than to re-tighten, because the next consumer copies this
shape. So each one has a test that has been SEEN TO FAIL, and two get special attention:

  * THE PIN IS A VALUE, AND IT GETS ITS OWN RED STATE. A wrong or truncated digest committed in
    ``demo/pin.py`` is the one defect that makes every subsequent verification pass against the wrong
    artifact — the checks all run, all succeed, and are all about something else. So one character is
    corrupted and the fetch must refuse. Rule 1 applied to the constant rather than the code.

  * UNAVAILABLE AND INTEGRITY ARE DIFFERENT EVENTS. Both look like "no usable corpus"; only one is
    retryable. If they ever collapse into a single type, a caller does the wrong thing half the time
    and readers learn that retrying helps — the wrong lesson from a verification tool.
"""
from __future__ import annotations

import hashlib
import io
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from demo import fetch, pin


def _tar_bytes(members: dict[str, bytes], *, type_override=None, dupe: str | None = None) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, body in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(body)
            if type_override is not None and name == next(iter(members)):
                info.type = type_override
                info.linkname = "elsewhere"
                info.size = 0
                tar.addfile(info)
                continue
            tar.addfile(info, io.BytesIO(body))
        if dupe is not None:
            info = tarfile.TarInfo(dupe)
            body = b"second copy"
            info.size = len(body)
            tar.addfile(info, io.BytesIO(body))
    return buf.getvalue()


def _valid_corpus() -> bytes:
    """A corpus that SHOULD pass everything — the positive control.

    Without it, a fetch that refused unconditionally would satisfy every negative test below, and
    refuses-the-bad would be indistinguishable from refuses-everything.
    """
    files = {m: f"content of {m}\n".encode() for m in pin.EXPECTED_MEMBERS if m != "SHA256SUMS"}
    sums = "".join(f"{hashlib.sha256(b).hexdigest()}  {n}\n" for n, b in sorted(files.items()))
    files["SHA256SUMS"] = sums.encode()
    return _tar_bytes(files)


class _Base(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp, ignore_errors=True))

    def _serve(self, blob: bytes):
        """Put ``blob`` where the fetch will find it, pinned to its true digest."""
        digest = hashlib.sha256(blob).hexdigest()

        def _fake_download(_url, dest):
            Path(dest).write_bytes(blob)

        return mock.patch.object(fetch, "_download", _fake_download), digest


class ThePinIsItselfAControl(_Base):
    """The pin is a VALUE. A test that only exercises the code around it leaves the value unchecked."""

    def test_a_corrupted_pin_makes_the_fetch_REFUSE(self) -> None:
        """One character. If this passes, every later check verifies the wrong artifact perfectly."""
        blob = _valid_corpus()
        patch, digest = self._serve(blob)
        bad = ("f" if digest[0] != "f" else "0") + digest[1:]
        with patch, mock.patch.object(fetch, "CORPUS_SHA256", bad):
            with self.assertRaises(fetch.CorpusIntegrityError) as caught:
                fetch.ensure_corpus(self.tmp)
        self.assertIn("DIGEST MISMATCH", str(caught.exception))

    def test_a_TRUNCATED_pin_also_refuses(self) -> None:
        """A truncated digest is the likelier typo — and a prefix comparison would accept it."""
        blob = _valid_corpus()
        patch, digest = self._serve(blob)
        with patch, mock.patch.object(fetch, "CORPUS_SHA256", digest[:-1]):
            with self.assertRaises(fetch.CorpusIntegrityError):
                fetch.ensure_corpus(self.tmp)

    def test_the_correct_pin_ACCEPTS(self) -> None:
        blob = _valid_corpus()
        patch, digest = self._serve(blob)
        with patch, mock.patch.object(fetch, "CORPUS_SHA256", digest):
            root = fetch.ensure_corpus(self.tmp)
        self.assertTrue((root / "MEASURED.json").exists())

    def test_the_SHIPPED_pin_is_a_well_formed_sha256(self) -> None:
        """Not that it is the RIGHT digest — that is what the release verifies — but that it could
        be one. A 63-character pin would fail every fetch forever, loudly but confusingly."""
        self.assertEqual(len(pin.CORPUS_SHA256), 64)
        self.assertTrue(all(c in "0123456789abcdef" for c in pin.CORPUS_SHA256))


class UnavailableIsNotIntegrity(_Base):
    """Two events, two types, two messages. Collapsing them is the erosion this guards against."""

    def test_a_transport_failure_is_UNAVAILABLE_and_says_it_is_retryable(self) -> None:
        def _boom(_url, _dest):
            raise OSError("connection reset")

        with mock.patch.object(fetch.urllib.request, "urlopen", side_effect=OSError("reset")):
            with self.assertRaises(fetch.CorpusUnavailable) as caught:
                fetch.ensure_corpus(self.tmp)
        self.assertIn("retrying is reasonable", str(caught.exception))

    def test_a_transport_failure_is_NOT_an_integrity_error(self) -> None:
        """The discriminator, asserted directly: nothing was read, so nothing may be claimed about
        the contents."""
        with mock.patch.object(fetch.urllib.request, "urlopen", side_effect=OSError("reset")):
            with self.assertRaises(fetch.CorpusUnavailable) as caught:
                fetch.ensure_corpus(self.tmp)
        self.assertNotIsInstance(caught.exception, fetch.CorpusIntegrityError)

    def test_a_digest_mismatch_is_NOT_unavailable_and_never_suggests_retrying(self) -> None:
        blob = _valid_corpus()
        patch, _digest = self._serve(blob)
        with patch, mock.patch.object(fetch, "CORPUS_SHA256", "0" * 64):
            with self.assertRaises(fetch.CorpusIntegrityError) as caught:
                fetch.ensure_corpus(self.tmp)
        self.assertNotIsInstance(caught.exception, fetch.CorpusUnavailable)
        self.assertIn("TERMINAL", str(caught.exception))
        self.assertNotIn("retry", str(caught.exception).lower().replace("retrying will not", ""))


class TheCacheIsVerifiedEveryRun(_Base):
    def test_a_POISONED_cache_is_caught_on_the_second_call(self) -> None:
        """A cache verified once and trusted after is a TOCTOU hole: it is writable by anything else
        running as this user, and by a crashed previous run."""
        blob = _valid_corpus()
        patch, digest = self._serve(blob)
        with patch, mock.patch.object(fetch, "CORPUS_SHA256", digest):
            fetch.ensure_corpus(self.tmp)
            (self.tmp / pin.CORPUS_ARTIFACT).write_bytes(b"swapped after verification")
            with self.assertRaises(fetch.CorpusIntegrityError):
                fetch.ensure_corpus(self.tmp)

    def test_a_failed_download_leaves_NO_cache_entry(self) -> None:
        """A poisoned partial would fail every later run — a self-inflicted denial of service."""
        with mock.patch.object(fetch.urllib.request, "urlopen", side_effect=OSError("reset")):
            with self.assertRaises(fetch.CorpusUnavailable):
                fetch.ensure_corpus(self.tmp)
        self.assertFalse((self.tmp / pin.CORPUS_ARTIFACT).exists())


class ADigestPinsBytesNotSemantics(_Base):
    """Each of these archives can match its digest perfectly and still be hostile or wrong."""

    def _expect_refusal(self, blob: bytes) -> str:
        patch, digest = self._serve(blob)
        with patch, mock.patch.object(fetch, "CORPUS_SHA256", digest):
            with self.assertRaises(fetch.CorpusIntegrityError) as caught:
                fetch.ensure_corpus(self.tmp)
        return str(caught.exception)

    def test_a_symlink_member_is_refused(self) -> None:
        files = {m: b"x\n" for m in pin.EXPECTED_MEMBERS}
        msg = self._expect_refusal(_tar_bytes(files, type_override=tarfile.SYMTYPE))
        self.assertIn("not a regular file", msg)

    def test_an_absolute_path_is_refused(self) -> None:
        files = {m: b"x\n" for m in pin.EXPECTED_MEMBERS}
        files["/etc/passwd"] = b"root\n"
        self.assertIn("absolute or traversing", self._expect_refusal(_tar_bytes(files)))

    def test_a_traversing_path_is_refused(self) -> None:
        files = {m: b"x\n" for m in pin.EXPECTED_MEMBERS}
        files["../escaped.py"] = b"x\n"
        self.assertIn("absolute or traversing", self._expect_refusal(_tar_bytes(files)))

    def test_a_DUPLICATE_member_is_refused(self) -> None:
        """Extraction overwrites the first with the second, so which bytes land depends on order."""
        files = {m: b"x\n" for m in pin.EXPECTED_MEMBERS}
        self.assertIn("TWICE", self._expect_refusal(_tar_bytes(files, dupe="MEASURED.json")))

    def test_a_MISSING_member_is_refused(self) -> None:
        files = {m: b"x\n" for m in pin.EXPECTED_MEMBERS if m != "WARRANT.md"}
        self.assertIn("MISSING", self._expect_refusal(_tar_bytes(files)))

    def test_an_EXTRA_member_is_refused_with_every_other_byte_correct(self) -> None:
        """EXACT-SET is a DISTINCT AXIS from content. Nothing here has wrong bytes."""
        files = {m: f"content of {m}\n".encode() for m in pin.EXPECTED_MEMBERS if m != "SHA256SUMS"}
        files["fixtures/uninvited/main.py"] = b"x\n"
        sums = "".join(f"{hashlib.sha256(b).hexdigest()}  {n}\n" for n, b in sorted(files.items()))
        files["SHA256SUMS"] = sums.encode()
        self.assertIn("UNEXPECTED", self._expect_refusal(_tar_bytes(files)))


class TheManifestIsParsedStrictly(_Base):
    def test_a_non_coreutils_line_is_refused(self) -> None:
        """A parser more permissive than the format will one day accept what it should refuse."""
        files = {m: b"x\n" for m in pin.EXPECTED_MEMBERS if m != "SHA256SUMS"}
        files["SHA256SUMS"] = b"deadbeef MEASURED.json\n"          # one space, short digest
        patch, digest = self._serve(_tar_bytes(files))
        with patch, mock.patch.object(fetch, "CORPUS_SHA256", digest):
            with self.assertRaises(fetch.CorpusIntegrityError) as caught:
                fetch.ensure_corpus(self.tmp)
        self.assertIn("coreutils format", str(caught.exception))

    def test_a_member_whose_bytes_changed_after_extraction_is_caught(self) -> None:
        files = {m: f"content of {m}\n".encode() for m in pin.EXPECTED_MEMBERS if m != "SHA256SUMS"}
        sums = "".join(f"{hashlib.sha256(b).hexdigest()}  {n}\n" for n, b in sorted(files.items()))
        files["SHA256SUMS"] = sums.encode()
        files["MEASURED.json"] = b"tampered, but SHA256SUMS still claims the original\n"
        patch, digest = self._serve(_tar_bytes(files))
        with patch, mock.patch.object(fetch, "CORPUS_SHA256", digest):
            with self.assertRaises(fetch.CorpusIntegrityError) as caught:
                fetch.ensure_corpus(self.tmp)
        self.assertIn("member digest mismatch", str(caught.exception))


class ThereIsNoWayToTurnVerificationOff(unittest.TestCase):
    """Fail-closed is a property of the code's SHAPE, not of its configuration — there is no flag to
    lose, no environment variable to set, and therefore nothing for a later consumer to copy."""

    def test_no_override_surface_exists_in_the_CODE(self) -> None:
        """⚠ THIS TEST'S METHOD CHANGED, AND THE CODE WAS RIGHT.

        Its first version grepped the lowercased file for words like ``insecure`` — and went red on
        ``fetch.py``'s own docstring, which contains the sentence *"there is no ``--insecure``"*. A
        substring scan cannot tell a sentence SAYING A THING DOES NOT EXIST from the thing existing.
        The property is about CODE, so the check reads the AST: environment access, and parameters
        whose names offer a way to switch verification off. Prose is not evidence either way.
        """
        import ast

        tree = ast.parse(Path(fetch.__file__).read_text())
        offenders: list[str] = []
        for node in ast.walk(tree):
            # environment access — the classic ungoverned override channel
            if isinstance(node, ast.Attribute) and node.attr in ("getenv", "environ"):
                offenders.append(f"environment access at line {node.lineno}")
            if isinstance(node, ast.Name) and node.id in ("getenv", "environ"):
                offenders.append(f"environment access at line {node.lineno}")
            # a parameter that offers to relax verification
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                args = node.args
                names = [a.arg for a in (*args.posonlyargs, *args.args, *args.kwonlyargs)]
                for n in names:
                    low = n.lower()
                    if any(s in low for s in ("insecure", "skip", "no_verify", "unsafe", "force",
                                              "verify")):
                        offenders.append(f"{node.name}() takes {n!r} at line {node.lineno}")
        self.assertEqual(offenders, [],
                         f"an override surface appeared in fetch.py: {offenders}")

    def test_the_only_path_to_a_corpus_runs_the_digest_check(self) -> None:
        """Asserted structurally: every return in ensure_corpus is downstream of _verify_digest."""
        src = Path(fetch.__file__).read_text()
        body = src.split("def ensure_corpus")[1]
        self.assertEqual(body.count("return"), 1, "ensure_corpus grew a second exit")
        self.assertLess(body.index("_verify_digest"), body.index("return"))


if __name__ == "__main__":
    unittest.main()
