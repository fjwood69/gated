"""Fetch the pinned demo corpus, verify it, and extract it — or refuse.

⚠ THIS IS THE FIRST CONSUMPTION PATH from ``gated`` to ``gated-uat``, so its shape is a
SPECIFICATION and not an example. Every constraint below is easier to relax now than to tighten
later, because the next consumer will be built to whatever this permits.

THE TWO FAILURE MODES ARE NOT THE SAME EVENT, and keeping them apart is the constraint most likely
to erode. Both present as "there is no usable corpus", and the tempting implementation collapses
them into one error path:

    CorpusUnavailable   the artifact could not be OBTAINED — DNS, timeout, 404, a broken pipe.
                        RETRYABLE. Nothing is known about integrity because nothing was read.

    CorpusIntegrityError  the artifact was obtained and IS WRONG — digest mismatch, a member that
                        should not be there, a member missing, a hostile path, a symlink.
                        TERMINAL. Retrying cannot help and must never be suggested: the bytes are
                        not the bytes we pinned, and they will not become them.

Collapsing these teaches a reader that retrying helps — precisely the wrong lesson from a tool whose
subject is verification. Each has its own type, its own message, and its own test that has been seen
to fail.

NO OVERRIDE EXISTS. There is no ``--insecure``, no environment variable, no warn-and-continue. Not
because an operator could not be trusted with one, but because the next consumer copies the flag, and
a verification path with a documented bypass is a verification path that will be bypassed. If the
digest does not match, this refuses, and the way forward is to fix the pin or the artifact — not to
tell the tool to stop looking.

VERIFY BEFORE EXTRACT IS AN ORDERING REQUIREMENT, NOT A PREFERENCE. Untrusted bytes are not written
to disk until the outer digest matches. Extracting first and checking afterwards would mean a hostile
archive had already run its paths through the filesystem before anything objected.
"""
from __future__ import annotations

import hashlib
import shutil
import tarfile
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

from demo.pin import CORPUS_ARTIFACT, CORPUS_SHA256, CORPUS_URL, EXPECTED_MEMBERS

FETCH_TIMEOUT_SECONDS = 60
_CHUNK = 64 * 1024


class CorpusUnavailable(Exception):
    """The artifact could not be OBTAINED. Retryable; says nothing about integrity."""


class CorpusIntegrityError(Exception):
    """The artifact was obtained and is WRONG. TERMINAL — never retry, never continue.

    A distinct type from ``CorpusUnavailable`` because the two demand opposite responses, and a
    caller that cannot tell them apart will do the wrong one half the time."""


def _download(url: str, dest: Path) -> None:
    """Obtain the bytes. Every failure here is UNAVAILABLE — nothing has been verified yet."""
    try:
        with urllib.request.urlopen(url, timeout=FETCH_TIMEOUT_SECONDS) as response:
            with dest.open("wb") as out:
                while chunk := response.read(_CHUNK):
                    out.write(chunk)
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, ValueError) as exc:
        # Deliberately broad: anything that stops the bytes arriving is the SAME event, and none of
        # it licenses a claim about the artifact's contents.
        raise CorpusUnavailable(
            f"could not obtain {url}: {type(exc).__name__}: {exc}. This is a TRANSPORT failure and "
            "says nothing about the corpus — retrying is reasonable"
        ) from exc


def _digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(_CHUNK):
            h.update(chunk)
    return h.hexdigest()


def _verify_digest(path: Path) -> None:
    """The pin check. Runs on EVERY call, including cache hits — see ``ensure_corpus``."""
    actual = _digest(path)
    if actual != CORPUS_SHA256:
        raise CorpusIntegrityError(
            f"DIGEST MISMATCH for {path.name}.\n"
            f"  expected (pinned in demo/pin.py): {CORPUS_SHA256}\n"
            f"  actual                          : {actual}\n"
            "This is TERMINAL. The bytes are not the bytes this demo pinned, and retrying will not "
            "change that. Either the artifact was replaced, or the pin is wrong — resolve which, and "
            "do not proceed on the assumption that it is harmless. There is no override."
        )


def _safe_members(tar: tarfile.TarFile) -> list[tarfile.TarInfo]:
    """Refuse anything that is not a plain file at a plain relative path.

    A digest pins BYTES, NOT SEMANTICS: an archive can match its digest perfectly and still contain a
    symlink, a device node, a hardlink, an absolute path or a ``..`` traversal. The pin proves the
    archive is the one we expected; it does not make its contents safe to unpack.
    """
    members = tar.getmembers()
    seen: set[str] = set()
    for m in members:
        if not m.isfile():
            raise CorpusIntegrityError(
                f"member {m.name!r} is not a regular file (type {m.type!r}). Symlinks, hardlinks and "
                "device nodes are refused: a pinned archive can still carry them")
        if m.name.startswith("/") or ".." in Path(m.name).parts:
            raise CorpusIntegrityError(
                f"member {m.name!r} has an absolute or traversing path — refused before extraction")
        if m.name in seen:
            raise CorpusIntegrityError(
                f"member {m.name!r} appears TWICE. Extraction would silently overwrite the first with "
                "the second, so which bytes land on disk would depend on member order")
        seen.add(m.name)
    return members


def _verify_member_set(names: set[str]) -> None:
    """EXACT-SET equality, reported as two DIRECTED differences.

    Missing and extra are different defects with different causes and must not share a message. This
    is a distinct axis from content equality: every member's bytes can be right while the set is
    wrong, and no digest check would notice.
    """
    missing = EXPECTED_MEMBERS - names
    extra = names - EXPECTED_MEMBERS
    if missing:
        raise CorpusIntegrityError(f"corpus is MISSING expected member(s): {sorted(missing)}")
    if extra:
        raise CorpusIntegrityError(
            f"corpus carries UNEXPECTED member(s): {sorted(extra)}. The expected set is pinned in "
            "demo/pin.py and is exact, not a minimum")


def _verify_per_member(root: Path) -> None:
    """Check every member against the corpus's OWN manifest, parsed strictly.

    The outer digest proves the archive is the one we pinned. This proves what LANDED ON DISK is what
    the archive said — extraction is a step where bytes can still change (filesystem normalisation,
    case collisions), and it is where the reader's own offline verification will be aimed.
    """
    sums = root / "SHA256SUMS"
    if not sums.exists():
        raise CorpusIntegrityError("corpus has no SHA256SUMS")
    for lineno, line in enumerate(sums.read_text().splitlines(), 1):
        if not line.strip():
            continue
        # STRICT coreutils form: 64 hex, exactly two spaces, then the path. A lenient split() would
        # accept lines this format does not permit, and a parser more permissive than the format is a
        # parser that will one day accept something it should have refused.
        if len(line) < 67 or line[64:66] != "  ":
            raise CorpusIntegrityError(f"SHA256SUMS line {lineno} is not coreutils format: {line!r}")
        expected, member = line[:64], line[66:]
        if len(expected) != 64 or any(c not in "0123456789abcdef" for c in expected):
            raise CorpusIntegrityError(f"SHA256SUMS line {lineno} has a malformed digest")
        target = root / member
        if not target.exists():
            raise CorpusIntegrityError(f"SHA256SUMS lists {member!r}, which was not extracted")
        if _digest(target) != expected:
            raise CorpusIntegrityError(f"member digest mismatch after extraction: {member}")


def ensure_corpus(cache_dir: Path) -> Path:
    """Return a directory holding the verified corpus. Fetches only if the cache is absent.

    ⚠ VERIFICATION RUNS ON EVERY CALL, INCLUDING CACHE HITS. A cache verified once and trusted
    thereafter is a TOCTOU hole: the cache is writable by whatever else runs as this user, and by a
    crashed previous run. Verification is cheap; assuming is not.

    There is no code path in this function that yields a corpus without a digest check. That is a
    property of its SHAPE, not of its configuration — there is no flag to lose.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    archive = cache_dir / CORPUS_ARTIFACT

    if not archive.exists():
        # Download to a temporary name and move into place only after the digest matches, so a
        # truncated or hostile download never occupies the cache path. A poisoned partial would
        # otherwise fail every subsequent run — a self-inflicted denial of service at best.
        with tempfile.TemporaryDirectory(dir=str(cache_dir)) as tmp:
            staged = Path(tmp) / CORPUS_ARTIFACT
            _download(CORPUS_URL, staged)
            _verify_digest(staged)
            shutil.move(str(staged), str(archive))
    else:
        _verify_digest(archive)

    extracted = cache_dir / "corpus"
    if extracted.exists():
        shutil.rmtree(extracted)
    extracted.mkdir()

    with tarfile.open(archive, "r:") as tar:
        members = _safe_members(tar)
        _verify_member_set({m.name for m in members})
        # filter="data" is pinned EXPLICITLY, not left to the default. Python 3.14 changes that
        # default, and a security-relevant behaviour that changes underneath a pinned consumer is the
        # same silent drift this whole path exists to refuse. It is defence in depth behind
        # _safe_members, not a replacement for it: the members were already vetted above.
        tar.extractall(extracted, members=members, filter="data")  # noqa: S202 — vetted above

    _verify_per_member(extracted)
    return extracted
