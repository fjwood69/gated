"""P3 step 0 — the countfile is published by ATOMIC RENAME, never truncate-then-write.

WHY THIS IS AN AST GUARD AND NOT A BEHAVIOURAL TEST, stated plainly because the distinction is the
whole warrant. A race window cannot be reliably seen red: a reader hammering ``cat`` during writes is
the strongest evidence available and is FLAKY BY CONSTRUCTION, and this suite already carries one
unexplained flake (gated#29) that nobody wants a second instance of. So the split ruled at the board
is: the window's existence was established BY READING THE CODE and REPRODUCED ONCE out of band (the
numbers are in the commit message and in ``write_count``'s own comment); THIS test is the standing
guard that the fix's SHAPE cannot be silently reverted.

Be honest about what that buys. This asserts the shape of the fix, NOT the absence of the race — the
two are not the same claim and only the reproduction speaks to the second. What makes the shape worth
pinning is that each of the three assertions below corresponds to a way the fix has a KNOWN silent
failure mode:

  * reverting to ``open(countfile, "w")`` restores the window verbatim;
  * dropping ``os.replace`` for a copy leaves a partial-write window;
  * moving the temp OFF the countfile's own directory degrades ``os.replace`` to copy-and-delete
    across a filesystem boundary — which reopens the exact window while every other check still
    passes. That third one is the reason the temp is spelled as a suffix ON ``countfile`` rather than
    assembled from a temp directory, and it is the one a reviewer is most likely to "tidy up".

Prose is deliberately not scanned. Tests in this tree have three times matched a COMMENT describing
the very code they were checking had been removed, so every assertion here parses the AST.

RED-PROOF MATRIX, run with bytecode caching disabled (``-B`` / ``PYTHONDONTWRITEBYTECODE=1`` /
``-p no:cacheprovider``, because stale ``__pycache__`` makes pytest run the UNMUTATED module and the
harness then UNDER-reports redness). Each revert was applied to a green tree and restored after:

    R1  revert to truncate-then-write                    all 3 red
    R2  temp in a temp dir instead of a sibling          ONLY test_the_temp_is_a_sibling...
    R3  copy instead of rename                           all 3 red
    R4  os.replace KEPT plus a stray truncating open     ONLY test_..._never_opened_for_truncating_write
    R5  a SECOND os.replace                              ONLY test_publication_goes_through_os_replace

R2/R4/R5 are ORTHOGONALITY witnesses and they are why the matrix has five rows rather than three. With
only R1–R3, tests 1 and 2 had no unique red witness: every revert that killed them killed the others
too, so nothing distinguished three real assertions from one assertion stated three ways. R4 and R5
were added after dissent made exactly that objection. A revert reddening EVERY assertion is weak
evidence for any individual one.
"""
from __future__ import annotations

import ast
import unittest
from pathlib import Path

_PROXY_SRC = Path(__file__).resolve().parent.parent / "observe" / "proxy.py"


def _write_count_def() -> ast.FunctionDef:
    """The nested ``write_count`` inside ``serve``, located structurally rather than by line."""
    tree = ast.parse(_PROXY_SRC.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "write_count":
            return node
    raise AssertionError(
        "observe/proxy.py no longer defines write_count — the countfile publication seam has moved "
        "and this guard is now blind. Re-point it rather than deleting it"
    )


def _assigned_exprs(fn: ast.FunctionDef, target: str) -> list[ast.expr]:
    """Every expression bound to ``target`` anywhere in ``fn``."""
    out: list[ast.expr] = []
    for node in ast.walk(fn):
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == target:
                    out.append(node.value)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if node.target.id == target and node.value is not None:
                out.append(node.value)
    return out


def _names_in(node: ast.expr) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


class CountfileIsPublishedAtomically(unittest.TestCase):
    """The reader is ``<rt> exec <proxy> cat <countfile>`` in ANOTHER PROCESS, holding no lock and
    unable to be made to hold one. The writer's in-process ``lock`` orders writers against each other
    and says nothing to that reader, so the window must be closed by construction."""

    def test_the_countfile_is_never_opened_for_truncating_write(self) -> None:
        """``open(countfile, "w")`` truncates first and publishes the value only at flush."""
        fn = _write_count_def()
        offenders = []
        for node in ast.walk(fn):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id == "open"):
                continue
            if not node.args:
                continue
            target = node.args[0]
            # The countfile itself, opened for writing, is the defect. A temp DERIVED from it is the fix.
            if isinstance(target, ast.Name) and target.id == "countfile":
                mode = node.args[1] if len(node.args) > 1 else None
                spelled = (mode.value if isinstance(mode, ast.Constant) else "w")
                if "w" in str(spelled) or "a" in str(spelled):
                    offenders.append(ast.dump(node))
        self.assertEqual(
            offenders, [],
            "write_count opens the countfile itself for writing — that TRUNCATES it, so a reader in "
            f"another process can observe an empty file and parse it as no-reading: {offenders}",
        )

    def test_publication_goes_through_os_replace(self) -> None:
        """Rename is what makes the swap atomic; a copy would reintroduce a partial-write window."""
        fn = _write_count_def()
        replaces = [
            n for n in ast.walk(fn)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
            and n.func.attr == "replace"
            and isinstance(n.func.value, ast.Name) and n.func.value.id == "os"
        ]
        self.assertEqual(
            len(replaces), 1,
            "write_count must publish the count with exactly one os.replace — a reader must see the "
            "whole old value or the whole new one, never a partial one",
        )

    def test_the_temp_is_a_sibling_of_the_countfile(self) -> None:
        """SAME FILESYSTEM OR THE FIX IS DECORATIVE.

        ``os.replace`` is atomic only WITHIN a filesystem. A temp under /tmp against a countfile on a
        mounted volume silently degrades to copy-and-delete and reopens the window — with os.replace
        still present and every other assertion here still green. So the source of the temp path is
        pinned: it must be DERIVED FROM ``countfile``, which makes same-directory a structural
        property rather than a convention someone can tidy away.
        """
        fn = _write_count_def()
        replaces = [
            n for n in ast.walk(fn)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
            and n.func.attr == "replace"
            and isinstance(n.func.value, ast.Name) and n.func.value.id == "os"
        ]
        self.assertTrue(replaces, "no os.replace to check the source of (see the previous assertion)")
        src = replaces[0].args[0]

        if isinstance(src, ast.Name):
            bindings = _assigned_exprs(fn, src.id)
            self.assertTrue(
                bindings,
                f"os.replace's source {src.id!r} is not bound inside write_count, so this guard "
                "cannot prove it is a sibling of the countfile",
            )
            derived = [b for b in bindings if "countfile" in _names_in(b)]
            self.assertEqual(
                len(derived), len(bindings),
                f"every binding of {src.id!r} must DERIVE from `countfile` so the temp lands in the "
                "countfile's own directory; a temp-dir path would make os.replace a cross-filesystem "
                "copy-and-delete and silently reopen the truncate window",
            )
        else:
            self.assertIn(
                "countfile", _names_in(src),
                "os.replace's source must derive from `countfile` (same directory, same filesystem)",
            )


if __name__ == "__main__":
    unittest.main()
