#!/usr/bin/env python3
"""Shared rig for the sweep suite — NOT a test module.

⚠ IT IS DELIBERATELY NAMED SO ``unittest discover`` DOES NOT COLLECT IT. It matches no ``test*.py``
pattern, so it contributes no tests and cannot be counted twice. ``tests`` is a package, so the
split modules reach it by relative import with no ``sys.path`` handling of their own.

⚠ THE SPLIT THIS SERVES IS GUARDED BY A DERIVED COUNT, NOT A DECLARED ONE. See
``test_sweep_split_integrity.py``: the union of classes discovered across every split module must
equal the pre-split census in ``PRE-SPLIT-CENSUS.json``. A per-file expected count is one edit away
from being updated to match a drop; a union-equals-total assertion cannot drift from what is there.
"""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import sweep as S  # noqa: E402

__all__ = ["S", "json", "unittest", "Path", "_SweepHarness"]


class _SweepHarness(unittest.TestCase):
    """Shared rig: drive the REAL ``sweep`` over a controlled namespace and corpus.

    ⚠ EVERY ASSERTION BELOW GOES THROUGH PRODUCTION CODE. The lesson is ``ExpectedCountPins``, which
    reimplemented ``max()`` in its own body and therefore could not have failed for any mutation of
    the module it claimed to pin — a test that discharges nothing, in the file whose header condemns
    exactly that.
    """

    TOKEN = "ZZ-SWEEP-CONTROL-TOKEN"

    def _rec(self, **kw):
        d = {"id": "R", "seed": "a seed", "variants": ["a seed"], "anchors": [], "nets_run": [],
             "tombstones": [], "surfaces_at_withdrawal": [], "expected_counts": {},
             "parent": None, "created": ""}
        d.update(kw)
        return d
    def _ns(self, records=None, manifest=None, make_records_dir=True):
        import tempfile
        ns = Path(tempfile.mkdtemp())
        if make_records_dir:
            (ns / "records").mkdir()
            for r in (records or []):
                (ns / "records" / f"{r['id']}.json").write_text(json.dumps(r), encoding="utf-8")
        if manifest is not None:
            (ns / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        return ns

    def _sweep(self, ns, items=None, ids=None, cfg_counts=None):
        import contextlib
        import io
        from types import SimpleNamespace
        from unittest import mock
        items = items if items is not None else [("docs/a.md", self.TOKEN)]
        cfg = {"control_token": self.TOKEN, "surfaces": [],
               "expected_counts": cfg_counts or {}}
        surf = S.SurfaceResult("docs", "filesystem", f"{len(items)} files", len(items), items)
        out = io.StringIO()
        with mock.patch.object(S, "load_config", return_value=cfg), \
             mock.patch.object(S, "gather_surfaces", return_value=[surf]), \
             mock.patch.object(S, "NAMESPACE", ns), contextlib.redirect_stdout(out):
            rc = S.sweep(SimpleNamespace(records=ids or [], show=40))
        return rc, out.getvalue()
