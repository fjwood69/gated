"""3.4 close-2 — the execution-closure audit tooling. Run: python3 -m unittest discover -s tests

Load-bearing: the authoring-time gate REFUSES dynamic import/exec (they escape a static closure, so
the 4-tuple identity would be spoofable); the strace parser flags any open outside the image root +
mount allowlist and any network syscall (the image must be --network=none).
"""
from __future__ import annotations

import unittest

from gate.closure_audit import (
    ClosureAuditError,
    DynamicImportError,
    assert_closure,
    assert_static_imports,
    audit_strace,
)


class DynamicImportGateTests(unittest.TestCase):
    def test_static_imports_pass(self) -> None:
        assert_static_imports("import os\nfrom pathlib import Path\n\ndef f():\n    return os.getcwd()\n")

    def test_importlib_refused(self) -> None:
        with self.assertRaises(DynamicImportError):
            assert_static_imports("import importlib\nm = importlib.import_module('x')\n")

    def test_from_importlib_refused(self) -> None:
        with self.assertRaises(DynamicImportError):
            assert_static_imports("from importlib import import_module\n")

    def test_eval_exec_dunder_import_refused(self) -> None:
        for src in ("y = eval('1+1')\n", "exec('x=1')\n", "m = __import__('os')\n"):
            with self.assertRaises(DynamicImportError):
                assert_static_imports(src)


class StraceClosureTests(unittest.TestCase):
    def test_opens_within_image_root_are_clean(self) -> None:
        lines = [
            'openat(AT_FDCWD, "/usr/lib/python3.11/os.py", O_RDONLY) = 3',
            'openat(AT_FDCWD, "/artifact/main.py", O_RDONLY) = 4',
        ]
        self.assertEqual(audit_strace(lines, image_root="/", allowed_prefixes=()), [])

    def test_open_outside_closure_flagged(self) -> None:
        lines = ['openat(AT_FDCWD, "/home/dev/.cache/evil.py", O_RDONLY) = 3']
        v = audit_strace(lines, image_root="/usr/", allowed_prefixes=("/artifact/", "/tmp/"))
        self.assertEqual(len(v), 1)
        self.assertIn("/home/dev/.cache/evil.py", v[0])

    def test_allowed_tmpfs_mount_is_clean(self) -> None:
        lines = ['openat(AT_FDCWD, "/tmp/calfx-abc/main.py", O_RDONLY) = 3']
        self.assertEqual(audit_strace(lines, image_root="/usr/", allowed_prefixes=("/tmp/",)), [])

    def test_network_syscall_flagged(self) -> None:
        lines = ['connect(3, {sa_family=AF_INET, sin_port=htons(443)}, 16) = 0']
        v = audit_strace(lines, image_root="/")
        self.assertEqual(len(v), 1)
        self.assertIn("network syscall", v[0])

    def test_assert_closure_raises_on_violation(self) -> None:
        with self.assertRaises(ClosureAuditError):
            assert_closure(['sendto(3, "x", 1, 0, ...) = 1'], image_root="/")
        assert_closure(['openat(AT_FDCWD, "/usr/lib/x.py", O_RDONLY) = 3'], image_root="/usr/")


if __name__ == "__main__":
    unittest.main()
