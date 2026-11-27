"""Regression tests for the unified CLI."""
from __future__ import annotations

import contextlib
import importlib.util
import io
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location(
    "analyst_pack", Path(__file__).with_name("analyst-pack.py")
)
assert spec and spec.loader
analyst_pack = importlib.util.module_from_spec(spec)
spec.loader.exec_module(analyst_pack)


class ShowTests(unittest.TestCase):
    def run_show(self, result: subprocess.CompletedProcess[str]) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        skill = {"_name": "example", "description": "An example skill."}
        with (
            patch.object(analyst_pack, "_load_skill", return_value=skill),
            patch.object(analyst_pack.os.path, "isfile", return_value=True),
            patch.object(analyst_pack.subprocess, "run", return_value=result),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            rc = analyst_pack.main(["show", "example"])
        return rc, stdout.getvalue(), stderr.getvalue()

    def test_failed_help_reports_error_and_exit_status(self):
        result = subprocess.CompletedProcess(
            args=[], returncode=2, stdout="", stderr="example: failed to load\n"
        )
        rc, _, stderr = self.run_show(result)
        self.assertEqual(rc, 2)
        self.assertIn("example: failed to load", stderr)

    def test_failed_help_without_stderr_still_reports_error(self):
        result = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr=""
        )
        rc, _, stderr = self.run_show(result)
        self.assertEqual(rc, 1)
        self.assertIn("Failed to show script commands for example", stderr)
        self.assertIn("exit code 1", stderr)

    def test_successful_help_preserves_output(self):
        result = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="usage: example scan\n", stderr=""
        )
        rc, stdout, stderr = self.run_show(result)
        self.assertEqual(rc, 0)
        self.assertIn("  usage: example scan", stdout)
        self.assertEqual(stderr, "")


if __name__ == "__main__":
    unittest.main()
