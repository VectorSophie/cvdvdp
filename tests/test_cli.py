import argparse
import contextlib
import datetime
import io
import os
import pathlib
import shutil
import tempfile
import unittest
from unittest import mock

from cvd import cli, gates

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
REAL_POLICIES = pathlib.Path(__file__).parent.parent / "policies" / "targets"
FIXED_NOW = datetime.datetime(2026, 7, 19, 9, 0, tzinfo=gates.KST)  # Sunday, within window, no blackout


class CliTestBase(unittest.TestCase):
    def setUp(self):
        self._old_cwd = os.getcwd()
        self.tmp = tempfile.mkdtemp()
        os.chdir(self.tmp)
        os.makedirs("policies/targets", exist_ok=True)
        os.makedirs("templates", exist_ok=True)
        shutil.copy(FIXTURES / "program.yaml", "policies/program.yaml")
        shutil.copy(FIXTURES / "target_full.yaml", "policies/targets/demo.yaml")
        shutil.copy(
            pathlib.Path(__file__).parent.parent / "templates" / "report-template.md",
            "templates/report-template.md",
        )

    def tearDown(self):
        os.chdir(self._old_cwd)
        shutil.rmtree(self.tmp, ignore_errors=True)


class TestCliSmoke(CliTestBase):
    def test_validate_policy_backfills(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = cli.main(["validate-policy", "demo"], now=FIXED_NOW)
        self.assertEqual(code, 0)
        self.assertIn("backfilled", buf.getvalue())

    def test_review_policy_marks_reviewed_on_yes(self):
        with mock.patch("builtins.input", return_value="y"):
            code = cli.main(["review-policy", "demo"], now=FIXED_NOW)
        self.assertEqual(code, 0)

    def test_scope_check_denied_before_review(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = cli.main(["scope-check", "demo", "https://login.example.com"], now=FIXED_NOW)
        self.assertEqual(code, 1)
        self.assertIn("DENIED", buf.getvalue())

    def test_full_flow_review_attest_scope_check_allowed(self):
        with mock.patch("builtins.input", return_value="y"):
            cli.main(["review-policy", "demo"], now=FIXED_NOW)
            cli.main(["attest-vpn", "demo"], now=FIXED_NOW)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = cli.main(["scope-check", "demo", "https://login.example.com"], now=FIXED_NOW)
        self.assertEqual(code, 0)
        self.assertIn("ALLOWED", buf.getvalue())

    def test_workspace_init_creates_dirs(self):
        code = cli.main(["workspace-init", "demo"], now=FIXED_NOW)
        self.assertEqual(code, 0)
        self.assertTrue(pathlib.Path("workspace/demo/sessions").is_dir())

    def test_session_start_log_stop_flow(self):
        cli.main(["workspace-init", "demo"], now=FIXED_NOW)
        with mock.patch("builtins.input", return_value="y"):
            cli.main(["review-policy", "demo"], now=FIXED_NOW)
            cli.main(["attest-vpn", "demo"], now=FIXED_NOW)
        cli.main(["session-start", "demo"], now=FIXED_NOW)
        code = cli.main(["session-log", "demo", "checked login flow"], now=FIXED_NOW)
        self.assertEqual(code, 0)
        code = cli.main(["session-stop", "demo", "--reason", "done for today"], now=FIXED_NOW)
        self.assertEqual(code, 0)

    def test_session_start_blocked_without_vpn_attestation(self):
        cli.main(["workspace-init", "demo"], now=FIXED_NOW)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = cli.main(["session-start", "demo"], now=FIXED_NOW)
        self.assertEqual(code, 1)
        self.assertIn("VPN", buf.getvalue())
        self.assertFalse(list(pathlib.Path("workspace/demo/sessions").glob("*.yaml")))

    def test_scope_check_allowed_without_vpn_attestation(self):
        # scope-check is local/offline planning, not live testing — must work
        # even before VPN is connected.
        with mock.patch("builtins.input", return_value="y"):
            cli.main(["review-policy", "demo"], now=FIXED_NOW)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = cli.main(["scope-check", "demo", "https://login.example.com"], now=FIXED_NOW)
        self.assertEqual(code, 0)
        self.assertIn("ALLOWED", buf.getvalue())

    def test_analyze_har_reports_denied_count(self):
        shutil.copy(FIXTURES / "sample.har", "sample.har")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = cli.main(["analyze-har", "demo", "sample.har"], now=FIXED_NOW)
        self.assertEqual(code, 1)  # sample.har contains 2 denied requests
        self.assertIn("Denied: 2", buf.getvalue())

    def test_generate_test_plan_for_real_target(self):
        shutil.copy(REAL_POLICIES / "nexon.yaml", "policies/targets/nexon.yaml")
        code = cli.main(["generate-test-plan", "nexon"], now=FIXED_NOW)
        self.assertEqual(code, 0)
        generated = list(pathlib.Path("workspace/nexon/test-plans").glob("*.yaml"))
        self.assertGreater(len(generated), 0)

    def test_generate_test_plan_unknown_target_returns_error(self):
        code = cli.main(["generate-test-plan", "demo"], now=FIXED_NOW)
        self.assertEqual(code, 1)

    def test_dry_run_allowed_and_clean(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = cli.main(
                ["dry-run", "demo", "https://login.example.com", "manually check IDOR on profile"],
                now=FIXED_NOW,
            )
        self.assertEqual(code, 0)
        self.assertIn("DRY RUN", buf.getvalue())

    def test_dry_run_flags_prohibited_description(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = cli.main(
                ["dry-run", "demo", "https://login.example.com", "run a brute force credential stuffing attack"],
                now=FIXED_NOW,
            )
        self.assertEqual(code, 1)
        self.assertIn("brute_force", buf.getvalue())

    def test_new_report_scaffolds_file(self):
        code = cli.main(["new-report", "demo", "Example IDOR finding"], now=FIXED_NOW)
        self.assertEqual(code, 0)
        files = list(pathlib.Path("workspace/demo/reports").glob("*.md"))
        self.assertEqual(len(files), 1)
        self.assertIn("Example IDOR finding", files[0].read_text())

    def test_validate_all_reports_per_target_status(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = cli.main(["validate-all"], now=FIXED_NOW)
        self.assertEqual(code, 0)
        self.assertIn("demo:", buf.getvalue())
