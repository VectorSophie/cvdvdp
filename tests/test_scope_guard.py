import pathlib
import datetime
import tempfile
import unittest
from cvd import policy, gates, scope_guard

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


class TestCheckUrl(unittest.TestCase):
    def setUp(self):
        self.full = policy.load_policy(FIXTURES / "program.yaml", FIXTURES / "target_full.yaml")
        self.app_only = policy.load_policy(FIXTURES / "program.yaml", FIXTURES / "target_app_only.yaml")

    def test_allowed_exact_domain_match(self):
        result = scope_guard.check_url(self.full, "https://login.example.com/auth")
        self.assertEqual(result.verdict, "ALLOWED")

    def test_denied_unlisted_domain(self):
        result = scope_guard.check_url(self.full, "https://evil.example.com/auth")
        self.assertEqual(result.verdict, "DENIED")

    def test_denied_similar_subdomain_not_matched(self):
        # "login.example.com" is in scope; "sub.login.example.com" must NOT match by suffix
        result = scope_guard.check_url(self.full, "https://sub.login.example.com/auth")
        self.assertEqual(result.verdict, "DENIED")

    def test_denied_explicit_out_of_scope_even_if_hostname_looks_related(self):
        result = scope_guard.check_url(self.full, "https://internal.example.com/admin")
        self.assertEqual(result.verdict, "DENIED")
        self.assertIn("explicit_out_of_scope", result.reason)

    def test_allowed_url_path_prefix_match(self):
        result = scope_guard.check_url(self.full, "https://gateway.example.com/payments/v4/charge")
        self.assertEqual(result.verdict, "ALLOWED")

    def test_denied_url_path_outside_allowed_version(self):
        result = scope_guard.check_url(self.full, "https://gateway.example.com/payments/v3/charge")
        self.assertEqual(result.verdict, "DENIED")

    def test_not_applicable_for_app_only_target(self):
        result = scope_guard.check_url(self.app_only, "https://anything.example.com")
        self.assertEqual(result.verdict, "NOT_APPLICABLE")


class TestEvaluate(unittest.TestCase):
    def setUp(self):
        self.full = policy.load_policy(FIXTURES / "program.yaml", FIXTURES / "target_full.yaml")

    def test_denied_when_not_reviewed(self):
        with tempfile.TemporaryDirectory() as d:
            now = datetime.datetime(2026, 7, 19, 9, 0, tzinfo=gates.KST)
            result = scope_guard.evaluate(self.full, pathlib.Path(d), "https://login.example.com", now, reviewed=False)
            self.assertEqual(result.verdict, "DENIED")
            self.assertIn("reviewed", result.reason)

    def test_denied_outside_testing_window(self):
        with tempfile.TemporaryDirectory() as d:
            workspace_dir = pathlib.Path(d)
            now = datetime.datetime(2026, 8, 1, 9, 0, tzinfo=gates.KST)
            gates.write_attestation(workspace_dir, now)
            result = scope_guard.evaluate(self.full, workspace_dir, "https://login.example.com", now, reviewed=True)
            self.assertEqual(result.verdict, "DENIED")
            self.assertIn("testing window", result.reason)

    def test_denied_during_blackout(self):
        with tempfile.TemporaryDirectory() as d:
            workspace_dir = pathlib.Path(d)
            now = datetime.datetime(2026, 7, 16, 5, 0, tzinfo=gates.KST)  # Thursday 05:00 KST
            gates.write_attestation(workspace_dir, now)
            result = scope_guard.evaluate(self.full, workspace_dir, "https://login.example.com", now, reviewed=True)
            self.assertEqual(result.verdict, "DENIED")
            self.assertIn("blackout", result.reason)

    def test_denied_when_vpn_not_attested(self):
        with tempfile.TemporaryDirectory() as d:
            workspace_dir = pathlib.Path(d)
            now = datetime.datetime(2026, 7, 19, 9, 0, tzinfo=gates.KST)
            result = scope_guard.evaluate(self.full, workspace_dir, "https://login.example.com", now, reviewed=True)
            self.assertEqual(result.verdict, "DENIED")
            self.assertIn("VPN", result.reason)

    def test_allowed_when_all_gates_pass_and_in_scope(self):
        with tempfile.TemporaryDirectory() as d:
            workspace_dir = pathlib.Path(d)
            now = datetime.datetime(2026, 7, 19, 9, 0, tzinfo=gates.KST)  # Sunday, not blackout
            gates.write_attestation(workspace_dir, now)
            result = scope_guard.evaluate(self.full, workspace_dir, "https://login.example.com", now, reviewed=True)
            self.assertEqual(result.verdict, "ALLOWED")

    def test_denied_when_redirect_target_leaves_scope(self):
        with tempfile.TemporaryDirectory() as d:
            workspace_dir = pathlib.Path(d)
            now = datetime.datetime(2026, 7, 19, 9, 0, tzinfo=gates.KST)
            gates.write_attestation(workspace_dir, now)
            result = scope_guard.evaluate(
                self.full, workspace_dir, "https://login.example.com", now, reviewed=True,
                redirect_target="https://evil.example.com",
            )
            self.assertEqual(result.verdict, "DENIED")
            self.assertIn("Redirect", result.reason)
