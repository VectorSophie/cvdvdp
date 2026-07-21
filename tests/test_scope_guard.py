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

    def test_denied_url_path_boundary_enforcement_no_trailing_slash(self):
        # Regression: allowed_urls entry WITHOUT trailing slash before * must still enforce boundary
        # Entry: "gateway.example.com/payments/v4*" (no slash before *)
        # Should allow v4/charge but deny v4-evil/charge
        from cvd.policy import Policy
        policy_obj = Policy(
            program={},
            target={
                "scope": {
                    "allowed_domains": [],
                    "allowed_urls": ["gateway.example.com/payments/v4*"],
                    "explicit_out_of_scope": [],
                    "allowed_apis": [],
                    "allowed_apps": [],
                }
            },
        )
        # Should allow valid path
        result = scope_guard.check_url(policy_obj, "https://gateway.example.com/payments/v4/charge")
        self.assertEqual(result.verdict, "ALLOWED")

        # Should deny boundary violation (v4-evil, not v4/)
        result = scope_guard.check_url(policy_obj, "https://gateway.example.com/payments/v4-evil/charge")
        self.assertEqual(result.verdict, "DENIED")

    def test_denied_substring_host_not_matched(self):
        # "login.example.com" in scope; "evil-login.example.com" must NOT match (not a real subdomain)
        result = scope_guard.check_url(self.full, "https://evil-login.example.com/auth")
        self.assertEqual(result.verdict, "DENIED")

    def test_denied_hostname_truncation_suffix_injection(self):
        # "login.example.com" in scope; "login.example.com.evil.net" must NOT match
        result = scope_guard.check_url(self.full, "https://login.example.com.evil.net/auth")
        self.assertEqual(result.verdict, "DENIED")

    def test_allowed_uppercase_hostname(self):
        # urllib.parse.urlparse lowercases hostnames; "LOGIN.EXAMPLE.COM" should match "login.example.com"
        result = scope_guard.check_url(self.full, "https://LOGIN.EXAMPLE.COM/auth")
        self.assertEqual(result.verdict, "ALLOWED")


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

    def test_denied_when_schedule_missing(self):
        # Policy with missing schedule should fail closed
        from cvd.policy import Policy
        with tempfile.TemporaryDirectory() as d:
            workspace_dir = pathlib.Path(d)
            now = datetime.datetime(2026, 7, 19, 9, 0, tzinfo=gates.KST)
            gates.write_attestation(workspace_dir, now)
            malformed_policy = Policy(program={}, target={"scope": {}})
            result = scope_guard.evaluate(
                malformed_policy, workspace_dir, "https://example.com", now, reviewed=True
            )
            self.assertEqual(result.verdict, "DENIED")
            self.assertIn("schedule", result.reason)

    def test_denied_when_schedule_incomplete(self):
        # Policy with schedule dict present but missing required keys should fail closed
        from cvd.policy import Policy
        with tempfile.TemporaryDirectory() as d:
            workspace_dir = pathlib.Path(d)
            now = datetime.datetime(2026, 7, 19, 9, 0, tzinfo=gates.KST)
            gates.write_attestation(workspace_dir, now)
            # Schedule present but missing testing_start/testing_end
            malformed_policy = Policy(program={}, target={"schedule": {"blackout_windows": []}, "scope": {}})
            result = scope_guard.evaluate(
                malformed_policy, workspace_dir, "https://example.com", now, reviewed=True
            )
            self.assertEqual(result.verdict, "DENIED")
            self.assertIn("required fields", result.reason)

    def test_denied_when_schedule_has_malformed_date(self):
        # Policy with schedule containing invalid date strings should fail closed
        from cvd.policy import Policy
        with tempfile.TemporaryDirectory() as d:
            workspace_dir = pathlib.Path(d)
            now = datetime.datetime(2026, 7, 19, 9, 0, tzinfo=gates.KST)
            gates.write_attestation(workspace_dir, now)
            # Schedule with malformed date string
            malformed_policy = Policy(
                program={},
                target={
                    "schedule": {
                        "testing_start": "not-a-date",
                        "testing_end": "2026-07-21",
                        "blackout_windows": [],
                    },
                    "scope": {},
                },
            )
            result = scope_guard.evaluate(
                malformed_policy, workspace_dir, "https://example.com", now, reviewed=True
            )
            self.assertEqual(result.verdict, "DENIED")
            self.assertIn("invalid date", result.reason)
