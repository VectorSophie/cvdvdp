import pathlib
import unittest
from cvd import policy, dry_run

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


class TestDryRun(unittest.TestCase):
    def setUp(self):
        self.full = policy.load_policy(FIXTURES / "program.yaml", FIXTURES / "target_full.yaml")

    def test_preview_reports_allowed_scope(self):
        result = dry_run.preview(self.full, "https://login.example.com/auth", "manually check login flow")
        self.assertEqual(result["scope_verdict"], "ALLOWED")

    def test_preview_reports_denied_scope(self):
        result = dry_run.preview(self.full, "https://evil.example.com", "manually check login flow")
        self.assertEqual(result["scope_verdict"], "DENIED")

    def test_preview_carries_prohibited_flags(self):
        result = dry_run.preview(self.full, "https://login.example.com", "run a brute force attack on login")
        flags = [f["flag"] for f in result["prohibited_flags"]]
        self.assertIn("brute_force", flags)

    def test_preview_never_touches_network(self):
        # structural guarantee check: dry_run module imports no networking-capable
        # library, confirmed independently by tests/test_no_networking_import.py;
        # this test just confirms preview() returns without requiring any live
        # connectivity or credentials.
        result = dry_run.preview(self.full, "https://login.example.com", "check something", request_count=1)
        self.assertIn("DRY RUN", result["vpn_boundary_note"])

    def test_high_request_count_produces_warning_note(self):
        result = dry_run.preview(self.full, "https://login.example.com", "check something", request_count=50)
        self.assertIn("50", result["rate_note"])
        self.assertIn("fuzzing", result["rate_note"].lower())


if __name__ == "__main__":
    unittest.main()
