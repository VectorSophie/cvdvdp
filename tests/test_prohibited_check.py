import pathlib
import unittest
from cvd import policy, prohibited_check

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


class TestProhibitedCheck(unittest.TestCase):
    def setUp(self):
        self.full = policy.load_policy(FIXTURES / "program.yaml", FIXTURES / "target_full.yaml")

    def test_flags_dos_keyword(self):
        findings = prohibited_check.check_action(self.full, "run a DoS flood against the login page")
        flags = [f["flag"] for f in findings]
        self.assertIn("dos", flags)

    def test_flags_brute_force_keyword(self):
        findings = prohibited_check.check_action(self.full, "attempt credential stuffing on the login form")
        flags = [f["flag"] for f in findings]
        self.assertIn("brute_force", flags)

    def test_flags_scanning_keyword_when_not_permitted(self):
        findings = prohibited_check.check_action(self.full, "run an automated scan with sqlmap against the API")
        flags = [f["flag"] for f in findings]
        self.assertIn("automated_scanning", flags)

    def test_does_not_flag_scanning_when_explicitly_permitted(self):
        target = dict(self.full.target)
        target["automation"] = {"scanner_allowed": True, "fuzzing_allowed": True}
        allowed_policy = policy.Policy(self.full.program, target)
        findings = prohibited_check.check_action(allowed_policy, "run an automated scan against the API")
        flags = [f["flag"] for f in findings]
        self.assertNotIn("automated_scanning", flags)

    def test_clean_description_flags_nothing(self):
        findings = prohibited_check.check_action(self.full, "manually check the login form for IDOR on the profile page")
        self.assertEqual(findings, [])

    def test_prohibited_field_false_suppresses_flag(self):
        target = dict(self.full.target)
        target["prohibited"] = {"dos": False}
        permissive_policy = policy.Policy(self.full.program, target)
        findings = prohibited_check.check_action(permissive_policy, "run a DoS flood against the login page")
        flags = [f["flag"] for f in findings]
        self.assertNotIn("dos", flags)


if __name__ == "__main__":
    unittest.main()
