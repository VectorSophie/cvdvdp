import pathlib
import unittest
from cvd import policy, test_plan

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


class TestTestPlanGeneration(unittest.TestCase):
    def setUp(self):
        self.full = policy.load_policy(FIXTURES / "program.yaml", FIXTURES / "target_full.yaml")

    def test_generate_returns_entries_for_known_target(self):
        entries = test_plan.generate("nexon", self.full)
        self.assertGreater(len(entries), 0)
        ids = [e["id"] for e in entries]
        self.assertIn("NX-001", ids)

    def test_generate_returns_empty_for_unknown_target(self):
        entries = test_plan.generate("not-a-real-target", self.full)
        self.assertEqual(entries, [])

    def test_entry_has_required_schema_fields(self):
        entries = test_plan.generate("samsunglife", self.full)
        required = {
            "id", "title", "hypothesis", "target_component", "applicable_standard",
            "vdp_status", "manual_or_automated", "preconditions", "safe_test_accounts",
            "exact_steps", "expected_secure_behavior", "potential_vulnerable_behavior",
            "stop_conditions", "cleanup_steps", "evidence_to_collect", "risk_if_successful",
            "reportability",
        }
        for entry in entries:
            self.assertTrue(required.issubset(entry.keys()))

    def test_all_seven_real_targets_have_at_least_one_entry(self):
        for target in ("lguplus", "nexon", "ncsoft", "tosspayments", "samsunglife", "estsecurity", "inca"):
            entries = test_plan.generate(target, self.full)
            self.assertGreater(len(entries), 0, f"{target} has no test-plan entries")

    def test_manual_or_automated_is_always_manual(self):
        # this project builds no automation capability; every generated entry
        # must reflect that.
        for target in ("lguplus", "nexon", "ncsoft", "tosspayments", "samsunglife", "estsecurity", "inca"):
            for entry in test_plan.generate(target, self.full):
                self.assertEqual(entry["manual_or_automated"], "manual")


if __name__ == "__main__":
    unittest.main()
