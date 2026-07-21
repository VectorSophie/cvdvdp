import pathlib
import unittest
from cvd import policy, report_scaffold

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
TEMPLATE_PATH = pathlib.Path(__file__).parent.parent / "templates" / "report-template.md"


class TestReportScaffold(unittest.TestCase):
    def setUp(self):
        self.full = policy.load_policy(FIXTURES / "program.yaml", FIXTURES / "target_full.yaml")

    def test_scaffold_fills_title(self):
        content = report_scaffold.scaffold("demo", "Example IDOR finding", self.full, TEMPLATE_PATH)
        self.assertIn("# Vulnerability Report — Example IDOR finding", content)

    def test_scaffold_fills_target_name(self):
        content = report_scaffold.scaffold("demo", "Example finding", self.full, TEMPLATE_PATH)
        self.assertIn("Test Target Full", content)

    def test_scaffold_fills_reporting_deadline_when_present(self):
        target = dict(self.full.target)
        target["reporting"] = {"discovery_deadline_hours": 72, "intrusion_deadline_hours": 12, "channel": "KISA FindTheGap"}
        p = policy.Policy(self.full.program, target)
        content = report_scaffold.scaffold("demo", "Example finding", p, TEMPLATE_PATH)
        self.assertIn("discovery + 72h", content)
        self.assertIn("KISA FindTheGap", content)

    def test_scaffold_preserves_rest_of_template(self):
        content = report_scaffold.scaffold("demo", "Example finding", self.full, TEMPLATE_PATH)
        self.assertIn("## VDP compliance checklist", content)


if __name__ == "__main__":
    unittest.main()
