import pathlib
import datetime
import tempfile
import unittest
from cvd import gates, policy

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


class TestTestingWindow(unittest.TestCase):
    def setUp(self):
        self.schedule = {
            "testing_start": "2026-06-29",
            "testing_end": "2026-07-21",
            "blackout_windows": [
                {"type": "weekly", "day": "Thursday", "start": "00:00", "end": "11:00", "timezone": "Asia/Seoul"}
            ],
        }

    def test_within_window(self):
        self.assertTrue(gates.is_within_testing_window(self.schedule, datetime.date(2026, 7, 10)))

    def test_before_window(self):
        self.assertFalse(gates.is_within_testing_window(self.schedule, datetime.date(2026, 6, 1)))

    def test_after_window(self):
        self.assertFalse(gates.is_within_testing_window(self.schedule, datetime.date(2026, 7, 22)))

    def test_boundary_dates_inclusive(self):
        self.assertTrue(gates.is_within_testing_window(self.schedule, datetime.date(2026, 6, 29)))
        self.assertTrue(gates.is_within_testing_window(self.schedule, datetime.date(2026, 7, 21)))

    def test_in_blackout_thursday_morning(self):
        # 2026-07-16 is a Thursday
        now = datetime.datetime(2026, 7, 16, 5, 0, tzinfo=gates.KST)
        self.assertTrue(gates.is_in_blackout(self.schedule, now))

    def test_not_in_blackout_thursday_afternoon(self):
        now = datetime.datetime(2026, 7, 16, 14, 0, tzinfo=gates.KST)
        self.assertFalse(gates.is_in_blackout(self.schedule, now))

    def test_not_in_blackout_other_weekday(self):
        now = datetime.datetime(2026, 7, 17, 5, 0, tzinfo=gates.KST)  # Friday
        self.assertFalse(gates.is_in_blackout(self.schedule, now))

    def test_no_blackout_windows_configured(self):
        schedule = {"testing_start": "2026-06-29", "testing_end": "2026-07-21", "blackout_windows": []}
        now = datetime.datetime(2026, 7, 16, 5, 0, tzinfo=gates.KST)
        self.assertFalse(gates.is_in_blackout(schedule, now))


class TestVpnAttestation(unittest.TestCase):
    def test_not_attested_when_no_file(self):
        with tempfile.TemporaryDirectory() as d:
            workspace_dir = pathlib.Path(d)
            now = datetime.datetime(2026, 7, 19, 9, 0, tzinfo=gates.KST)
            self.assertFalse(gates.is_vpn_attested(workspace_dir, now))

    def test_attested_immediately_after_write(self):
        with tempfile.TemporaryDirectory() as d:
            workspace_dir = pathlib.Path(d)
            now = datetime.datetime(2026, 7, 19, 9, 0, tzinfo=gates.KST)
            gates.write_attestation(workspace_dir, now)
            self.assertTrue(gates.is_vpn_attested(workspace_dir, now))

    def test_attestation_expires_after_ttl(self):
        with tempfile.TemporaryDirectory() as d:
            workspace_dir = pathlib.Path(d)
            attested_at = datetime.datetime(2026, 7, 19, 9, 0, tzinfo=gates.KST)
            gates.write_attestation(workspace_dir, attested_at)
            later = attested_at + datetime.timedelta(hours=5)
            self.assertFalse(gates.is_vpn_attested(workspace_dir, later))

    def test_attestation_fresh_within_ttl(self):
        with tempfile.TemporaryDirectory() as d:
            workspace_dir = pathlib.Path(d)
            attested_at = datetime.datetime(2026, 7, 19, 9, 0, tzinfo=gates.KST)
            gates.write_attestation(workspace_dir, attested_at)
            later = attested_at + datetime.timedelta(hours=3)
            self.assertTrue(gates.is_vpn_attested(workspace_dir, later))


class TestBuildStatus(unittest.TestCase):
    def test_build_status_fields(self):
        p = policy.load_policy(FIXTURES / "program.yaml", FIXTURES / "target_full.yaml")
        with tempfile.TemporaryDirectory() as d:
            workspace_dir = pathlib.Path(d)
            now = datetime.datetime(2026, 7, 19, 9, 0, tzinfo=gates.KST)
            gates.write_attestation(workspace_dir, now)
            status = gates.build_status(p, workspace_dir, now, reviewed=True)
            self.assertEqual(status["target"], "Test Target Full")
            self.assertTrue(status["policy_reviewed"])
            self.assertTrue(status["testing_window_open"])
            self.assertFalse(status["blackout_active"])  # 2026-07-19 is a Sunday
            self.assertTrue(status["vpn_attested"])
            self.assertEqual(status["automation"], "Prohibited - manual research only")
            self.assertEqual(status["scope_asset_count"], 3)  # 2 domains + 1 url
            self.assertEqual(status["reporting_deadline_days_left"], 5)  # 2026-07-24 minus 2026-07-19
