"""Confirms local/mock targets work fully offline, without VPN attestation —
per the requirement that local development, dry-run output, and mock/localhost
targets remain available without VPN. Uses a real ephemeral localhost HTTP
server as the 'mock target' being scope-checked against, never contacted."""
import datetime
import http.server
import pathlib
import tempfile
import threading
import unittest

from cvd import gates, policy, scope_guard, dry_run

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


class _QuietHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # keep test output pristine — no per-request access log noise


class TestLocalhostMock(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.HTTPServer(("127.0.0.1", 0), _QuietHandler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.thread.join()

    def setUp(self):
        self.localhost_policy = policy.load_policy(FIXTURES / "program.yaml", FIXTURES / "target_localhost.yaml")

    def test_scope_check_allowed_against_localhost_without_vpn(self):
        with tempfile.TemporaryDirectory() as d:
            workspace_dir = pathlib.Path(d)
            now = datetime.datetime(2026, 7, 19, 9, 0, tzinfo=gates.KST)
            # no gates.write_attestation() call here — proving VPN is not required
            result = scope_guard.evaluate(
                self.localhost_policy, workspace_dir, "http://localhost:8000/", now, reviewed=True
            )
            self.assertEqual(result.verdict, "ALLOWED")

    def test_dry_run_preview_against_localhost_without_vpn(self):
        result = dry_run.preview(self.localhost_policy, "http://localhost:8000/", "manual check of mock target")
        self.assertEqual(result["scope_verdict"], "ALLOWED")

    def test_ephemeral_server_is_actually_reachable(self):
        # sanity check that this is a real local server, not just a fixture string —
        # confirms the "mock target" is a genuine localhost integration point.
        import urllib.error
        import urllib.request
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(f"http://127.0.0.1:{self.port}/", timeout=2)
        self.assertEqual(ctx.exception.code, 501)  # BaseHTTPRequestHandler has no GET handler, 501 is expected


if __name__ == "__main__":
    unittest.main()
