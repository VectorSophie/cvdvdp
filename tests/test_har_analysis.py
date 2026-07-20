import pathlib
import unittest
from cvd import policy, har_analysis

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


class TestExtractUrls(unittest.TestCase):
    def test_extracts_all_request_urls(self):
        urls = har_analysis.extract_urls(FIXTURES / "sample.har")
        self.assertEqual(len(urls), 5)
        self.assertIn("https://evil.example.com/steal", urls)


class TestAnalyze(unittest.TestCase):
    def setUp(self):
        self.full = policy.load_policy(FIXTURES / "program.yaml", FIXTURES / "target_full.yaml")

    def test_deduplicates_and_counts_verdicts(self):
        summary = har_analysis.analyze(self.full, FIXTURES / "sample.har")
        self.assertEqual(summary["total_unique_requests"], 4)  # duplicate login URL collapses
        self.assertEqual(summary["allowed"], 2)  # login + payments/v4
        self.assertEqual(summary["denied"], 2)  # evil.example.com + payments/v3

    def test_flagged_entries_have_no_query_string_or_body(self):
        summary = har_analysis.analyze(self.full, FIXTURES / "sample.har")
        flagged_urls = [f["url_sanitized"] for f in summary["flagged"]]
        self.assertIn("https://evil.example.com/steal", flagged_urls)
        # confirm the sensitive query string from the login URL never appears anywhere in output,
        # even though that particular URL was ALLOWED and not in the flagged list
        self.assertNotIn("abc123secrettoken", str(summary))
