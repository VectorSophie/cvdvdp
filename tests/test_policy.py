import pathlib
import unittest
import datetime
import tempfile
from cvd import policy

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


class TestLoadPolicy(unittest.TestCase):
    def test_load_policy_reads_both_files(self):
        p = policy.load_policy(FIXTURES / "program.yaml", FIXTURES / "target_full.yaml")
        self.assertEqual(p.target["name"], "Test Target Full")
        self.assertEqual(p.program["name"], "Test Program")

    def test_get_prefers_target_over_program(self):
        p = policy.load_policy(FIXTURES / "program.yaml", FIXTURES / "target_full.yaml")
        schedule = p.get("schedule")
        self.assertEqual(schedule["testing_start"], "2026-06-29")
        self.assertTrue(len(schedule["blackout_windows"]) == 1)

    def test_get_falls_back_to_program_when_target_missing_key(self):
        p = policy.load_policy(FIXTURES / "program.yaml", FIXTURES / "target_full.yaml")
        self.assertEqual(p.get("name"), "Test Target Full")  # target has 'name', wins
        self.assertIsNone(p.get("nonexistent_key"))


class TestContentHash(unittest.TestCase):
    def setUp(self):
        self.tmp = FIXTURES.parent / "_tmp_hash_test.yaml"
        self.tmp.write_text(
            "name: Hash Test\ncontent_hash: unknown\nfoo: bar\n"
        )

    def tearDown(self):
        if self.tmp.exists():
            self.tmp.unlink()

    def test_compute_hash_excludes_content_hash_field(self):
        data_a = {"name": "x", "content_hash": "aaa", "foo": "bar"}
        data_b = {"name": "x", "content_hash": "bbb", "foo": "bar"}
        self.assertEqual(policy.compute_hash(data_a), policy.compute_hash(data_b))

    def test_compute_hash_changes_when_other_field_changes(self):
        data_a = {"name": "x", "content_hash": "aaa", "foo": "bar"}
        data_b = {"name": "x", "content_hash": "aaa", "foo": "baz"}
        self.assertNotEqual(policy.compute_hash(data_a), policy.compute_hash(data_b))

    def test_validate_backfills_unknown_hash(self):
        result = policy.validate_content_hash(self.tmp)
        self.assertEqual(result, "backfilled")
        text = self.tmp.read_text()
        self.assertNotIn("content_hash: unknown", text)

    def test_validate_ok_after_backfill(self):
        policy.validate_content_hash(self.tmp)  # backfills
        result = policy.validate_content_hash(self.tmp)
        self.assertEqual(result, "ok")

    def test_validate_stale_after_edit(self):
        policy.validate_content_hash(self.tmp)  # backfills
        with open(self.tmp, "a") as f:
            f.write("new_field: added\n")
        result = policy.validate_content_hash(self.tmp)
        self.assertEqual(result, "stale")


class TestReviewGate(unittest.TestCase):
    def test_is_reviewed_false_when_never_reviewed(self):
        with tempfile.TemporaryDirectory() as d:
            base = pathlib.Path(d)
            self.assertFalse(policy.is_reviewed(base, "demo", "hash123"))

    def test_mark_reviewed_then_is_reviewed_true(self):
        with tempfile.TemporaryDirectory() as d:
            base = pathlib.Path(d)
            now = datetime.datetime(2026, 7, 19, 9, 0, tzinfo=datetime.timezone.utc)
            policy.mark_reviewed(base, "demo", "hash123", now)
            self.assertTrue(policy.is_reviewed(base, "demo", "hash123"))

    def test_is_reviewed_false_if_hash_changed_since_review(self):
        with tempfile.TemporaryDirectory() as d:
            base = pathlib.Path(d)
            now = datetime.datetime(2026, 7, 19, 9, 0, tzinfo=datetime.timezone.utc)
            policy.mark_reviewed(base, "demo", "hash123", now)
            self.assertFalse(policy.is_reviewed(base, "demo", "hash999"))
