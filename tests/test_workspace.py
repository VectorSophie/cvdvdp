import pathlib
import datetime
import tempfile
import json
import yaml
import unittest
from cvd import workspace, gates

FIXTURE_TARGET = {"name": "Test Target Full", "scope": {"allowed_domains": ["login.example.com"]}}


class TestInitWorkspace(unittest.TestCase):
    def test_creates_all_subdirs(self):
        with tempfile.TemporaryDirectory() as d:
            base = pathlib.Path(d)
            now = datetime.datetime(2026, 7, 19, 9, 0, tzinfo=gates.KST)
            target_dir = workspace.init_workspace(base, "demo", FIXTURE_TARGET, "hash123", now)
            for sub in workspace.SUBDIRS:
                self.assertTrue((target_dir / sub).is_dir(), f"{sub} not created")

    def test_writes_policy_snapshot(self):
        with tempfile.TemporaryDirectory() as d:
            base = pathlib.Path(d)
            now = datetime.datetime(2026, 7, 19, 9, 0, tzinfo=gates.KST)
            target_dir = workspace.init_workspace(base, "demo", FIXTURE_TARGET, "hash123", now)
            snapshot_path = target_dir / "policy-snapshot" / "snapshot.yaml"
            self.assertTrue(snapshot_path.exists())
            data = yaml.safe_load(snapshot_path.read_text())
            self.assertEqual(data["content_hash"], "hash123")
            self.assertEqual(data["policy"]["name"], "Test Target Full")


class TestSessionRecorder(unittest.TestCase):
    def _target_dir(self, base):
        now = datetime.datetime(2026, 7, 19, 9, 0, tzinfo=gates.KST)
        return workspace.init_workspace(base, "demo", FIXTURE_TARGET, "hash123", now), now

    def test_session_start_creates_file_with_expected_fields(self):
        with tempfile.TemporaryDirectory() as d:
            base = pathlib.Path(d)
            target_dir, now = self._target_dir(base)
            session_path = workspace.session_start(target_dir, "demo", "hash123", vpn_attested=True, now=now)
            self.assertTrue(session_path.exists())
            data = yaml.safe_load(session_path.read_text())
            self.assertEqual(data["target"], "demo")
            self.assertEqual(data["status"], "open")
            self.assertEqual(data["test_ids"], [])
            self.assertEqual(data["requests"], 0)
            self.assertTrue(data["vpn_attested"])

    def test_session_log_appends_note_and_increments_requests(self):
        with tempfile.TemporaryDirectory() as d:
            base = pathlib.Path(d)
            target_dir, now = self._target_dir(base)
            session_path = workspace.session_start(target_dir, "demo", "hash123", True, now)
            flagged = workspace.session_log(session_path, "checked login flow", test_id="T1")
            self.assertFalse(flagged)
            data = yaml.safe_load(session_path.read_text())
            self.assertEqual(data["requests"], 1)
            self.assertEqual(data["test_ids"], ["T1"])
            self.assertEqual(data["notes"][0]["note"], "checked login flow")

    def test_session_log_flags_and_masks_sensitive_note(self):
        with tempfile.TemporaryDirectory() as d:
            base = pathlib.Path(d)
            target_dir, now = self._target_dir(base)
            session_path = workspace.session_start(target_dir, "demo", "hash123", True, now)
            flagged = workspace.session_log(session_path, "found account for researcher@example.com")
            self.assertTrue(flagged)
            data = yaml.safe_load(session_path.read_text())
            self.assertNotIn("researcher@example.com", data["notes"][0]["note"])

    def test_session_stop_standard_deadline(self):
        with tempfile.TemporaryDirectory() as d:
            base = pathlib.Path(d)
            target_dir, now = self._target_dir(base)
            session_path = workspace.session_start(target_dir, "demo", "hash123", True, now)
            result = workspace.session_stop(session_path, "finished planned checks", now)
            self.assertEqual(result["status"], "closed")
            self.assertEqual(result["reporting_deadline_hours"], 72)

    def test_session_stop_intrusion_deadline(self):
        with tempfile.TemporaryDirectory() as d:
            base = pathlib.Path(d)
            target_dir, now = self._target_dir(base)
            session_path = workspace.session_start(target_dir, "demo", "hash123", True, now)
            result = workspace.session_stop(session_path, "unexpected network intrusion", now, intrusion=True)
            self.assertEqual(result["reporting_deadline_hours"], 12)

    def test_find_open_session_returns_open_one(self):
        with tempfile.TemporaryDirectory() as d:
            base = pathlib.Path(d)
            target_dir, now = self._target_dir(base)
            session_path = workspace.session_start(target_dir, "demo", "hash123", True, now)
            found = workspace.find_open_session(target_dir)
            self.assertEqual(found, session_path)

    def test_find_open_session_returns_none_after_stop(self):
        with tempfile.TemporaryDirectory() as d:
            base = pathlib.Path(d)
            target_dir, now = self._target_dir(base)
            session_path = workspace.session_start(target_dir, "demo", "hash123", True, now)
            workspace.session_stop(session_path, "done", now)
            found = workspace.find_open_session(target_dir)
            self.assertIsNone(found)


class TestAppendAudit(unittest.TestCase):
    def test_appends_masked_json_line(self):
        with tempfile.TemporaryDirectory() as d:
            base = pathlib.Path(d)
            now = datetime.datetime(2026, 7, 19, 9, 0, tzinfo=gates.KST)
            target_dir = workspace.init_workspace(base, "demo", FIXTURE_TARGET, "hash123", now)
            workspace.append_audit(target_dir, "scope-check", {"url": "researcher@example.com"}, now)
            audit_path = target_dir / "audit.jsonl"
            self.assertTrue(audit_path.exists())
            line = audit_path.read_text().strip().splitlines()[0]
            entry = json.loads(line)
            self.assertEqual(entry["command"], "scope-check")
            self.assertNotIn("researcher@example.com", entry["args"]["url"])

    def test_appends_multiple_lines(self):
        with tempfile.TemporaryDirectory() as d:
            base = pathlib.Path(d)
            now = datetime.datetime(2026, 7, 19, 9, 0, tzinfo=gates.KST)
            target_dir = workspace.init_workspace(base, "demo", FIXTURE_TARGET, "hash123", now)
            workspace.append_audit(target_dir, "cmd-one", {}, now)
            workspace.append_audit(target_dir, "cmd-two", {}, now)
            lines = (target_dir / "audit.jsonl").read_text().strip().splitlines()
            self.assertEqual(len(lines), 2)


class TestTargetIsolation(unittest.TestCase):
    def test_two_targets_get_separate_workspace_trees_and_sessions(self):
        with tempfile.TemporaryDirectory() as d:
            base = pathlib.Path(d)
            now = datetime.datetime(2026, 7, 19, 9, 0, tzinfo=gates.KST)
            dir_a = workspace.init_workspace(base, "target-a", {"name": "A"}, "hashA", now)
            dir_b = workspace.init_workspace(base, "target-b", {"name": "B"}, "hashB", now)
            self.assertNotEqual(dir_a, dir_b)

            session_a = workspace.session_start(dir_a, "target-a", "hashA", True, now)
            session_b = workspace.session_start(dir_b, "target-b", "hashB", True, now)

            # target-a's session file must not exist anywhere under target-b's tree, and vice versa
            self.assertNotIn(str(dir_b), str(session_a))
            self.assertNotIn(str(dir_a), str(session_b))

            # find_open_session on target-a's dir must never return target-b's session
            found_a = workspace.find_open_session(dir_a)
            self.assertEqual(found_a, session_a)
            self.assertNotEqual(found_a, session_b)
