# Compliance-Core CLI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the `cvd` CLI covering Phase 3 (Compliance Core) and the workspace/session-recorder slice of Phase 4, per `docs/superpowers/specs/2026-07-19-compliance-core-design.md`.

**Architecture:** A pure-Python package with no HTTP client dependency anywhere (structural guarantee that this tool cannot send a request to a target). Each module owns one responsibility (policy loading/validation, date/VPN/review gates, sensitive-data masking, scope matching, workspace/session files, HAR analysis) and takes explicit `now`/`base_dir` parameters instead of calling `datetime.now()` or hardcoding paths internally, so every function is testable without mocking the clock or the filesystem root. `cli.py` is the only module that reads real time/real paths/real stdin and wires the rest together.

**Tech Stack:** Python 3, stdlib `argparse`/`unittest`/`unittest.mock`/`hashlib`/`json`/`re`/`zoneinfo`, plus `PyYAML` (the one third-party dependency). No requests/httpx/urllib.request or any other networking library anywhere in `cvd/`.

## Global Constraints

- No HTTP client import anywhere in `cvd/` (requests, httpx, urllib.request, socket, http.client) — enforced by a static test in the final task.
- No database — all persistent state is YAML or JSON-lines files.
- Hostname/path scope matching is always exact/prefix match, never substring, suffix, or wildcard-as-regex — `subdomains_implicitly_allowed: false` on every real target file must hold in code, not just in the YAML.
- `unknown` in any policy field is never treated as permission.
- Every module function that needs the current time takes an explicit `now: datetime.datetime` parameter (timezone-aware, `Asia/Seoul`) — no bare `datetime.now()` calls outside `cli.py`.
- Every module function that touches the filesystem takes an explicit `base_dir` or full path parameter — no hardcoded `"workspace/"` string literals outside `cli.py`'s argument wiring.
- Test fixtures use synthetic mock policy data (`tests/fixtures/`) — never real target YAML from `policies/targets/`, and never real captured HAR/traffic data.
- Commit after every task.

---

## File Structure

```
cvd/
  __init__.py
  __main__.py       # entry point: python -m cvd ...
  policy.py         # load_yaml, Policy, compute_hash, validate_content_hash, mark_reviewed, is_reviewed
  masking.py        # redact, contains_sensitive
  gates.py          # is_within_testing_window, is_in_blackout, VPN attestation, build_status
  scope_guard.py    # check_url, evaluate
  workspace.py      # init_workspace, session_start/log/stop, append_audit, find_open_session
  har_analysis.py   # extract_urls, analyze
  cli.py            # argparse wiring, main(argv)
tests/
  fixtures/
    program.yaml
    target_full.yaml       # nexon-shaped: domains + structured weekly blackout
    target_minimal.yaml    # samsunglife-shaped: single bare domain, no blackout
    target_app_only.yaml   # estsecurity-shaped: no domains/urls, allowed_apps only
    sample.har
  test_policy.py
  test_masking.py
  test_gates.py
  test_scope_guard.py
  test_workspace.py
  test_har_analysis.py
  test_cli.py
  test_no_networking_import.py
```

---

### Task 1: Project scaffolding + `policy.py`

**Files:**
- Create: `cvd/__init__.py` (empty)
- Create: `cvd/policy.py`
- Create: `tests/__init__.py` (empty)
- Create: `tests/fixtures/program.yaml`
- Create: `tests/fixtures/target_full.yaml`
- Create: `tests/fixtures/target_minimal.yaml`
- Create: `tests/fixtures/target_app_only.yaml`
- Test: `tests/test_policy.py`

**Interfaces:**
- Produces: `policy.load_yaml(path: pathlib.Path) -> dict`; `class Policy` with `.program: dict`, `.target: dict`, `.get(key, default=None)` (target overrides program at top-level key); `policy.load_policy(program_path, target_path) -> Policy`; `policy.compute_hash(data: dict) -> str`; `policy.validate_content_hash(path: pathlib.Path) -> str` (returns `"ok"`, `"backfilled"`, or `"stale"`); `policy.review_state_path(base_dir: pathlib.Path, target: str) -> pathlib.Path`; `policy.mark_reviewed(base_dir: pathlib.Path, target: str, content_hash: str, now: datetime.datetime) -> None`; `policy.is_reviewed(base_dir: pathlib.Path, target: str, current_content_hash: str) -> bool`.

- [ ] **Step 1: Create package/test-package init files**

```bash
mkdir -p cvd tests/fixtures
touch cvd/__init__.py tests/__init__.py
```

- [ ] **Step 2: Write the fixture policy YAMLs**

`tests/fixtures/program.yaml`:
```yaml
name: Test Program
schedule:
  testing_start: "2026-06-29"
  testing_end: "2026-07-21"
  reporting_end: "2026-07-24"
  blackout_windows: []
  timezone: Asia/Seoul
scope:
  allowed_domains: []
  allowed_urls: []
  allowed_apis: []
  allowed_apps: []
  explicit_out_of_scope: []
  subdomains_implicitly_allowed: false
```

`tests/fixtures/target_full.yaml`:
```yaml
name: Test Target Full
content_hash: unknown
schedule:
  testing_start: "2026-06-29"
  testing_end: "2026-07-21"
  reporting_end: "2026-07-24"
  blackout_windows:
    - type: weekly
      day: Thursday
      start: "00:00"
      end: "11:00"
      timezone: Asia/Seoul
  timezone: Asia/Seoul
scope:
  allowed_domains:
    - login.example.com
    - api.example.com
  allowed_urls:
    - "gateway.example.com/payments/v4/*"
  allowed_apis: []
  allowed_apps: []
  explicit_out_of_scope:
    - "internal.example.com"
  subdomains_implicitly_allowed: false
```

`tests/fixtures/target_minimal.yaml`:
```yaml
name: Test Target Minimal
content_hash: unknown
schedule:
  testing_start: "2026-06-29"
  testing_end: "2026-07-21"
  reporting_end: "2026-07-24"
  blackout_windows: []
  timezone: Asia/Seoul
scope:
  allowed_domains:
    - www.example.com
  allowed_urls: []
  allowed_apis: []
  allowed_apps: []
  explicit_out_of_scope: []
  subdomains_implicitly_allowed: false
```

`tests/fixtures/target_app_only.yaml`:
```yaml
name: Test Target App Only
content_hash: unknown
schedule:
  testing_start: "2026-06-29"
  testing_end: "2026-07-21"
  reporting_end: "2026-07-24"
  blackout_windows: []
  timezone: Asia/Seoul
scope:
  allowed_domains: []
  allowed_urls: []
  allowed_apis: []
  allowed_apps:
    - "Example Desktop App v1.0, Windows 11 only"
  explicit_out_of_scope: []
  subdomains_implicitly_allowed: false
```

- [ ] **Step 3: Write the failing tests for loading and precedence**

`tests/test_policy.py`:
```python
import pathlib
import unittest
import datetime
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
```

- [ ] **Step 2b: Run test to verify it fails**

Run: `python -m unittest tests.test_policy -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'cvd.policy'` (or `ImportError`)

- [ ] **Step 4: Implement `load_yaml`, `Policy`, `load_policy`**

`cvd/policy.py`:
```python
import pathlib
import re
import hashlib
import datetime
import yaml


def load_yaml(path: pathlib.Path) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


class Policy:
    def __init__(self, program: dict, target: dict):
        self.program = program
        self.target = target

    def get(self, key, default=None):
        if key in self.target:
            return self.target[key]
        return self.program.get(key, default)


def load_policy(program_path: pathlib.Path, target_path: pathlib.Path) -> Policy:
    program = load_yaml(program_path)
    target = load_yaml(target_path)
    return Policy(program, target)
```

- [ ] **Step 5: Run test to verify loading/precedence passes**

Run: `python -m unittest tests.test_policy -v`
Expected: `test_load_policy_reads_both_files`, `test_get_prefers_target_over_program`, `test_get_falls_back_to_program_when_target_missing_key` all PASS

- [ ] **Step 6: Write failing tests for content-hash compute/validate/backfill**

Append to `tests/test_policy.py`:
```python
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
```

- [ ] **Step 7: Run to verify failure**

Run: `python -m unittest tests.test_policy -v`
Expected: FAIL — `AttributeError: module 'cvd.policy' has no attribute 'compute_hash'`

- [ ] **Step 8: Implement `compute_hash` and `validate_content_hash`**

Append to `cvd/policy.py`:
```python
def compute_hash(data: dict) -> str:
    stripped = {k: v for k, v in data.items() if k != "content_hash"}
    canonical = yaml.safe_dump(stripped, sort_keys=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _write_hash_line(path: pathlib.Path, new_hash: str) -> None:
    text = path.read_text(encoding="utf-8")
    updated = re.sub(
        r"^content_hash:.*$", f"content_hash: {new_hash}", text, count=1, flags=re.MULTILINE
    )
    path.write_text(updated, encoding="utf-8")


def validate_content_hash(path: pathlib.Path) -> str:
    data = load_yaml(path)
    computed = compute_hash(data)
    stored = data.get("content_hash")
    if not stored or stored == "unknown":
        _write_hash_line(path, computed)
        return "backfilled"
    if stored == computed:
        return "ok"
    return "stale"
```

- [ ] **Step 9: Run to verify pass**

Run: `python -m unittest tests.test_policy -v`
Expected: all `TestContentHash` cases PASS

- [ ] **Step 10: Write failing tests for the review-gate sidecar**

Append to `tests/test_policy.py`:
```python
import tempfile


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
```

- [ ] **Step 11: Run to verify failure**

Run: `python -m unittest tests.test_policy -v`
Expected: FAIL — `AttributeError: module 'cvd.policy' has no attribute 'is_reviewed'`

- [ ] **Step 12: Implement the review-gate sidecar functions**

Append to `cvd/policy.py`:
```python
def review_state_path(base_dir: pathlib.Path, target: str) -> pathlib.Path:
    return base_dir / ".review-state" / f"{target}.yaml"


def mark_reviewed(base_dir: pathlib.Path, target: str, content_hash: str, now: datetime.datetime) -> None:
    path = review_state_path(base_dir, target)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "reviewed": True,
        "reviewed_at": now.isoformat(),
        "content_hash_at_review": content_hash,
    }
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def is_reviewed(base_dir: pathlib.Path, target: str, current_content_hash: str) -> bool:
    path = review_state_path(base_dir, target)
    if not path.exists():
        return False
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not data.get("reviewed"):
        return False
    return data.get("content_hash_at_review") == current_content_hash
```

- [ ] **Step 13: Run full test file to verify everything passes**

Run: `python -m unittest tests.test_policy -v`
Expected: all tests PASS (9 tests total)

- [ ] **Step 14: Add PyYAML dependency declaration and commit**

Create `requirements.txt`:
```
PyYAML>=6.0
```

```bash
pip install -r requirements.txt
git add cvd/__init__.py cvd/policy.py tests/__init__.py tests/fixtures/ tests/test_policy.py requirements.txt
git commit -m "feat: add policy loading, content-hash validation, and review-gate sidecar"
```

---

### Task 2: `masking.py`

**Files:**
- Create: `cvd/masking.py`
- Test: `tests/test_masking.py`

**Interfaces:**
- Consumes: nothing (no dependency on Task 1)
- Produces: `masking.redact(text: str) -> str`; `masking.contains_sensitive(text: str) -> bool`

- [ ] **Step 1: Write the failing tests**

`tests/test_masking.py`:
```python
import unittest
from cvd import masking


class TestMasking(unittest.TestCase):
    def test_redacts_email(self):
        out = masking.redact("contact me at researcher@example.com please")
        self.assertNotIn("researcher@example.com", out)
        self.assertIn("[REDACTED:email]", out)

    def test_redacts_cookie_header(self):
        out = masking.redact("Cookie: session=abc123xyz; other=1")
        self.assertNotIn("session=abc123xyz", out)

    def test_redacts_bearer_token(self):
        out = masking.redact("Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")
        self.assertNotIn("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", out)

    def test_redacts_korean_phone_number(self):
        out = masking.redact("call 010-1234-5678 for details")
        self.assertNotIn("010-1234-5678", out)

    def test_redacts_korean_rrn_shaped_string(self):
        out = masking.redact("id number 901231-1234567 on file")
        self.assertNotIn("901231-1234567", out)

    def test_leaves_plain_text_alone(self):
        out = masking.redact("logged in as admin, checked the dashboard")
        self.assertEqual(out, "logged in as admin, checked the dashboard")

    def test_contains_sensitive_true_for_email(self):
        self.assertTrue(masking.contains_sensitive("reach me at a@b.com"))

    def test_contains_sensitive_false_for_plain_text(self):
        self.assertFalse(masking.contains_sensitive("nothing sensitive here"))
```

- [ ] **Step 2: Run to verify failure**

Run: `python -m unittest tests.test_masking -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'cvd.masking'`

- [ ] **Step 3: Implement `masking.py`**

`cvd/masking.py`:
```python
import re

PATTERNS = [
    ("cookie_header", re.compile(r"(?i)cookie:\s*\S+")),
    ("auth_bearer", re.compile(r"(?i)(authorization:\s*)?bearer\s+[a-z0-9._~+/=-]+")),
    ("email", re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")),
    ("phone_kr", re.compile(r"01[016789]-?\d{3,4}-?\d{4}")),
    ("rrn_kr", re.compile(r"\d{6}-?[1-4]\d{6}")),
    ("high_entropy_token", re.compile(r"\b[A-Za-z0-9_-]{32,}\b")),
]


def redact(text: str) -> str:
    result = text
    for label, pattern in PATTERNS:
        result = pattern.sub(f"[REDACTED:{label}]", result)
    return result


def contains_sensitive(text: str) -> bool:
    return any(pattern.search(text) for _, pattern in PATTERNS)
```

- [ ] **Step 4: Run to verify pass**

Run: `python -m unittest tests.test_masking -v`
Expected: all 8 tests PASS

- [ ] **Step 5: Commit**

```bash
git add cvd/masking.py tests/test_masking.py
git commit -m "feat: add sensitive-data masking for logs and session records"
```

---

### Task 3: `gates.py` — testing window, blackout, VPN attestation, status banner

**Files:**
- Create: `cvd/gates.py`
- Test: `tests/test_gates.py`

**Interfaces:**
- Consumes: `policy.Policy` (Task 1) for `build_status`
- Produces: `gates.KST` (a `zoneinfo.ZoneInfo`); `gates.parse_date(s: str) -> datetime.date`; `gates.is_within_testing_window(schedule: dict, today: datetime.date) -> bool`; `gates.is_in_blackout(schedule: dict, now: datetime.datetime) -> bool`; `gates.attestation_path(workspace_dir: pathlib.Path) -> pathlib.Path`; `gates.write_attestation(workspace_dir: pathlib.Path, now: datetime.datetime) -> None`; `gates.is_vpn_attested(workspace_dir: pathlib.Path, now: datetime.datetime, ttl_hours: int = 4) -> bool`; `gates.build_status(policy: "policy.Policy", workspace_dir: pathlib.Path, now: datetime.datetime, reviewed: bool) -> dict` (keys: `target`, `policy_reviewed`, `testing_window_open`, `blackout_active`, `vpn_attested`, `automation`, `scope_asset_count`, `reporting_deadline_days_left`).

- [ ] **Step 1: Write failing tests for the date/blackout checks**

`tests/test_gates.py`:
```python
import pathlib
import datetime
import tempfile
import unittest
from cvd import gates

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
```

- [ ] **Step 2: Run to verify failure**

Run: `python -m unittest tests.test_gates -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'cvd.gates'`

- [ ] **Step 3: Implement the date/blackout portion of `gates.py`**

`cvd/gates.py`:
```python
import datetime
import zoneinfo
import pathlib
import yaml

KST = zoneinfo.ZoneInfo("Asia/Seoul")
ATTESTATION_TTL_HOURS = 4
ATTESTATION_FILENAME = ".session-state.yaml"

_WEEKDAY_NAMES = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]


def parse_date(s: str) -> datetime.date:
    return datetime.date.fromisoformat(s)


def is_within_testing_window(schedule: dict, today: datetime.date) -> bool:
    start = parse_date(schedule["testing_start"])
    end = parse_date(schedule["testing_end"])
    return start <= today <= end


def is_in_blackout(schedule: dict, now: datetime.datetime) -> bool:
    windows = schedule.get("blackout_windows") or []
    for window in windows:
        if not isinstance(window, dict):
            continue
        if window.get("type") != "weekly":
            continue
        if _WEEKDAY_NAMES[now.weekday()] != window.get("day"):
            continue
        start_t = datetime.time.fromisoformat(window["start"])
        end_t = datetime.time.fromisoformat(window["end"])
        if start_t <= now.time() <= end_t:
            return True
    return False
```

- [ ] **Step 4: Run to verify the date/blackout tests pass**

Run: `python -m unittest tests.test_gates -v`
Expected: all 8 `TestTestingWindow` cases PASS

- [ ] **Step 5: Write failing tests for VPN attestation**

Append to `tests/test_gates.py`:
```python
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
```

- [ ] **Step 6: Run to verify failure**

Run: `python -m unittest tests.test_gates -v`
Expected: FAIL — `AttributeError: module 'cvd.gates' has no attribute 'write_attestation'`

- [ ] **Step 7: Implement VPN attestation functions**

Append to `cvd/gates.py`:
```python
def attestation_path(workspace_dir: pathlib.Path) -> pathlib.Path:
    return workspace_dir / ATTESTATION_FILENAME


def write_attestation(workspace_dir: pathlib.Path, now: datetime.datetime) -> None:
    workspace_dir.mkdir(parents=True, exist_ok=True)
    data = {"vpn_attested_at": now.isoformat()}
    attestation_path(workspace_dir).write_text(yaml.safe_dump(data), encoding="utf-8")


def is_vpn_attested(workspace_dir: pathlib.Path, now: datetime.datetime, ttl_hours: int = ATTESTATION_TTL_HOURS) -> bool:
    path = attestation_path(workspace_dir)
    if not path.exists():
        return False
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    raw = data.get("vpn_attested_at")
    if not raw:
        return False
    attested_at = datetime.datetime.fromisoformat(raw)
    return (now - attested_at) <= datetime.timedelta(hours=ttl_hours)
```

- [ ] **Step 8: Run to verify pass**

Run: `python -m unittest tests.test_gates -v`
Expected: all `TestVpnAttestation` cases PASS

- [ ] **Step 9: Write failing test for the status banner**

Append to `tests/test_gates.py`:
```python
from cvd import policy


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
```

- [ ] **Step 10: Run to verify failure**

Run: `python -m unittest tests.test_gates -v`
Expected: FAIL — `AttributeError: module 'cvd.gates' has no attribute 'build_status'`

- [ ] **Step 11: Implement `build_status`**

Append to `cvd/gates.py`:
```python
def _count_scope_assets(target: dict) -> int:
    scope = target.get("scope", {}) or {}
    total = 0
    for key in ("allowed_domains", "allowed_urls", "allowed_apis", "allowed_apps"):
        total += len(scope.get(key) or [])
    return total


def build_status(policy_obj, workspace_dir: pathlib.Path, now: datetime.datetime, reviewed: bool) -> dict:
    schedule = policy_obj.get("schedule")
    reporting_end = parse_date(schedule["reporting_end"])
    return {
        "target": policy_obj.target.get("name"),
        "policy_reviewed": reviewed,
        "testing_window_open": is_within_testing_window(schedule, now.date()),
        "blackout_active": is_in_blackout(schedule, now),
        "vpn_attested": is_vpn_attested(workspace_dir, now),
        "automation": "Prohibited - manual research only",
        "scope_asset_count": _count_scope_assets(policy_obj.target),
        "reporting_deadline_days_left": (reporting_end - now.date()).days,
    }
```

- [ ] **Step 12: Run to verify pass**

Run: `python -m unittest tests.test_gates -v`
Expected: all tests PASS (13 tests total)

- [ ] **Step 13: Update the real `policies/targets/nexon.yaml` with the structured blackout schema**

Modify `policies/targets/nexon.yaml` — change:
```yaml
  blackout_windows:
    - "Every Thursday 00:00-11:00 KST (정기점검/scheduled maintenance) — testing prohibited during this window"
```
to:
```yaml
  blackout_windows:
    - type: weekly
      day: Thursday
      start: "00:00"
      end: "11:00"
      timezone: Asia/Seoul
      notes: "정기점검/scheduled maintenance — testing prohibited during this window"
```

Then re-run `python -c "from cvd import policy; policy.load_yaml('policies/targets/nexon.yaml')"` from the repo root to confirm it still parses as valid YAML.

- [ ] **Step 14: Commit**

```bash
git add cvd/gates.py tests/test_gates.py policies/targets/nexon.yaml
git commit -m "feat: add testing-window, blackout, VPN attestation, and status-banner gates"
```

---

### Task 4: `scope_guard.py`

**Files:**
- Create: `cvd/scope_guard.py`
- Test: `tests/test_scope_guard.py`

**Interfaces:**
- Consumes: `policy.Policy` (Task 1), `gates.is_within_testing_window`/`is_in_blackout`/`is_vpn_attested` (Task 3)
- Produces: `class ScopeResult` with `.verdict: str` (one of `"ALLOWED"`, `"DENIED"`, `"NEEDS_CLARIFICATION"`, `"NOT_APPLICABLE"`) and `.reason: str`; `scope_guard.check_url(policy_obj, url: str) -> ScopeResult`; `scope_guard.evaluate(policy_obj, workspace_dir: pathlib.Path, url: str, now: datetime.datetime, reviewed: bool, redirect_target: str = None) -> ScopeResult`

- [ ] **Step 1: Write failing tests for `check_url`**

`tests/test_scope_guard.py`:
```python
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
```

- [ ] **Step 2: Run to verify failure**

Run: `python -m unittest tests.test_scope_guard -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'cvd.scope_guard'`

- [ ] **Step 3: Implement `check_url`**

`cvd/scope_guard.py`:
```python
import urllib.parse


class ScopeResult:
    def __init__(self, verdict: str, reason: str):
        self.verdict = verdict
        self.reason = reason

    def __repr__(self):
        return f"{self.verdict}: {self.reason}"

    def __eq__(self, other):
        return isinstance(other, ScopeResult) and self.verdict == other.verdict and self.reason == other.reason


def check_url(policy_obj, url: str) -> ScopeResult:
    scope = policy_obj.target.get("scope", {}) or {}
    allowed_domains = scope.get("allowed_domains") or []
    allowed_urls = scope.get("allowed_urls") or []
    out_of_scope = scope.get("explicit_out_of_scope") or []

    if not allowed_domains and not allowed_urls:
        return ScopeResult(
            "NOT_APPLICABLE",
            "This target's scope is not URL-based; see scope.allowed_apps in the target policy file.",
        )

    parsed = urllib.parse.urlparse(url)
    hostname = parsed.hostname or ""
    host_and_path = f"{hostname}{parsed.path}"

    for pattern in out_of_scope:
        if hostname == pattern or host_and_path.startswith(pattern):
            return ScopeResult("DENIED", f"Matches explicit_out_of_scope entry: {pattern!r}")

    if hostname in allowed_domains:
        return ScopeResult("ALLOWED", f"Hostname {hostname!r} matches scope.allowed_domains")

    for entry in allowed_urls:
        prefix = entry[:-1] if entry.endswith("*") else entry
        if host_and_path.startswith(prefix):
            return ScopeResult("ALLOWED", f"URL matches scope.allowed_urls entry: {entry!r}")

    return ScopeResult(
        "DENIED",
        f"Hostname {hostname!r} not in scope.allowed_domains and URL not in scope.allowed_urls",
    )
```

- [ ] **Step 4: Run to verify pass**

Run: `python -m unittest tests.test_scope_guard -v`
Expected: all 7 `TestCheckUrl` cases PASS

- [ ] **Step 5: Write failing tests for `evaluate` (the full gate + scope orchestration)**

Append to `tests/test_scope_guard.py`:
```python
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
```

- [ ] **Step 6: Run to verify failure**

Run: `python -m unittest tests.test_scope_guard -v`
Expected: FAIL — `AttributeError: module 'cvd.scope_guard' has no attribute 'evaluate'`

- [ ] **Step 7: Implement `evaluate`**

Append to `cvd/scope_guard.py`:
```python
from . import gates


def evaluate(policy_obj, workspace_dir, url: str, now, reviewed: bool, redirect_target: str = None) -> ScopeResult:
    if not reviewed:
        return ScopeResult("DENIED", "Policy has not been reviewed yet. Run: cvd review-policy <target>")

    schedule = policy_obj.get("schedule")
    if not gates.is_within_testing_window(schedule, now.date()):
        return ScopeResult(
            "DENIED",
            f"Outside authorized testing window {schedule['testing_start']}..{schedule['testing_end']}",
        )
    if gates.is_in_blackout(schedule, now):
        return ScopeResult("DENIED", "Currently inside a blackout window for this target")
    if not gates.is_vpn_attested(workspace_dir, now):
        return ScopeResult(
            "DENIED", "VPN not attested this session (or attestation expired). Run: cvd attest-vpn <target>"
        )

    result = check_url(policy_obj, url)
    if result.verdict == "ALLOWED" and redirect_target:
        redirect_result = check_url(policy_obj, redirect_target)
        if redirect_result.verdict != "ALLOWED":
            return ScopeResult("DENIED", f"Redirect target leaves scope: {redirect_result.reason}")
    return result
```

- [ ] **Step 8: Run to verify pass**

Run: `python -m unittest tests.test_scope_guard -v`
Expected: all 13 tests PASS

- [ ] **Step 9: Commit**

```bash
git add cvd/scope_guard.py tests/test_scope_guard.py
git commit -m "feat: add scope guard with date/blackout/VPN gate orchestration"
```

---

### Task 5: `workspace.py` — workspace init, session recorder, audit log

**Files:**
- Create: `cvd/workspace.py`
- Test: `tests/test_workspace.py`

**Interfaces:**
- Consumes: `gates.KST` (Task 3), `masking.redact`/`masking.contains_sensitive` (Task 2)
- Produces: `workspace.SUBDIRS: list[str]`; `workspace.init_workspace(base_dir: pathlib.Path, target: str, target_policy_dict: dict, content_hash: str, now: datetime.datetime) -> pathlib.Path`; `workspace.session_start(target_dir: pathlib.Path, target: str, content_hash: str, vpn_attested: bool, now: datetime.datetime) -> pathlib.Path`; `workspace.session_log(session_path: pathlib.Path, note: str, test_id: str = None) -> bool` (returns whether the note tripped the masking advisory); `workspace.session_stop(session_path: pathlib.Path, reason: str, now: datetime.datetime, intrusion: bool = False) -> dict`; `workspace.find_open_session(target_dir: pathlib.Path) -> pathlib.Path | None`; `workspace.append_audit(target_dir: pathlib.Path, command: str, args: dict, now: datetime.datetime) -> None`

- [ ] **Step 1: Write failing tests for `init_workspace`**

`tests/test_workspace.py`:
```python
import pathlib
import datetime
import tempfile
import json
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
            import yaml
            data = yaml.safe_load(snapshot_path.read_text())
            self.assertEqual(data["content_hash"], "hash123")
            self.assertEqual(data["policy"]["name"], "Test Target Full")
```

- [ ] **Step 2: Run to verify failure**

Run: `python -m unittest tests.test_workspace -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'cvd.workspace'`

- [ ] **Step 3: Implement `init_workspace`**

`cvd/workspace.py`:
```python
import pathlib
import datetime
import json
import yaml
from . import masking

SUBDIRS = [
    "policy-snapshot",
    "reconnaissance",
    "attack-surface",
    "test-plans",
    "sessions",
    "findings",
    "reports",
    "cleanup",
]


def init_workspace(
    base_dir: pathlib.Path, target: str, target_policy_dict: dict, content_hash: str, now: datetime.datetime
) -> pathlib.Path:
    target_dir = base_dir / "workspace" / target
    for sub in SUBDIRS:
        (target_dir / sub).mkdir(parents=True, exist_ok=True)
    snapshot = {
        "policy": target_policy_dict,
        "content_hash": content_hash,
        "snapshotted_at": now.isoformat(),
    }
    (target_dir / "policy-snapshot" / "snapshot.yaml").write_text(
        yaml.safe_dump(snapshot, sort_keys=False), encoding="utf-8"
    )
    return target_dir
```

- [ ] **Step 4: Run to verify pass**

Run: `python -m unittest tests.test_workspace -v`
Expected: both `TestInitWorkspace` cases PASS

- [ ] **Step 5: Write failing tests for the session recorder**

Append to `tests/test_workspace.py`:
```python
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
```

Add `import yaml` to the top of `tests/test_workspace.py` (needed by the assertions above).

- [ ] **Step 6: Run to verify failure**

Run: `python -m unittest tests.test_workspace -v`
Expected: FAIL — `AttributeError: module 'cvd.workspace' has no attribute 'session_start'`

- [ ] **Step 7: Implement the session recorder functions**

Append to `cvd/workspace.py`:
```python
def session_start(
    target_dir: pathlib.Path, target: str, content_hash: str, vpn_attested: bool, now: datetime.datetime
) -> pathlib.Path:
    sessions_dir = target_dir / "sessions"
    sessions_dir.mkdir(parents=True, exist_ok=True)
    now_utc = now.astimezone(datetime.timezone.utc)
    filename = now_utc.strftime("%Y%m%dT%H%M%S%fZ") + ".yaml"
    path = sessions_dir / filename
    data = {
        "target": target,
        "start_time_kst": now.isoformat(),
        "start_time_utc": now_utc.isoformat(),
        "policy_content_hash": content_hash,
        "vpn_attested": vpn_attested,
        "test_ids": [],
        "requests": 0,
        "test_data_created": [],
        "notes": [],
        "status": "open",
    }
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return path


def session_log(session_path: pathlib.Path, note: str, test_id: str = None) -> bool:
    data = yaml.safe_load(session_path.read_text(encoding="utf-8"))
    flagged = masking.contains_sensitive(note)
    entry = {"note": masking.redact(note)}
    if test_id:
        entry["test_id"] = test_id
        data["test_ids"].append(test_id)
    data["notes"].append(entry)
    data["requests"] += 1
    session_path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return flagged


def session_stop(session_path: pathlib.Path, reason: str, now: datetime.datetime, intrusion: bool = False) -> dict:
    data = yaml.safe_load(session_path.read_text(encoding="utf-8"))
    now_utc = now.astimezone(datetime.timezone.utc)
    data["end_time_kst"] = now.isoformat()
    data["end_time_utc"] = now_utc.isoformat()
    data["stop_reason"] = masking.redact(reason)
    data["status"] = "closed"
    data["reporting_deadline_hours"] = 12 if intrusion else 72
    deadline = now + datetime.timedelta(hours=data["reporting_deadline_hours"])
    data["reporting_deadline_at_kst"] = deadline.isoformat()
    session_path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return data


def find_open_session(target_dir: pathlib.Path) -> pathlib.Path:
    sessions_dir = target_dir / "sessions"
    if not sessions_dir.is_dir():
        return None
    candidates = sorted(sessions_dir.glob("*.yaml"), reverse=True)
    for path in candidates:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if data.get("status") == "open":
            return path
    return None
```

- [ ] **Step 8: Run to verify pass**

Run: `python -m unittest tests.test_workspace -v`
Expected: all `TestSessionRecorder` cases PASS

- [ ] **Step 9: Write failing test for `append_audit`**

Append to `tests/test_workspace.py`:
```python
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
```

- [ ] **Step 10: Run to verify failure**

Run: `python -m unittest tests.test_workspace -v`
Expected: FAIL — `AttributeError: module 'cvd.workspace' has no attribute 'append_audit'`

- [ ] **Step 11: Implement `append_audit`**

Append to `cvd/workspace.py`:
```python
def append_audit(target_dir: pathlib.Path, command: str, args: dict, now: datetime.datetime) -> None:
    audit_path = target_dir / "audit.jsonl"
    masked_args = {k: masking.redact(str(v)) for k, v in args.items()}
    entry = {"time_kst": now.isoformat(), "command": command, "args": masked_args}
    with open(audit_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
```

- [ ] **Step 12: Write and verify the target-isolation test**

Append to `tests/test_workspace.py`:
```python
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
```

Run: `python -m unittest tests.test_workspace -v`
Expected: PASS immediately (isolation falls out of `init_workspace` namespacing sessions under `base_dir / "workspace" / target` — this test exists to guarantee that stays true as the code evolves, not because it's expected to fail first)

- [ ] **Step 13: Run full test file to verify everything passes**

Run: `python -m unittest tests.test_workspace -v`
Expected: all tests PASS

- [ ] **Step 14: Commit**

```bash
git add cvd/workspace.py tests/test_workspace.py
git commit -m "feat: add workspace init, session recorder, and audit log"
```

---

### Task 6: `har_analysis.py`

**Files:**
- Create: `cvd/har_analysis.py`
- Create: `tests/fixtures/sample.har`
- Test: `tests/test_har_analysis.py`

**Interfaces:**
- Consumes: `scope_guard.check_url` (Task 4)
- Produces: `har_analysis.extract_urls(har_path: pathlib.Path) -> list[str]`; `har_analysis.analyze(policy_obj, har_path: pathlib.Path) -> dict` (keys: `total_unique_requests`, `allowed`, `denied`, `needs_clarification`, `not_applicable`, `flagged` — a list of `{"url_sanitized": str, "verdict": str, "reason": str}` for every non-`ALLOWED` entry)

- [ ] **Step 1: Write the synthetic fixture HAR file**

`tests/fixtures/sample.har` (synthetic, not real captured traffic):
```json
{
  "log": {
    "version": "1.2",
    "entries": [
      {"request": {"method": "GET", "url": "https://login.example.com/auth?token=abc123secrettoken"}},
      {"request": {"method": "GET", "url": "https://login.example.com/auth?token=abc123secrettoken"}},
      {"request": {"method": "GET", "url": "https://evil.example.com/steal"}},
      {"request": {"method": "GET", "url": "https://gateway.example.com/payments/v4/charge"}},
      {"request": {"method": "GET", "url": "https://gateway.example.com/payments/v3/charge"}}
    ]
  }
}
```

- [ ] **Step 2: Write the failing tests**

`tests/test_har_analysis.py`:
```python
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
```

- [ ] **Step 3: Run to verify failure**

Run: `python -m unittest tests.test_har_analysis -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'cvd.har_analysis'`

- [ ] **Step 4: Implement `har_analysis.py`**

`cvd/har_analysis.py`:
```python
import json
import pathlib
import urllib.parse
from . import scope_guard


def extract_urls(har_path: pathlib.Path) -> list:
    data = json.loads(har_path.read_text(encoding="utf-8"))
    urls = []
    for entry in data.get("log", {}).get("entries", []):
        url = entry.get("request", {}).get("url")
        if url:
            urls.append(url)
    return urls


def _sanitize(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"


def analyze(policy_obj, har_path: pathlib.Path) -> dict:
    urls = extract_urls(har_path)
    unique_urls = sorted(set(urls))
    results = []
    for url in unique_urls:
        result = scope_guard.check_url(policy_obj, url)
        results.append((url, result))

    flagged = []
    for url, result in results:
        if result.verdict != "ALLOWED":
            flagged.append({"url_sanitized": _sanitize(url), "verdict": result.verdict, "reason": result.reason})

    return {
        "total_unique_requests": len(unique_urls),
        "allowed": sum(1 for _, r in results if r.verdict == "ALLOWED"),
        "denied": sum(1 for _, r in results if r.verdict == "DENIED"),
        "needs_clarification": sum(1 for _, r in results if r.verdict == "NEEDS_CLARIFICATION"),
        "not_applicable": sum(1 for _, r in results if r.verdict == "NOT_APPLICABLE"),
        "flagged": flagged,
    }
```

- [ ] **Step 5: Run to verify pass**

Run: `python -m unittest tests.test_har_analysis -v`
Expected: all 4 tests PASS

- [ ] **Step 6: Commit**

```bash
git add cvd/har_analysis.py tests/fixtures/sample.har tests/test_har_analysis.py
git commit -m "feat: add HAR analysis reusing scope guard matching logic"
```

---

### Task 7: `cli.py` — argparse wiring for all subcommands

**Files:**
- Create: `cvd/cli.py`
- Create: `cvd/__main__.py`
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: everything from Tasks 1–6 (`policy`, `gates`, `scope_guard`, `workspace`, `har_analysis`)
- Produces: `cli.main(argv: list = None, now: datetime.datetime = None) -> int`; `cli.build_parser() -> argparse.ArgumentParser`; `cli.cmd_review_policy`, `cli.cmd_validate_policy`, `cli.cmd_attest_vpn`, `cli.cmd_status`, `cli.cmd_scope_check`, `cli.cmd_workspace_init`, `cli.cmd_session_start`, `cli.cmd_session_log`, `cli.cmd_session_stop`, `cli.cmd_analyze_har` — each `(args: argparse.Namespace, now: datetime.datetime) -> int`, except the two interactive ones which take an extra `input_fn: callable = None`.

**Important design note carried into the code below:** `main()` takes an optional `now` override specifically so tests never depend on the real wall clock — every fixture uses fixed 2026 dates, and a test that called the real `datetime.now()` would pass or fail depending on what day it's actually run, which is a bug, not a flaky test to tolerate. Similarly, the two interactive command functions default `input_fn` to `None` and resolve it to the builtin `input` *inside the function body*, not in the parameter list — a default value of `input_fn=input` in the signature would capture the real `input` function once at module-import time, before `unittest.mock.patch("builtins.input", ...)` ever runs, so the patch would silently have no effect and the test would hang waiting on real stdin.

- [ ] **Step 1: Write the failing smoke tests**

`tests/test_cli.py`:
```python
import argparse
import contextlib
import datetime
import io
import os
import pathlib
import shutil
import tempfile
import unittest
from unittest import mock

from cvd import cli, gates

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
FIXED_NOW = datetime.datetime(2026, 7, 19, 9, 0, tzinfo=gates.KST)  # Sunday, within window, no blackout


class CliTestBase(unittest.TestCase):
    def setUp(self):
        self._old_cwd = os.getcwd()
        self.tmp = tempfile.mkdtemp()
        os.chdir(self.tmp)
        os.makedirs("policies/targets", exist_ok=True)
        shutil.copy(FIXTURES / "program.yaml", "policies/program.yaml")
        shutil.copy(FIXTURES / "target_full.yaml", "policies/targets/demo.yaml")

    def tearDown(self):
        os.chdir(self._old_cwd)
        shutil.rmtree(self.tmp, ignore_errors=True)


class TestCliSmoke(CliTestBase):
    def test_validate_policy_backfills(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = cli.main(["validate-policy", "demo"], now=FIXED_NOW)
        self.assertEqual(code, 0)
        self.assertIn("backfilled", buf.getvalue())

    def test_review_policy_marks_reviewed_on_yes(self):
        with mock.patch("builtins.input", return_value="y"):
            code = cli.main(["review-policy", "demo"], now=FIXED_NOW)
        self.assertEqual(code, 0)

    def test_scope_check_denied_before_review(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = cli.main(["scope-check", "demo", "https://login.example.com"], now=FIXED_NOW)
        self.assertEqual(code, 1)
        self.assertIn("DENIED", buf.getvalue())

    def test_full_flow_review_attest_scope_check_allowed(self):
        with mock.patch("builtins.input", return_value="y"):
            cli.main(["review-policy", "demo"], now=FIXED_NOW)
            cli.main(["attest-vpn", "demo"], now=FIXED_NOW)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = cli.main(["scope-check", "demo", "https://login.example.com"], now=FIXED_NOW)
        self.assertEqual(code, 0)
        self.assertIn("ALLOWED", buf.getvalue())

    def test_workspace_init_creates_dirs(self):
        code = cli.main(["workspace-init", "demo"], now=FIXED_NOW)
        self.assertEqual(code, 0)
        self.assertTrue(pathlib.Path("workspace/demo/sessions").is_dir())

    def test_session_start_log_stop_flow(self):
        cli.main(["workspace-init", "demo"], now=FIXED_NOW)
        with mock.patch("builtins.input", return_value="y"):
            cli.main(["review-policy", "demo"], now=FIXED_NOW)
            cli.main(["attest-vpn", "demo"], now=FIXED_NOW)
        cli.main(["session-start", "demo"], now=FIXED_NOW)
        code = cli.main(["session-log", "demo", "checked login flow"], now=FIXED_NOW)
        self.assertEqual(code, 0)
        code = cli.main(["session-stop", "demo", "--reason", "done for today"], now=FIXED_NOW)
        self.assertEqual(code, 0)

    def test_analyze_har_reports_denied_count(self):
        shutil.copy(FIXTURES / "sample.har", "sample.har")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = cli.main(["analyze-har", "demo", "sample.har"], now=FIXED_NOW)
        self.assertEqual(code, 1)  # sample.har contains 2 denied requests
        self.assertIn("Denied: 2", buf.getvalue())
```

- [ ] **Step 2: Run to verify failure**

Run: `python -m unittest tests.test_cli -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'cvd.cli'`

- [ ] **Step 3: Implement `cvd/cli.py`**

```python
import argparse
import datetime
import pathlib
import sys

from . import policy, gates, scope_guard, workspace, har_analysis

PROGRAM_POLICY_PATH = pathlib.Path("policies/program.yaml")
BASE_DIR = pathlib.Path(".")


def _target_policy_path(target: str) -> pathlib.Path:
    return pathlib.Path("policies/targets") / f"{target}.yaml"


def _load(target: str):
    return policy.load_policy(PROGRAM_POLICY_PATH, _target_policy_path(target))


def _now() -> datetime.datetime:
    return datetime.datetime.now(gates.KST)


def _current_content_hash(target: str) -> str:
    data = policy.load_yaml(_target_policy_path(target))
    return policy.compute_hash(data)


def cmd_review_policy(args, now, input_fn=None):
    if input_fn is None:
        input_fn = input
    target_path = _target_policy_path(args.target)
    status = policy.validate_content_hash(target_path)
    p = _load(args.target)
    print(f"--- Policy for {args.target} ({status}) ---")
    print(f"Scope: {p.target.get('scope')}")
    print(f"Prohibited: {p.target.get('prohibited')}")
    print(f"Reporting: {p.target.get('reporting')}")
    answer = input_fn("Confirm you have reviewed this policy in full? [y/N] ")
    if answer.strip().lower() != "y":
        print("Not marked reviewed.")
        return 1
    content_hash = _current_content_hash(args.target)
    policy.mark_reviewed(BASE_DIR, args.target, content_hash, now)
    print(f"{args.target} marked reviewed.")
    return 0


def cmd_validate_policy(args, now):
    status = policy.validate_content_hash(_target_policy_path(args.target))
    print(status)
    return 0 if status != "stale" else 1


def cmd_attest_vpn(args, now, input_fn=None):
    if input_fn is None:
        input_fn = input
    workspace_dir = pathlib.Path("workspace") / args.target
    answer = input_fn("Confirm KISA VPN is connected and active for this session? [y/N] ")
    if answer.strip().lower() != "y":
        print("VPN not attested.")
        return 1
    gates.write_attestation(workspace_dir, now)
    print(f"VPN attested for {args.target} at {now.isoformat()}")
    return 0


def cmd_status(args, now):
    p = _load(args.target)
    content_hash = _current_content_hash(args.target)
    reviewed = policy.is_reviewed(BASE_DIR, args.target, content_hash)
    workspace_dir = pathlib.Path("workspace") / args.target
    status = gates.build_status(p, workspace_dir, now, reviewed)
    print(f"Target: {status['target']}")
    print(f"Policy: {'Reviewed' if status['policy_reviewed'] else 'NOT reviewed'}")
    print(f"Testing window: {'Open' if status['testing_window_open'] else 'Closed'}")
    print(f"Blackout window: {'Yes' if status['blackout_active'] else 'No'}")
    print(f"KISA VPN: {'Verified' if status['vpn_attested'] else 'NOT verified'}")
    print(f"Automation: {status['automation']}")
    print(f"Scope: {status['scope_asset_count']} explicitly listed assets")
    print(f"Reporting deadline: {status['reporting_deadline_days_left']} days remaining")
    return 0


def cmd_scope_check(args, now):
    p = _load(args.target)
    content_hash = _current_content_hash(args.target)
    reviewed = policy.is_reviewed(BASE_DIR, args.target, content_hash)
    workspace_dir = pathlib.Path("workspace") / args.target
    result = scope_guard.evaluate(p, workspace_dir, args.url, now, reviewed, redirect_target=args.redirect_target)
    workspace.append_audit(workspace_dir, "scope-check", {"url": args.url}, now)
    print(f"{result.verdict}: {result.reason}")
    return 0 if result.verdict == "ALLOWED" else 1


def cmd_workspace_init(args, now):
    data = policy.load_yaml(_target_policy_path(args.target))
    content_hash = policy.compute_hash(data)
    workspace.init_workspace(BASE_DIR, args.target, data, content_hash, now)
    print(f"Workspace initialized for {args.target}")
    return 0


def cmd_session_start(args, now):
    target_dir = pathlib.Path("workspace") / args.target
    vpn_ok = gates.is_vpn_attested(target_dir, now)
    content_hash = _current_content_hash(args.target)
    session_path = workspace.session_start(target_dir, args.target, content_hash, vpn_ok, now)
    workspace.append_audit(target_dir, "session-start", {}, now)
    print(f"Session started: {session_path}")
    return 0


def cmd_session_log(args, now):
    target_dir = pathlib.Path("workspace") / args.target
    session_path = workspace.find_open_session(target_dir)
    if session_path is None:
        print("No open session for this target. Run: cvd session-start <target>")
        return 1
    flagged = workspace.session_log(session_path, args.note, test_id=args.test_id)
    workspace.append_audit(target_dir, "session-log", {"note": args.note}, now)
    if flagged:
        print("ADVISORY: this note looks like it may contain personal data — have you stopped testing and notified the org?")
    print(f"Logged to {session_path}")
    return 0


def cmd_session_stop(args, now):
    target_dir = pathlib.Path("workspace") / args.target
    session_path = workspace.find_open_session(target_dir)
    if session_path is None:
        print("No open session for this target.")
        return 1
    result = workspace.session_stop(session_path, args.reason, now, intrusion=args.intrusion)
    workspace.append_audit(target_dir, "session-stop", {"reason": args.reason}, now)
    print(
        f"Session closed. Reporting deadline: {result['reporting_deadline_hours']}h "
        f"-> {result['reporting_deadline_at_kst']}"
    )
    return 0


def cmd_analyze_har(args, now):
    p = _load(args.target)
    summary = har_analysis.analyze(p, pathlib.Path(args.har_file))
    print(f"Total unique requests: {summary['total_unique_requests']}")
    print(
        f"Allowed: {summary['allowed']}  Denied: {summary['denied']}  "
        f"Needs clarification: {summary['needs_clarification']}  Not applicable: {summary['not_applicable']}"
    )
    for item in summary["flagged"]:
        print(f"  {item['verdict']}: {item['url_sanitized']} ({item['reason']})")
    return 0 if summary["denied"] == 0 and summary["needs_clarification"] == 0 else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cvd")
    sub = parser.add_subparsers(dest="command", required=True)

    p1 = sub.add_parser("review-policy")
    p1.add_argument("target")
    p1.set_defaults(func=cmd_review_policy)

    p2 = sub.add_parser("validate-policy")
    p2.add_argument("target")
    p2.set_defaults(func=cmd_validate_policy)

    p3 = sub.add_parser("attest-vpn")
    p3.add_argument("target")
    p3.set_defaults(func=cmd_attest_vpn)

    p4 = sub.add_parser("status")
    p4.add_argument("target")
    p4.set_defaults(func=cmd_status)

    p5 = sub.add_parser("scope-check")
    p5.add_argument("target")
    p5.add_argument("url")
    p5.add_argument("--redirect-target", default=None)
    p5.set_defaults(func=cmd_scope_check)

    p6 = sub.add_parser("workspace-init")
    p6.add_argument("target")
    p6.set_defaults(func=cmd_workspace_init)

    p7 = sub.add_parser("session-start")
    p7.add_argument("target")
    p7.set_defaults(func=cmd_session_start)

    p8 = sub.add_parser("session-log")
    p8.add_argument("target")
    p8.add_argument("note")
    p8.add_argument("--test-id", default=None)
    p8.set_defaults(func=cmd_session_log)

    p9 = sub.add_parser("session-stop")
    p9.add_argument("target")
    p9.add_argument("--reason", required=True)
    p9.add_argument("--intrusion", action="store_true")
    p9.set_defaults(func=cmd_session_stop)

    p10 = sub.add_parser("analyze-har")
    p10.add_argument("target")
    p10.add_argument("har_file")
    p10.set_defaults(func=cmd_analyze_har)

    return parser


def main(argv=None, now=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if now is None:
        now = _now()
    return args.func(args, now)


if __name__ == "__main__":
    sys.exit(main())
```

`cvd/__main__.py`:
```python
import sys
from .cli import main

if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Run to verify pass**

Run: `python -m unittest tests.test_cli -v`
Expected: all 7 tests PASS

- [ ] **Step 5: Manual smoke test of the real entry point**

Run: `python -m cvd status nexon` from the repo root (using the real `policies/` files, not fixtures)
Expected: prints a status banner for Nexon showing `Policy: NOT reviewed`, `KISA VPN: NOT verified`, and a scope count of 8 — confirms the real policy files parse correctly end-to-end, not just the synthetic fixtures.

- [ ] **Step 6: Commit**

```bash
git add cvd/cli.py cvd/__main__.py tests/test_cli.py
git commit -m "feat: wire cvd CLI subcommands (review-policy, validate-policy, attest-vpn, status, scope-check, workspace-init, session-start/log/stop, analyze-har)"
```

---

### Task 8: Static no-networking safety test, `.gitignore` update, README, full suite run

**Files:**
- Create: `tests/test_no_networking_import.py`
- Modify: `.gitignore`
- Create: `README.md` (repo root — only if one doesn't already exist; if it does, add a "Compliance-core CLI" section instead of overwriting)

**Interfaces:**
- Consumes: nothing new
- Produces: nothing new — this task is verification + documentation only

- [ ] **Step 1: Write the failing static-safety test**

`tests/test_no_networking_import.py`:
```python
import ast
import pathlib
import unittest

CVD_DIR = pathlib.Path(__file__).parent.parent / "cvd"

FORBIDDEN_MODULES = {
    "requests",
    "httpx",
    "urllib.request",
    "http.client",
    "socket",
    "aiohttp",
    "urllib3",
}


def _imported_modules(path: pathlib.Path) -> set:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    modules = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                modules.add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module)
    return modules


class TestNoNetworkingImport(unittest.TestCase):
    def test_no_forbidden_networking_modules_anywhere_in_cvd(self):
        offenders = []
        for path in CVD_DIR.rglob("*.py"):
            found = _imported_modules(path) & FORBIDDEN_MODULES
            if found:
                offenders.append((str(path), found))
        self.assertEqual(offenders, [], f"Networking-capable imports found: {offenders}")
```

- [ ] **Step 2: Run to verify it passes immediately**

Run: `python -m unittest tests.test_no_networking_import -v`
Expected: PASS immediately — this test should already pass given Tasks 1–7 never imported any networking module. If it fails, that's a real bug introduced in an earlier task: find which file imported a forbidden module and remove that import/dependency before proceeding (do not weaken this test to make it pass).

- [ ] **Step 3: Add a `.review-state/` and `workspace/` guard to `.gitignore`**

The repo's existing `.gitignore` (from Phase 1) already ignores `workspace/`, `evidence/`, and `sessions/`. Confirm `.review-state/` is also covered — read the current `.gitignore` and add a line for it if missing:

```
.review-state/
```

- [ ] **Step 4: Write the README usage section**

If `README.md` does not exist at the repo root, create it with this content. If it exists, append a `## Compliance-core CLI` section with this content instead of overwriting the file:

```markdown
## Compliance-core CLI

Install the one dependency and run the tool as a module — no packaging/install step required:

\`\`\`bash
pip install -r requirements.txt
python -m cvd status <target>
\`\`\`

Where `<target>` is one of: `lguplus`, `nexon`, `ncsoft`, `tosspayments`, `samsunglife`, `estsecurity`, `inca` (matching the filenames under `policies/targets/`).

Typical session:

\`\`\`bash
python -m cvd validate-policy nexon      # backfills/checks the policy file's content hash
python -m cvd review-policy nexon        # prints the policy, asks you to confirm you've read it
python -m cvd attest-vpn nexon           # confirms KISA VPN is active (attestation expires after 4h)
python -m cvd status nexon               # shows the safety banner: window/blackout/VPN/scope/deadline
python -m cvd workspace-init nexon       # creates workspace/nexon/{sessions,findings,...}
python -m cvd session-start nexon
python -m cvd scope-check nexon https://sso.nexon.com/foo   # ALLOWED / DENIED / NEEDS_CLARIFICATION, with the quoted policy reason
python -m cvd session-log nexon "checked SSO session binding" --test-id T1
python -m cvd session-stop nexon --reason "finished planned checks"
python -m cvd analyze-har nexon path/to/exported.har   # retroactive check on a browser session you already ran
\`\`\`

This tool never sends a network request itself (no HTTP client dependency exists anywhere in `cvd/` — verified by `tests/test_no_networking_import.py`). `scope-check` and `analyze-har` are pre/post-checks you run around testing you do yourself in a browser or other tool.
```

- [ ] **Step 5: Run the full test suite**

Run: `python -m unittest discover -s tests -v`
Expected: every test from Tasks 1–8 PASSES (roughly 60 test cases total across `test_policy.py`, `test_masking.py`, `test_gates.py`, `test_scope_guard.py`, `test_workspace.py`, `test_har_analysis.py`, `test_cli.py`, `test_no_networking_import.py`)

- [ ] **Step 6: Commit**

```bash
git add tests/test_no_networking_import.py .gitignore README.md
git commit -m "test: add static no-networking-import safety check; document cvd CLI usage"
```
