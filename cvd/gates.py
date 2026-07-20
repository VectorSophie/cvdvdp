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
