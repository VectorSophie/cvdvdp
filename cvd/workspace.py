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
        entry["test_id"] = masking.redact(test_id)
        data["test_ids"].append(masking.redact(test_id))
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


def append_audit(target_dir: pathlib.Path, command: str, args: dict, now: datetime.datetime) -> None:
    audit_path = target_dir / "audit.jsonl"
    masked_args = {k: masking.redact(str(v)) for k, v in args.items()}
    entry = {"time_kst": now.isoformat(), "command": command, "args": masked_args}
    with open(audit_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
