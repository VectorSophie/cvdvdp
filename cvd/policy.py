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
