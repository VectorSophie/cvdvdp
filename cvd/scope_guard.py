import urllib.parse
from . import gates


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
