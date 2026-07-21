"""Offline preview of a planned test action. Never sends a network request —
this module (and this whole package) has no HTTP client capability at all.
The VPN gate applies at the point a human actually transmits a request to a
live target (outside this tool, in their own browser/curl/Burp) — not here.
"""
from . import scope_guard, prohibited_check


def preview(policy_obj, url: str, description: str, request_count: int = 1) -> dict:
    scope_result = scope_guard.check_url(policy_obj, url)
    prohibited_flags = prohibited_check.check_action(policy_obj, description)

    if request_count <= 1:
        rate_note = (
            "Manual, single-request pace assumed; this tool has no automated "
            "request capability of any kind."
        )
    else:
        rate_note = (
            f"{request_count} requests planned — this tool cannot send any of them "
            f"automatically. A count this high implies manual repetition; re-confirm "
            f"this isn't fuzzing/enumeration/mass-action before proceeding, since every "
            f"researched target treats those as prohibited by default."
        )

    vpn_boundary_note = (
        "DRY RUN — nothing was sent. This tool has zero networking capability. "
        "Before actually transmitting this to a live target yourself (browser/curl/Burp), "
        "confirm KISA VPN is connected: run `cvd attest-vpn <target>` then `cvd session-start <target>`."
    )

    return {
        "scope_verdict": scope_result.verdict,
        "scope_reason": scope_result.reason,
        "prohibited_flags": prohibited_flags,
        "request_count": request_count,
        "rate_note": rate_note,
        "vpn_boundary_note": vpn_boundary_note,
    }
