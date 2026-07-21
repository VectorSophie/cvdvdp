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
    # scope-check may run before workspace-init; append_audit doesn't create its dir.
    workspace_dir.mkdir(parents=True, exist_ok=True)
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
