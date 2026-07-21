import argparse
import datetime
import pathlib
import sys

import yaml

from . import policy, gates, scope_guard, workspace, har_analysis, dry_run, test_plan, report_scaffold

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
    if not vpn_ok:
        print(
            "Refusing to start a testing session: VPN not attested this session "
            "(or attestation expired). Run: cvd attest-vpn <target>"
        )
        return 1
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


def cmd_generate_test_plan(args, now):
    p = _load(args.target)
    entries = test_plan.generate(args.target, p)
    if not entries:
        print(f"No documented hypotheses for {args.target!r} — nothing generated.")
        return 1
    plans_dir = pathlib.Path("workspace") / args.target / "test-plans"
    plans_dir.mkdir(parents=True, exist_ok=True)
    for entry in entries:
        out_path = plans_dir / f"{entry['id']}.yaml"
        out_path.write_text(yaml.safe_dump(entry, sort_keys=False), encoding="utf-8")
    print(f"Generated {len(entries)} test-plan entries for {args.target} under {plans_dir}")
    return 0


def cmd_dry_run(args, now):
    p = _load(args.target)
    result = dry_run.preview(p, args.url, args.description, request_count=args.count)
    print(f"Scope: {result['scope_verdict']} — {result['scope_reason']}")
    if result["prohibited_flags"]:
        print("PROHIBITED-ACTION FLAGS:")
        for flag in result["prohibited_flags"]:
            print(f"  - {flag['flag']}: {flag['reason']}")
    else:
        print("No prohibited-action keywords matched.")
    print(result["rate_note"])
    print(result["vpn_boundary_note"])
    clean = result["scope_verdict"] == "ALLOWED" and not result["prohibited_flags"]
    return 0 if clean else 1


def cmd_new_report(args, now):
    p = _load(args.target)
    reports_dir = pathlib.Path("workspace") / args.target / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    template_path = pathlib.Path("templates/report-template.md")
    content = report_scaffold.scaffold(args.target, args.title, p, template_path)
    safe_title = "".join(c if c.isalnum() else "-" for c in args.title.lower()).strip("-")[:50]
    out_path = reports_dir / f"{safe_title or 'report'}.md"
    out_path.write_text(content, encoding="utf-8")
    print(f"Report scaffold written to {out_path}")
    return 0


def cmd_validate_all(args, now):
    targets_dir = pathlib.Path("policies/targets")
    required_keys = ("name", "schedule", "scope", "prohibited", "reporting", "privacy")
    all_ok = True
    for target_path in sorted(targets_dir.glob("*.yaml")):
        status = policy.validate_content_hash(target_path)
        data = policy.load_yaml(target_path)
        missing = [k for k in required_keys if k not in data]
        ok = status != "stale" and not missing
        all_ok = all_ok and ok
        print(f"{target_path.stem}: {status}, missing_keys={missing or 'none'} [{'OK' if ok else 'ISSUE'}]")
    return 0 if all_ok else 1


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

    p11 = sub.add_parser("generate-test-plan")
    p11.add_argument("target")
    p11.set_defaults(func=cmd_generate_test_plan)

    p12 = sub.add_parser("dry-run")
    p12.add_argument("target")
    p12.add_argument("url")
    p12.add_argument("description", help="Free-text description of the planned action, e.g. 'check IDOR on profile endpoint'")
    p12.add_argument("--count", type=int, default=1, help="Planned request count (for rate/scale estimation)")
    p12.set_defaults(func=cmd_dry_run)

    p13 = sub.add_parser("new-report")
    p13.add_argument("target")
    p13.add_argument("title")
    p13.set_defaults(func=cmd_new_report)

    p14 = sub.add_parser("validate-all")
    p14.set_defaults(func=cmd_validate_all)

    return parser


def main(argv=None, now=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if now is None:
        now = _now()
    return args.func(args, now)


if __name__ == "__main__":
    sys.exit(main())
