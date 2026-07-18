# Compliance-Core CLI Design (Phase 3 + partial Phase 4)

Status: approved by user 2026-07-19. Covers the master project brief's Phase 3 (Compliance Core) in full, plus only the workspace-skeleton and session-recorder pieces of Phase 4 (Research Workspace) — see Non-goals for what's excluded from Phase 4. Phase 5 (Finding Manager, Report Generator) and Phase 6 (optional active automation) are explicitly out of scope for this build.

## Context

Phase 1 research is complete: `policies/program.yaml` and `policies/targets/{7 orgs}.yaml` are populated and sourced, and `checklists/*.md` give a manual, docs-only path to test today. This design covers the CLI tooling to mechanically enforce that policy data going forward, for this and future cycles of the CVD/VDP program — it does not gate the testing already happening off the checklists.

## Non-goals (explicit)

- No request-intercepting proxy. The Scope Guard is a pre-check the researcher runs voluntarily before testing in whatever tool they already use (browser, Burp, curl). It cannot force the researcher not to type a URL directly.
- No active automation, scanning, or fuzzing capability of any kind. No HTTP client dependency exists anywhere in this package — a structural guarantee, not just a policy.
- No Finding Manager or Report Generator logic (Phase 5) — the report template from Phase 1 remains a manually-filled Markdown file for now.
- No database. Flat YAML/JSON-lines files only.
- **Of the master brief's Phase 4 list, this build covers only the workspace skeleton and session recorder.** Research Planner (generating structured test-plan YAML from hypotheses), HAR/HTTP-record analysis, and dedicated evidence-management tooling are NOT part of this build — `test-plans/`, `reconnaissance/`, and `attack-surface/` are created as empty directories by `workspace init` (so the directory contract holds) but nothing populates them automatically. The Phase 1 checklists remain the actual test-plan artifact for now.

## A. Tech stack & layout

- Python, stdlib `argparse` for the CLI, `PyYAML` for policy parsing (the one real third-party dependency), stdlib `unittest`/`unittest.mock` for tests.
- No HTTP client library anywhere in the package (requests/httpx/urllib.request), by design — makes "this tool cannot send a request to a target" true by construction.
- No database — session/audit records are flat YAML/JSON-lines files under each target's workspace, matching the existing policy-file style.

```
cvd/
  policy.py       # load/validate policies/program.yaml + targets/*.yaml, content-hash check, review-gate sidecar
  scope_guard.py  # scope-check command logic
  gates.py        # VPN attestation, date/blackout window checks, status banner
  masking.py      # sensitive-data redaction for logs/session records
  workspace.py    # workspace init, session start/log/stop
  cli.py          # argparse wiring
tests/
  fixtures/       # mock policy YAMLs only — never real target data
  test_*.py
workspace/        # gitignored — per-target sessions/audit logs live here
```

## B. Policy engine (`policy.py`)

- Loads `policies/program.yaml` and a given `policies/targets/<name>.yaml`; validates required top-level keys are present per the schema already in use.
- **Precedence, hardcoded:** target-specific values always override program-level values. `unknown` is never treated as permission — a check against an `unknown` field returns `NEEDS_CLARIFICATION`, never `ALLOWED`.
- **Content-hash check:** hash of each YAML file is compared against its own `content_hash` field. First real run backfills the hash; after that, an unrecorded change to the file makes `cvd validate-policy <target>` fail loudly.
- **Manual-review gate:** a target starts unreviewed. `cvd review-policy <target>` prints the full parsed policy and asks for y/n confirmation, then stamps a `reviewed_at` timestamp into a local sidecar file (not into the source policy YAML, to avoid churning sourced documents with tool state). `scope-check` and session commands refuse to run against an unreviewed target.
- **Blackout-window schema addition:** `blackout_windows` entries gain a structured form alongside the existing human-readable string, e.g.:
  ```yaml
  blackout_windows:
    - type: weekly
      day: Thursday
      start: "00:00"
      end: "11:00"
      timezone: Asia/Seoul
      notes: "Every Thursday 00:00-11:00 KST (정기점검/scheduled maintenance)"
  ```
  Applied to `policies/targets/nexon.yaml` as part of implementation (currently free-text only).

## C. Scope Guard (`scope_guard.py`)

`cvd scope-check <target> <url> [--redirect-target <url>]`

Order of checks:
1. Refuse if the target's policy hasn't been reviewed.
2. Date/time checks, independent of URL: inside `testing_start`–`testing_end`? Inside any structured blackout window? Computed in Asia/Seoul, displayed in both KST and UTC. Either failing → `DENIED`, checked before scope matching.
3. VPN attestation: must exist and be fresh (see Gates). Missing/stale → `DENIED`.
4. URL parsing via stdlib `urllib.parse`. Hostname matched against `scope.allowed_domains` by **exact match only** — no substring/suffix/wildcard, ever (`subdomains_implicitly_allowed: false` on every target). Path-level scope (`scope.allowed_urls`, e.g. Toss Payments' gateway paths) matched by literal prefix, not regex.
5. `scope.explicit_out_of_scope` checked even against an apparently in-scope host — `DENIED` with the quoted policy reason if matched.
6. `--redirect-target`, if supplied, is scope-checked the same way and flagged if it would leave scope — the practical substitute for "don't follow redirects out of scope" in a tool that isn't a proxy.
7. Output is always `ALLOWED` / `DENIED` / `NEEDS_CLARIFICATION` / `NOT_APPLICABLE`, each with the specific policy field and quoted evidence — never a bare yes/no. `NOT_APPLICABLE` covers app-only-scope targets (EST Security) or checks against a target whose scope isn't URL-shaped.

## D. Gates (`gates.py`)

- **VPN attestation:** `cvd attest-vpn <target>` prompts for a y/n confirmation and writes a timestamped attestation into `workspace/<target>/.session-state.yaml` (gitignored), expiring after 4 hours by default. Every scope-check/session command checks freshness, not just presence.
- **Status banner:** `cvd status <target>` — target name, policy reviewed y/n, testing window open/closed, blackout active y/n, VPN attestation fresh y/n, automation posture, in-scope asset count, countdown to the reporting deadline.
- **Human Approval Gate (master brief Section 6):** not built in this pass — this tool has no code path that sends a network request, so there is nothing for an approval gate to intercept yet. Revisit only if a future phase adds real active automation.

## E. Workspace + Session Recorder (`workspace.py`) + masking (`masking.py`)

- `cvd workspace init <target>` creates `workspace/<target>/{policy-snapshot,reconnaissance,attack-surface,test-plans,sessions,findings,reports,cleanup}/`. `findings/` and `reports/` are created empty now so the directory contract holds even before Phase 5 exists.
- `policy-snapshot/` receives a copy of the target's policy YAML + content hash at init time, so `cvd diff-policy` has a concrete baseline.
- `cvd session start <target>` → `workspace/<target>/sessions/<UTC-timestamp>.yaml`: start time (KST+UTC), target, policy content-hash, VPN attestation result, empty `test_ids`/`requests`/`test_data_created`.
- `cvd session log <target> <note> [--test-id ID]` appends a masked note and increments the request counter.
- `cvd session stop <target> --reason <text>` records end time + stop reason, prints a cleanup-checklist prompt from what was logged, marks the session closed. If `--reason intrusion`, computes and displays the 12h emergency deadline instead of the standard 72h.
- **Masking (`masking.py`):** every string written to a session file, audit log, or session-log note passes through a redaction filter first — regex patterns for cookies, `Authorization`/Bearer tokens, emails, phone numbers, Korean RRN-shaped strings, and generic high-entropy tokens. This is a disk-write filter, not a substitute for the researcher's own screenshot-masking obligations under each target's policy.
- **Audit log:** every command invocation appends one masked JSON line to `workspace/<target>/audit.jsonl`.
- If a `session log` note trips the masking filter, print an advisory: "this looks like it may contain personal data — have you stopped testing and notified the org?" — advisory only, since this tool doesn't see live traffic and can't force a stop.

## F. Testing strategy

Stdlib `unittest`, fixtures are mock policy YAMLs under `tests/fixtures/` — never real target data.

| Required test (master brief Section 10) | Covered how |
|---|---|
| Block out-of-scope domains/subdomains | exact-match assertions incl. a near-miss subdomain case |
| Block out-of-scope redirects | `--redirect-target` flagged when it leaves scope |
| Block outside authorized period / blackout windows | fixed fake "now" outside window, and inside Nexon's Thursday window |
| Block when VPN attestation missing/stale | no attestation file, and one >4h old |
| Block before policy review | `reviewed: false` sidecar fixture |
| Correct 72h/12h deadline math, both timezones | fixed input timestamps → exact KST+UTC output |
| Token/PII masking in logs | cookie/email/phone-shaped string never appears unmasked in written output |
| Policy-change detection | mutate a fixture after hashing → `validate-policy` fails |
| Target isolation | target A's files never reference or land in target B's workspace |
| Personal-data advisory | note containing a masking hit triggers the advisory prompt |

**Explicitly not tested, because the capability doesn't exist:** scanner/automation blocking, request-budget enforcement, "dry-run sends no requests" as a runtime check (no live mode exists to compare against — the equivalent guarantee is a static assertion that no networking import exists anywhere in `cvd/`).

## Open items carried forward as uncertainties

- VPN attestation expiry is hardcoded at 4 hours by default — no config surface for this in v1; revisit if it proves wrong in practice.
- Blackout-window structured schema is being introduced now; only `nexon.yaml` currently needs a non-empty entry, but the schema itself applies to all targets.
