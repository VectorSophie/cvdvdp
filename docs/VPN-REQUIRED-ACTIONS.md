# What requires VPN, and what doesn't

The `cvd` CLI has **zero networking capability anywhere in the package** (verified structurally by `tests/test_no_networking_import.py` — no HTTP client library exists in `cvd/`). Every subcommand is either local file/policy processing or advisory output. Because of that, the VPN gate applies at exactly one point: **the moment a human transmits an actual request to a live target**, which happens outside this tool entirely (your browser, curl, Burp, etc.) — this tool can only refuse to help you get there without an attestation on record.

## Works right now, no VPN needed

All of these are local/offline and safe to run at any time, on any machine:

| Command | What it does |
|---|---|
| `cvd validate-policy <target>` / `validate-all` | Content-hash drift check + required-key validation, purely local |
| `cvd review-policy <target>` | Prints the policy, records your review confirmation locally |
| `cvd status <target>` | Status banner — reads local state only |
| `cvd scope-check <target> <url>` | Pure classification of a URL string against policy data — no traffic sent |
| `cvd dry-run <target> <url> <description>` | Scope check + prohibited-action keyword detection + rate estimate — no traffic sent |
| `cvd generate-test-plan <target>` | Emits structured test-plan YAML from documented hypotheses |
| `cvd new-report <target> <title>` | Scaffolds a report file from the template |
| `cvd analyze-har <target> <har-file>` | Retroactive scope analysis of a HAR file you already captured |
| `cvd workspace-init <target>` | Creates the local directory tree |

## Requires VPN attestation before it proceeds

| Command | Why |
|---|---|
| `cvd attest-vpn <target>` | This *is* the attestation step — answer honestly |
| `cvd session-start <target>` | Hard-blocks (refuses, exit code 1) if `attest-vpn` hasn't been run this session or the attestation has expired (4h TTL). This is the CLI's proxy for "you are now beginning actual testing activity." |

## Requires VPN in reality, but the CLI cannot enforce it

The CLI is not a proxy — it never sees or blocks your actual browser/curl/Burp traffic. These require VPN per every target's own VDP, and it's on you (the researcher) to have it connected before doing them, regardless of what the CLI says:

- Actually navigating to / interacting with any in-scope URL for a live target
- Authentication or authorization testing against a live target
- Any modified/crafted HTTP request sent to a live target
- Endpoint enumeration performed manually against a live target
- Live PoC execution/verification against a live target

**Not required to be on VPN:** submitting a finding to KISA FindTheGap (the reporting portal is separate from the target's own infrastructure — none of the 7 researched VDPs state the target's VPN is needed for report submission itself).

## Remaining actions blocked until KISA VPN access is available

As of this writing, VPN access has not been confirmed. Until it is:

- [ ] Obtain KISA VPN provisioning details (contact: cvd@kisa.or.kr / 02-405-6697, or check whatever channel confirmed your program registration)
- [ ] Run `cvd attest-vpn <target>` once connected, per target, before that target's first `session-start`
- [ ] Everything in the "works right now" table above can and should continue in the meantime — scope-checks, dry-runs, test-plan generation, and report scaffolding for all 7 targets are all safe to do today.
