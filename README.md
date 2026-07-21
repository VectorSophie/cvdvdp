## Compliance-core CLI

Install the one dependency and run the tool as a module — no packaging/install step required:

```bash
pip install -r requirements.txt
python -m cvd status <target>
```

Where `<target>` is one of: `lguplus`, `nexon`, `ncsoft`, `tosspayments`, `samsunglife`, `estsecurity`, `inca` (matching the filenames under `policies/targets/`).

Typical session:

```bash
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
```

Offline planning tools — all work without VPN, before you've even started a session:

```bash
python -m cvd validate-all                                          # content-hash + required-key check across all 7 targets
python -m cvd dry-run nexon https://sso.nexon.com/foo "check session binding"   # scope + prohibited-action check + rate estimate, sends nothing
python -m cvd generate-test-plan nexon                               # structured test-plan YAML from documented hypotheses, under workspace/nexon/test-plans/
python -m cvd new-report nexon "Session fixation on SSO"             # scaffolds a report file from templates/report-template.md
```

This tool never sends a network request itself (no HTTP client dependency exists anywhere in `cvd/` — verified by `tests/test_no_networking_import.py`). `scope-check`, `dry-run`, and `analyze-har` are pre/post-checks you run around testing you do yourself in a browser or other tool. See `docs/VPN-REQUIRED-ACTIONS.md` for exactly which actions do and don't require VPN.
