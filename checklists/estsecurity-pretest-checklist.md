# Pre-Test Checklist — EST Security

Full policy: `policies/targets/estsecurity.yaml`. Do not test until every box below is checked.

**This target is NOT a website.** Scope is the Alyac (알약) desktop antivirus application, versions 2.5 and 3.0, Windows 11 only. Treat this as a local-software-analysis task, not a network-testing task — the Scope Guard / domain-matching mental model does not apply here.

## Gate

- [ ] KISA VPN connected and verified active for this session (still required per program eligibility even though scope is a local app)
- [ ] Current date/time is within 2026-06-29 – 2026-07-21 — **only 3 days remain as of 2026-07-18**
- [ ] Confirmed you have installed exactly Alyac v2.5 or v3.0 on Windows 11 — no other version, no other OS
- [ ] Obtained the exact installer/version-verification method from EST Security before starting (not captured in research pass — ask company or re-check live page)

## Scope

Alyac desktop app v2.5 or v3.0, Windows 11 only.

Explicitly out of scope: Alyac's backend infrastructure/network/third-party services, and the **Alyac mobile app** (do not test the mobile version under any circumstance — it is named as out of scope specifically to distinguish it from the in-scope desktop version).

## Attack-surface hints

- AV/security products: typical attack surface includes local privilege escalation via the AV's own service/driver, self-protection bypass, update-mechanism integrity (does the app verify signatures on updates?), and scan-engine handling of malformed files (without needing an actual malware sample — malformed/edge-case files, not live malware, per this project's malware-upload ban).
- No network scope is listed — do not attempt to probe any EST Security domain/API; it is explicitly out of scope here regardless of what you might find while the app is running.

## Permitted vs excluded

Excluded-findings list captured for this target is largely generic boilerplate (rate-limiting, admin-page-exposure, debug leakage) that mostly doesn't apply to a desktop product — treat with caution and re-verify the live page for any Alyac-specific carve-outs before assuming a finding is or isn't reportable.

**Explicitly banned regardless:** any actual malware upload/execution (per this project's non-negotiable principles) — testing scan-engine handling must use safe, non-functional test artifacts (e.g. EICAR-style test files), never live malicious code.

## Stop conditions

- Personal data / credit info / trade secret accessed → stop immediately, notify EST Security (escvdvdpinfo@estsecurity.com), mask, delete after reporting.
- Unintended network intrusion → stop immediately, report within **12 hours**.

## Reporting

Channel: KISA FindTheGap (https://hacker.findthegap.co.kr) or escvdvdpinfo@estsecurity.com. Standard deadline: **72h**. Emergency: **12h**. Disclosure: 120 days (+60d extension) after KISA shares the report.
