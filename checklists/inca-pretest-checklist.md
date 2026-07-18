# Pre-Test Checklist — INCA Internet / nProtect

Full policy: `policies/targets/inca.yaml`. Do not test until every box below is checked.

**This target is mixed scope: 5 web domains/console + a Windows desktop security product requiring a specific setup step before testing.**

## Gate

- [ ] KISA VPN connected and verified active for this session
- [ ] Current date/time is within 2026-06-29 – 2026-07-21 — **only 3 days remain as of 2026-07-18**
- [ ] nProtect Online Security v1.0 installed via the company-provided installer URL (get exact link from INCA/live page — not captured in this research pass)
- [ ] Security feature activated via the company-provided test-activation URL **before** any testing begins — testing before this step is done is not covered by scope

## Scope

Domains: `bwtd.nprotect2.net/*`, `supdated.nprotect.net/*`, `nsrs.nprotect.net/*`, `cclean.nprotect.net/*`, and the management console `nosoriginv.nprotect.net`.
App: nProtect Online Security v1.0, Windows 11 only, once installed+activated as above.

## Attack-surface hints (from scope alone)

- `nosoriginv.nprotect.net` is called out as a "console" — likely an admin/management interface: prioritize authentication/authorization on this one specifically, admin interfaces are high-value targets.
- `supdated.nprotect.net` (update server naming) and `cclean.nprotect.net` — check update-integrity verification (does the client verify signatures/checksums on what it fetches from these domains?) as a hypothesis, without needing to actually tamper with a live update.
- Desktop product component: same category of hypotheses as EST Security's Alyac (self-protection bypass, privilege escalation via the security service, malformed-file handling using safe test artifacts only, never live malware).

## Permitted vs excluded

**Important correction on record:** an earlier automated search summary incorrectly claimed this target's scope was the Alyac app (that's EST Security's product, not INCA's) — this checklist reflects the corrected, primary-source-verified scope. If you see "Alyac" referenced anywhere in relation to INCA, it's wrong.

Excluded-findings list captured is shared program boilerplate (rate-limiting, admin-page-exposure alone, debug leakage, DoS, low-proof reports) — re-verify the live page for nProtect-specific carve-outs.

## Stop conditions

- Personal data / credit info / trade secret accessed → stop immediately, notify INCA (vuln@inca.co.kr), mask, delete after reporting.
- Unintended network intrusion → stop immediately, report within **12 hours**.

## Reporting

Channel: KISA FindTheGap (https://hacker.findthegap.co.kr) or vuln@inca.co.kr. Standard deadline: **72h**. Emergency: **12h**. Disclosure: 120 days (+60d extension) after KISA shares the report.
