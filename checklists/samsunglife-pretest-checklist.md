# Pre-Test Checklist — Samsung Life

Full policy: `policies/targets/samsunglife.yaml`. Do not test until every box below is checked.

## Gate

- [ ] KISA VPN connected and verified active for this session
- [ ] Current date/time is within 2026-06-29 – 2026-07-21 — **only 3 days remain as of 2026-07-18**
- [ ] No blackout window applies
- [ ] Confirmed scope hasn't changed since 2026-07-18 (scope is unusually narrow for a major insurer — worth a sanity check on the live page)

## Scope (exact — ONE domain, nothing else)

`www.samsunglife.com` — no subdomains, no app, no API. This is the narrowest scope of all 7 targets.

## Attack-surface hints (from scope alone)

- Single-domain scope on a life insurer strongly implies the fruitful surface is customer-facing: login/authentication, policy/account lookup, contact/consultation forms, and any member-area functionality reachable from this one domain.
- Given the org type, any account data encountered may include **health, financial, or beneficiary information** — treat any personal-data encounter here with extra caution, this is the highest-sensitivity target in the set.
- No app, no set-top box, no API in scope — do not attempt to test the Samsung Life mobile app or any backend API even if discovered; it is not in the enumerated scope.

## Permitted vs excluded

This target has the longest exclusion list (34 items) of all 7 — notably it explicitly excludes unauthorized intrusion into production systems as an illegal act rather than a rewardable finding, and separately excludes MITM, DLL hijacking, side-channel/hardware attacks, FRIDA/Xposed runtime exploitation, root/jailbreak-detection bypass, VPN-detection bypass, deep links, and app-dependent findings (none of which apply anyway since no app is in scope here).

**Worth manual testing within scope:** authentication/session handling, business-logic flaws in any account/policy-lookup workflow on `www.samsunglife.com`, authorization boundaries between customer roles if any exist on this domain.

## Stop conditions

- Personal data (especially health/financial/beneficiary info), credit info, or trade secret accessed → **stop immediately**, notify Samsung Life (itsecurity.manager@samsung.com / 02-751-8448), mask, delete after reporting.
- Unintended network intrusion → stop immediately, report within **12 hours**.

## Reporting

Channel: KISA FindTheGap (https://hacker.findthegap.co.kr). Standard deadline: **72h**. Emergency: **12h**. Disclosure: 120 days (+60d extension) after KISA shares the report.
