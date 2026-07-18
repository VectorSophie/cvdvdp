# Pre-Test Checklist — NCSoft (NC)

Full policy: `policies/targets/ncsoft.yaml`. Do not test until every box below is checked.

## Gate

- [ ] KISA VPN connected and verified active for this session
- [ ] Current date/time is within 2026-06-29 – 2026-07-21 — **only 3 days remain as of 2026-07-18**
- [ ] No blackout window applies to NCSoft (do NOT carry over Nexon's Thursday blackout — it is Nexon-specific, confirmed not stated here)

## Scope (exact — 2 domains only)

`www.nc.com`, `corporate.nc.com`

Testing outside these two URLs is explicitly prohibited by the VDP text itself ("명시된 URL 외에 발굴 금지").

## Attack-surface hints (from scope alone)

- Only 2 domains, both appear to be corporate/marketing sites rather than a game client or account system — attack surface is likely narrower than Nexon's (no dedicated login/SSO subdomain listed). Expect the primary opportunities to be in contact/support forms, member-area functionality (if any exists on these domains), and any admin-facing paths reachable from `corporate.nc.com`.
- NCSoft is the only target whose VDP explicitly distinguishes CSRF **on member/admin functions** (implicitly in-scope) from CSRF on generic functions (excluded) — if a member or admin area exists within these 2 domains, CSRF there is worth checking; CSRF elsewhere is not.

## Permitted vs excluded

**Do not bother testing:** self-XSS, reflected XSS, open redirect, DoS, brute force/fuzzing/scanning, missing headers, TLS/DNS/email config, CSRF outside member/admin functions, error-message/source-code/IP/admin-page-existence disclosure, previously-disclosed 0-days.

**Worth manual testing within scope:** CSRF on any member/admin function found within the 2 domains, authorization boundaries if any account/member system exists on `www.nc.com`, business-logic flaws in any form/submission workflow.

## Stop conditions

- Personal data / credit info / trade secret accessed → **stop immediately** — NCSoft's VDP has the strongest, most unambiguous "stop immediately" wording of all 7 targets. Notify NCSoft (vdp@ncsoft.com), mask, delete after reporting.
- Unintended network intrusion → stop immediately, report within **12 hours**.

## Reporting

Channel: KISA FindTheGap (https://hacker.findthegap.co.kr) or vdp@ncsoft.com / 02-6201-0554. Standard deadline: **72h**. Emergency: **12h**. Disclosure: 120 days (+60d extension) after KISA shares the report.
