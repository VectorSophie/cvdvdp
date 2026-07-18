# Pre-Test Checklist — Nexon

Full policy: `policies/targets/nexon.yaml`. Do not test until every box below is checked.

## Gate

- [ ] KISA VPN connected and verified active for this session
- [ ] Current date/time is within 2026-06-29 – 2026-07-21 — **only 3 days remain as of 2026-07-18**
- [ ] **Not** currently inside the weekly blackout window: every Thursday 00:00–11:00 KST
- [ ] No test-account/sandbox process is documented — you are working against what appears to be production; budget risk accordingly

## Scope (exact — 8 domains only)

`www.nexon.com`, `myinfo.nexon.com`, `accountweb-bff-api.nexon.com`, `nxlogin.nexon.com`, `login.nexon.com`, `sso.nexon.com`, `join.nexon.com`, `session.nexon.com`

Explicitly out of scope: payment/identity-verification providers, third-party SDKs, external SNS (Discord/Instagram/Facebook/YouTube), third-party auth (Facebook/Google/Naver/Apple/Steam/Xbox/PlayStation), any other user's account.

## Attack-surface hints (from scope alone)

- 5 of the 8 domains are auth-related (`nxlogin`, `login`, `sso`, `join`, `session`) — this is clearly an SSO/account-system-focused scope. Prioritize: session token issuance/binding, SSO cross-domain trust boundaries, account-linking/join flow, session fixation/expiry.
- `accountweb-bff-api.nexon.com` — a BFF (backend-for-frontend) API layer: check for authorization consistency between this API and the user-facing `myinfo`/`www` domains (classic BFF-vs-frontend authorization drift).
- `myinfo.nexon.com` — user profile/account data: IDOR on profile fields, object-level authorization for account-owned data.

## Permitted vs excluded

**Do not bother testing:** anything via third-party auth providers or SNS integrations (out of scope by definition), CSRF on generic functions (logout/bookmark), DoS, open redirect, brute force/fuzzing/scanning, mass content creation, cloud/infra config, game-cheat-only reports, MITM-dependent findings, missing headers, TLS/protocol version issues, negligible-impact findings.

**Worth manual testing within scope:** SSO/session trust boundaries across the 5 auth domains, account-linking and join-flow business logic, IDOR on `myinfo`, authorization consistency between `accountweb-bff-api` and the user-facing domains.

## Stop conditions

- Personal data / credit info / trade secret accessed → **stop immediately** (this file applies the stricter reading over Nexon's own slightly softer wording — see `uncertainties` in the policy file), notify Nexon (bugbounty@nexon.co.kr), mask, delete after reporting.
- Unintended network intrusion → stop immediately, report within **12 hours**.
- Any attack targeting another real user's account → stop, this is explicitly out of scope regardless of technical feasibility.

## Reporting

Channel: KISA FindTheGap (https://hacker.findthegap.co.kr). Standard deadline: **72h**. Emergency: **12h**. Disclosure venue: KISA KNVD DB, 120 days (+60d extension) after KISA shares the report.
