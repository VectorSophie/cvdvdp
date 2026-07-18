# Pre-Test Checklist — LG U+

Full policy: `policies/targets/lguplus.yaml`. Do not test until every box below is checked.

## Gate

- [ ] KISA VPN connected and verified active for this session
- [ ] Current date/time is within 2026-06-29 – 2026-07-21 (discovery window) — **only 3 days remain as of 2026-07-18**
- [ ] No blackout window applies (none published for LG U+)
- [ ] Test account registered using your OWN real identity (per FAQ — not a synthetic identity)
- [ ] Any post/comment/inquiry you create includes the tag `[정보보안점검팀] 보안점검 중입니다.` in title and body

## Scope (exact — no subdomains beyond these)

Web: `www.lguplus.com`, `m.lguplus.com`, `privacy.lguplus.com`, `account.lguplus.com`, `chatbot.lguplus.com`, `mglobal.lguplus.com`
Set-top box: UHD4T (fw ≥ v03.02.0267), UHD4K (fw ≥ v02.02.0160)
App: Android U+one ≥ 7.0.23, iOS U+one ≥ 4.0.26

Everything else — including any other lguplus.com subdomain — is out of scope.

## Attack-surface hints (from scope alone, no extra recon performed)

- `account.lguplus.com` — dedicated login domain: prioritize auth/session logic, password reset, account-recovery token binding
- `chatbot.lguplus.com` — customer-support chatbot: check for injection into support workflows, and note the mandatory `[정보보안점검팀]` tag applies to any test content sent through it
- `privacy.lguplus.com` — itself hosts the VDP; unlikely to be a fruitful target but is in scope
- Set-top box + mobile app scope means this target spans web AND client software/firmware — different test approach per asset

## Permitted vs excluded (see `docs/research/methodology.md` for the full cross-target table)

**Do not bother testing / will not be accepted:** reflected XSS, open redirect, mobile deep-link bugs, missing security headers, TLS/cipher issues, rooted/jailbroken-only bugs, EOL-browser-only bugs, DoS, brute force/fuzzing/scanning, mass content creation, self-only-impact bugs.

**Worth manual testing within scope:** authentication/session handling on `account.lguplus.com`, authorization boundaries between account tiers, business-logic/state-transition flaws, IDOR on user-owned objects, input handling in forms/APIs actually reachable from the 6 listed domains.

## Stop conditions

- Personal data, credit info, or trade secret accessed → **stop immediately**, notify LG U+ (bugbounty@lguplus.co.kr), mask any unavoidable screenshot, delete after reporting. Resuming requires LG U+ approval.
- Unintended network intrusion → stop immediately, report within **12 hours** (vs. 72h standard) to KISA FindTheGap.

## Reporting

Channel: KISA FindTheGap (https://hacker.findthegap.co.kr). Fields: service/product name, discovery timestamp, PoC, exploitation scenario, intrusion timestamp if applicable. Standard deadline: **72h from discovery**. Emergency deadline: **12h from intrusion**.
