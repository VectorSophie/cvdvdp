# Pre-Test Checklist — Toss Payments

Full policy: `policies/targets/tosspayments.yaml`. Do not test until every box below is checked.

## Gate

- [ ] KISA VPN connected and verified active for this session
- [ ] Current date/time is within 2026-06-29 – 2026-07-21 — **only 3 days remain as of 2026-07-18**
- [ ] No blackout window applies
- [ ] **Payment flows: confirmed you will use only researcher-controlled test data — no real transactions, no real card/bank details, no real merchant funds, under any circumstance**

## Scope (exact — 2 domains + 6 specific API gateway paths, versioned)

`www.tosspayments.com`, `developers.tosspayments.com`, and on `homepage-api-gateway.tosspayments.com` only: `/developers-centre/*`, `/webhook/v1/*`, `/merchants/v1/*`, `/merchants/v2/*`, `/payments/v4/*`, `/payment-widget/v1/*`.

Any other path or version on the gateway (e.g. `payments/v3`, `merchants/v3`) is **not** in scope — re-verify against the live page before assuming otherwise, this scope is unusually granular.

## Attack-surface hints (from scope alone)

- Two merchant API versions (v1 and v2) both in scope simultaneously — classic setup for an **inconsistent-authorization-across-API-versions** hypothesis (Section 5 of the master brief): check whether an authorization check present in v2 is missing or weaker in v1, or vice versa.
- `webhook/v1` in scope: webhook endpoints are a common source of missing signature verification or replay issues — check whether webhook calls are properly authenticated/verified as coming from Toss's own systems.
- `payment-widget/v1` + `payments/v4`: widget-to-backend trust boundary — check whether client-supplied values (amount, currency, order ID, status) are re-validated server-side rather than trusted from the widget.

## Permitted vs excluded

**Do not bother testing:** DoS, findings requiring excessive user interaction or disabled security features, rate-limiting-alone reports, legacy-library-disclosure-alone, admin-page-exposure-alone, debug-info-leakage-alone.

**Worth manual testing within scope:** authorization consistency between `merchants/v1` and `merchants/v2`, webhook signature/authenticity verification, server-side re-validation of client-supplied payment/order values on `payment-widget/v1` → `payments/v4`, object-level authorization on merchant-owned resources.

**Explicitly banned regardless of what a finding would prove:** any real payment/transaction execution. Use sandbox/test payment credentials only, if Toss provides them — if no sandbox is confirmed available, treat all payment-flow testing as blocked pending clarification from the company, per this project's non-negotiable unauthorized-payment-testing ban.

## Stop conditions

- Personal data / credit info / financial info / trade secret accessed → **stop immediately**, notify Toss (security.team@tosspayments.com), mask, delete after reporting.
- Unintended network intrusion → stop immediately, report within **12 hours**.
- Any point where a real transaction might execute → stop before executing it, regardless of how promising the finding looks.

## Reporting

Channel: KISA FindTheGap (https://hacker.findthegap.co.kr) or security.team@tosspayments.com. Standard deadline: **72h**. Emergency: **12h**. Disclosure: 120 days (+60d extension) after KISA shares the report.
