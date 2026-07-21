"""Generates structured, offline test-plan entries per target from the
hypotheses already documented in checklists/<target>-pretest-checklist.md.
This does not invent new attack ideas beyond what Phase 1 research already
identified as permitted/worth-testing for each target — it formalizes that
same content into the machine-readable schema from the master project brief.
"""

_HYPOTHESES = {
    "lguplus": [
        {
            "id": "LGU-001",
            "title": "Authentication/session handling on account.lguplus.com",
            "hypothesis": "Session tokens are not correctly bound to account/device, or expire/invalidate incorrectly",
            "target_component": "account.lguplus.com",
        },
        {
            "id": "LGU-002",
            "title": "IDOR on user-owned objects",
            "hypothesis": "Object references for user-owned data are not authorization-checked server-side",
            "target_component": "www.lguplus.com / m.lguplus.com",
        },
    ],
    "nexon": [
        {
            "id": "NX-001",
            "title": "SSO/session trust boundaries across the 5 auth domains",
            "hypothesis": "Session/SSO tokens issued on one auth domain are trusted on another without proper re-validation",
            "target_component": "nxlogin/login/sso/join/session.nexon.com",
        },
        {
            "id": "NX-002",
            "title": "Authorization consistency between accountweb-bff-api and user-facing domains",
            "hypothesis": "The BFF API enforces different (weaker) authorization than the user-facing frontend",
            "target_component": "accountweb-bff-api.nexon.com",
        },
        {
            "id": "NX-003",
            "title": "IDOR on myinfo.nexon.com",
            "hypothesis": "Profile/account object references are not authorization-checked server-side",
            "target_component": "myinfo.nexon.com",
        },
    ],
    "ncsoft": [
        {
            "id": "NC-001",
            "title": "CSRF on member/admin functions",
            "hypothesis": "State-changing member/admin functions lack CSRF protection",
            "target_component": "www.nc.com",
        },
        {
            "id": "NC-002",
            "title": "Authorization boundaries for account/member system",
            "hypothesis": "Member-area functionality does not correctly enforce per-account authorization",
            "target_component": "www.nc.com",
        },
    ],
    "tosspayments": [
        {
            "id": "TP-001",
            "title": "Authorization consistency between merchants/v1 and merchants/v2",
            "hypothesis": "An authorization check present in one API version is missing or weaker in the other",
            "target_component": "homepage-api-gateway.tosspayments.com/merchants/{v1,v2}",
        },
        {
            "id": "TP-002",
            "title": "Webhook signature/authenticity verification",
            "hypothesis": "Webhook calls are not properly verified as originating from Toss's own systems",
            "target_component": "homepage-api-gateway.tosspayments.com/webhook/v1",
        },
        {
            "id": "TP-003",
            "title": "Server-side re-validation of client-supplied payment/order values",
            "hypothesis": "Client-supplied amount/currency/order-id/status values are trusted without server-side re-validation",
            "target_component": "payment-widget/v1 -> payments/v4",
        },
    ],
    "samsunglife": [
        {
            "id": "SL-001",
            "title": "Authentication/session handling",
            "hypothesis": "Session tokens are not correctly bound or expire/invalidate incorrectly",
            "target_component": "www.samsunglife.com",
        },
        {
            "id": "SL-002",
            "title": "Authorization boundaries between customer roles",
            "hypothesis": "Account/policy-lookup workflows do not correctly enforce per-customer authorization",
            "target_component": "www.samsunglife.com",
        },
    ],
    "estsecurity": [
        {
            "id": "EST-001",
            "title": "Update-mechanism integrity",
            "hypothesis": "Alyac does not verify signatures/checksums on updates it fetches",
            "target_component": "Alyac desktop app v2.5/v3.0, Windows 11",
        },
        {
            "id": "EST-002",
            "title": "Self-protection / local privilege boundary",
            "hypothesis": "The AV's self-protection mechanism can be bypassed via its own service/driver",
            "target_component": "Alyac desktop app v2.5/v3.0, Windows 11",
        },
    ],
    "inca": [
        {
            "id": "INCA-001",
            "title": "Authentication/authorization on the management console",
            "hypothesis": "nosoriginv.nprotect.net console does not correctly enforce admin authentication/authorization",
            "target_component": "nosoriginv.nprotect.net",
        },
        {
            "id": "INCA-002",
            "title": "Update-integrity verification",
            "hypothesis": "nProtect Online Security does not verify signatures/checksums on updates from supdated/cclean domains",
            "target_component": "supdated.nprotect.net / cclean.nprotect.net",
        },
    ],
}


def generate(target: str, policy_obj) -> list:
    entries = []
    for h in _HYPOTHESES.get(target, []):
        entries.append({
            "id": h["id"],
            "title": h["title"],
            "hypothesis": h["hypothesis"],
            "target_component": h["target_component"],
            "applicable_standard": "OWASP Top 10:2025 / OWASP WSTG v4.2",
            "vdp_status": "RELEVANT_AND_PERMITTED",
            "manual_or_automated": "manual",
            "preconditions": [
                "KISA VPN connected and attested (cvd attest-vpn)",
                "Policy reviewed (cvd review-policy)",
                "Researcher-controlled test account registered per target's own FAQ, if applicable",
            ],
            "safe_test_accounts": "Researcher-controlled test account only; no real user data",
            "exact_steps": [
                "Manually navigate to the target component in a standard browser",
                "Attempt to observe the hypothesized behavior using only your own test account/data",
                "Stop at the first observation that confirms or refutes the hypothesis — do not escalate further",
            ],
            "expected_secure_behavior": "Access/authorization is correctly enforced; no cross-account or cross-session leakage",
            "potential_vulnerable_behavior": h["hypothesis"],
            "stop_conditions": [
                "Personal data, credit info, or trade secret encountered",
                "Unintended network intrusion",
            ],
            "cleanup_steps": ["Delete any test data created", "Log out of the test session"],
            "evidence_to_collect": ["Masked screenshot", "Request/response with sensitive fields redacted", "Timestamps (KST+UTC)"],
            "risk_if_successful": "See hypothesis field for the specific impact this test targets",
            "reportability": "Report via KISA FindTheGap within 72h of discovery (12h if intrusion occurred)",
        })
    return entries
