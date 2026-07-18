# Methodology

## Standard versions in use (researched 2026-07-18)

| Standard | Version | Notes | Source |
|---|---|---|---|
| OWASP Web Security Testing Guide | v4.2 (2020-12-03) | v5.0 in development, not yet stable — use v4.2 as the current stable methodology reference | owasp.org/www-project-web-security-testing-guide/ |
| OWASP Top 10 (web) | Top 10:2025 (final, Jan 2026) | First update since 2021; A01 Broken Access Control still #1 (absorbed SSRF); A02 Security Misconfiguration moved up; new A10:2025 Mishandling of Exceptional Conditions | owasp.org/Top10/2025/ |
| OWASP API Security Top 10 | 2023 edition | No 2025/2026 revision found | owasp.org/API-Security/ |
| CWE | v4.20 (updated 2026-06-10) | | cwe.mitre.org/data/index.html |
| CVSS | v4.0 (Nov 2023) | Still current major version | first.org/cvss/ |
| PTES | Effectively unmaintained | Community-run, no governing body, examples outdated, pentest-standard.org unreachable. Practitioner consensus treats **OWASP WSTG as the de facto current methodology** for web/API scope, with NIST SP 800-115 as the complementary process framework. PTES's phase names (pre-engagement → intel gathering → threat modeling → vuln analysis → exploitation → post-exploitation → reporting) are used here only as a legacy vocabulary, not a technical checklist. | pentest-standard.org (unreachable); multiple 2025 practitioner comparison articles |

**Decision:** Use OWASP WSTG v4.2 as the primary test-case source, OWASP Top 10:2025 and API Security Top 10 (2023) for categorization, CWE v4.20 / CVSS v4.0 for classification and scoring in reports. PTES phase names may appear in session/report structure as familiar vocabulary only.

## Classifying test categories against the 7 VDPs, not against OWASP alone

Per the project's own instruction, OWASP categories are not used as a scan list — every candidate test class is checked against what the 7 researched VDPs actually permit or explicitly exclude. The 7 VDPs turned out to share a large common core (identical program template for at least Toss Payments / EST Security / INCA; near-identical for LG U+ / Nexon / NCSoft / Samsung Life), so one shared table covers most targets, with per-target deltas called out.

| Candidate test class | Classification | Basis |
|---|---|---|
| Manual auth/session/IDOR/business-logic testing within listed scope, using researcher-controlled test accounts | `RELEVANT_AND_PERMITTED` | Core purpose of the program; not excluded by any of the 7 VDPs |
| Manual input-validation testing (SQLi, command injection, SSRF within scope) | `RELEVANT_AND_PERMITTED` | Not excluded by any of the 7 VDPs; standard OWASP Top 10 categories |
| Automated scanners / fuzzers of any kind | `EXPLICITLY_EXCLUDED` | Prohibited AND/OR invalidated as a finding source in all 7 VDPs (`policies/targets/*.yaml` → `automation.scanner_allowed: false`) |
| Brute force / credential stuffing / OTP-2FA bypass | `EXPLICITLY_EXCLUDED` | Named directly in Nexon's VDP; banned under this project's own non-negotiable principles regardless of whether a given target's VDP names it explicitly |
| DoS/DDoS or load-style testing | `EXPLICITLY_EXCLUDED` | Named in every VDP as prohibited AND excluded as a finding |
| Reflected XSS | `EXPLICITLY_EXCLUDED` for LG U+, Nexon (as "open redirect"-adjacent... actually listed separately), NCSoft, Samsung Life (all list it by name); `REQUIRES_CLARIFICATION` for Toss Payments/EST Security/INCA (not named in the captured exclusion list — may still be excluded, re-verify) | Per-target exclusion lists |
| Self-XSS | `EXPLICITLY_EXCLUDED` | Named directly for NCSoft and Samsung Life; treat as excluded program-wide by analogy |
| Open redirect | `EXPLICITLY_EXCLUDED` | Named directly for LG U+, Nexon, Samsung Life |
| Missing security headers (CSP/HSTS/X-Frame-Options etc.) | `EXPLICITLY_EXCLUDED` | Named directly for LG U+, Nexon, NCSoft, Samsung Life |
| TLS/cipher/protocol version issues | `EXPLICITLY_EXCLUDED` | Named directly for LG U+, Nexon, NCSoft, Samsung Life |
| CSRF on low-impact/generic functions (logout, bookmarking) | `EXPLICITLY_EXCLUDED`; CSRF on **member/admin** functions is `RELEVANT_AND_PERMITTED` for NCSoft (explicitly carved back in) | NCSoft VDP explicitly distinguishes "CSRF outside member/admin functions" (excluded) from implied in-scope CSRF on those functions |
| Mobile deep-link vulnerabilities | `EXPLICITLY_EXCLUDED` | Named directly for LG U+ and Samsung Life |
| Findings only on rooted/jailbroken devices or emulators | `EXPLICITLY_EXCLUDED` | Named directly for LG U+ and Samsung Life |
| Mass content creation (posts/comments/messages) | `EXPLICITLY_EXCLUDED` as a finding, and treated as `POTENTIALLY_PROHIBITED` as a technique under this project's own non-negotiable ban on mass-content-creation testing | LG U+ exclusion list + project principles |
| Social engineering / phishing (incl. against the org's own staff or users) | `EXPLICITLY_EXCLUDED` and program-wide prohibited technique | Named in every VDP |
| Physical attacks | `EXPLICITLY_EXCLUDED` and program-wide prohibited technique | Named in every VDP |
| Passive JS-bundle / public-API-doc reading, service fingerprinting from public pages | `RELEVANT_AND_PERMITTED` (passive OSINT, no requests to the target beyond normal page loads) | Not addressed as prohibited anywhere; consistent with the project's "Safe Default Automation" categories |
| Any request to a domain/path not explicitly enumerated in the target's `scope.allowed_domains`/`allowed_urls` | `EXPLICITLY_EXCLUDED` (out of scope, full stop) | `subdomains_implicitly_allowed: false` on every target file — never assume a subdomain is in scope |
| Testing Alyac scope items other than the desktop app v2.5/3.0 on Windows 11 (EST Security) | `EXPLICITLY_EXCLUDED` | Mobile app and backend explicitly out of scope per `policies/targets/estsecurity.yaml` |
| Testing nProtect before completing the required install+activation steps (INCA) | `REQUIRES_CLARIFICATION` until setup is verified complete | `policies/targets/inca.yaml` uncertainties |
| Real-money payment/transaction testing (Toss Payments) | `EXPLICITLY_EXCLUDED` | This project's own non-negotiable ban on unauthorized payment testing; use researcher-controlled test data only |
| Automated crawling for endpoint discovery | `POTENTIALLY_PROHIBITED` — treated as scanner-adjacent, not permitted by default anywhere | No target grants crawling permission; `automation.crawling_allowed` is `false`/`unknown` on every target file |

## Where this leaves the actual test plan

Because 15–34 finding categories are excluded per target and every form of automation is off the table, the realistically fruitful, permitted surface is narrow: **manual authentication/session/authorization logic, business-logic and state-transition flaws, and input handling within the exact enumerated scope** — which is exactly what Section 5 of the master project brief calls "high-value hypotheses." The per-target checklists in `checklists/` translate this into a concrete pre-test list per organization.
