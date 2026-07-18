# Vulnerability Report — [Title]

Fill in every section. Do not exaggerate impact. Reproduction steps must be detailed enough for the organization to verify the issue while excluding unnecessary sensitive information (no real personal data, no real credentials, no real payment details in this document — mask/redact per `policies/targets/<target>.yaml` → `privacy`).

## Summary

- **Target service/organization:**
- **Affected URL(s) / product+version:** (must match an entry in `policies/targets/<target>.yaml` → `scope`)
- **Vulnerability category:**
- **CWE:**
- **OWASP mapping:** (Top 10:2025 / API Security Top 10 2023 — see `docs/research/methodology.md`)
- **CVSS v4.0 (supporting estimate only, not the final word):**

## Timing

- **Discovery timestamp (KST / UTC):**
- **Testing stop timestamp (KST / UTC):**
- **Network-intrusion timestamp, if applicable (KST / UTC):** — triggers the 12h emergency deadline instead of the standard 72h
- **Reporting deadline for this finding:** [discovery + 72h, or intrusion + 12h if applicable]

## Environment

- **Testing environment:** KISA VPN session, test account/product version used
- **Preconditions:** (auth state, role, specific config needed to reproduce)

## Reproduction

1.
2.
3.

## Actual behavior vs. expected secure behavior

- **Actual:**
- **Expected:**

## Proof of Concept

Minimal PoC only — stop at the smallest evidence that demonstrates the issue. No continued exploration, no lateral movement, no additional account/data access beyond what's needed to prove the vulnerability.

## Security impact and realistic attack scenario

- **Affected roles/user scope:**
- **Realistic scenario:**

## Personal information

- **Was personal/credit/trade-secret information accessed?** Yes/No
- If yes: what stop action was taken, when, and confirmation of masking/deletion per `policies/<target>.yaml` → `privacy`

## Cleanup

- **Test data/accounts created during testing:**
- **Cleanup actions taken:**
- **Remaining cleanup, if any:**

## Recommended remediation

## Evidence attachments

(list files; masked/redacted per privacy rules; store under the target's evidence workspace, never in this shared template)

## VDP compliance checklist

- [ ] Testing occurred only within `policies/targets/<target>.yaml` → `scope`
- [ ] No prohibited technique used (DoS, brute force, social engineering, physical attack, malware, destructive action — see `policies/targets/<target>.yaml` → `prohibited`)
- [ ] Testing stopped immediately on personal-data/credit-info/trade-secret access, if encountered
- [ ] Reported within the applicable deadline (72h standard / 12h if network intrusion occurred)
- [ ] No public disclosure without prior company agreement (120-day minimum wait from KISA's report-share date, +60d possible extension)
- [ ] Report submitted via KISA FindTheGap (https://hacker.findthegap.co.kr) or the target's listed direct contact
