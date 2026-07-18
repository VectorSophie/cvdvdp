# Program Overview: 취약점 신고·조치·공개제도(CVD/VDP) 시범사업

All claims below were retrieved 2026-07-18. Machine-readable/mechanically-enforceable versions of everything here live in `policies/program.yaml` and `policies/targets/*.yaml` — this document is the human-readable research trail behind those files.

## Program identity

"취약점 신고·조치·공개제도(CVD/VDP) 시범사업" (Coordinated Vulnerability Disclosure / Vulnerability Disclosure Program pilot project), hosted by the Ministry of Science and ICT and the National Intelligence Service, organized and operated by KISA (한국인터넷진흥원). Announced 2026-05-28.

- Source: https://cvdvdp.kr/, accessed 2026-07-18. Confidence: high.
- Corroborated by: Boannews (m.boannews.com/html/detail.html?tab_type=1&idx=143845), ZDNet Korea (zdnet.co.kr/view/?no=20260528102723), 전자신문/etnews (etnews.com/20260528000278), all accessed 2026-07-18.

## Program purpose

Prevent personal-data leakage and network-operation disruption ("개인정보 유출, 망 운영저해 등") by channeling white-hat vulnerability research through a structured, KISA-mediated disclosure process instead of ad hoc or unauthorized testing.

- Source: ZDNet Korea coverage, accessed 2026-07-18. Confidence: high.

## Participant eligibility

- South Korean nationals only, age 19+ as of the pilot application date.
- Individual researchers only — **organizations (companies, universities, government bodies) are explicitly excluded from participating as researchers in this pilot**, even though the general definition of "정보보호연구자" would normally include them.
- Required before testing: (1) submit pilot application, (2) submit personal-data collection/use consent, (3) complete pilot-related training, (4) submit a signed VDP-compliance pledge, (5) execute a personal-data-processing-delegation contract under the Personal Information Protection Act.

Source: identical text across LG U+ and Samsung Life VDP §1 (and, by the templated structure observed, presumably all 7 targets); https://cvdvdp.kr/. Confidence: high.

## Vulnerability discovery period

**2026-06-29 to 2026-07-21.** Confirmed identically on cvdvdp.kr and on every one of the 7 researched company VDP pages. Confidence: high.

**⚠️ As of today (2026-07-18), 3 days of the discovery window remain.**

## Reporting period / deadline after discovery

- Standard: **72 hours from the moment of discovery.**
- If the researcher's action results in actual network intrusion ("망에 침입"): discovery activity must stop immediately, and the report is due within **12 hours from the moment of intrusion**.
- The overall VDP validity period (during which reported vulnerabilities are being remediated/disclosed) runs 2026-06-29 to **2026-07-24**.

Source: identical text across all 7 target VDPs. Confidence: high.

## Emergency reporting deadline after actual intrusion

The 12-hour figure above **is** the emergency/intrusion deadline — confirmed verbatim in LG U+'s and Samsung Life's VDP text ("망에 침입한 때부터 12시간 이내에 신고"), and consistent with the fields captured for Nexon, NCSoft, Toss Payments, EST Security, and INCA. No separate, larger "emergency reporting" figure exists distinct from this 12-hour rule. Confidence: high.

## Reporting channel

- **Private companies:** KISA's FindTheGap portal, https://hacker.findthegap.co.kr — account registration required for non-members. Each of the 7 target VDPs also lists a direct company contact email/phone as a secondary channel.
- **Public institutions:** hackthegov@ncsc.go.kr (per initial program-overview research; **not independently re-verified against a public-institution VDP document** in this pass — treat as medium confidence pending direct confirmation, since this project's scope is currently the 7 private-sector targets only).

## Disclosure restrictions

- Researcher may publicly disclose only **after 120 days** from when KISA shares the report with the company, or after the company's own earlier notice — and only **after reaching agreement with the company** on disclosure.
- The company may request up to a further **60-day extension** with a stated reason.
- Disclosure location is KISA's KNVD database (https://knvd.krcert.or.kr); the researcher may choose to be credited by name or anonymously.
- **Unauthorized disclosure without prior agreement removes legal protection and creates criminal liability exposure** — confirmed via program-overview research (cvdvdp.kr). Confidence: high.

## Conditions for legal/safe-harbor protection

Legal protection is conditioned on **strict adherence to the specific participating organization's VDP**, not merely on program-level participation. Compliant activity is treated as "good faith security research" and the company will represent this to any third party that brings action against the researcher over VDP-compliant conduct. Violating the VDP is treated as unauthorized access ("접근권한" violation) under 정보통신망법 §48(1).

Source: identical §7(1) and §9 language across LG U+, Samsung Life, and (by extension) other targets using the same template. Confidence: high.

## Prohibited activities (common across all 7 researched targets)

DoS/DDoS, brute force (incl. credential stuffing, OTP/2FA bypass), social engineering (phishing/voice phishing), physical attacks, malware installation/propagation, data destruction/alteration/falsification, reverse-engineering beyond the vulnerability search itself, testing outside the enumerated scope, monetary demands outside a formal bug-bounty program, and disclosing findings to any third party other than the company/KISA.

Confidence: high (identical or near-identical language across every target policy retrieved).

## Required actions when personal information is encountered

**Stop the vulnerability-discovery activity immediately** and notify the company. If a screenshot is unavoidable for proof purposes, it must be mosaic/masked so the content is unrecognizable, and deleted immediately after reporting. The researcher must not record, store, retain, print, or leak (to any party outside the company's control) any personal information, credit information, or trade secret encountered. Resuming testing after such a stop requires the company's approval.

Where the VDP and the personal-data-processing-delegation contract conflict, **the contract governs personal-data matters; the VDP governs everything else** (identical wording in LG U+ and Samsung Life; treated as the working assumption for all 7 targets in `policies/program.yaml`).

Confidence: high.

## Confirmed participants (15 total)

- **Private (7, matching the user's target list exactly):** LG U+, Nexon, NCSoft, Toss Payments, Samsung Life, EST Security, INCA Internet.
- **Public (8, out of scope for this project unless the user extends it):** Ministry of Economy and Finance, Ministry of Interior and Safety, Ministry of Land/Infrastructure/Transport, KDCA, HIRA, Korea Transportation Safety Authority, Bank of Korea, KEPCO.

Source: https://cvdvdp.kr/, accessed 2026-07-18. Confidence: high.

## Ambiguities and contradictions — flagged as NEEDS_CLARIFICATION

1. **KISA VPN mechanics.** Every target VDP states testing is only permitted through a KISA-provided VPN, but no public page describes how that VPN is provisioned, connected to, or how its state would be verified by tooling. Treat as something confirmed by the researcher's own attestation at session start, not something software can check.
2. **Blackout windows conflict.** One secondary source (ZDNet) describes the program as authorized "365 days, 24 hours" with no restricted windows. This directly conflicts with Nexon's own VDP, which specifies a weekly **Thursday 00:00–11:00 KST** maintenance blackout. Resolution: target-specific VDP text always overrides general program-level claims — applied in `policies/targets/nexon.yaml` only, not carried over to other targets.
3. **Request-rate/concurrency limits.** No target publishes a numeric rate or concurrency limit anywhere. Treated as "manual, human-paced, single request at a time" by default in every target file, pending explicit permission otherwise.
4. **Public-institution reporting channel** (hackthegov@ncsc.go.kr) is medium-confidence, sourced from program-overview secondary material rather than a directly fetched public-institution VDP — not currently load-bearing since this project's active scope is the 7 private-sector targets.
