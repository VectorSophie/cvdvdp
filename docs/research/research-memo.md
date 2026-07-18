# Research Memo (Section 13)

Written after completing program-overview and per-target VDP research for all 7 confirmed targets (LG U+, Nexon, NCSoft, Toss Payments, Samsung Life, EST Security, INCA), 2026-07-18.

## 1. Where is automation most dangerous in this program?

Two places, both already confirmed by the research rather than hypothetical:

- **Scope drift across near-identical domains.** Several targets (LG U+, Nexon) have multiple similarly-named subdomains where only some are in scope (e.g. Nexon's 8 auth domains vs. its main `www.nexon.com` — easy to typo or pattern-match into an out-of-scope sibling subdomain). Any tool that does prefix/wildcard matching instead of exact enumeration would silently authorize out-of-scope requests. This is the single highest-risk automation surface in the whole program.
- **Treating "automation prohibited" as a per-tool setting instead of a per-target fact.** All 7 targets ban scanners/fuzzers, but they express it differently (explicit technique ban vs. finding-exclusion vs. both) — a generic "automation on/off" toggle would either be right by accident or wrong by construction. It has to read the specific target's `automation.*` fields, not a global default.

A distant third: the KISA-VPN and blackout-window facts are unverifiable by software (no API exists to check either), so any automation that "checks" them is just re-stating an attestation the human already made — worth building as an explicit checklist step, never a silent green light.

## 2. How do differences between target policies affect the architecture?

More than expected going in. Concretely:

- **Scope shapes vary by kind, not just by size.** Samsung Life is one bare domain. EST Security is a desktop app with no domain at all. INCA mixes 5 domains with a desktop app that needs a pre-test setup step. A Scope Guard built purely around domain/URL matching would have nothing to check for EST Security and would incorrectly report "no scope configured" as an error rather than "this target's scope is non-network." The schema already has `allowed_apps` for this, but any enforcement logic has to treat "app-only scope" as a valid, non-degenerate case.
- **Personal-data stop-wording differs in strictness even under one program template** (Nexon reads slightly softer than NCSoft). The safe design choice — already applied in `policies/targets/nexon.yaml` — is to always apply the strictest reading found anywhere in the set, not the reading a specific target's document literally says, and record the discrepancy in `uncertainties` rather than silently pick one.
- **Blackout windows are genuinely per-target**, not inheritable (Nexon has one, NCSoft explicitly doesn't). Any caching or "apply program defaults" logic must not propagate a blackout window between targets.

Net effect on architecture (moot for this cycle since we're shipping docs, not code, but worth recording for if a CLI is built later): the policy schema cannot get away with a single "scope enforcement" code path — it needs at least two shapes (network-scope, product-scope) and per-field strictness resolution, not a flat merge of program.yaml + target.yaml.

## 3. Which useful features can operate without sending network requests?

Everything actually built this cycle: policy structuring (`policies/*.yaml`), the cross-target methodology classification table, and the per-target checklists are all derived from pages already fetched once for research purposes — no repeated or exploratory traffic to any target asset. Looking forward, the same is true of: report drafting from the template, deadline/countdown tracking against the dates already captured, and masking/redaction of researcher-provided evidence. None of that needs to touch a target's live systems again.

## 4. Which technically possible tests should still not be performed?

Beyond what the 7 VDPs explicitly exclude (already tabulated in `docs/research/methodology.md`), three things are technically easy but deliberately out:

- **Confirming the KISA-VPN requirement by trying without it first.** Trivial to test empirically; also the one action that would turn "policy compliance" into "a violation used to verify the policy." Take the requirement as given.
- **Probing whether Nexon's Thursday blackout is actually enforced server-side** (e.g. hitting the domains right at 00:00 KST to see what changes). That's testing the *organization's operational behavior* rather than a *vulnerability*, and it's exactly the kind of boundary-testing this project's own principles rule out.
- **Using the discovered nProtect console (`nosoriginv.nprotect.net`) or Nexon's BFF API to probe for *other* organizations' data** even if such cross-tenant leakage were structurally easy to check for. Any hypothesis test that could touch another real user's or organization's data crosses from "authorized scope" into "third-party data access," which is banned outright regardless of technical feasibility.

## 5. What controls must be enforced before focusing on vulnerability discovery?

For this cycle, given the docs-only MVP decision, the "controls" are procedural, not code-enforced — every per-target checklist's **Gate** section functions as that control, and it front-loads exactly four checks: VPN active, inside the discovery window (already tight — 3 days left when this was written), outside any target-specific blackout, and any required pre-test setup (test-account identity, product install/activation) complete. Nothing below the Gate section should be read, let alone acted on, until every Gate box is checked. If a future cycle builds the actual Scope Guard code from Section 2/6 of the master brief, it should encode exactly these four checks as hard blocks, not warnings.

## 6. What is the most practical MVP within the remaining program period?

Answered empirically rather than theoretically, since the timeline turned out to be far tighter than a first read of the master brief suggested: **3 days of discovery window and 6 days to the reporting deadline, discovered mid-research.** A multi-phase CLI (policy engine → Scope Guard → workspace → planner → session recorder → finding manager → report generator) cannot be built, tested, and trusted for safety-critical use in that window. The user, presented with this finding, chose the docs/checklists-only path: per-target policy YAML (mechanically precise even without code enforcing it), a manual pre-test checklist per target, and one shared report template — all usable starting today, all directly traceable to primary-source policy text. Any CLI/automation work from the master brief's Phases 3–6 is deferred to a future cycle of the program (if it repeats) rather than attempted on a compressed, unsafe timeline this time.
