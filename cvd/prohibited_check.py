"""Offline, heuristic detector for prohibited-technique keywords in a planned
test-action description, cross-referenced against the target's own policy
fields. This is a keyword scan, not a semantic classifier — it will miss
rephrased or obfuscated descriptions of the same techniques. Treat a clean
result as "nothing obvious flagged", never as an affirmative clearance.
"""

_PATTERNS = [
    ("dos", ("dos", "ddos", "denial of service", "flood"), "prohibited", "dos"),
    ("brute_force", ("brute force", "brute-force", "credential stuffing", "password spray"), "prohibited", "brute_force"),
    ("social_engineering", ("phishing", "voice phishing", "social engineering", "pretext"), "prohibited", "social_engineering"),
    ("physical_attack", ("physical access", "physical attack"), "prohibited", "physical_attack"),
    ("malware", ("malware", "ransomware", "live exploit", "worm"), "prohibited", "malware"),
    ("mass_content_creation", ("mass post", "mass comment", "bulk create", "spam", "repeated post"), "prohibited", "mass_content_creation"),
    ("destructive_actions", ("delete all", "wipe", "drop table", "truncate", "format disk"), "prohibited", "destructive_actions"),
]


def check_action(policy_obj, description: str) -> list:
    """Return a list of {"flag": str, "reason": str} dicts for anything the
    description matches, unless the target's own policy explicitly permits it
    (an explicit `False` on the matching `prohibited.<key>` field). Absence,
    `None`, or `"unknown"` never counts as permission."""
    text = description.lower()
    prohibited = policy_obj.target.get("prohibited", {}) or {}
    automation = policy_obj.target.get("automation", {}) or {}
    findings = []

    for flag, keywords, section, key in _PATTERNS:
        if any(kw in text for kw in keywords) and prohibited.get(key) is not False:
            findings.append({
                "flag": flag,
                "reason": f"Description matches {flag!r} keyword pattern; "
                          f"target policy does not explicitly permit this ({section}.{key})",
            })

    scanning_keywords = ("scan", "scanner", "fuzz", "nmap", "sqlmap", "burp intruder", "automated attack")
    scanner_permitted = automation.get("scanner_allowed") is True and automation.get("fuzzing_allowed") is True
    if any(kw in text for kw in scanning_keywords) and not scanner_permitted:
        findings.append({
            "flag": "automated_scanning",
            "reason": "Description matches automated-scanning/fuzzing keyword pattern; "
                      "this target's automation.scanner_allowed/fuzzing_allowed is not explicitly True",
        })

    return findings
