"""Scaffolds a new report file from templates/report-template.md with the
fields we already know (target name, reporting deadlines/channel) pre-filled.
Plain string substitution — no templating dependency needed for this."""
import pathlib


def scaffold(target: str, title: str, policy_obj, template_path: pathlib.Path) -> str:
    template = template_path.read_text(encoding="utf-8")
    reporting = policy_obj.target.get("reporting", {}) or {}

    filled = template.replace(
        "# Vulnerability Report — [Title]",
        f"# Vulnerability Report — {title}",
    )
    filled = filled.replace(
        "- **Target service/organization:**",
        f"- **Target service/organization:** {policy_obj.target.get('name', target)}",
    )
    filled = filled.replace(
        "- **Reporting deadline for this finding:** [discovery + 72h, or intrusion + 12h if applicable]",
        "- **Reporting deadline for this finding:** discovery + "
        f"{reporting.get('discovery_deadline_hours', 72)}h (or intrusion + "
        f"{reporting.get('intrusion_deadline_hours', 12)}h if applicable) — channel: "
        f"{reporting.get('channel', 'see policy file')}",
    )
    return filled
