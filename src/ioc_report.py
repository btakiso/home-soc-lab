"""Generate a Markdown IOC incident report from a Snort log or Splunk CSV.

Usage (PRD FR-6.3):
    python src/ioc_report.py --input <log file> --out <report.md>

Standard library only. Input format is detected from the file extension
and content by parse_logs.detect_format.
"""

import argparse
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from parse_logs import classify, extract_iocs, parse_file  # noqa: E402

# MITRE ATT&CK mapping per PRD section 7, keyed by attack class.
MITRE = {
    "port_scan": [
        ("T1046", "Network Service Discovery"),
        ("T1595", "Active Scanning"),
    ],
    "brute_force": [
        ("T1110.001", "Brute Force: Password Guessing"),
        ("T1078", "Valid Accounts (success path only, if a login succeeded)"),
    ],
    "lateral_movement": [
        ("T1021.002", "SMB / Windows Admin Shares"),
        ("T1021.006", "Windows Remote Management (WinRM)"),
    ],
}

CLASS_LABELS = {
    "port_scan": "Port scan",
    "brute_force": "Brute force",
    "lateral_movement": "Lateral movement",
    "other": "Other",
}

# Recommended actions per attack class, drawn from the triage playbooks
# (docs/playbooks/) and written in lab terms.
ACTIONS = {
    "port_scan": [
        "Confirm the source is the lab attacker (192.168.56.30) and the scan matches a planned scenario; an unexpected source is a finding on its own.",
        "Record the scanned ports and hosts in the incident notes; scanned services define the follow-on risk surface.",
        "Check for follow-on connection attempts from the same source in the hours after the scan (see brute force and lateral movement sections if present).",
        "No containment for an authorized lab scan; if the source is not the lab attacker, isolate the source host from the lab network and escalate.",
    ],
    "brute_force": [
        "Identify the targeted accounts from the attempted usernames and confirm whether any attempt succeeded (Splunk: follow the failures with a successful logon for the same user).",
        "If a login succeeded, treat it as a compromise: disable or reset the account, end active sessions, and review what the account touched.",
        "Verify the targeted service enforces lockout or throttling and MFA where available; note gaps in the incident report.",
        "Block or rate-limit the source at the sensor or host firewall if the attempts continue, and keep the source IP on the watch list.",
    ],
    "lateral_movement": [
        "Treat internal host-to-host SMB or WinRM from a workstation as high severity until explained; identify both endpoints and the initiating account.",
        "Isolate the initiating host from the lab network if the movement was not part of a planned scenario.",
        "Review authentication logs on every destination host for successful logons from the source, and reset any account that was used.",
        "Check whether SMB signing and WinRM authentication hardening are in place on the targets; record gaps as eradication actions.",
    ],
    "other": [
        "Review the unmatched signatures manually, confirm whether they are true positives, and add a classification rule or playbook note if the pattern repeats.",
    ],
}


def build_report(records, skipped, input_name):
    """Build the Markdown report text from parsed records."""
    lines = []
    total = len(records)
    ordered = sorted(records, key=lambda r: r["sort_key"])
    iocs = extract_iocs(records)
    sig_counts = Counter(r["signature"] for r in records)
    class_counts = Counter(classify(r["signature"]) for r in records)
    classes_present = [c for c in ("port_scan", "brute_force", "lateral_movement", "other") if class_counts.get(c)]

    lines.append("# Incident Report: IOC Summary")
    lines.append("")
    lines.append("- Source file: `%s`" % input_name)
    lines.append("- Total events parsed: %d" % total)
    if skipped:
        lines.append("- Lines skipped (unrecognized format): %d" % skipped)
    if ordered:
        lines.append("- First event: %s" % ordered[0]["timestamp"])
        lines.append("- Last event: %s" % ordered[-1]["timestamp"])
    lines.append("- Unique source IPs: %d" % len(iocs["source_ips"]))
    lines.append("- Attack classes detected: %s" % ", ".join(CLASS_LABELS[c] for c in classes_present))
    lines.append("")

    lines.append("## Summary: events by signature")
    lines.append("")
    lines.append("| Signature | Attack class | Events |")
    lines.append("|---|---|---|")
    for signature, count in sig_counts.most_common():
        lines.append("| %s | %s | %d |" % (signature, CLASS_LABELS[classify(signature)], count))
    lines.append("")

    lines.append("## MITRE ATT&CK mapping")
    lines.append("")
    lines.append("| Attack class | Technique ID | Technique |")
    lines.append("|---|---|---|")
    for klass in classes_present:
        for tech_id, tech_name in MITRE.get(klass, []):
            lines.append("| %s | %s | %s |" % (CLASS_LABELS[klass], tech_id, tech_name))
    lines.append("")

    lines.append("## IOC table")
    lines.append("")

    def ioc_section(title, values, sort_numeric=False):
        lines.append("### %s" % title)
        lines.append("")
        lines.append("| IOC | Events | First seen | Last seen |")
        lines.append("|---|---|---|---|")
        keys = sorted(values, key=lambda v: (v is None, v if sort_numeric and isinstance(v, int) else str(v)))
        for value in keys:
            entry = values[value]
            lines.append("| %s | %d | %s | %s |" % (value, entry["count"], entry["first_seen"], entry["last_seen"]))
        lines.append("")

    ioc_section("Source IPs", iocs["source_ips"])
    ioc_section("Destination ports", iocs["dest_ports"], sort_numeric=True)
    ioc_section("Attempted usernames", iocs["usernames"])
    if not iocs["usernames"]:
        lines.append("No usernames present in this source (Snort alert logs do not carry usernames; use the Splunk export for account detail).")
        lines.append("")

    lines.append("## Timeline")
    lines.append("")
    lines.append("| Attack class | Events | First seen | Last seen |")
    lines.append("|---|---|---|---|")
    for klass in classes_present:
        group = [r for r in ordered if classify(r["signature"]) == klass]
        lines.append(
            "| %s | %d | %s | %s |"
            % (CLASS_LABELS[klass], len(group), group[0]["timestamp"], group[-1]["timestamp"])
        )
    lines.append("")

    lines.append("## Recommended actions")
    lines.append("")
    for klass in classes_present:
        lines.append("### %s" % CLASS_LABELS[klass])
        lines.append("")
        for action in ACTIONS[klass]:
            lines.append("- %s" % action)
        lines.append("")

    lines.append("---")
    lines.append("Generated by src/ioc_report.py from %s. Lab data only (192.168.56.0/24)." % input_name)
    lines.append("")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Generate a Markdown IOC incident report from a Snort log or Splunk CSV export.")
    parser.add_argument("--input", required=True, help="input log file (Snort alert log or Splunk CSV export)")
    parser.add_argument("--out", required=True, help="output Markdown report path")
    args = parser.parse_args(argv)

    records, skipped = parse_file(args.input)
    if not records:
        print("error: no events parsed from %s" % args.input, file=sys.stderr)
        return 2
    report = build_report(records, skipped, os.path.basename(args.input))
    out_dir = os.path.dirname(os.path.abspath(args.out))
    os.makedirs(out_dir, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as handle:
        handle.write(report)
    print("wrote %s (%d events, %d skipped)" % (args.out, len(records), skipped))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
