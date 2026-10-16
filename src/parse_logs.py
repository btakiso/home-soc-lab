"""Parse Snort alert_fast logs and Splunk CSV exports into common records.

Standard library only. Used by ioc_report.py and by the unit tests.

A "record" is a dict with these keys:
    timestamp   raw timestamp string as it appeared in the source
    sort_key    normalized string that sorts chronologically within a file
    src_ip      source IP address
    src_port    source port (int) or None
    dest_ip     destination IP address
    dest_port   destination port (int) or None
    protocol    protocol string, e.g. TCP
    signature   alert signature / event signature text
    user        attempted username when the source carries one, else ""
    source      "snort" or "splunk_csv"
"""

import csv
import re

# Snort alert_fast line, e.g.:
# 10/10-14:02:11.100001  [**] [1:1000001:0] SOC LAB SCAN Nmap SYN Port Scan [**] \
# [Priority: 2] {TCP} 192.168.56.30:52344 -> 192.168.56.20:22
SNORT_RE = re.compile(
    r"^(?P<ts>\d{2}/\d{2}-\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+"
    r"\[\*\*\]\s+\[\d+:\d+:\d+\]\s+"
    r"(?P<signature>.+?)\s+\[\*\*\]\s+"
    r"(?:\[Priority:\s*\d+\]\s+)?"
    r"\{(?P<proto>[A-Za-z0-9]+)\}\s+"
    r"(?P<src>\d{1,3}(?:\.\d{1,3}){3})(?::(?P<sport>\d+))?\s+->\s+"
    r"(?P<dst>\d{1,3}(?:\.\d{1,3}){3})(?::(?P<dport>\d+))?\s*$"
)

IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")

# Attack-class keyword rules, checked in order. Signatures in this project
# carry an explicit class tag (SCAN / BRUTE / LATERAL); the fallbacks cover
# common phrasings from stock Snort rules and Splunk exports.
CLASS_RULES = (
    ("lateral_movement", ("LATERAL", "SMB", "WINRM", "ADMIN SHARES")),
    ("brute_force", ("BRUTE", "FAILED PASSWORD", "PASSWORD GUESSING")),
    ("port_scan", ("SCAN", "PORTSCAN", "NMAP")),
)


def classify(signature):
    """Return the attack class for a signature, or "other"."""
    text = (signature or "").upper()
    for klass, keywords in CLASS_RULES:
        if any(word in text for word in keywords):
            return klass
    return "other"


def _snort_sort_key(ts):
    # "10/10-14:02:11.100001" -> "10-10T14:02:11.100001" (sorts within a file)
    return ts[0:2] + "-" + ts[3:5] + "T" + ts[6:]


def parse_snort_line(line):
    """Parse one alert_fast line into a record, or None if it does not match."""
    match = SNORT_RE.match(line.strip())
    if not match:
        return None
    ts = match.group("ts")
    return {
        "timestamp": ts,
        "sort_key": _snort_sort_key(ts),
        "src_ip": match.group("src"),
        "src_port": int(match.group("sport")) if match.group("sport") else None,
        "dest_ip": match.group("dst"),
        "dest_port": int(match.group("dport")) if match.group("dport") else None,
        "protocol": match.group("proto"),
        "signature": match.group("signature").strip(),
        "user": "",
        "source": "snort",
    }


def parse_snort_text(text):
    """Parse a whole Snort alert log; unparsable lines are skipped."""
    records = []
    skipped = 0
    for line in text.splitlines():
        if not line.strip():
            continue
        record = parse_snort_line(line)
        if record is None:
            skipped += 1
        else:
            records.append(record)
    return records, skipped


def parse_splunk_csv_text(text):
    """Parse a Splunk CSV export into records.

    Expected columns at minimum: _time, src, dest, dest_port, signature, user.
    Extra columns are ignored. Rows missing src or signature are skipped.
    """
    records = []
    skipped = 0
    reader = csv.DictReader(text.splitlines())
    if reader.fieldnames is None:
        return records, 0
    for row in reader:
        src = (row.get("src") or "").strip()
        signature = (row.get("signature") or "").strip()
        if not src or not signature:
            skipped += 1
            continue
        ts = (row.get("_time") or "").strip()
        dest_port = (row.get("dest_port") or "").strip()
        src_port = (row.get("src_port") or "").strip()
        records.append(
            {
                "timestamp": ts,
                "sort_key": ts,
                "src_ip": src,
                "src_port": int(src_port) if src_port.isdigit() else None,
                "dest_ip": (row.get("dest") or "").strip(),
                "dest_port": int(dest_port) if dest_port.isdigit() else None,
                "protocol": (row.get("proto") or row.get("protocol") or "").strip(),
                "signature": signature,
                "user": (row.get("user") or "").strip(),
                "source": "splunk_csv",
            }
        )
    return records, skipped


def detect_format(path, text):
    """Detect "snort" or "splunk_csv" from extension first, then content."""
    suffix = str(path).lower().rsplit(".", 1)[-1]
    if suffix == "csv":
        return "splunk_csv"
    for line in text.splitlines():
        if not line.strip():
            continue
        if "[**]" in line and "->" in line:
            return "snort"
        if line.startswith("_time,") or line.startswith("_time;"):
            return "splunk_csv"
        break
    if suffix in ("log", "txt", "alert"):
        return "snort"
    raise ValueError("could not detect log format for %s" % path)


def parse_file(path):
    """Parse a log file, auto-detecting format. Returns (records, skipped)."""
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        text = handle.read()
    fmt = detect_format(path, text)
    if fmt == "snort":
        return parse_snort_text(text)
    return parse_splunk_csv_text(text)


def extract_iocs(records):
    """Extract IOCs from records: source IPs, dest ports, signatures, users.

    Returns a dict of sorted lists plus per-IOC event counts and first/last
    seen timestamps.
    """

    def bucket(values):
        out = {}
        for value, record in values:
            if value in ("", None):
                continue
            entry = out.setdefault(
                value, {"count": 0, "first_seen": record["timestamp"], "last_seen": record["timestamp"], "_first_key": record["sort_key"], "_last_key": record["sort_key"]}
            )
            entry["count"] += 1
            if record["sort_key"] < entry["_first_key"]:
                entry["_first_key"] = record["sort_key"]
                entry["first_seen"] = record["timestamp"]
            if record["sort_key"] > entry["_last_key"]:
                entry["_last_key"] = record["sort_key"]
                entry["last_seen"] = record["timestamp"]
        for entry in out.values():
            del entry["_first_key"]
            del entry["_last_key"]
        return out

    return {
        "source_ips": bucket((r["src_ip"], r) for r in records),
        "dest_ports": bucket((r["dest_port"], r) for r in records),
        "signatures": bucket((r["signature"], r) for r in records),
        "usernames": bucket((r["user"], r) for r in records),
    }
