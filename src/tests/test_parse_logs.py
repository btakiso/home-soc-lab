import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from parse_logs import (  # noqa: E402
    classify,
    detect_format,
    extract_iocs,
    parse_file,
    parse_snort_line,
    parse_snort_text,
)

SAMPLES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples")
SNORT_SAMPLE = os.path.join(SAMPLES, "snort-alerts.log")
CSV_SAMPLE = os.path.join(SAMPLES, "splunk-export.csv")

EXPECTED_TOTAL = 17
EXPECTED_BY_SIGNATURE = {
    "SOC LAB SCAN Nmap SYN Port Scan": 8,
    "SOC LAB BRUTE SSH Failed Password Attempt": 4,
    "SOC LAB BRUTE RDP Connection Attempt": 2,
    "SOC LAB LATERAL SMB Connection Attempt": 2,
    "SOC LAB LATERAL WinRM Connection Attempt": 1,
}


def test_snort_line_parses_all_fields():
    line = (
        "10/10-14:02:11.100001  [**] [1:1000001:0] SOC LAB SCAN Nmap SYN Port Scan "
        "[**] [Priority: 2] {TCP} 192.168.56.30:52344 -> 192.168.56.20:22"
    )
    record = parse_snort_line(line)
    assert record is not None
    assert record["src_ip"] == "192.168.56.30"
    assert record["dest_ip"] == "192.168.56.20"
    assert record["dest_port"] == 22
    assert record["protocol"] == "TCP"
    assert record["signature"] == "SOC LAB SCAN Nmap SYN Port Scan"


def test_snort_line_rejects_garbage():
    assert parse_snort_line("this is not an alert line") is None
    records, skipped = parse_snort_text("garbage\n\nmore garbage\n")
    assert records == []
    assert skipped == 2


def test_snort_sample_counts():
    records, skipped = parse_file(SNORT_SAMPLE)
    assert skipped == 0
    assert len(records) == EXPECTED_TOTAL
    assert Counter(r["signature"] for r in records) == EXPECTED_BY_SIGNATURE


def test_csv_sample_matches_snort_sample():
    snort_records, _ = parse_file(SNORT_SAMPLE)
    csv_records, skipped = parse_file(CSV_SAMPLE)
    assert skipped == 0
    assert len(csv_records) == len(snort_records)
    assert Counter(r["signature"] for r in csv_records) == EXPECTED_BY_SIGNATURE


def test_all_three_attack_classes_present():
    records, _ = parse_file(SNORT_SAMPLE)
    classes = {classify(r["signature"]) for r in records}
    assert classes == {"port_scan", "brute_force", "lateral_movement"}


def test_source_ips_use_lab_attacker_and_pivot():
    records, _ = parse_file(SNORT_SAMPLE)
    iocs = extract_iocs(records)
    assert set(iocs["source_ips"]) == {"192.168.56.30", "192.168.56.20"}
    assert iocs["source_ips"]["192.168.56.30"]["count"] == 14
    assert iocs["source_ips"]["192.168.56.20"]["count"] == 3


def test_dest_ports_extracted():
    records, _ = parse_file(SNORT_SAMPLE)
    iocs = extract_iocs(records)
    assert set(iocs["dest_ports"]) == {22, 80, 443, 445, 3389, 5985}


def test_usernames_only_from_csv():
    snort_records, _ = parse_file(SNORT_SAMPLE)
    csv_records, _ = parse_file(CSV_SAMPLE)
    assert extract_iocs(snort_records)["usernames"] == {}
    usernames = extract_iocs(csv_records)["usernames"]
    assert set(usernames) == {"admin", "root", "socadmin", "administrator"}
    assert usernames["admin"]["count"] == 3


def test_first_last_seen_ordering():
    records, _ = parse_file(SNORT_SAMPLE)
    iocs = extract_iocs(records)
    entry = iocs["signatures"]["SOC LAB SCAN Nmap SYN Port Scan"]
    assert entry["first_seen"] == "10/10-14:02:11.100001"
    assert entry["last_seen"] == "10/10-14:02:12.100990"
    assert entry["count"] == 8


def test_detect_format_by_extension_and_content():
    with open(SNORT_SAMPLE, encoding="utf-8") as handle:
        snort_text = handle.read()
    with open(CSV_SAMPLE, encoding="utf-8") as handle:
        csv_text = handle.read()
    assert detect_format(SNORT_SAMPLE, snort_text) == "snort"
    assert detect_format(CSV_SAMPLE, csv_text) == "splunk_csv"
    assert detect_format("mystery.txt", snort_text) == "snort"
    assert detect_format("mystery.txt", csv_text) == "splunk_csv"
