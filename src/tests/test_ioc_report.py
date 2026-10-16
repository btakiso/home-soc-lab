import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ioc_report  # noqa: E402
from parse_logs import parse_file  # noqa: E402

SAMPLES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples")
SNORT_SAMPLE = os.path.join(SAMPLES, "snort-alerts.log")
CSV_SAMPLE = os.path.join(SAMPLES, "splunk-export.csv")


def _report_for(path):
    records, skipped = parse_file(path)
    return ioc_report.build_report(records, skipped, os.path.basename(path))


def test_report_has_all_sections_for_snort():
    report = _report_for(SNORT_SAMPLE)
    for heading in (
        "## Summary: events by signature",
        "## MITRE ATT&CK mapping",
        "## IOC table",
        "## Timeline",
        "## Recommended actions",
    ):
        assert heading in report


def test_report_maps_all_mitre_techniques():
    report = _report_for(SNORT_SAMPLE)
    for technique in ("T1046", "T1595", "T1110.001", "T1021.002", "T1021.006"):
        assert technique in report


def test_report_contains_key_iocs():
    report = _report_for(SNORT_SAMPLE)
    assert "192.168.56.30" in report
    assert "192.168.56.20" in report
    assert "Total events parsed: 17" in report


def test_report_actions_keyed_to_each_class():
    report = _report_for(SNORT_SAMPLE)
    assert "### Port scan" in report
    assert "### Brute force" in report
    assert "### Lateral movement" in report


def test_report_from_csv_includes_usernames():
    report = _report_for(CSV_SAMPLE)
    assert "socadmin" in report
    assert "administrator" in report


def test_cli_end_to_end(tmp_path):
    out = tmp_path / "incident-test.md"
    rc = ioc_report.main(["--input", SNORT_SAMPLE, "--out", str(out)])
    assert rc == 0
    text = out.read_text(encoding="utf-8")
    assert text.startswith("# Incident Report")
    assert "T1110.001" in text
    assert b"\r\n" not in out.read_bytes()
