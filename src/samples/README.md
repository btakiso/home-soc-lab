# Sample Logs

Fictional lab data on the lab addressing plan (192.168.56.0/24, attacker
192.168.56.30). The same 17 events in two formats, so the parser and report
generator run with no lab at all:

- snort-alerts.log: Snort alert_fast format. 8 port-scan alerts, 6 brute-force
  alerts (SSH and RDP), 3 lateral-movement alerts (SMB and WinRM, sourced from
  the Windows target 192.168.56.20 acting as the pivot).
- splunk-export.csv: a Splunk CSV export of the same events (columns _time,
  src, src_port, dest, dest_port, proto, signature, user). This is the format
  that carries attempted usernames; Snort alerts do not.

No real-world data, no credentials.
