"""Lab 8 - Additional 2  Snort NIDS - log analysis
Run Snort first (see README.md), then:
    python3 analyze_alerts.py /var/log/snort/alert       (default: sample_alert.log here)
Prints alert counts by rule, source IP and protocol, and flags likely intrusions."""
import sys, pathlib; sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[3]))
from islib import *

path = sys.argv[1] if len(sys.argv) > 1 else str(pathlib.Path(__file__).with_name("sample_alert.log"))
banner(f"Snort alerts in {path}")
alerts = analyze_snort_alerts(path)

banner("Potential intrusions")
by_src = Counter(a["src_ip"] for a in alerts)
for ip, cnt in by_src.most_common():
    rules = sorted({a["msg"] for a in alerts if a["src_ip"] == ip})
    verdict = "LIKELY ATTACKER" if cnt >= 3 or any("injection" in r or "traversal" in r for r in rules) else "watch"
    print(f"  {ip:15} {cnt:3d} alerts  [{verdict}]  {rules}")
