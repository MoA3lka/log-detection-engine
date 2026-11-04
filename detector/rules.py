""""Detection rules that turn parsed events into alerts."""

from collections import defaultdict
from datetime import datetime

from detector.parser import parse_file

BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW_SECONDS = 60

def to_datetime(timestamp):
    """Convert 'Dec 10 06:55:48' into a datetime so we can do time maths."""
    #Syslog timestamps have no year, so we add one to keep Python within 60 Seconds
    return datetime.strptime("2026 " + timestamp, "%Y %b %d %H:%M:%S")

def detect_brute_force(events):
    """Rule 1: flag IPs with too many failed logins in a short time window."""

    #Group the time of failed logins by source IP
    failures = defaultdict(list)
    for event in events:
        if event["event"] == "failed_password":
            failures[event["ip"]].append(to_datetime(event["timestamp"]))

    alerts = []

    #slide a 60 seconds window along each IP's failures
    for ip, times in failures.items():
        times.sort()
        start = 0
        for end in range(len(times)):
            #shrink the window from the left until it spans 60 seconds or less
            while(times[end] - times[start]).total_seconds() > BRUTE_FORCE_WINDOW_SECONDS:
                start += 1

            attempts_in_window = end - start + 1
            if attempts_in_window > BRUTE_FORCE_THRESHOLD:
                alerts.append({
                    "rule": "ssh_brute_force",
                    "severity": "high",
                    "mitre_technique": "T1110.001",
                    "ip": ip,
                    "attempts_in_window": attempts_in_window,
                    "total_failed_attempts": len(times),
                    "window_start": times[start].strftime("%b %d %H:%M:%S"),
                    "window_end": times[end].strftime("%b %d %H:%M:%S"),
                })
                break # one alert per IP is enough

    return alerts

# Quick manual check run wiht 'python -m detector.rules'
if __name__ == "__main__":
    for path in ["samples/generated_attack.log", "samples/OpenSSH_2k.log"]:
        alerts = detect_brute_force(parse_file(path))
        print(f"\n{path}: {len(alerts)} brute-force alert(s)")
        for alert in alerts:
            print(alert)