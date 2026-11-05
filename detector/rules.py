""""Detection rules that turn parsed events into alerts."""

from collections import defaultdict
from datetime import datetime

from detector.parser import parse_file

BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW_SECONDS = 60

# Rule 2 settings: a successful login after at least 3 failures from the same IP in the previous 10minutes
LOGIN_AFTER_FAILURES_MIN_FAILURES = 3
LOGIN_AFTER_FAILURES_LOOKBACK_SECONDS = 600

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

def detect_login_after_failures(events):
    """Rule 2: flag a sucessful login from an IP that just failed several Times."""

    # Rememebr When each IP failed, so we can look back from each successful login
    failures = defaultdict(list)
    alerts = []

    for event in events:
        if event["event"] == "failed_password":
            failures[event["ip"]].append(to_datetime(event["timestamp"]))

        elif event["event"] == "accepted_password":
            login_time = to_datetime(event["timestamp"])

            #count this IP's failures within the lookback window before the login
            recent_failures = 0 # starts the tally at zero
            for failure_time in failures[event["ip"]]: #goes through each failure time for this IP only
                seconds_before = (login_time - failure_time).total_seconds() # asks how long before the login the failure happened
                if 0 <= seconds_before <= LOGIN_AFTER_FAILURES_LOOKBACK_SECONDS: #checks the failure was before the login the failure happend
                    recent_failures += 1 

            if recent_failures >= LOGIN_AFTER_FAILURES_MIN_FAILURES:
                alerts.append({
                    "rule": "ssh_login_after_failures",
                    "severity" : "critical",
                    "mitre_technique" : "T1110.001",
                    "ip" : event["ip"],
                    "user" : event["user"],
                    "failed_attempts_before_login" : recent_failures,
                    "login_time" : event["timestamp"],
                })
    return alerts

if __name__ == "__main__":
    for path in ["samples/generated_attack.log", "samples/OpenSSH_2k.log"]:
        events = parse_file(path)
        print(f"\n{path}")
        print(f"Rule 1 (brute force): {len(detect_brute_force(events))} alert(s)")

        rule2_alerts = detect_login_after_failures(events)
        print(f" Rule 2 (login after failures): {len(rule2_alerts)} alert(s)")

        for alert in rule2_alerts:
            print("  ", alert)