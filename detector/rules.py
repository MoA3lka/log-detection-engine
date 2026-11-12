""""Detection rules that turn parsed events into alerts."""
import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path


import yaml

from detector.parser import parse_file


# Rule file live in the rules/ folder at the project root
RULES_DIR = Path(__file__).resolve().parent.parent / "rules"


def load_rule(rule_id):
    """Load one rule's YAML file, e.g. rules/ssh_brute_force.yml."""
    with open(RULES_DIR / f"{rule_id}.yml", encoding="utf-8") as f:
        # safe_load only reads plain data and never runs code from teh file

        return yaml.safe_load(f)
    
def to_datetime(timestamp):
    """Convert 'Dec 10 06:55:48' into a datetime so we can do time maths."""
    #Syslog timestamps have no year, so we add one to keep Python within 60 Seconds
    return datetime.strptime("2026 " + timestamp, "%Y %b %d %H:%M:%S")

def detect_brute_force(events):
    """Rule 1: flag IPs with too many failed logins in a short time window."""

    rule = load_rule("ssh_brute_force")
    threshold = rule["settings"]["threshold"]
    window_seconds = rule["settings"]["window_seconds"]

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
            while (times[end] - times[start]).total_seconds() > window_seconds:
                start += 1

            attempts_in_window = end - start + 1
            if attempts_in_window > threshold:
                alerts.append({
                    "rule": rule["id"],
                    "severity": rule["severity"],
                    "mitre_technique": rule["mitre_technique"],
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
    rule = load_rule("ssh_login_after_failures")
    min_failures = rule["settings"]["min_failures"]
    lookback_seconds = rule["settings"]["lookback_seconds"]

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
                if 0 <= seconds_before <= lookback_seconds: #checks the failure was before the login the failure happend
                    recent_failures += 1 

            if recent_failures >= min_failures:
                alerts.append({
                    "rule": rule["id"],
                    "severity" : rule["severity"],
                    "mitre_technique" : rule["mitre_technique"],
                    "ip" : event["ip"],
                    "user" : event["user"],
                    "failed_attempts_before_login" : recent_failures,
                    "login_time" : event["timestamp"],
                })
    return alerts

#sudo 
def detect_sudo_activity(events):
    """Rule 3: flag sudo commands, with higher severity for sensitive ones."""

    rule= load_rule("sudo_activity")
    keywords = rule["settings"]["sensitive_keywords"]

    alerts = []
    for event in events:
        if event["event"] != "sudo_command":
            continue
        #Sensitive commands (reading password hashes, creating users...) are high severity
        is_sensitive = any(keyword in event["command"] for keyword in keywords)

        alerts.append({
            "rule": rule["id"],
            "severity": rule["settings"]["sensitive_severity"] if is_sensitive else rule["severity"],
            "mitre_technique": rule["mitre_technique"],
            "user": event["user"],
            "run_as": event["run_as"],
            "command": event["command"],
            "time": event["timestamp"],
        })
    return alerts


def run_all_rules(events):
    """Run every detection rule and return all alerts in one lists."""
    return(
        detect_brute_force(events)
        + detect_login_after_failures(events)
        + detect_sudo_activity(events)
        + detect_password_spraying(events)
        +detect_new_user_created(events)
    )

if __name__ == "__main__":
    events = parse_file("samples/generated_attack.log")
    alerts = run_all_rules(events)

    # save alerts as JSON so other tools (or people) can read them
    with open("alerts.json", "w") as f:
        json.dump(alerts, f, indent=2)

    print(f"{len(alerts)} alert(s) written to alerts.json")
    for alert in alerts:
        print(f"[{alert['severity'].upper()}] {alert['rule']}")



def detect_password_spraying(events):
    """Rule 4: flag IPs that try many different usernames."""
    rule = load_rule("password_spraying")
    min_usernames = rule["settings"]["min_usernames"]

    #collect the different usernames each IP tried
    usernames_by_ip = defaultdict(set)
    for event in events:
        if event["event"] in ("failed_password", "invalid_user"):
            usernames_by_ip[event["ip"]].add(event["user"])

    alerts = []
    for ip, usernames in usernames_by_ip.items():
        if len(usernames) >= min_usernames:
            alerts.append({
                "rule": rule["id"],
                "severity": rule["severity"],
                "mitre_technique": rule["mitre_technique"],
                "ip": ip,
                "usernames_tried": len(usernames),
                "sample_usernames": sorted(usernames)[:10],
            })
    return alerts


def detect_new_user_created(events):
    """Rule 5: flag every new user account."""
    rule = load_rule("new_user_created")

    alerts = []
    for event in events:
        if event["event"] == "user_created":
            alerts.append({
                "rule": rule["id"],
                "severity": rule["severity"],
                "mitre_technique": rule["mitre_technique"],
                "new_user": event["user"],
                "time": event["timestamp"],
                "host": event["host"],
            })
    return alerts
