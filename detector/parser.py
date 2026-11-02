import re  # regex tools for finding patterns in text
from collections import Counter # counts how many times each thing appears

# Regex patterns for the ssh events we care about
# Complied once at load time and reused for every line.
FAILED = re.compile(r"Failed password for (invalid user )?(\S+) from (\S+)") # failed password
ACCEPTED = re.compile(r"Accepted password for (\S+) from (\S+)") # accepted password
INVALID = re.compile(r"Invalid user (\S+) from (\S+)") # invalid users


def parse_line(line): 
    #turn one log into a dict, or return none if we dont care about it
    # Skiip malformed lines that don't have the "header: message" format
    if ": " not in line:
        return None

    header, message = line .strip().split(": ", 1)
    parts = header.split()
    if len(parts) < 5:
        return None
    # Header fields: timestamp, host, and process name (without the PID)
    event = {
        "timestamp": " ".join(parts[0:3]),
        "host": parts[3],
        "process": parts[4].split("[")[0],
    }

    # Match the message against each event type; first match witns
    match = FAILED.search(message)
    if match:
        event["event"] = "failed_password"
        event["user"] = match.group(2)
        event["ip"] = match.group(3)
        return event

    match = ACCEPTED.search(message)
    if match:
        event["event"] = "accpeted_password"
        event["user"] = match.group(1)
        event["ip"] = match.group(2)
        return event

    match = INVALID.search(message)
    if match:
        event["event"] = "invalid_user"
        event["user"] = match.group(1)
        event["ip"] = match.group(2)
        return event
    # Anything else is noise for the detection rules
    return None

def parse_file(path):
    #read a whole log file and return a list of parsed events.
    events = []
    with open(path) as f:
        for line in f:
            event = parse_line(line)
            if event is not None:
                events.append(event)
    return events

# Quick manual check: run with 'python detector/parser.py
if __name__ == "__main__":
    events = parse_file("samples/OpenSSH_2k.log")
    print(f"Parsed{len(events)} events")
    # Preview the first few parsed events
    for event in events[:10]:
        print(event)

    # Summary: events by type, and the top sources of failed logins
    event_counts = Counter(e["event"]for e in events)
    print(event_counts)

    failed_ips = Counter(e["ip"] for e in events if e["event"] == "failed_password")
    print("Top 5 attacking IPs:", failed_ips.most_common(5))