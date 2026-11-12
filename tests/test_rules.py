from detector.parser import parse_file, parse_line
from detector.rules import (
    detect_brute_force,
    detect_login_after_failures,
    detect_new_user_created,
    detect_password_spraying,
    detect_sudo_activity,
    run_all_rules,
)


def make_events(lines):
    """Turn a list of log line into parsed event"""
    return[parse_line(line) for line in lines]

def failed_login(time, ip):
    return f"Dec 10 {time} testhost sshd[1]: Failed password for root from {ip} port 1 ssh2"

def accepted_login(time, ip, user="root"):
    return f"Dec 10 {time} testhost sshd[1]: Accepted password for {user} from {ip} port 1 ssh2"

def invalid_user(time, ip, user):
    return f"DEC 10 {time} testhost sshd[1]: Invalid user {user} from {ip}"

def sudo(command, user="root"):
    return f"Dec 10 10:00:00 testhost sudo: {user} : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND={command}"


#--- Rule 1: Brute force --

def test_brute_force_fires_on_fast_attack():
    times = ["10:00:01", "10:00:05", "10:00:09", "10:00:14", "10:00:20", "10:00:26"]
    events = make_events([failed_login(t, "203.0.113.45") for t in times])

    alerts = detect_brute_force(events)

    assert len(alerts) == 1
    assert alerts[0]["ip"] == "203.0.113.45"
    assert alerts[0]["mitre_technique"] == "T1110.001"

def test_brute_force_ignores_slow_attack():
    times = ["10:05:00", "10:05:30", "10:06:00", "10:06:30", "10:07:00", "10:07:30"]

    events = make_events([failed_login(t, "198.51.100.7") for t in times])

    assert detect_brute_force(events) == []


# -- Rule 2: login after failures --

def test_login_after_failures_fires_when_attacker_gets_in():
    lines = [failed_login(t, "203.0.113.45") for t in ["10:00:01", "10:00:05", "10:00:09"]]
    lines.append(accepted_login("10:00:40", "203.0.113.45"))

    alerts = detect_login_after_failures(make_events(lines))

    assert len(alerts) == 1
    assert alerts[0]["severity"] == "critical"
    assert alerts[0]["failed_attempts_before_login"] == 3


def test_login_after_failures_ignores_user_who_mistypes_twice():
    lines = [
        failed_login("10:10:00", "198.51.100.20"),
        failed_login("10:10:08", "198.51.100.20"),
        accepted_login("10:10:15", "198.51.100.20", user="alice"),
    ]

    assert detect_login_after_failures(make_events(lines)) == []


# --- Rule 3: sudo activity ---

def test_sensitive_sudo_command_is_high_severity():
    alerts = detect_sudo_activity(make_events([sudo("/bin/cat /etc/shadow")]))

    assert len(alerts) == 1
    assert alerts[0]["severity"] == "high"


def test_normal_sudo_command_is_low_severity():
    alerts = detect_sudo_activity(make_events([sudo("/usr/bin/apt update", user="alice")]))

    assert len(alerts) == 1
    assert alerts[0]["severity"] == "low"

# --- Rule 4: password spraying --
def test_password_spraying_fires_on_many_usernames():
    users = ["oracle", "test", "guest", "ubuntu", "postgres"]
    events = make_events([invalid_user("10:20:00", "203.0.113.77", u) for u in users])

    alerts = detect_password_spraying(events)

    assert len(alerts) == 1
    assert alerts[0]["usernames_tried"] == 5
    assert alerts[0]["mitre_technique"] == "T1110.003"

def test_password_spraying_ignores_brute_force_on_one_account():
    times = ["10:00:01", "10:00:05", "10:00:09", "10:00:14", "10:00:20", "10:00:26"]
    events = make_events([failed_login(t, "203.0.113.45") for t in times])

    assert detect_password_spraying(events) ==[]



# --Rule 5: new user created ---
def test_new_user_created_fires():
    line = "Dec 10 10:01:31 testhost useradd[2201]: new user: name=backdoor, UID=1001, GID=1001, home=/home/backdoor, shell=/bin/bash"

    alerts = detect_new_user_created(make_events([line]))

    assert len(alerts) == 1
    assert alerts[0]["new_user"] == "backdoor"
    assert alerts[0]["mitre_technique"] == "T1136.001"

# --- All rules together ---

def test_full_attack_story_produces_expected_alerts():
    alerts = run_all_rules(parse_file("samples/generated_attack.log"))

    severities = [alert["severity"] for alert in alerts]
    assert severities == ["high", "critical", "high", "high", "low", "medium", "high"]

def test_every_alert_has_the_required_fields():
    alerts = run_all_rules(parse_file("samples/generated_attack.log"))

    for alert in alerts:
        assert alert["rule"]
        assert alert["severity"] in ["low", "medium", "high", "critical"]
        assert alert["mitre_technique"].startswith("T")
