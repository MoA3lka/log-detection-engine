"""Tests for the log parser."""

import pytest

from detector.parser import parse_line


def test_parses_failed_password_for_invalid_user():
    line = "Dec 10 06:55:48 LabSZ sshd[24200]: Failed password for invalid user webmaster from 173.234.31.186 port 38926 ssh2"

    event = parse_line(line)

    assert event["event"] == "failed_password"
    assert event["user"] == "webmaster"
    assert event["ip"] == "173.234.31.186"
    assert event["timestamp"] == "Dec 10 06:55:48"
    assert event["host"] == "LabSZ"
    assert event["process"] == "sshd"


def test_parses_failed_password_for_existing_user():
    line = "Dec 10 07:13:43 LabSZ sshd[24300]: Failed password for root from 5.36.59.76 port 42393 ssh2"

    event = parse_line(line)

    assert event["event"] == "failed_password"
    assert event["event"] == "failed_password"

def test_parses_accepted_password():
    line = "Dec 10 09:32:20 LabSZ sshd[24680]: Accepted password for fztu from 119.137.62.142 port 49116 ssh2"

    event = parse_line(line)

    assert event["event"] == "accepted_password"
    assert event["user"] == "fztu"
    assert event["ip"] == "119.137.62.142"


def test_parses_sudo_command():
    line = "Dec 10 10:01:10 testhost sudo:     root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/cat /etc/shadow"

    event = parse_line(line)

    assert event["event"] == "sudo_command"
    assert event["user"] == "root"
    assert event["run_as"] == "root"
    assert event["command"] == "/bin/cat /etc/shadow"


@pytest.mark.parametrize("line", [
    "",
    "Garbage: line",
    "Dec 10 sshd: Failed password for root from 203.0.113.50 port 1 ssh2",
    "Dec 10 10:15:00 testhost sshd[1005]:",
    "Dec 99 10:15:00 testhost sshd[1006]: Failed password for root from 203.0.113.51 port 2 ssh2",
    "Dec 10 25:61:00 testhost sshd[1007]: Failed password for root from 203.0.113.52 port 3 ssh2",
])
def test_skips_malformed_lines(line):
    assert parse_line(line) is None