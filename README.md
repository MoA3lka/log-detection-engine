# Log Detection Engine
![CI](https://github.com/MoA3lka/log-detection-engine/actions/workflows/ci.yml/badge.svg)

A Python tool that parses Linux authentication logs and flags suspicious
activity using detection rules mapped to MITRE ATT&CK.

## Status
🚧 In progress

## Features
- [x] Parser: turns raw SSH and sudo log lines into structured events
- [x] Rule 1: SSH brute force (more than 5 failed logins from one IP within 60 seconds), MITRE T1110.001
- [x] Rule 2: successful login after repeated failures, MITRE T1110.001
- [x] Rule 3: privileged (sudo) activity, with higher severity for sensitive commands, MITRE T1548.003
- [x] Rule settings defined in YAML (thresholds, severity, MITRE IDs)
- [x] JSON alert output with severity
- [x] Robust parsing: skips malformed lines, impossible timestamps and invalid characters without crashing
- [x] Command-line interface
- [x] 18 automated tests (pytest)
- [x] CI (GitHub Actions)
- [x] Docker packaging

## Quick start
Requires Python 3.10+. Run from the project root.

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

Analyse a log file:

```bash
python -m detector --input samples/generated_attack.log
```

| Option | Description |
|---|---|
| `--input` | Path to the log file to analyse (required) |
| `--output` | Where to save alerts (default: `alerts.json`) |

Run `python -m detector --help` for details.

## Run with Docker

```bash
docker build -t log-detection-engine .
docker run --rm -v "$PWD/samples:/data:ro" log-detection-engine --input /data/generated_attack.log --output /tmp/alerts.json
```

The image runs as a non-root user, and logs are mounted read-only.


## Running tests

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -v
```

## Results so far
Run against 2,000 real SSH log lines from the LogHub dataset:
- 519 failed logins, 112 invalid-user attempts
- Rule 1 flagged **6** source IPs
- Top attacker: `183.62.140.253` with 286 failed logins, 6 of them within 10 seconds

## Project structure
```
detector/
  __main__.py   # command-line interface
  parser.py     # turns log lines into structured events
  rules.py      # detection rule logic
rules/          # rule settings in YAML (thresholds, severity, MITRE IDs)
samples/
  OpenSSH_2k.log          # real SSH logs (LogHub)
  generated_attack.log    # test log with a known expected result
  malformed.log           # deliberately broken lines to test robust parsing
tests/          # pytest tests for the parser and rules
requirements.txt        # runtime dependencies
requirements-dev.txt    # development dependencies (pytest)
```

## Data
- `OpenSSH_2k.log` comes from [LogHub](https://github.com/logpai/loghub) (logpai/loghub).
- `generated_attack.log` and `malformed.log` are synthetic test data using
  documentation IP ranges (203.0.113.0/24, 198.51.100.0/24).