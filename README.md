# Log Detection Engine

A Python tool that parses Linux SSH authentication logs and flags suspicious
activity using detection rules mapped to MITRE ATT&CK.

## Status
 In progress

## Features
- [x] Parser: turns raw SSH log lines into structured events (timestamp, host, process, event, user, IP)
- [x] Rule 1: SSH brute force (more than 5 failed logins from one IP within 60 seconds), MITRE T1110.001
- [ ] Rule 2: successful login after repeated failures
- [ ] Rule 3: privileged (sudo) activity
- [ ] JSON alert output with severity
- [ ] Rules defined in YAML
- [ ] Tests (pytest) and CI (GitHub Actions)
- [ ] Docker packaging

## Quick start
Requires Python 3.10+. Run from the project root:

```bash
python -m detector.rules
```

## Results so far
Run against 2,000 real SSH log lines from the LogHub dataset:
- 519 failed logins, 112 invalid-user attempts
- Rule 1 flagged **X** source IPs
- Top attacker: `183.62.140.253` with 286 failed logins, 6 of them within 10 seconds

## Project structure
```
detector/
  parser.py   # turns log lines into structured events
  rules.py    # detection rules that produce alerts
samples/
  OpenSSH_2k.log          # real SSH logs (LogHub)
  generated_attack.log    # small test log with a known expected result
```

## Data
- `OpenSSH_2k.log` comes from [LogHub](https://github.com/logpai/loghub) (logpai/loghub).
- `generated_attack.log` is synthetic test data using documentation IP ranges
  (203.0.113.0/24, 198.51.100.0/24).