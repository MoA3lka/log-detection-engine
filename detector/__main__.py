"""Command-Line entry point python -m detector --input <log filge>"""

import argparse
import json
import sys
from pathlib import Path


from detector.parser import parse_file
from detector.rules import run_all_rules

def main():
    # Describe the options the tool accepts
    parser = argparse.ArgumentParser(
        prog="python -m detector",
        description="Detect suspicious activity in Linux auth logs."
    )
    parser.add_argument("--input", required=True, help="path to the log file to analyse")
    parser.add_argument("--output", default="alerts.json", help="where to save alerts (default: alerts.json)")
    args = parser.parse_args()

    # Parse the log, with a friednly message if the file doesn't exist
    try:
        events = parse_file(args.input)
    except FileNotFoundError:
        print(f"Error: log file not found: {args.input}")
        sys.exit(1)

    alerts = run_all_rules(events)

    # Make sure the output folder exists (e.g. results/ in results/alerts.json)
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    
    # Save alerts as JSON so other tools (or people) can read them
    with open(args.output, "w") as f:
        json.dump(alerts, f, indent=2)

    # Print a short summary
    print(f"Parse {len(events)} events from {args.input}")
    print(f"{len(alerts)} alert(s) written to {args.output}")
    for alert in alerts:
        print(f"[{alert['severity'].upper()}] {alert['rule']}")

if __name__ == "__main__":
    main()



