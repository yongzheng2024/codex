"""Command-line entry point for the snapshot understanding tool."""

import argparse
import json
from pathlib import Path
import subprocess
import sys
import uuid

from .compact import compact
from .overview import overview
from . import NETX, analyze


def main():
    parser = argparse.ArgumentParser(description="Summarize Cornetto reference predicates and associate Batfish evidence with device roles.")
    parser.add_argument("snapshot", type=Path, help="Batfish snapshot or Cornetto scenario directory")
    parser.add_argument("--queries", type=Path, help="Concrete flows and conditional BGP policy tests")
    parser.add_argument("--specifications", type=Path, help="Reference intents in Cornetto CSV format")
    parser.add_argument("--mode", choices=("full", "compact"), default="full")
    parser.add_argument("--runs", type=Path, default=NETX / "runs", help="Compact-mode evidence store")
    args = parser.parse_args()
    try:
        report = analyze(args.snapshot, queries_path=args.queries, specifications=args.specifications)
        if args.mode == "compact":
            run = args.runs.resolve() / uuid.uuid4().hex
            run.mkdir(parents=True)
            result = run / "result.json"
            with result.open("x") as stream:
                json.dump(report, stream)
            summary_path = run / "summary.md"
            if args.specifications:
                summary_path.write_text(overview(report))
            report = compact(report, result)
            if args.specifications:
                report["overview"] = str(summary_path)
        json.dump(report, sys.stdout)
        print()
        return 0
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        print(json.dumps({"status": "error", "reason": str(error)}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
