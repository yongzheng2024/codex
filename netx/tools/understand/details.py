"""Resolve a report pointer and optionally page the selected array."""

import argparse
import json
from pathlib import Path
import sys
from uuid import UUID


def resolve(value, pointer):
    if pointer in ("", "#"):
        return value
    if not pointer.startswith("#/"):
        raise ValueError("Expected a report pointer starting with #/")
    for part in pointer[2:].split("/"):
        key = part.replace("~1", "/").replace("~0", "~")
        if isinstance(value, list):
            if not key.isdecimal():
                raise ValueError("Expected a nonnegative array index")
            value = value[int(key)]
        else:
            value = value[key]
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("result_id", type=UUID)
    parser.add_argument("pointer", help="A pointer from the overview, e.g. '#/summaries/0'")
    parser.add_argument("--runs", type=Path, default=Path(__file__).resolve().parents[2] / "runs")
    parser.add_argument("--offset", type=int, default=0)
    parser.add_argument("--limit", type=int, default=20)
    args = parser.parse_args()
    try:
        if args.offset < 0 or args.limit < 1:
            raise ValueError("Expected a nonnegative offset and positive limit")
        path = args.runs / args.result_id.hex / "result.json"
        value = resolve(json.loads(path.read_text()), args.pointer)
        if isinstance(value, list):
            value = {"total": len(value), "offset": args.offset, "items": value[args.offset:args.offset + args.limit]}
        print(json.dumps(value))
        return 0
    except (OSError, ValueError, TypeError, KeyError, IndexError) as error:
        print(json.dumps({"status": "error", "reason": str(error)}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
