"""Summarize sampled Cornetto intents and collect current simulator evidence."""

import argparse
from collections import Counter
import csv
import json
from pathlib import Path
import random
import re
import tempfile

from netx.tools.understand import NETX, analyze
from netx.tools.understand.inputs import read_specs


DATASET = NETX / "benchmarks/cornetto/cornetto-benchmark/main_dataset"
STANZAS = [re.compile(rf"^\s*{command}\s+", re.MULTILINE | re.IGNORECASE)
           for command in ("router bgp", "router ospf", "router isis", "ip access-group")]


def mixed_scenarios(dataset):
    """Select small Cisco scenarios declaring three routing processes and an attached ACL."""
    eligible = []
    for scenario in sorted(dataset.glob("scenario-*")):
        configs = sorted((scenario / "final_configs/configs").glob("*.cfg"))
        if not 1 <= len(configs) <= 30:
            continue
        config = "\n".join(path.read_text() for path in configs)
        if all(pattern.search(config) for pattern in STANZAS):
            eligible.append(scenario)
    return eligible


def replay(scenario, count, rng, output):
    source = scenario / "specifications/specifications_10pct.csv"
    rows = read_specs(source)
    selected = sorted(rng.sample(rows, min(count, len(rows))), key=lambda row: row["line"])
    if not selected:
        raise ValueError(f"No intent rows in {source}")
    directory = output / scenario.name
    directory.mkdir()
    sample = directory / "sample.csv"
    with sample.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=[k for k in selected[0] if k != "line"], extrasaction="ignore")
        writer.writeheader()
        writer.writerows(selected)
    report = analyze(scenario, specifications=source, specification_lines={row["line"] for row in selected})
    details = directory / "result.json"
    details.write_text(json.dumps(report))
    facts = report["evidence"]
    summary_for_row = {ref: f"#/summaries/{i}" for i, summary in enumerate(report["summaries"])
                       for ref in summary["evidence"]}
    sampled_rows = [
        {"sourceLine": row["line"], "sampleLine": i + 2, "node": row["node"], "prefix": row["prefix"],
         "predicate": row["predicate_type"], "sources": row["sources"],
         "summary": summary_for_row[f"#/benchmark/rows/{i}"]}
        for i, row in enumerate(selected)
    ]
    flows = [q for q in facts["queries"] if q["kind"] == "flows"]
    return {
        "scenario": scenario.name, "sourceCsv": str(source.resolve()), "eligibleRows": len(rows),
        "devices": len(facts["files"]), "status": report["status"], "gaps": report["gaps"],
        "routesByProtocol": dict(Counter(r["protocol"] for r in facts["routes"] if r["inMainRib"])),
        "representativeFlows": len(flows),
        "flowsWithAclDenials": sum(bool(q["result"]["denials"]) for q in flows if not q["error"]),
        "summaryCount": len(report["summaries"]),
        "roles": dict(Counter(r["role"] for r in report["roleHypotheses"])),
        "sampledRows": sampled_rows, "details": str(details),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=DATASET)
    parser.add_argument("--include", type=Path, help="Also check this scenario, independently of the mixed pool.")
    parser.add_argument("--seed", type=int, default=300)
    parser.add_argument("--scenarios", type=int, default=3)
    parser.add_argument("--rows", type=int, default=5)
    args = parser.parse_args()
    pool = mixed_scenarios(args.dataset)
    if not 0 <= args.scenarios <= len(pool) or args.rows < 1 or not (args.scenarios or args.include):
        parser.error(f"Choose 0 to {len(pool)} mixed scenarios, at least one scenario overall and at least one row.")
    rng = random.Random(args.seed)
    picked = rng.sample(pool, args.scenarios)
    if args.include and args.include.name not in {s.name for s in picked}:
        picked.append(args.include)
    runs = NETX / "runs"
    runs.mkdir(exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix="cornetto-sample-", dir=runs))
    print(output, flush=True)
    manifest = {"seed": args.seed, "dataset": str(args.dataset.resolve()), "eligibleMixedScenarios": len(pool),
                "sampledScenarios": [s.name for s in picked], "results": []}
    for scenario in picked:
        result = replay(scenario, args.rows, rng, output)
        manifest["results"].append(result)
        (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        print(scenario.name, result["status"], result["summaryCount"], "intent groups", flush=True)


if __name__ == "__main__":
    main()
