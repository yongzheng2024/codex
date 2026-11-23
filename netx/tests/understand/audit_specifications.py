"""Replay every published sample for one Cornetto scenario against two independent data planes."""

import argparse
from collections import Counter, defaultdict
import csv
import gzip
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
from unittest.mock import Mock

from netx.tools.understand import _snapshot_facts
from netx.tools.understand.inputs import read_specs, reference_input
from netx.tools.understand.prefix_graphs import compare_graphs
from netx.tools.understand.report import model_gaps
from netx.tools.understand.summaries import imported_properties, summarize


FIELDS = ("predicate_type", "node", "prefix", "waypoint", "num_routes", "sources")


def scorer_membership(answer):
    """Decode the original Java answers through pybatfish and run Cornetto's online extractor."""
    from pybatfish.datamodel.answer import TableAnswer
    from netx.benchmarks.cornetto.src.utils.evaluation_utils.forwarding_analysis.extract_forwarding_predicates import (
        extract_forwarding_predicates,
    )
    frames = {k: TableAnswer({"answerElements": [v]}) for k, v in answer.items()}
    session = Mock()
    session.q.ipOwners.return_value.answer.return_value = frames["ipOwners"]
    session.q.layer1Edges.return_value.answer.return_value = frames["layer1"]
    predicates = extract_forwarding_predicates(frames["forwarding"].frame(), bf=session)
    return {(kind, p.node, p.prefix, getattr(p, "waypoint", ""), str(getattr(p, "num_routes", "")))
            for kind in ("reachability", "isolation", "waypointing", "load_balancing")
            for p in getattr(predicates, kind)}


def verify_summary(rows, path):
    """Expand each summary and check its exact parameters, membership and original row pointers."""
    props = list(imported_properties(rows, reference_input(path)))
    summaries = summarize(props)
    indices = set()
    for group in summaries:
        members = defaultdict(set)
        for ref in group["evidence"]:
            index = int(ref.rsplit("/", 1)[1])
            p = props[index]
            if (index in indices or ref != p.evidence or group["kind"] != p.kind
                    or group["parameters"] != p.parameters or group["scope"] != p.scope):
                raise ValueError(f"{path}:{rows[index]['line']} incorrect summary membership")
            indices.add(index)
            members[p.prefix].add(p.node)
        if set(members) != set(group["prefixes"]) or group["exceptions"].keys() - members.keys():
            raise ValueError(f"{path}: summary prefixes differ")
        base = set(group["baseNodes"])
        for prefix, nodes in members.items():
            diff = group["exceptions"].get(prefix, {})
            if (base - set(diff.get("remove", ()))) | set(diff.get("add", ())) != nodes:
                raise ValueError(f"{path}: source set differs for {prefix}")
    if len(indices) != len(rows):
        raise ValueError(f"{path}: missing summary members")
    return len(summaries)


def forwarding_keys(rows):
    """Preserve multiplicity when comparing the columns consumed by the graph extractor."""
    keys = Counter()
    for row in rows:
        node = row["Node"]["name"] if isinstance(row["Node"], dict) else row["Node"]
        key = (node, row["VRF"], row["Prefix"], row["Action"],
               row.get("Next_Hop_IP"), row.get("Next_Hop_Interface"))
        keys[key] += 1
    return keys


def audit(scenario, facts, original, output):
    output.mkdir(parents=True, exist_ok=True)
    paths = sorted((scenario / "specifications").glob("specifications_*pct.csv"))
    if not paths:
        raise ValueError(f"{scenario}: missing specification files")
    unique = {}
    entries = []
    files = {}
    samples = {}
    for path in paths:
        rows = read_specs(path)
        files[path.name] = {"rows": len(rows), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                            "summaries": verify_summary(rows, path)}
        indices = []
        for r in rows:
            k = tuple(r[f] for f in FIELDS)
            if k not in unique:
                unique[k] = len(entries)
                entries.append(dict(zip(FIELDS, k)))
            indices.append((r["line"], unique[k]))
        samples[path.name] = indices
    topology = json.loads((scenario / "data_and_metrics/topology.json").read_text())
    gaps = model_gaps(facts, {"declaredNodes": [n["hostname"] for n in topology["nodes"]]})
    native = compare_graphs(facts["cornettoTables"], entries, "fault_injected", gaps)["rows"]
    oracle = scorer_membership(original)
    native_rows = forwarding_keys(facts["cornettoTables"]["forwarding"])
    scorer_rows = forwarding_keys(original["forwarding"]["rows"])
    native_only = native_rows - scorer_rows
    scorer_only = scorer_rows - native_rows
    original_presence = ["present" if k[:-1] in oracle else "absent" for k in unique]
    baseline = samples.get("specifications_100pct.csv")
    full = {idx for _, idx in baseline} if baseline is not None else None
    labels = defaultdict(set)
    for k in unique:
        labels[k[:-1]].add(k[-1])
    ledger = output / "differences.csv.gz"
    flagged = set()
    with gzip.open(ledger, "wt", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(("file", "line", *FIELDS, "publishedFaulty", "netx", "scorer", "representativePrefix"))
        for name, indices in samples.items():
            counts = Counter()
            for line, i in indices:
                comparison = native[i]
                published, observed = comparison["snapshotReference"], comparison["presence"]
                reference = original_presence[i]
                counts[comparison["agreement"]] += 1
                counts["engineDifferences"] += observed != reference
                if full is not None:
                    counts["labelsOutsideFullSample"] += i not in full
                if observed != published or observed != reference:
                    flagged.add(i)
                    writer.writerow((name, line, *(entries[i][k] for k in FIELDS), published,
                                     observed, reference, comparison["representativePrefix"]))
            files[name].update(counts)
    result = {"scenario": scenario.name, "files": files, "engine": facts["engine"], "modelGaps": gaps,
              "uniqueLabeledRows": len(unique), "uniquePredicates": len(labels),
              "multipleRawLabels": sum(len(s) > 1 for s in labels.values()), "uniqueFlagged": len(flagged),
              "uniqueEngineDifferences": sum(row["presence"] != other
                                             for row, other in zip(native, original_presence, strict=True)),
              "forwardingRows": native_rows.total(), "scorerForwardingRows": scorer_rows.total(),
              "netxOnlyForwardingRows": native_only.total(), "scorerOnlyForwardingRows": scorer_only.total(),
              "tableDifferenceExamples": {"netx": list(native_only)[:5], "scorer": list(scorer_only)[:5]}}
    (output / "comparison.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", type=Path)
    parser.add_argument("--reference-jar", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as t:
        tmp = Path(t)
        snapshot = args.scenario.resolve() / "final_configs"
        facts = _snapshot_facts(snapshot, {"cornettoTablesOnly": True}, tmp)
        java = Path(os.environ["JAVA_HOME"]) / "bin/java" if "JAVA_HOME" in os.environ else "java"
        src = Path(__file__).parent / "reference/CornettoReference.java"
        answers = tmp / "rows.json"
        subprocess.run([java, "-cp", args.reference_jar.resolve(), src, snapshot, tmp / "work", answers], check=True)
        audit(args.scenario.resolve(), facts, json.loads(answers.read_text()), args.output)


if __name__ == "__main__":
    main()
