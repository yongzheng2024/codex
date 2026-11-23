"""In-process Python entry point for NetX snapshot understanding."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile

from .inputs import load_queries, prepare_snapshot, read_specs, reference_input, reference_matches_snapshot
from .report import build_report
from .summaries import imported_properties, probe_members, summarize

NETX = Path(__file__).resolve().parents[2]
BACKEND = NETX / "simulators/batfish/bazel-bin/projects/netx/snapshot_facts"


def analyze(snapshot_path: Path, *, queries_path: Path | None = None,
            specifications: Path | None = None, specification_lines: set[int] | None = None):
    """Analyze one snapshot, optionally sampling reference rows by their original CSV line."""
    if not BACKEND.is_file():
        raise ValueError("Build //projects/netx:snapshot_facts from netx/simulators/batfish first")
    rows = read_specs(specifications) if specifications else []
    rows_in_file = len(rows) if specifications else None
    if specification_lines is not None:
        rows = [row for row in rows if row["line"] in specification_lines]
        if len(rows) != len(specification_lines):
            raise ValueError("Requested specification lines are missing from the reference CSV")
    plan = load_queries(queries_path)
    with tempfile.TemporaryDirectory(prefix="netx-understand-") as tmp:
        temp = Path(tmp)
        snapshot, provenance = prepare_snapshot(snapshot_path.resolve(), temp)
        reference = reference_input(specifications)
        summaries = summarize(imported_properties(rows, reference))
        if specifications and "flows" not in plan and reference_matches_snapshot(reference, provenance):
            plan["intentMembers"] = probe_members(summaries, rows)
        queries, output = temp / "queries.json", temp / "facts.json"
        queries.write_text(json.dumps(plan))
        subprocess.run([BACKEND, snapshot, queries, temp / "work", output], check=True, stdout=sys.stderr)
        facts = json.loads(output.read_text())
    return build_report(facts, plan, rows, provenance, specifications, rows_in_file=rows_in_file,
                        summaries=summaries)
