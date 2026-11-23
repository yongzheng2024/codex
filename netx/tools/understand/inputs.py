"""Read NetX queries and adapt the versioned Cornetto interchange formats."""

import csv
from filecmp import cmp
import json
import re
import shutil
from ipaddress import IPv4Network
from pathlib import Path


def is_cornetto_scenario(path):
    """Recognize the scenario layout independently for the CSV and the simulated configs."""
    return (path.name.startswith("scenario-") and (path / "final_configs/configs").is_dir()
            and ((path / "specifications").is_dir() or (path / "data_and_metrics/topology.json").is_file()))


def reference_input(path):
    if path is None:
        return {"file": None, "scenario": None, "source": None,
                "configurationState": None, "nominalSamplePercent": None}
    location = path.resolve()
    scenario = location.parent.parent
    if location.parent.name == "specifications" and is_cornetto_scenario(scenario):
        sample = re.fullmatch(r"specifications_(100|[1-9][0-9]?)pct\.csv", location.name)
        return {"file": str(location), "scenario": scenario.name, "source": "Cornetto",
                "configurationState": "golden_vs_faulty",
                "nominalSamplePercent": int(sample[1]) if sample else None}
    return {"file": str(location), "scenario": None, "source": "supplied CSV",
            "configurationState": "supplied_reference", "nominalSamplePercent": None}


def reference_matches_snapshot(reference, provenance):
    """Check a recognized Cornetto reference against the scenario used for simulation."""
    if not reference["scenario"] or not provenance["scenario"]:
        return True
    if reference["scenario"] != provenance["scenario"]:
        return False
    csv_path = Path(reference["file"])
    local_csv = Path(provenance["snapshot"]).parent / "specifications" / csv_path.name
    # Copies of a scenario can share the same published reference across checkouts.
    return local_csv == csv_path or (local_csv.is_file() and cmp(csv_path, local_csv, shallow=False))


def read_specs(path):
    """Preserve each Cornetto row, including combined or unfamiliar status labels."""
    fields = {"predicate_type", "node", "prefix", "waypoint", "num_routes", "sources"}
    rows = []
    with path.open(encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        if not fields.issubset(reader.fieldnames or []):
            raise ValueError(f"{path} needs the Cornetto columns {sorted(fields)}")
        for row in reader:
            try:
                if None in row or any(row[k] is None for k in fields):
                    raise ValueError("unexpected number of columns")
                kind = row["predicate_type"]
                if kind not in {"reachability", "waypointing", "load_balancing", "isolation"}:
                    raise ValueError(f"unknown predicate {kind!r}")
                IPv4Network(row["prefix"])
                if not row["node"].strip():
                    raise ValueError("missing source router")
                if kind == "waypointing":
                    if not row["waypoint"].strip():
                        raise ValueError("waypointing requires a waypoint router")
                elif row["waypoint"]:
                    raise ValueError("waypoint is only used for waypointing")
                if kind == "load_balancing":
                    if int(row["num_routes"]) < 2:
                        raise ValueError("num_routes must be at least 2")
                elif row["num_routes"]:
                    raise ValueError("num_routes is only used for load_balancing")
            except (TypeError, ValueError) as error:
                raise ValueError(f"{path}:{reader.line_num} {error}") from error
            rows.append(dict(row, line=reader.line_num))
    return rows


def load_queries(path):
    plan = json.loads(path.read_text()) if path else {}
    if not isinstance(plan, dict) or set(plan) - {"prefixes", "flows", "policyTests"}:
        raise ValueError("Expected an object with prefixes, flows or policyTests")
    for kind, entries in plan.items():
        if not isinstance(entries, list):
            raise ValueError(f"{kind} must be an array")
        if kind == "prefixes":
            if not all(isinstance(prefix, str) for prefix in entries):
                raise ValueError("Route prefixes must be IPv4 prefix strings")
            plan[kind] = [str(IPv4Network(prefix)) for prefix in entries]
            continue
        ids = set()
        for q in entries:
            if not isinstance(q, dict) or not isinstance(q.get("id"), str) or not q["id"].strip():
                raise ValueError(f"Each {kind} query needs a nonempty string id")
            if q["id"] in ids:
                raise ValueError(f"Duplicate {kind} id {q['id']!r}")
            ids.add(q["id"])
            keys = {
                "flows": {"flow"},
                "policyTests": {"nodes", "policies", "direction", "route"},
            }[kind]
            if set(q) - keys - {"id"}:
                raise ValueError(f"Unexpected fields in {q['id']}")
            if kind == "flows":
                if not isinstance(q.get("flow"), dict):
                    raise ValueError("A concrete flow object is required")
            elif (not all(isinstance(q.get(k), str) and q[k].strip() for k in ("nodes", "policies"))
                  or q.get("direction") not in ("IN", "OUT") or not isinstance(q.get("route"), dict)):
                raise ValueError("A policy test needs nodes, policies, direction (IN/OUT) and route")
    return plan


def prepare_snapshot(path: Path, temp: Path):
    """Stage the benchmark's physical links using Batfish's native layer-1 format."""
    if (path / "final_configs/configs").is_dir():
        path = path / "final_configs"
    if not (path / "configs").is_dir():
        raise ValueError(f"Missing configs/ under {path}")
    state = "as_supplied"
    scenario = None
    if path.name in {"final_configs", "initial_configs"} and is_cornetto_scenario(path.parent):
        state = "fault_injected" if path.name == "final_configs" else "original_correct"
        scenario = path.parent.name
    provenance = {"snapshot": str(path), "scenario": scenario, "configurationState": state}
    topology = path.parent / "data_and_metrics/topology.json"
    native = ("batfish/layer1_topology.json", "layer1_topology.json", "testrig_layer1_topology")
    if scenario is None or not topology.is_file() or any((path / f).exists() for f in native):
        return path, {**provenance, "topology": "Batfish snapshot inputs and inference"}

    data = json.loads(topology.read_text())
    hosts = {n["id"]: n["hostname"] for n in data["nodes"]}
    edges = []
    for link in data["links"]:
        left, right = [
            {"hostname": hosts[end["node"]], "interfaceName": end["name"]}
            for end in link["interfaces"]
        ]
        edges.extend([{"node1": left, "node2": right}, {"node1": right, "node2": left}])
    staged = temp / "snapshot"
    shutil.copytree(path, staged)
    (staged / "batfish").mkdir(exist_ok=True)
    (staged / native[0]).write_text(json.dumps({"edges": edges}))
    return staged, {**provenance, "topology": str(topology), "links": len(data["links"]),
                    "declaredNodes": sorted(hosts.values())}
