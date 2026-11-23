"""Compare Cornetto predicate membership on the simulated snapshot with its published state."""

from collections import Counter, defaultdict

from .summaries import reference_presences


def prefix_graphs(tables):
    """Decode the same node and interface values that pybatfish exposes in its frames."""
    import pandas as pd
    from netx.benchmarks.cornetto.src.utils.evaluation_utils.forwarding_analysis.build_forwarding_graphs import (
        graphs_from_tables,
    )

    def node(value):
        return value["name"] if isinstance(value, dict) else value

    def interface(value):
        return f"{value['hostname']}[{value['interface']}]"

    owners = defaultdict(set)
    for row in tables["ipOwners"]:
        owners[row["IP"]].add(node(row["Node"]))
    links = defaultdict(set)
    for row in tables["layer1"]:
        local, remote = interface(row["Interface"]), interface(row["Remote_Interface"])
        links[local].add(remote)
        links[remote].add(local)
    frame = pd.DataFrame.from_records([{**row, "Node": node(row["Node"])} for row in tables["forwarding"]])
    return graphs_from_tables(frame, "current", links, owners)


def compare_graphs(tables, rows, state, model_gaps):
    """Keep exact scorer membership separate from the CSV label and device evidence."""
    # The published extractor imports NetworkX lazily and wraps its import error.
    import networkx  # noqa: F401
    from netx.benchmarks.cornetto.src.utils.evaluation_utils.forwarding_analysis.predicates import (
        IsolationPredicate, LoadBalancingPredicate, ReachabilityPredicate, WaypointPredicate, collect_predicates,
    )

    groups = prefix_graphs(tables)
    wanted = {row["prefix"] for row in rows}
    waypoints = {row["waypoint"] for row in rows if row["predicate_type"] == "waypointing"}
    # NOTE: Cornetto emits predicates only for the first prefix of each graph signature.
    # Group the full table before restricting evaluation to prefixes requested by the CSV.
    relevant = (g for g in groups if g.graph.prefix in wanted)
    observed = set(collect_predicates(relevant, waypoint_nodes=waypoints).all())
    representatives = {prefix: group.graph.prefix for group in groups for prefix in group.prefixes}
    comparisons = []
    for index, row in enumerate(rows):
        kind = row["predicate_type"]
        node, prefix = row["node"], row["prefix"]
        if kind == "load_balancing":
            predicate = LoadBalancingPredicate(node, prefix, int(row["num_routes"]))
        elif kind == "waypointing":
            predicate = WaypointPredicate(node, prefix, row["waypoint"])
        elif kind == "isolation":
            predicate = IsolationPredicate(node, prefix)
        else:
            predicate = ReachabilityPredicate(node, prefix)
        expected, faulty = reference_presences(row["sources"])
        reference = {"fault_injected": faulty, "original_correct": expected}[state]
        presence = "present" if predicate in observed else "absent"
        agreement = "unspecified"
        if reference != "unspecified":
            agreement = "matches" if presence == reference else "differs"
        comparisons.append({"row": f"#/benchmark/rows/{index}", "presence": presence,
                            "representativePrefix": representatives.get(prefix),
                            "snapshotReference": reference, "agreement": agreement})
    return {"status": "computed", "method": "cornetto_forwarding_analysis_0.1", "configurationState": state,
            "modelStatus": "partial" if model_gaps else "ok", "rows": comparisons,
            "counts": dict(Counter(c["agreement"] for c in comparisons))}
