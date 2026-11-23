"""Associate current observations and reported properties with evidence-backed role hypotheses."""

import json

from .inputs import reference_input, reference_matches_snapshot
from .intent_evaluation import evaluate_intents
from .role_validation import SUCCESSFUL_DISPOSITIONS
from .roles import role_hypotheses
from .summaries import imported_properties, summarize


def model_gaps(facts, provenance):
    gaps = []
    for field in ("parseStatus", "conversionStatus"):
        for name, status in facts[field].items():
            if status != "PASSED":
                gaps.append(f"{field} {name} ({status})")
    for field in ("parseWarnings", "conversionWarnings"):
        for name, warnings in facts[field].items():
            if any(warnings.get(key) for key in ("Red flags", "Unimplemented features", "Parse warnings")):
                gaps.append(f"{field} for {name}")
    # Batfish canonicalizes hostnames to lowercase. Keep original spellings in diagnostics.
    modeled = {d["node"].lower() for d in facts["domains"]}
    missing = {name for name in provenance.get("declaredNodes", []) if name.lower() not in modeled}
    if missing:
        gaps.append("Missing topology devices: " + ", ".join(sorted(missing)))
    return gaps


def flow_behavior(result):
    traces = result["traces"]
    successful = [t for t in traces if t["disposition"] in SUCCESSFUL_DISPOSITIONS]
    complete = bool(traces) and len(traces) == result["totalPaths"]
    determinate = complete and all(t["disposition"] != "INSUFFICIENT_INFO" for t in traces)
    observed = bool(successful) if successful or determinate else None
    paths = [[h["node"]["name"] for h in trace["hops"]] for trace in successful]
    waypoints = None
    if determinate:
        waypoints = sorted(set.intersection(*(set(path[1:-1]) for path in paths))) if paths else []
    first_hops = {path[1] for path in paths if len(path) > 1}
    return {"reachable": observed, "pathsComplete": complete, "waypoints": waypoints,
            "successfulNextHopCount": len(first_hops) if determinate else None,
            "dispositions": sorted({t["disposition"] for t in traces})}


def describe_queries(facts, plan, gaps):
    requests = {(kind, q["id"]): q for kind in ("flows", "policyTests") for q in plan.get(kind, [])}
    for q in facts["queries"]:
        kind = q["kind"]
        q["request"] = requests.get((kind, q["id"]), {})
        q["basis"] = {"flows": "simulated_packet", "policyTests": "conditional_policy_test"}[kind]
        if q["error"]:
            gaps.append(f"Query {q['id']}: {q['error']}")
        elif kind == "flows":
            behavior = flow_behavior(q["result"])
            q["behavior"] = behavior
            if not behavior["pathsComplete"]:
                gaps.append(f"Trace enumeration incomplete for {q['id']}")
            if "INSUFFICIENT_INFO" in behavior["dispositions"]:
                gaps.append(f"Batfish reported insufficient forwarding information for {q['id']}")


def policy_definitions(facts):
    """Index vendor definitions by name without attributing an individual rule hit."""
    index = {}
    for node, files in facts["files"].items():
        names = {}
        for file in files:
            for kind, definitions in facts["definitions"].get(file, {}).items():
                if not any(token in kind for token in ("policy", "route-map", "route map")):
                    continue
                for name, definition in definitions.items():
                    names.setdefault(name, []).append({
                        "file": file, "structure": kind, "name": name, "lines": definition["definitionLines"],
                    })
        index[node] = names
    return index


def build_report(facts, plan, rows, provenance, specs_path, *, rows_in_file=None, summaries=None):
    # Batfish executes routing iterations in parallel and exposes sets of routes and peers.
    for key in ("routes", "events", "domains", "bgpSessions", "originExports"):
        if key not in facts:
            continue
        facts[key].sort(key=lambda r: json.dumps(r, sort_keys=True))
    definitions = policy_definitions(facts)
    for event in facts["events"]:
        node, policy = event["node"], event["policy"]
        if policy:
            dependencies = facts["policySources"].get(node, {}).get(policy, [])
            event["policyDefinitions"] = [
                definition for name in sorted({policy, *dependencies})
                for definition in definitions.get(node, {}).get(name, [])
            ]
        if event["action"] == "rejected":
            event["cause"] = "policy" if event["policy"] is not None else "core_protocol"
    facts["modelGaps"] = model_gaps(facts, provenance)
    gaps = list(facts["modelGaps"])
    describe_queries(facts, plan, gaps)
    reference = reference_input(specs_path)
    if summaries is None:
        summaries = summarize(imported_properties(rows, reference))
    role_summaries = summaries
    if not reference_matches_snapshot(reference, provenance):
        gaps.append(f"Cornetto reference {reference['file']} could not be matched to snapshot {provenance['snapshot']}")
        role_summaries = []
        for summary in summaries:
            summary.update(relatedRoles=[], endpointObservations=[], packetObservations=[], deviceRoles=[], responsibilityGroups=[],
                           attributedRows=0, unattributedRows=list(summary["evidence"]))
    roles = role_hypotheses(facts, role_summaries, rows, intent_only=specs_path is not None)
    state = provenance["configurationState"]
    comparison = {}
    if plan.get("checkIntents"):
        if "intentObservations" not in facts:
            raise ValueError("Rebuild //projects/netx:snapshot_facts for native intent observations")
        comparison["intentEvaluation"] = evaluate_intents(facts, rows, state)
    facts["configurationState"] = state
    for i, role in enumerate(roles):
        role["configurationState"] = state
        if role["validation"]["status"] == "inconsistent":
            gaps.append(f"Role evidence disagrees at #/roleHypotheses/{i}")
    return {
        "status": "partial" if gaps else "ok", "scenario": {
            "fault_injected": "Single snapshot of the fault-injected Cornetto configuration",
            "original_correct": "Single snapshot of the original correct Cornetto configuration",
            "as_supplied": "Single snapshot of the supplied configuration",
        }[state],
        "input": provenance, "simulation": {"bgpMultipathExport": facts.get("bgpMultipathExport", "unspecified")},
        "routeFocus": plan.get("prefixes", "all prefixes"),
        "flowScope": ("explicit flows" if "flows" in plan else
                      "up to 64 ICMP probes for members sampled across summaries" if "intentMembers" in plan else
                      "first 64 inter-device representative VRF pairs"),
        "benchmark": {**reference, "rowsInFile": rows_in_file, "rows": rows},
        **comparison, "summaries": summaries, "gaps": gaps, "evidence": facts,
        "roleHypotheses": roles,
    }
