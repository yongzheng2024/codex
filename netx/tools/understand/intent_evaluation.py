"""Bind reference rows to observations from the same NetX convergence as the device roles."""

from collections import Counter

from .summaries import reference_presences


def evaluate_intents(facts, rows, state):
    observations = {(item["node"], item["prefix"]): (i, item)
                    for i, item in enumerate(facts["intentObservations"])}
    nodes = {domain["node"] for domain in facts["domains"] if domain["vrf"] == "default"}
    checks = []
    counts = Counter(satisfied=0, violated=0, unknown=0)
    for i, row in enumerate(rows):
        index, obs = observations[row["node"].lower(), row["prefix"]]
        kind = row["predicate_type"]
        holds = obs.get("received")
        if kind == "load_balancing":
            peers = obs.get("nextHopNodes")
            holds = None if peers is None else len(peers) == int(row["num_routes"])
        elif kind == "isolation" and holds is not None:
            holds = not holds
        elif kind == "waypointing" and row["waypoint"].lower() not in nodes:
            holds = None
        elif kind == "waypointing" and holds is not False:
            transit = obs.get("waypoints")
            holds = row["waypoint"].lower() in transit if holds and transit is not None else None
        if facts["modelGaps"]:
            holds = None
        presence = "unknown" if holds is None else "present" if holds else "absent"
        target, faulty = reference_presences(row["sources"])
        result = ("unknown" if holds is None or target == "unspecified"
                  else "satisfied" if presence == target else "violated")
        counts[result] += 1
        checks.append({"row": f"#/benchmark/rows/{i}", "line": row["line"], "presence": presence,
                       "repairTarget": target, "faultyReference": faulty, "result": result,
                       "evidence": f"#/evidence/intentObservations/{index}"})
    return {"method": "netx_endpoint_probe_and_fib", "configurationState": state,
            "vrf": "default", "counts": dict(counts), "rows": checks}
