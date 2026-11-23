"""Lossless summaries of scoped node/prefix relations."""

from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from ipaddress import IPv4Network
import json


@dataclass
class Property:
    kind: str
    node: str
    prefix: str
    scope: dict
    evidence: str
    parameters: dict = field(default_factory=dict)


def reference_presences(label):
    """Return the expected and fault-injected presence implied by a Cornetto status."""
    # NOTE: Cornetto's broken tag takes precedence over an accompanying intact tag.
    tags = {tag.strip().lower() for tag in label.split("|")}
    if tags - {"intact", "broken_added", "broken_removed"} or {"broken_added", "broken_removed"} <= tags:
        return "unspecified", "unspecified"
    if "broken_added" in tags:
        return "absent", "present"
    if "broken_removed" in tags:
        return "present", "absent"
    if "intact" in tags:
        return "present", "present"
    return "unspecified", "unspecified"


def imported_properties(rows, reference):
    for i, row in enumerate(rows):
        parameters = {}
        kind = row["predicate_type"]
        if kind == "waypointing":
            parameters["waypoint"] = row["waypoint"]
        elif kind == "load_balancing":
            parameters["numRoutes"] = int(row["num_routes"])
        expected, faulty = reference_presences(row["sources"])
        scope = {"source": reference["source"], "configurationState": reference["configurationState"],
                 "sources": row["sources"], "expectedPresence": expected, "faultyPresence": faulty}
        yield Property(kind, row["node"], row["prefix"], scope, f"#/benchmark/rows/{i}", parameters)


def membership_pattern(by_scope, *, include_ties=False):
    """Encode a relation as a base set with exact per-scope additions and removals."""
    frequency = Counter(member for members in by_scope.values() for member in members)
    threshold = len(by_scope) // 2 + 1
    if include_ties:
        threshold = (len(by_scope) + 1) // 2
    base = {member for member, count in frequency.items() if count >= threshold}
    exceptions = {scope: {"add": sorted(members - base), "remove": sorted(base - members)}
                  for scope, members in sorted(by_scope.items()) if members != base}
    return sorted(base), exceptions


def summarize(properties):
    """Use the majority node set as the base for each prefix in the group.

    Membership is exact within the recorded relation. A missing member can also
    mean the property was never sampled. Preserve duplicate evidence references.
    """
    groups = defaultdict(list)
    for p in properties:
        key = (p.kind, json.dumps(p.scope, sort_keys=True), json.dumps(p.parameters, sort_keys=True))
        groups[key].append(p)
    result = []
    for (kind, scope, parameters), members in sorted(groups.items()):
        by_prefix = defaultdict(set)
        for p in members:
            by_prefix[p.prefix].add(p.node)
        base, exceptions = membership_pattern(by_prefix)
        params = json.loads(parameters)
        subject = {"reachability": "Reachability", "isolation": "Isolation",
                   "waypointing": f"Paths through {params.get('waypoint')}",
                   "load_balancing": f"Load balancing across exactly {params.get('numRoutes')} next-hop routers"}[kind]
        if base and not exceptions and len(base) <= 4:
            subject += " from " + ", ".join(sorted(base))
        destinations = sorted(by_prefix)
        target = destinations[0] if len(destinations) == 1 else f"{len(destinations)} destination prefixes"
        result.append({"intent": f"{subject} to {target}", "kind": kind, "scope": json.loads(scope),
                       "parameters": params,
                       "prefixes": sorted(by_prefix), "baseNodes": sorted(base),
                       "exceptions": exceptions, "evidence": [p.evidence for p in members]})
    return result


def probe_members(summaries, rows, limit=64):
    """Sample distinct source/prefix pairs round-robin across the reference summaries."""
    remaining = deque(iter(s["evidence"]) for s in summaries)
    selected = {}
    while remaining and len(selected) < limit:
        members = remaining.popleft()
        for ref in members:
            row = rows[int(ref.rsplit("/", 1)[1])]
            key = row["node"].lower(), str(IPv4Network(row["prefix"]))
            if key not in selected:
                selected[key] = {"node": key[0], "prefix": key[1]}
                remaining.append(members)
                break
    return list(selected.values())
