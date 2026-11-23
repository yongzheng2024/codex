"""Assign observations to the individual members of a forwarding-intent summary."""

from collections import defaultdict
from ipaddress import IPv4Address, IPv4Network

from .responsibilities import summarize_device_roles as summarize_device_roles


class IntentLinks:
    def __init__(self, summaries, rows, facts):
        self.summaries = summaries
        self.by_source_prefix = defaultdict(lambda: defaultdict(list))
        self.matches = defaultdict(list)
        self.vrfs = defaultdict(set)
        interfaces = {}
        for domain in facts["domains"]:
            node, vrf = domain["node"], domain["vrf"]
            self.vrfs[node].add(vrf)
            for iface in domain["interfaces"]:
                interfaces[node, iface] = vrf
        members = defaultdict(lambda: defaultdict(list))
        networks = {}
        for i, summary in enumerate(summaries):
            summary["relatedRoles"] = []
            summary["endpointObservations"] = []
            summary["packetObservations"] = []
            for prefix in summary["prefixes"]:
                if prefix not in networks:
                    networks[prefix] = IPv4Network(prefix)
            for ref in summary["evidence"]:
                row = rows[int(ref.rsplit("/", 1)[1])]
                source, prefix = row["node"].lower(), row["prefix"]
                if summary["kind"] == "waypointing" and source == row["waypoint"].lower():
                    continue
                self.by_source_prefix[source, str(networks[prefix])][i].append(ref)
                members[source][networks[prefix], i].append(ref)

        self.probes = defaultdict(list)
        for i, q in enumerate(facts["queries"]):
            if q["kind"] != "flows" or q["error"]:
                continue
            flow = q["result"]["flow"]
            node, dst = flow["ingressNode"].lower(), IPv4Address(flow["dstIp"])
            vrf = flow.get("ingressVrf") or interfaces.get((node, flow.get("ingressInterface")))
            for (prefix, group), refs in members[node].items():
                if dst in prefix:
                    self.matches[i].append((group, refs))
                    self.probes[node, vrf, str(prefix), group].append(i)
                    summaries[group]["packetObservations"].append({
                        "flow": f"#/evidence/queries/{i}", "rows": refs,
                        "dispositions": q["behavior"]["dispositions"],
                    })

    def record_endpoints(self, deliveries):
        for (node, _, _, _), observations in deliveries.items():
            for flow, step in observations:
                for group, refs in self.matches[flow]:
                    summary = self.summaries[group]
                    if (summary["kind"] == "waypointing"
                            and summary["parameters"]["waypoint"].lower() == node):
                        summary["endpointObservations"].append({
                            "node": node, "rows": refs, "flow": f"#/evidence/queries/{flow}", "step": step,
                        })

    def attach(self, role, node, flows, waypoint_steps, anchors):
        """Join packet evidence and protocol evidence using their respective scopes."""
        links = []
        for flow in sorted(set(flows)):
            for group, rows in self.matches[flow]:
                summary = self.summaries[group]
                kind = summary["kind"]
                basis = "packet_scope"
                steps = {}
                if kind == "waypointing":
                    if (not waypoint_steps or flow not in waypoint_steps
                            or summary["parameters"]["waypoint"].lower() != node):
                        continue
                    basis = "observed_waypoint"
                    steps = {"steps": waypoint_steps[flow]}
                elif kind == "load_balancing":
                    # The predicate counts outgoing next-hop routers at its source.
                    # Source selection and the peers supplying its routes use exact-prefix joins below.
                    continue
                elif kind == "isolation" and role not in {"Access control", "Isolation"}:
                    continue
                links.append(self._link(group, rows, basis, flow=f"#/evidence/queries/{flow}", **steps))

        for source, vrf, prefix, basis in sorted(set(anchors)):
            for group, rows in self.by_source_prefix.get((source, prefix), {}).items():
                kind = self.summaries[group]["kind"]
                if kind == "waypointing" or (kind == "isolation" and basis != "member_route_filter"):
                    continue
                if kind == "load_balancing" and basis == "member_route_filter":
                    continue
                probes = self.probes[source, vrf, prefix, group]
                if self.vrfs[source] != {vrf} and not probes:
                    continue  # The CSV has no VRF. Disambiguate with a scoped probe.
                links.append(self._link(group, rows, basis, source=source, vrf=vrf,
                                        probes=[f"#/evidence/queries/{i}" for i in probes]))
        return links

    def _link(self, group, rows, basis, **evidence):
        scope = self.summaries[group]["scope"]
        return {"summary": f"#/summaries/{group}", "expectedPresence": scope["expectedPresence"],
                "faultyPresence": scope["faultyPresence"], "basis": basis, "rows": rows, **evidence}
