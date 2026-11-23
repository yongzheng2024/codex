"""Cross-check scoped role observations against other facts from the same snapshot."""

from collections import Counter, defaultdict
from ipaddress import IPv4Interface
import json


SUCCESSFUL_DISPOSITIONS = {"ACCEPTED", "DELIVERED_TO_SUBNET", "EXITS_NETWORK"}


def preserves_destination(trace):
    """Check that no transformation rewrites the packet destination along this branch."""
    for hop in trace["hops"]:
        for step in hop["steps"]:
            if step["type"] == "Transformation" and any(d["fieldName"] == "dstIp" for d in step["detail"]["flowDiffs"]):
                return False
    return True


def accepted_at_original_destination(trace):
    return trace["disposition"] == "ACCEPTED" and preserves_destination(trace)


def validation(status, method, *refs):
    return {"status": status, "method": method, "evidence": list(refs)}


def forwarding_key(node, vrf, protocol, network, next_hop, admin, metric):
    return node, vrf, protocol, network, json.dumps(next_hop, sort_keys=True), admin, metric


def vrf_outcome(query):
    """Classify only complete VRF-origin probes with uniform delivery or a local lookup miss."""
    result = query["result"]
    flow = result["flow"]
    if not flow.get("ingressVrf") or flow.get("ingressInterface") or not query["behavior"]["pathsComplete"]:
        return None
    dispositions = set(query["behavior"]["dispositions"])
    if dispositions == {"ACCEPTED"}:
        return "delivered"
    if dispositions == {"NO_ROUTE"}:
        for trace in result["traces"]:
            if len(trace["hops"]) != 1 or trace["hops"][0]["node"]["name"] != flow["ingressNode"]:
                return None
            steps = trace["hops"][0]["steps"]
            if not any(s["type"] == "Routing" and s["action"] == "NO_ROUTE"
                       and s["detail"]["vrf"] == flow["ingressVrf"] for s in steps):
                return None
        return "noRoute"
    return None


class RoleValidation:
    """Index independent observables once, retaining pointers to their original records."""

    def __init__(self, facts):
        self.origin_flows = defaultdict(set)
        self.local_destinations = {}
        self.deliveries = defaultdict(list)
        self.received = defaultdict(list)
        self.sessions = defaultdict(list)
        self.sender_counts = Counter()
        self.fib_identities = Counter()
        self.forwarding = defaultdict(list)
        self.edges = {}
        self.vrf_pairs = defaultdict(list)

        for domain in facts["domains"]:
            for iface, addresses in domain.get("activeAddresses", {}).items():
                for address in addresses:
                    configured = IPv4Interface(address)
                    key = domain["node"], domain["vrf"], iface, str(configured.network)
                    self.local_destinations[domain["node"], iface, str(configured.ip)] = key
        for i, route in enumerate(facts["routes"]):
            attrs = route["attributes"]
            key = route["node"], route["vrf"], attrs["network"]
            ref = f"#/evidence/routes/{i}"
            if route["inMainRib"] and route["inFib"]:
                self.fib_identities[self._route_key(route)] += 1
            sender = attrs.get("receivedFrom", {}).get("ip")
            if sender and route["bgpStatus"] and attrs.get("originMechanism") == "LEARNED":
                self.received[(*key, sender)].append((route, ref))
        for i, session in enumerate(facts.get("bgpSessions", ())):
            key = tuple(session[k] for k in ("node", "vrf", "peer", "peerVrf", "peerIp"))
            self.sessions[key].append((session["localIp"], f"#/evidence/bgpSessions/{i}"))
            self.sender_counts[session["peer"], session["peerVrf"], session["localIp"]] += 1
        for i, edge in enumerate(facts["layer3Edges"]):
            key = tuple(edge[k] for k in ("node1", "node1interface", "node2", "node2interface"))
            self.edges[key] = f"#/evidence/layer3Edges/{i}"

        self._index_queries(facts["queries"])

    def _index_queries(self, queries):
        probes = defaultdict(lambda: defaultdict(dict))
        for i, query in enumerate(queries):
            if query["kind"] != "flows" or query["error"]:
                continue
            result = query["result"]
            ref = f"#/evidence/queries/{i}"
            for t, trace in enumerate(result["traces"]):
                accepted = accepted_at_original_destination(trace)
                for h, hop in enumerate(trace["hops"]):
                    for s, step in enumerate(hop["steps"]):
                        step_ref = f"{ref}/result/traces/{t}/hops/{h}/steps/{s}"
                        if (accepted and h == len(trace["hops"]) - 1
                                and step["type"] == "Inbound" and step["action"] == "ACCEPTED"):
                            dest = hop["node"]["name"], step["detail"]["interface"], result["flow"]["dstIp"]
                            if dest in self.local_destinations:
                                key = self.local_destinations[dest]
                                self.deliveries[key].append((i, step_ref))
                                self.origin_flows[key[0], key[1], key[3]].add(i)
                        if (step["type"] == "Routing" and step["action"] == "NULL_ROUTED"
                                and h == len(trace["hops"]) - 1 and preserves_destination(trace)):
                            for route in step["detail"]["routes"]:
                                self.origin_flows[hop["node"]["name"], step["detail"]["vrf"], route["network"]].add(i)
                        if step["type"] != "Routing" or step["action"] != "FORWARDED":
                            continue
                        detail = step["detail"]
                        for r, route in enumerate(detail["routes"]):
                            key = forwarding_key(hop["node"]["name"], detail["vrf"], route["protocol"],
                                                 route["network"], route["nextHop"], route["admin"], route["metric"])
                            ptr = f"{step_ref}/detail/routes/{r}"
                            self.forwarding[key].append((i, ptr))
            flow = result["flow"]
            outcome = vrf_outcome(query)
            if outcome is None:
                continue
            headers = json.dumps({k: v for k, v in flow.items() if k != "ingressVrf"}, sort_keys=True)
            probes[flow["ingressNode"], headers][outcome].setdefault(flow["ingressVrf"], i)
        for (node, _), outcomes in probes.items():
            for supplied, delivered in outcomes["delivered"].items():
                for missing, no_route in outcomes["noRoute"].items():
                    if supplied != missing:
                        self.vrf_pairs[node].append((supplied, missing, delivered, no_route))

    def distribution(self, event):
        if event["action"] == "sent":
            key = tuple(event[k] for k in ("node", "vrf", "peer", "peerVrf", "peerIp"))
            sessions = self.sessions[key]
            if len(sessions) == 1:
                sender, ref = sessions[0]
                routes = self.received[event["peer"], event["peerVrf"], event["prefix"], sender]
                if routes and self.sender_counts[event["peer"], event["peerVrf"], sender] == 1:
                    matches = [m for r, _ in routes if self.fib_identities[self._route_key(r)] == 1
                               for m in self.forwarding_matches(r)]
                    check = validation("corroborated", "peer_received_from_session", ref,
                                       *(p for _, p in routes), *(p for _, p in matches))
                    return check, [i for i, _ in matches]
        return validation("observed", "prefix_tracer_event_only"), []

    @staticmethod
    def _route_key(route):
        attrs = route["attributes"]
        return forwarding_key(route["node"], route["vrf"], route["protocol"], attrs["network"],
                              route["nextHop"], attrs["administrativeCost"], attrs.get("metric", 0))

    def forwarding_matches(self, route):
        return self.forwarding.get(self._route_key(route), ()) if route["inMainRib"] and route["inFib"] else ()

    def isolation(self, node, vrfs):
        # One paired observation is sufficient for an example. Name exactly the two tested VRFs.
        for supplied, missing, delivered, no_route in self.vrf_pairs[node]:
            if supplied in vrfs and missing in vrfs:
                result = validation("corroborated", "paired_vrf_packet",
                                    f"#/evidence/queries/{delivered}", f"#/evidence/queries/{no_route}")
                result.update(deliveryVrf=supplied, noRouteVrf=missing)
                return result, [delivered, no_route]
        return validation("configured", "populated_vrfs_only"), []

    def transit(self, node, iface, trace, h, trace_ref):
        if h + 1 < len(trace["hops"]):
            successor = trace["hops"][h + 1]
            for s, step in enumerate(successor["steps"]):
                if step["type"] == "EnterInputInterface" and step["action"] == "RECEIVED":
                    peer = step["detail"]["inputInterface"]
                    edge = self.edges.get((node, iface, peer["hostname"], peer["interface"]))
                    if edge and peer["hostname"] == successor["node"]["name"]:
                        check = validation("corroborated", "next_hop_received_on_link", edge,
                                           f"{trace_ref}/hops/{h + 1}/steps/{s}")
                        return {**check, "nextNode": peer["hostname"]}
        return validation("observed", "transmission_only")


def acl_validation(denial, traces, ref):
    """Join the ACL replay to the denying filter on the same packet path and interface."""
    t = denial["pathIndex"]
    trace = traces[t]
    for h, hop in enumerate(trace["hops"]):
        if hop["node"]["name"] != denial["node"]:
            continue
        output = None
        for s, step in enumerate(hop["steps"]):
            detail = step["detail"]
            if step["type"] == "Routing":
                output = detail.get("outputInterface")
            if step["type"] != "Filter" or step["action"] != "DENIED":
                continue
            iface = detail.get("inputInterface") if trace["disposition"] == "DENIED_IN" else output
            if (trace["disposition"] in {"DENIED_IN", "DENIED_OUT"} and iface == denial["iface"]
                    and detail["type"] == denial["direction"] and detail["filter"] == denial["filter"]
                    and detail["flow"] == denial["packet"]):
                return validation("corroborated", "filter_step_and_acl_replay",
                                  f"{ref}/result/traces/{t}/hops/{h}/steps/{s}")
    return validation("inconsistent", "acl_replay_unmatched")
