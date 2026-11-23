"""Identify the device that introduced an advertised prefix into a modeled protocol domain."""

from collections import defaultdict

from .role_validation import validation


def origin_roles(facts, verify):
    local_protocols = {"connected", "local", "static", "aggregate", "kernel"}
    source_routes = defaultdict(lambda: defaultdict(list))
    candidates = defaultdict(lambda: defaultdict(set))
    candidate_refs = defaultdict(list)
    for i, route in enumerate(facts["routes"]):
        attrs = route["attributes"]
        key = route["node"], route["vrf"], attrs["network"]
        if route["inMainRib"]:
            source_routes[key][route["protocol"]].append(f"#/evidence/routes/{i}")
        if (route["bgpStatus"] and attrs.get("receivedFrom", {}).get("class", "").endswith(".ReceivedFromSelf")):
            candidates[key][attrs["originMechanism"]].add(attrs["srcProtocol"])
            candidate_refs[key, attrs["originMechanism"]].append(f"#/evidence/routes/{i}")

    exports = defaultdict(list)
    for i, event in enumerate(facts.get("originExports", ())):
        key = event["node"], event["vrf"], event["prefix"]
        protocol = event["sourceProtocol"]
        # A BGP-to-BGP export transformation can overwrite the original source protocol.
        protocols = (candidates[key][event["mechanism"]] if protocol in {"bgp", "ibgp"} else {protocol})
        # FRR's independent network policy can seed a local kernel candidate outside the main RIB.
        network_seed = event["mechanism"] == "NETWORK" and protocols == {"kernel"}
        if network_seed or event["mechanism"] == "GENERATED" or (
                protocols and protocols <= local_protocols and protocols <= source_routes[key].keys()):
            exports[key].append((event, f"#/evidence/originExports/{i}"))
    for (node, vrf, prefix), entries in sorted(exports.items()):
        peers = set()
        checks = set()
        anchors = []
        for event, _ in entries:
            peers.add(event["peer"])
            checks.update(candidate_refs[(node, vrf, prefix), event["mechanism"]])
            check, _ = verify.distribution({**event, "action": "sent"})
            if check["status"] == "corroborated":
                checks.update(check["evidence"])
                anchors.append((event["peer"], event["peerVrf"], prefix, "origin_advertised_to_member"))
        for protocol in local_protocols:
            checks.update(source_routes[node, vrf, prefix].get(protocol, ()))
        check = (validation("corroborated", "origin_export_cross_check", *sorted(checks))
                 if checks else validation("observed", "local_bgp_advertisement"))
        scope = {"vrf": vrf, "prefix": prefix, "protocol": "bgp", "peers": sorted(peers)}
        yield ("Origin", node, scope, "Originates the prefix into BGP.", [ref for _, ref in entries],
               check, verify.origin_flows[node, vrf, prefix], anchors)

    # External OSPF routes retain the ASBR hostname. IS-IS routes retain the originating NET system ID.
    # An internal OSPF route has no advertiser identity in the exported route record.
    domains = defaultdict(list)
    for i, domain in enumerate(facts["domains"]):
        if domain.get("runsOspf"):
            domains["ospf", domain["node"]].append((domain, i))
        if domain.get("isisSystemId"):
            domains["isis", domain["isisSystemId"]].append((domain, i))
    advertisements = defaultdict(list)
    for i, route in enumerate(facts["routes"]):
        attrs = route["attributes"]
        if route["protocol"] in {"ospfE1", "ospfE2"}:
            protocol, identity = "ospf", attrs["advertiser"]
        elif route["protocol"] in {"isisL1", "isisL2", "isisEL1", "isisEL2"}:
            protocol, identity = "isis", attrs["systemId"]
        else:
            continue
        owners = domains[protocol, identity]
        if len(owners) != 1 or not route["inMainRib"]:
            continue
        domain, d = owners[0]
        if route["node"] == domain["node"]:
            continue
        advertisements[domain["node"], domain["vrf"], attrs["network"], protocol, d].append((route, i))
    for (node, vrf, prefix, protocol, d), entries in sorted(advertisements.items()):
        scope = {"vrf": vrf, "prefix": prefix, "protocol": protocol}
        sources = source_routes[node, vrf, prefix]
        local = [ref for p in local_protocols for ref in sources.get(p, ())]
        attached_default = protocol == "isis" and all(r["attributes"].get("attach") for r, _ in entries)
        originates = (bool(local) and sources.keys() <= local_protocols) or attached_default
        reason = ("Originates an external OSPF advertisement." if protocol == "ospf"
                  else "Originates the prefix into IS-IS.")
        if not originates:
            reason = "Distributes an external OSPF advertisement." if protocol == "ospf" else "Advertises an IS-IS route."
        basis = "member_learned_origin" if originates else "member_received_route"
        anchors = [(r["node"], r["vrf"], prefix, basis) for r, _ in entries]
        matches = [i for r, _ in entries for i, _ in verify.forwarding_matches(r)]
        yield ("Origin" if originates else "Distribution", node, scope, reason,
               [f"#/evidence/routes/{i}" for _, i in entries],
               validation("corroborated", "advertiser_identity_in_remote_route", f"#/evidence/domains/{d}", *sorted(local)),
               matches, anchors)
