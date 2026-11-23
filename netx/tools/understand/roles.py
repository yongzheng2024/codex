"""Infer scoped device responsibilities from route, domain and packet observations."""

from collections import defaultdict

from .origins import origin_roles
from .responsibilities import summarize_device_roles
from .role_intents import IntentLinks
from .role_validation import RoleValidation, accepted_at_original_destination, acl_validation, validation


def role_hypotheses(facts, summaries, rows, *, intent_only=None):
    roles = []
    links = IntentLinks(summaries, rows, facts)
    if intent_only is None:
        intent_only = bool(summaries or rows)
    verify = RoleValidation(facts)

    links.record_endpoints(verify.deliveries)

    def add(role, node, scope, reason, refs, check, flows=(), anchors=(), waypoint_steps=None):
        eligible_flows = () if check["status"] == "inconsistent" else flows
        member_links = links.attach(role, node, eligible_flows, waypoint_steps, anchors)
        if intent_only and not member_links:
            return
        groups = sorted({link["summary"] for link in member_links})
        for group in groups:
            summary = summaries[int(group.rsplit("/", 1)[1])]
            summary["relatedRoles"].append(f"#/roleHypotheses/{len(roles)}")
        roles.append({"role": role, "node": node, "scope": scope, "interpretation": reason,
                      "evidence": refs, "configFiles": facts["files"].get(node, []),
                      "validation": check, "relatedSummaries": groups, "intentLinks": member_links})

    for origin in origin_roles(facts, verify):
        add(*origin)

    routes = defaultdict(list)
    for i, route in enumerate(facts["routes"]):
        attrs = route["attributes"]
        node, vrf, prefix = route["node"], route["vrf"], attrs["network"]
        ref = f"#/evidence/routes/{i}"
        routes[node, vrf, prefix].append((route, ref))
    for (node, vrf, prefix), entries in routes.items():
        bgp = [(r, ref) for r, ref in entries if r["bgpStatus"]]
        installed = [(r, ref) for r, ref in entries if r["inMainRib"] and r["inFib"]]
        other = [(r, ref) for r, ref in installed if not r["bgpStatus"]]
        rib_failure = any(r["bgpStatus"] == "BEST" and not r["inMainRib"]
                          and r["attributes"].get("originMechanism") == "LEARNED" for r, _ in bgp)
        if rib_failure and other:
            basis = "cross_protocol"
            reason = "Installs a non-BGP route while a learned BGP best route is outside the main RIB."
            choices = bgp + other
        elif len(bgp) > 1 and any(r["bgpStatus"] == "BEST" for r, _ in bgp):
            basis = "bgp_candidates"
            reason = "Selects among accepted BGP candidates."
            choices = bgp
        elif len({(r["nextHop"].get("interface"), r["nextHop"].get("ip"))
                  for r, _ in installed if r["nextHop"]["type"] in {"ip", "interface"}}) > 1:
            basis = "installed_multipath"
            reason = "Installs multiple next hops for the same prefix."
            choices = installed
        else:
            continue
        matches = [match for r, _ in choices for match in verify.forwarding_matches(r)]
        check = (validation("corroborated", "installed_route_in_packet_lookup", *(ref for _, ref in matches))
                 if matches else validation("observed", "routing_tables_only"))
        scope = {"vrf": vrf, "prefix": prefix, "basis": basis,
                 "installedNextHops": [r["nextHop"] for r, _ in installed]}
        hops = sorted({hop.get("ip") or hop.get("interface") or hop["type"] for hop in scope["installedNextHops"]})
        if hops:
            reason += " Installed next hops include " + ", ".join(hops) + "."
        add("Selection", node, scope, reason, [ref for _, ref in choices], check,
            flows=[i for i, _ in matches], anchors=[(node, vrf, prefix, "selection_at_member")])

    for i, event in enumerate(facts["events"]):
        if event["action"] == "rejected" and event["policy"] is None:
            continue  # Core BGP rejection has no policy attribution.
        scope = {k: event[k] for k in ("vrf", "prefix", "peer", "peerVrf", "peerIp", "direction", "policy", "action")}
        check, flows = verify.distribution(event)
        peer = event["peer"]
        anchors = []
        if event["action"] == "rejected":
            if event["direction"] == "export":
                receiver, vrf = peer, event["peerVrf"]
                reason = f"Filters BGP exports to {peer}."
            else:
                receiver, vrf = event["node"], event["vrf"]
                reason = f"Filters BGP imports from {peer}."
            anchors.append((receiver, vrf, event["prefix"], "member_route_filter"))
            policies = sorted({d["name"] for d in event.get("policyDefinitions", ())})
            if policies:
                reason += " Policy definitions include " + ", ".join(policies) + "."
        else:
            reason = f"Advertises BGP routes to {peer}."
            if check["status"] == "corroborated":
                anchors.append((peer, event["peerVrf"], event["prefix"], "member_received_route"))
        add("Distribution", event["node"], scope, reason, [f"#/evidence/events/{i}"], check, flows, anchors)

    populated = defaultdict(list)
    for i, domain in enumerate(facts["domains"]):
        if domain["interfaces"] or domain["configuredLeaks"]:
            populated[domain["node"]].append((i, domain["vrf"]))
    for node, domains in populated.items():
        if len(domains) > 1:
            vrfs = sorted(vrf for _, vrf in domains)
            check, flows = verify.isolation(node, vrfs)
            add("Isolation", node, {"vrfs": vrfs},
                "Maintains distinct routing contexts on this device.",
                [f"#/evidence/domains/{i}" for i, _ in domains], check, flows)

    for i, query in enumerate(facts["queries"]):
        if query["kind"] != "flows" or query["error"]:
            continue
        ref = f"#/evidence/queries/{i}"
        result = query["result"]
        for j, denial in enumerate(result["denials"]):
            scope = {k: denial[k] for k in ("iface", "direction", "filter", "ruleIndex", "rule", "packet", "pathIndex")}
            scope["flow"] = query["id"]
            add("Access control", denial["node"], scope, "Denies this packet at the interface filter.",
                [f"{ref}/result/denials/{j}"], acl_validation(denial, result["traces"], ref), flows=[i])
        for t, trace in enumerate(result["traces"]):
            trace_ref = f"{ref}/result/traces/{t}"
            accepted = accepted_at_original_destination(trace)
            for h, hop in enumerate(trace["hops"]):
                if h == 0 and not result["flow"].get("ingressInterface"):
                    continue  # A locally originated probe does not establish a transit responsibility here.
                forwarding_scope = {}
                for s, step in enumerate(hop["steps"]):
                    if step["type"] == "EnterInputInterface":
                        detail = step["detail"]
                        forwarding_scope["inputInterface"] = detail["inputInterface"]["interface"]
                        forwarding_scope["vrf"] = detail.get("inputVrf")
                    if step["type"] == "Routing":
                        forwarding_scope["vrf"] = step["detail"]["vrf"]
                    if step["action"] == "TRANSMITTED":
                        iface = step["detail"]["outputInterface"]["interface"]
                        scope = {**forwarding_scope, "flow": query["id"], "pathIndex": t, "interface": iface}
                        transformed = step["detail"].get("transformedFlow")
                        if transformed is None:
                            # The original destination is carried by each linked probe and reference prefix.
                            scope["packetClass"] = {k: v for k, v in result["flow"].items() if k != "dstIp"}
                        else:
                            scope["packet"] = transformed
                        node = hop["node"]["name"]
                        ptr = f"{trace_ref}/hops/{h}/steps/{s}"
                        check = verify.transit(node, iface, trace, h, trace_ref)
                        if "nextNode" in check:
                            scope["nextNode"] = check["nextNode"]
                        # Cornetto's prefix sink is reached by an accepting router.
                        waypoint_steps = None
                        if accepted and 0 < h < len(trace["hops"]) - 1:
                            waypoint_steps = {i: [ptr]}
                        add("Transit", node, scope, "Forwards the observed traffic through the output interface.",
                            [ptr], check, flows=[i],
                            waypoint_steps=waypoint_steps)
    summarize_device_roles(summaries, roles, rows)
    return roles
