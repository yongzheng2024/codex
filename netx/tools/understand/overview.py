"""Render the reference summaries and attributed responsibilities for a compact run."""

from collections import defaultdict

from .details import resolve
from .responsibilities import originated_prefixes


def _examples(values, limit=4):
    preview = ", ".join(f"`{v}`" for v in values[:limit])
    return preview if len(values) <= limit else f"{preview} and {len(values) - limit} more"


def _scope_text(conditions):
    labels = {"vrf": "VRF", "peer": "peer", "peerVrf": "peer VRF", "peerIp": "peer IP", "policy": "policy",
              "iface": "interface", "inputInterface": "ingress", "interface": "egress", "nextNode": "next router",
              "filter": "filter", "rule": "rule",
              "flow": "probe", "direction": "direction", "peers": "peers", "vrfs": "VRFs"}
    parts = []
    for key, label in labels.items():
        if key in conditions:
            value = conditions[key]
            display = _examples(value) if isinstance(value, list) else f"`{value}`"
            parts.append(f"{label} {display}" if value is not None else f"{label} unreported")
    packet = conditions.get("packetClass") or conditions.get("packet")
    if packet:
        parts.extend(f"{label} `{packet[key]}`" for key, label in
                     (("ipProtocol", "protocol"), ("srcIp", "source"), ("dstIp", "destination"),
                      ("srcPort", "source port"), ("dstPort", "destination port")) if packet.get(key) is not None)
    return ", ".join(parts)


def _group_item(group, report):
    members = group["members"]
    nodes = sorted({m["node"] for m in members})
    facts = [f"- {_examples(nodes, len(nodes))} — {group['description']}"]
    if scope := _scope_text(group["conditions"]):
        facts.append(f"{scope}.")
    if group["basePrefixes"] and group["role"] != "Origin":
        label = "Base reference prefixes" if group["prefixExceptions"] else "Reference prefixes"
        facts.append(f"{label} include {_examples(group['basePrefixes'])}.")
    counts = group["validationCounts"]
    statuses = ", ".join(f"{count} {status}" for status, count in sorted(counts.items()))
    row_label = "row" if group["memberCount"] == 1 else "rows"
    assignment_label = "assignment" if sum(counts.values()) == 1 else "assignments"
    facts.append(f"{group['memberCount']} {row_label} ({statuses} {assignment_label}).")
    lines = [" ".join(facts)]
    for m in members:
        details = [_scope_text(m["localConditions"])]
        if group["role"] == "Origin":
            contribution = resolve(report, m["contribution"])
            published = originated_prefixes(report, contribution)
            details.append(f"originated prefixes {_examples(published)}")
            if published != contribution["prefixes"]:
                details.append(f"linked reference prefixes {_examples(contribution['prefixes'])}")
        else:
            delta = group["prefixExceptions"].get(m["contribution"], {})
            for operation, label in (("add", "additional prefixes"), ("remove", "excluded prefixes")):
                if delta.get(operation):
                    details.append(f"{label} {_examples(delta[operation])}")
        if any(details):
            lines.append(f"  - `{m['node']}` — " + ", ".join(filter(None, details)) + ".")
    return lines


def _group_lines(groups, report):
    by_role = defaultdict(list)
    for group in groups:
        by_role[group["role"]].append(group)
    lines = []
    for role in ("Origin", "Distribution", "Selection", "Transit", "Isolation", "Access control"):
        if role not in by_role:
            continue
        lines.extend(["", f"**{role}**", ""])
        for group in by_role[role]:
            lines.extend(_group_item(group, report))
    return lines


def _device_lines(summary, report):
    if "responsibilityGroups" in summary:
        lines = _group_lines(summary["responsibilityGroups"], report)
        peer_groups = [g for device in summary["deviceRoles"] for g in device["actionGroups"]
                       if len({m["localConditions"].get("peer") for m in g["members"]}) > 1]
        if peer_groups:
            lines.extend(["", "**Actions across peers on one device**", ""])
            for group in peer_groups:
                lines.extend(_group_item(group, report))
        return lines
    # Reports saved before structured responsibility grouping retain their device view.
    by_role = defaultdict(list)
    for device in summary["deviceRoles"]:
        by_role[device["role"]].append(device)
    lines = []
    for role in ("Origin", "Distribution", "Selection", "Transit", "Isolation", "Access control"):
        devices = by_role[role]
        if not devices:
            continue
        lines.extend(["", f"**{role}**", ""])
        for device in devices:
            for c in device["contributions"]:
                lines.append(f"- `{device['node']}` for {_examples(c['prefixes'])} — {c['description']}")
    return lines


def _role_highlight(summary, report, outcomes):
    """Select an illustrative linked action, keeping each device's own prefix scope."""
    kind = summary["kind"]
    focus = {"load_balancing": "Selection", "waypointing": "Transit", "isolation": "Isolation",
             "reachability": "Origin"}.get(kind)

    def order(candidate):
        device, part = candidate
        filtering = kind in {"reachability", "isolation"} and part.get("action") in {"reject", "deny_packet"}
        return (not filtering, device["role"] != focus, -part["memberCount"], device["node"], device["role"])

    candidates = sorted(((d, c) for d in summary["deviceRoles"] for c in d["contributions"]), key=order)
    if not candidates:
        if summary["endpointObservations"]:
            observation = f"The named waypoint `{summary['parameters']['waypoint']}` accepted a probed packet."
        elif outcomes:
            observation = f"Probes returned {_examples(outcomes, 2)}."
        else:
            observation = "No device action or packet observation is linked to these rows."
        return "None attributed", observation

    names = _examples(list(dict.fromkeys(d["node"] for d, _ in candidates)), 4)
    device, part = candidates[0]
    node, role = device["node"], device["role"]
    scope = part.get("conditions", {})
    if kind == "load_balancing" and role == "Selection":
        choices = []
        for other, contribution in candidates:
            conditions = contribution.get("conditions", {})
            if other is not device or conditions.get("vrf") != scope.get("vrf"):
                continue
            hops = conditions.get("installedNextHops", [])
            if not hops or any(h["type"] not in {"ip", "interface"} for h in hops):
                continue
            count = len({(h.get("interface"), h.get("ip")) for h in hops})
            label = "next hop" if count == 1 else "next hops"
            choices.append(f"{count} {label} for {_examples(contribution['prefixes'], 2)}")
            if len(choices) == 2:
                break
        if choices:
            return names, f"`{node}` installed " + " and ".join(choices) + "."
    if part.get("action") == "reject" and scope.get("direction") in {"import", "export"}:
        direction = "imports from" if scope["direction"] == "import" else "exports to"
        return names, f"`{node}` filtered BGP {direction} `{scope['peer']}` for {_examples(part['prefixes'], 2)}."
    if role == "Origin" and "intentLinks" in part:
        publishers = {}
        for other, contribution in candidates:
            conditions = contribution.get("conditions", {})
            if (other["role"] == role and other["node"] not in publishers
                    and (conditions.get("vrf"), conditions.get("protocol")) == (scope.get("vrf"), scope["protocol"])):
                prefixes = originated_prefixes(report, contribution)
                publishers[other["node"]] = f"`{other['node']}` ({_examples(prefixes, 2)})"
                if len(publishers) == 2:
                    break
        protocol = {"bgp": "BGP", "ospf": "OSPF", "isis": "IS-IS"}[scope["protocol"]]
        return names, f"Observed {protocol} origins include " + " and ".join(publishers.values()) + "."
    if role == "Access control" and scope.get("filter"):
        return names, f"`{node}` denied a probed packet at `{scope['filter']}` on `{scope['iface']}`."
    if role == "Transit" and scope.get("interface"):
        return names, f"`{node}` forwarded a probed packet through `{scope['interface']}`."
    return names, f"`{node}` — {part['description']} Linked reference prefixes include {_examples(part['prefixes'], 2)}."


def overview(report):
    summaries = report["summaries"]
    lines = ["# Intent Summary", "",
             f"{len(report['benchmark']['rows'])} reference rows form {len(summaries)} intent summaries.",
             "", "[Device Roles](#device-roles) · [Full evidence and row references](result.json)"]
    # Use the summary position because different reference labels can yield identical intent titles.
    for number, s in enumerate(summaries, start=1):
        scope = s["scope"]
        lines.extend(["", f'<a id="intent-{number}"></a>', "", f"## {s['intent']}", "",
                      f"Reference label `{scope['sources']}`. The reference records the expected predicate as "
                      f"{scope['expectedPresence']} and its fault-injected state as {scope['faultyPresence']}.",
                      "", f"Destinations include {_examples(s['prefixes'])}."])
        if s["exceptions"]:
            if s["baseNodes"]:
                lines.append(f"The base source set includes {_examples(s['baseNodes'])}.")
            lines.append(f"{len(s['exceptions'])} prefixes carry source membership exceptions.")
        lines.extend(["", f"[Device roles for this intent](#roles-{number})"])

    lines.extend(["", "# Device Roles", "",
                  f"Roles describe the `{report['input']['configurationState']}` snapshot. "
                  "Coverage counts reference rows with scoped device evidence."])
    for number, s in enumerate(summaries, start=1):
        outcomes = sorted({d for observation in s["packetObservations"] for d in observation["dispositions"]})
        devices, observation = _role_highlight(s, report, outcomes)
        lines.extend(["", f'<a id="roles-{number}"></a>', "", f"## {s['intent']}", "",
                      f"**Key devices** {devices}  ", f"**Observation** {observation}", "",
                      f"[Reference intent](#intent-{number}) · `{s['scope']['sources']}` · "
                      f"Device evidence covers {s['attributedRows']} of {len(s['evidence'])} reference rows.", "",
                      "<details><summary>Role details and evidence</summary>"])
        lines.extend(_device_lines(s, report))
        missing = s["unattributedRows"]
        if missing:
            rows = [report["benchmark"]["rows"][int(ref.rsplit("/", 1)[1])] for ref in missing[:4]]
            examples = [f"{row['node']} → {row['prefix']} (line {row['line']})" for row in rows]
            lines.extend(["", f"{len(missing)} rows await device evidence. Examples include {_examples(examples)}."])
        if outcomes:
            lines.extend(["", f"Observed packet outcomes include {_examples(outcomes)}."])
        if s["endpointObservations"]:
            lines.extend(["", f"The named waypoint accepted the destination on {len(s['endpointObservations'])} observed branches."])
        lines.extend(["", "</details>"])
    return "\n".join(lines) + "\n"
