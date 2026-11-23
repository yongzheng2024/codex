"""Two views of the same intent-linked device actions in a single snapshot."""

from collections import Counter, defaultdict
import json

from .details import resolve
from .summaries import membership_pattern


_ACTIONS = {"Origin": "originate", "Selection": "select", "Transit": "forward",
            "Isolation": "separate_vrfs", "Access control": "deny_packet"}


def originated_prefixes(report, contribution):
    """Read advertised networks from the assignments, including covering routes for more specific intents."""
    assignments = {link.rsplit("/intentLinks/", 1)[0] for link in contribution["intentLinks"]}
    return sorted({resolve(report, ptr)["scope"]["prefix"] for ptr in assignments})


def _conditions(record):
    scope = record["scope"]
    # The assignment retains its exact route prefix and trace branch. Packet and
    # interface identities must still agree to group concrete forwarding actions.
    conditions = {k: v for k, v in scope.items() if k not in {"prefix", "pathIndex", "action"}}
    if "packetClass" in conditions or (record["role"] == "Access control" and "packet" in conditions):
        conditions.pop("flow", None)
    if record["role"] == "Distribution":
        action = "reject" if scope.get("action") == "rejected" else "advertise"
        if "peer" in scope:
            conditions["protocol"] = "bgp"
    else:
        action = _ACTIONS[record["role"]]
    for key in ("installedNextHops", "peers", "vrfs"):
        if key in conditions:
            conditions[key] = sorted(conditions[key], key=_key)
    return action, conditions


def _key(value):
    return json.dumps(value, sort_keys=True)


def _group_contributions(contexts, *, across_devices):
    """Factor peer-specific scopes on one device, or compare devices targeting the same peer."""
    groups = defaultdict(list)
    for node, ptr, contribution, rows in contexts:
        role, action, conditions = contribution["role"], contribution["action"], contribution["conditions"]
        common = dict(conditions)
        if role == "Distribution" and conditions.get("protocol") == "bgp":
            # Local policy names and addresses can differ for the same action toward
            # the same peer. Keep them on the member and retain both VRF scopes.
            common.pop("policy", None)
            common.pop("peerIp", None)
            if not across_devices:
                common.pop("peer", None)
        # Interface names alone cannot identify a shared forwarding boundary across routers.
        local_node = node if role == "Transit" and "nextNode" not in common else ""
        groups[role, action, _key(common), local_node].append((node, ptr, contribution, rows))

    result = []
    for (role, action, _, _), entries in sorted(groups.items()):
        first = entries[0][2]
        conditions = {k: v for k, v in first["conditions"].items()
                      if all(k in c["conditions"] and c["conditions"][k] == v for _, _, c, _ in entries)}
        description = first["description"]
        if len(entries) > 1 and conditions.get("protocol") == "bgp":
            peer = conditions.get("peer", "the listed peers")
            if action == "reject":
                description = (f"Filters BGP exports to {peer}." if conditions["direction"] == "export"
                               else f"Filters BGP imports from {peer}.")
            elif action == "advertise":
                description = f"Advertises BGP routes to {peer}."
        base, exceptions = membership_pattern({ptr: set(c["prefixes"]) for _, ptr, c, _ in entries},
                                              include_ties=True)
        members = []
        covered = set()
        statuses = Counter()
        for node, ptr, c, rows in entries:
            covered.update(rows)
            statuses.update(c["validationCounts"])
            members.append({"node": node, "contribution": ptr,
                            "localConditions": {k: v for k, v in c["conditions"].items() if k not in conditions}})
        result.append({"role": role, "action": action, "description": description, "conditions": conditions,
                       "basePrefixes": base, "prefixExceptions": exceptions, "members": members,
                       "memberCount": len(covered), "validationCounts": dict(statuses)})
    return result


def summarize_device_roles(summaries, roles, rows):
    """Partition actual intent links, preserving multiple links or duplicate rows for one assignment."""
    by_summary = [defaultdict(lambda: defaultdict(list)) for _ in summaries]
    for i, record in enumerate(roles):
        if not record["intentLinks"]:
            continue
        action, conditions = _conditions(record)
        context = action, _key(conditions)
        for j, link in enumerate(record["intentLinks"]):
            group = int(link["summary"].rsplit("/", 1)[1])
            by_summary[group][record["node"], record["role"]][context].append((i, j))

    prefix_for = {f"#/benchmark/rows/{i}": row["prefix"] for i, row in enumerate(rows)}
    for group, (summary, devices) in enumerate(zip(summaries, by_summary)):
        covered = set()
        device_roles = []
        contexts = []
        for (node, role), actions in sorted(devices.items()):
            base_ptr = f"#/summaries/{group}/deviceRoles/{len(device_roles)}"
            contributions = []
            member_rows = set()
            records = set()
            device_contexts = []
            for (action, encoded_conditions), links in sorted(actions.items()):
                refs = {ref for i, j in links for ref in roles[i]["intentLinks"][j]["rows"]}
                indices = sorted({i for i, _ in links})
                ptr = f"{base_ptr}/contributions/{len(contributions)}"
                contribution = {
                    "role": role, "action": action, "conditions": json.loads(encoded_conditions),
                    "description": roles[indices[0]]["interpretation"],
                    "memberCount": len(refs), "prefixes": sorted({prefix_for[ref] for ref in refs}),
                    "intentLinks": [f"#/roleHypotheses/{i}/intentLinks/{j}" for i, j in links],
                    "validationCounts": dict(Counter(roles[i]["validation"]["status"] for i in indices)),
                }
                contributions.append(contribution)
                device_contexts.append((node, ptr, contribution, refs))
                member_rows.update(refs)
                records.update(indices)
            device_roles.append({
                "node": node, "role": role, "prefixes": sorted({prefix_for[ref] for ref in member_rows}),
                "memberCount": len(member_rows), "actionGroups": _group_contributions(device_contexts, across_devices=False),
                "contributions": contributions, "assignments": [f"#/roleHypotheses/{i}" for i in sorted(records)],
            })
            contexts.extend(device_contexts)
            covered.update(member_rows)
        summary["deviceRoles"] = device_roles
        summary["responsibilityGroups"] = _group_contributions(contexts, across_devices=True)
        summary["attributedRows"] = len(covered)
        summary["unattributedRows"] = [ref for ref in summary["evidence"] if ref not in covered]
