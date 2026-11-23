"""Bound the overview while preserving pointers into the corresponding full report."""

from collections import Counter, defaultdict

from .details import resolve
from .responsibilities import originated_prefixes


def _group_examples(report, groups, pointer, limit):
    examples = []
    for j, group in enumerate(groups[:limit]):
        scopes = []
        for member in group["members"][:4]:
            scope = dict(member)
            delta = group["prefixExceptions"].get(member["contribution"], {})
            for operation, field in (("add", "addedPrefixExamples"), ("remove", "removedPrefixExamples")):
                if delta.get(operation):
                    scope[field] = delta[operation][:3]
            if group["role"] == "Origin":
                contribution = resolve(report, member["contribution"])
                scope["originatedPrefixExamples"] = originated_prefixes(report, contribution)[:3]
            scopes.append(scope)
        examples.append({
            "role": group["role"], "action": group["action"], "description": group["description"],
            "conditionExamples": {k: v[:3] if isinstance(v, list) else v for k, v in group["conditions"].items()
                                  if k not in {"packet", "packetClass"}},
            "memberCount": group["memberCount"], "validationCounts": group["validationCounts"],
            "basePrefixExamples": group["basePrefixes"][:3], "exceptionCount": len(group["prefixExceptions"]),
            "scopeCount": len(group["members"]), "scopeExamples": scopes, "details": f"{pointer}/{j}",
        })
    return examples


def compact(report, result_path):
    evidence = report["evidence"]
    roles = {}
    statuses = {name: dict.fromkeys(("corroborated", "observed", "configured", "inconsistent"), 0)
                for name in ("Origin", "Distribution", "Selection", "Transit", "Isolation", "Access control")}
    for i, role in enumerate(report["roleHypotheses"]):
        name, status = role["role"], role["validation"]["status"]
        statuses[name][status] += 1
        if name not in roles or (status == "corroborated" and roles[name]["validation"] != status):
            roles[name] = {"node": role["node"], "scope": role["scope"], "validation": status,
                           "method": role["validation"]["method"], "details": f"#/roleHypotheses/{i}"}
    summaries = []
    for i, s in enumerate(report["summaries"][:12]):
        by_node = defaultdict(list)
        for j, device in enumerate(s["deviceRoles"]):
            by_node[device["node"]].append({
                "role": device["role"], "memberCount": device["memberCount"],
                "contributions": [{"description": c["description"], "memberCount": c["memberCount"],
                                   "prefixExamples": c["prefixes"][:3],
                                   "details": f"#/summaries/{i}/deviceRoles/{j}/contributions/{k}"}
                                  for k, c in enumerate(device["contributions"][:3])],
                **({"actionGroupCount": len(device["actionGroups"]),
                    "actionGroupDetails": f"#/summaries/{i}/deviceRoles/{j}/actionGroups"}
                   if "actionGroups" in device else {}),
                "prefixExamples": device["prefixes"][:3],
                "details": f"#/summaries/{i}/deviceRoles/{j}",
            })
        devices = [{"node": node, "roles": roles_at_node} for node, roles_at_node in list(by_node.items())[:12]]
        groups = s.get("responsibilityGroups", [])
        summaries.append({
            "intent": s["intent"], "kind": s["kind"], "parameters": s["parameters"], "scope": s["scope"],
            "properties": len(s["evidence"]), "prefixCount": len(s["prefixes"]),
            "prefixExamples": s["prefixes"][:3], "baseNodeExamples": s["baseNodes"][:3],
            "exceptionPrefixCount": len(s["exceptions"]), "relatedRoleCount": len(s["relatedRoles"]),
            "attributedRows": s["attributedRows"], "unattributedRows": len(s["unattributedRows"]),
            "deviceCount": len(by_node), "devices": devices,
            **({"responsibilityGroupCount": len(groups), "responsibilityGroups":
                _group_examples(report, groups, f"#/summaries/{i}/responsibilityGroups", 12)}
                if "responsibilityGroups" in s else {}),
            "packetDispositions": sorted({d for o in s["packetObservations"] for d in o["dispositions"]}),
            "endpointObservationCount": len(s["endpointObservations"]), "details": f"#/summaries/{i}",
        })
    return {
        "status": report["status"], "scenario": report["scenario"], "batfishVersion": evidence["batfishVersion"],
        "input": {k: report["input"][k] for k in ("snapshot", "scenario", "configurationState")},
        "simulation": report["simulation"],
        "benchmark": {k: v for k, v in report["benchmark"].items() if k != "rows"},
        "result_id": result_path.parent.name, "details": str(result_path),
        "gapCount": len(report["gaps"]), "gaps": report["gaps"][:8],
        "intentRows": len(report["benchmark"]["rows"]),
        "summaryCount": len(report["summaries"]), "summaries": summaries,
        **({"roleExamples": roles} if report["benchmark"]["file"] is None else {}),
        "roleValidationCounts": statuses,
        "bgpCandidates": dict(Counter(r["bgpStatus"] for r in evidence["routes"] if r["bgpStatus"])),
        "routingEvents": dict(Counter(e.get("cause", e["action"]) for e in evidence["events"])),
    }
