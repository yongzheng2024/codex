"""Exact reconstruction of device responsibilities and their intent evidence."""

from collections import Counter
import unittest

from netx.tools.understand.compact import _group_examples
from netx.tools.understand.details import resolve
from netx.tools.understand.overview import _group_item
from netx.tools.understand.responsibilities import summarize_device_roles


class ResponsibilityTests(unittest.TestCase):
    def setUp(self):
        self.prefixes = [f"192.0.{i}.0/24" for i in range(3)]
        self.rows = [{"node": node, "prefix": self.prefixes[p]} for node, p in
                     [("a", 0), ("a", 1), ("a", 2), ("a", 0), ("b", 0), ("b", 1), ("c", 2), ("a", 0)]]
        self.summaries = [{"scope": {"expectedPresence": value}, "evidence": [self.row(i) for i in indices]}
                          for value, indices in [("present", range(7)), ("absent", [7])]]
        self.roles = []
        self.report = {"summaries": self.summaries, "roleHypotheses": self.roles, "benchmark": {"rows": self.rows}}

    @staticmethod
    def row(i):
        return f"#/benchmark/rows/{i}"

    def add(self, node, role, scope, *indices, status="observed"):
        self.roles.append({"node": node, "role": role, "scope": scope, "interpretation": "Observed action.",
                           "evidence": [f"observation-{len(self.roles)}"], "configurationState": "fault_injected",
                           "validation": {"status": status}, "intentLinks": [
                               {"summary": "#/summaries/0", "expectedPresence": "present",
                                "rows": [self.row(i) for i in indices]}]})

    def bgp(self, node, peer, prefix, indices, status="observed", **changes):
        scope = dict(prefix=self.prefixes[prefix], vrf="default", peerVrf="default", peer=peer, peerIp=node + "-ip",
                     direction="export", action="sent", policy=node + "-" + peer)
        self.add(node, "Distribution", {**scope, **changes}, *indices, status=status)

    def assert_round_trip(self, summary_index, groups):
        expected = Counter(f"#/roleHypotheses/{i}/intentLinks/{j}"
                           for i, r in enumerate(self.roles) for j, link in enumerate(r["intentLinks"])
                           if link["summary"] == f"#/summaries/{summary_index}")
        actual = Counter()
        for group in groups:
            records, rows = set(), set()
            for m in group["members"]:
                part = resolve(self.report, m["contribution"])
                self.assertEqual({**group["conditions"], **m["localConditions"]}, part["conditions"])
                delta = group["prefixExceptions"].get(m["contribution"], {"add": [], "remove": []})
                prefixes = set(group["basePrefixes"]).difference(delta["remove"]).union(delta["add"])
                part_rows = set()
                for ref in part["intentLinks"]:
                    link = resolve(self.report, ref)
                    assignment = ref.rsplit("/intentLinks/", 1)[0]
                    record = resolve(self.report, assignment)
                    self.assertEqual(link["expectedPresence"], self.summaries[summary_index]["scope"]["expectedPresence"])
                    self.assertEqual((record["node"], record["role"]), (m["node"], group["role"]))
                    self.assertTrue(record["evidence"])
                    self.assertEqual(record["configurationState"], "fault_injected")
                    part_rows.update(link["rows"])
                    records.add(assignment)
                self.assertEqual(prefixes, {resolve(self.report, ref)["prefix"] for ref in part_rows})
                self.assertEqual(len(part_rows), part["memberCount"])
                actual.update(part["intentLinks"])
                rows.update(part_rows)
            self.assertEqual(group["memberCount"], len(rows))
            self.assertEqual(group["validationCounts"], Counter(resolve(self.report, ref)["validation"]["status"]
                                                               for ref in records))
        self.assertEqual(actual, expected)

    def test_peer_exceptions_validation_and_both_views_expand_to_the_original_links(self):
        self.bgp("r2", "a", 0, [0, 3], "corroborated")
        # The same assignment has two observations for one summary and a link into a second summary.
        self.roles[0]["intentLinks"].extend([
            {"summary": "#/summaries/0", "rows": [self.row(0)], "expectedPresence": "present", "basis": "packet_scope"},
            {"summary": "#/summaries/1", "rows": [self.row(7)], "expectedPresence": "absent"}])
        for node, peer, p, indices in [("r2", "a", 1, [1]), ("r2", "a", 2, [2]),
                                      ("r2", "b", 0, [4]), ("r2", "b", 1, [5]),
                                      ("r3", "a", 0, [0, 3]), ("r3", "a", 1, [1])]:
            self.bgp(node, peer, p, indices)
        summarize_device_roles(self.summaries, self.roles, self.rows)
        for i, s in enumerate(self.summaries):
            self.assert_round_trip(i, s["responsibilityGroups"])
            self.assert_round_trip(i, [g for d in s["deviceRoles"] for g in d["actionGroups"]])
        summary = self.summaries[0]
        self.assertEqual(summary["unattributedRows"], [self.row(6)])
        shared, = [g for g in summary["responsibilityGroups"] if g["conditions"].get("peer") == "a"]
        self.assertEqual(shared["memberCount"], 4)
        self.assertEqual(shared["validationCounts"], {"corroborated": 1, "observed": 4})
        r3, = [m for m in shared["members"] if m["node"] == "r3"]
        self.assertEqual(r3["localConditions"]["policy"], "r3-a")
        self.assertEqual(shared["prefixExceptions"][r3["contribution"]], {"add": [], "remove": [self.prefixes[2]]})
        r2, = [d for d in summary["deviceRoles"] if d["node"] == "r2"]
        action, = r2["actionGroups"]
        b, = [m for m in action["members"] if m["localConditions"]["peer"] == "b"]
        self.assertEqual(action["prefixExceptions"][b["contribution"]]["remove"], [self.prefixes[2]])

    def test_origin_preview_reads_advertised_prefix_even_when_probe_links_a_more_specific_row(self):
        self.add("isp", "Origin", {"vrf": "default", "protocol": "bgp", "prefix": "192.0.0.0/16"}, 0, 1)
        summarize_device_roles(self.summaries, self.roles, self.rows)
        group, = self.summaries[0]["responsibilityGroups"]
        rendered = "\n".join(_group_item(group, self.report))
        self.assertIn("originated prefixes `192.0.0.0/16`", rendered)
        self.assertIn("linked reference prefixes `192.0.0.0/24`, `192.0.1.0/24`", rendered)
        example, = _group_examples(self.report, [group], "#/summaries/0/responsibilityGroups", 1)
        self.assertEqual(example["scopeExamples"][0]["originatedPrefixExamples"], ["192.0.0.0/16"])
        self.assertEqual(example["basePrefixExamples"], self.prefixes[:2])

    def test_directions_vrfs_policy_and_observed_packet_constrain_grouping(self):
        for diff in [{}, {"policy": "alternate"}, {"direction": "import", "action": "rejected"},
                     {"action": "rejected"}, {"vrf": "guest"}, {"peerVrf": "tenant"}]:
            self.bgp("r1", "a", 0, [0], **diff)
        packet = {"srcIp": "10.0.0.1", "dstPort": 443}
        scope = dict(iface="Eth1", filter="GUEST", direction="INGRESS_FILTER", flow="tls",
                     rule="deny tcp", ruleIndex=2, packet=packet, pathIndex=0)
        for diff in [{}, {"pathIndex": 1}, {"iface": "Eth2"}, {"filter": "WEB"}, {"direction": "EGRESS_FILTER"},
                     {"ruleIndex": 5}, {"packet": {**packet, "srcIp": "10.0.0.2"}}]:
            self.add("r1", "Access control", {**scope, **diff}, 0)
        summarize_device_roles(self.summaries, self.roles, self.rows)
        summary = self.summaries[0]
        acl, bgp = summary["deviceRoles"]
        self.assertEqual(len(acl["contributions"]), 6)
        self.assertEqual(len(bgp["contributions"]), 6)
        self.assertEqual(len(bgp["actionGroups"]), 5)
        self.assertEqual(len(summary["responsibilityGroups"]), 11)
        self.assert_round_trip(0, summary["responsibilityGroups"])
        self.assertEqual(self.summaries[1]["responsibilityGroups"], [])

    def test_transit_groups_follow_observed_boundaries_and_probe_headers(self):
        scope = dict(vrf="tenant", interface="Eth1", inputInterface="Eth0", nextNode="hub",
                     packetClass={"ipProtocol": "TCP", "dstPort": 80})
        self.add("left", "Transit", {**scope, "flow": "web-1"}, 0)
        self.add("left", "Transit", {**scope, "flow": "web-2"}, 1)
        self.add("right", "Transit", {**scope, "flow": "web-1"}, 0)
        self.add("left", "Transit", {**scope, "flow": "other-hop", "nextNode": "right"}, 0)
        self.add("left", "Transit", {**scope, "flow": "tls", "packetClass": {"ipProtocol": "TCP", "dstPort": 443}}, 0)
        unconfirmed = {k: v for k, v in scope.items() if k != "nextNode"}
        for node in ("left", "right"):
            self.add(node, "Transit", {**unconfirmed, "flow": "boundary"}, 2)
        summarize_device_roles(self.summaries, self.roles, self.rows)
        groups = self.summaries[0]["responsibilityGroups"]
        self.assertEqual(len(groups), 5)
        shared, = [g for g in groups if len(g["members"]) == 2]
        self.assertEqual(shared["validationCounts"], {"observed": 3})
        self.assertEqual(shared["conditions"]["nextNode"], "hub")
        self.assertEqual(shared["memberCount"], 2)
        self.assert_round_trip(0, groups)
