"""Regression tests for the public command, the live data plane and summary semantics."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from netx.tools.understand import NETX, analyze
from netx.tools.understand.details import resolve
from netx.tools.understand.report import flow_behavior, model_gaps
from netx.tools.understand.roles import role_hypotheses
from netx.tools.understand.summaries import Property, summarize
from netx.tests.understand.protocol_cases import IBDP, packet

HERE = Path(__file__).resolve().parent
SCENARIO = NETX / "benchmarks/cornetto/cornetto-benchmark/main_dataset/scenario-006"


class SummaryTests(unittest.TestCase):
    def test_topology_device_comparison_uses_batfish_hostname_case(self):
        facts = {"domains": [{"node": "edge-ny"}], "parseStatus": {}, "conversionStatus": {},
                 "parseWarnings": {}, "conversionWarnings": {}}
        self.assertEqual(model_gaps(facts, {"declaredNodes": ["Edge-NY"]}), [])
        self.assertEqual(model_gaps(facts, {"declaredNodes": ["Edge-NY", "Edge-SF"]}),
                         ["Missing topology devices: Edge-SF"])

    def test_exact_expansion_with_both_exception_signs_and_duplicates(self):
        properties = [
            Property("waypointing", node, prefix, {"scenario": "s"}, str(i), {"waypoint": "w"})
            for i, (node, prefix) in enumerate([
                ("a", "10.0.0.0/24"), ("b", "10.0.0.0/24"), ("a", "10.0.1.0/24"),
                ("c", "10.0.2.0/24"), ("a", "10.0.1.0/24"),
            ])
        ]
        summary, = summarize(properties)
        self.assertEqual(summary["baseNodes"], ["a"])
        self.assertEqual(summary["exceptions"]["10.0.2.0/24"], {"add": ["c"], "remove": ["a"]})
        self.assertEqual(summary["evidence"], ["0", "1", "2", "3", "4"])
        for prefix in summary["prefixes"]:
            diff = summary["exceptions"].get(prefix, {"add": [], "remove": []})
            members = set(summary["baseNodes"]).difference(diff["remove"]).union(diff["add"])
            self.assertEqual(members, {p.node for p in properties if p.prefix == prefix})

    def test_waypoint_and_multipath_observations(self):
        traces = [{"disposition": "ACCEPTED", "hops": [{"node": {"name": n}} for n in path]}
                  for path in (["a", "left", "core", "b"], ["a", "right", "core", "b"])]
        for total, waypoints, count in [(2, ["core"], 2), (3, None, None)]:
            observation = flow_behavior({"traces": traces, "totalPaths": total})
            self.assertEqual(observation["waypoints"], waypoints)
            self.assertEqual(observation["successfulNextHopCount"], count)

    def test_partial_traces_do_not_support_negative_or_universal_claims(self):
        for disposition, total in [("DENIED_IN", 2), ("INSUFFICIENT_INFO", 1)]:
            behavior = flow_behavior({"traces": [{"disposition": disposition}], "totalPaths": total})
            self.assertIsNone(behavior["reachable"])
            self.assertIsNone(behavior["waypoints"])
            self.assertIsNone(behavior["successfulNextHopCount"])


class SnapshotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        args = [sys.executable, "-m", "netx.tools.understand", str(HERE / "snapshot"),
                "--queries", str(HERE / "queries.json"), "--specifications", str(HERE / "intents.csv")]
        cls.report = json.loads(subprocess.check_output(args))
        cls.compact = json.loads(subprocess.check_output(args + ["--mode", "compact", "--runs", cls.temp.name]))
        cls.facts = cls.report["evidence"]
        cls.queries = {q["id"]: q for q in cls.facts["queries"]}

    def test_compact_details_and_all_role_links(self):
        self.assertEqual(self.report["status"], "ok")
        self.assertEqual(json.loads(Path(self.compact["details"]).read_text()), self.report)
        detail = subprocess.check_output([
            sys.executable, "-m", "netx.tools.understand.details", self.compact["result_id"],
            "#/evidence/routes", "--limit", "1", "--runs", self.temp.name,
        ])
        self.assertEqual(json.loads(detail)["items"], self.facts["routes"][:1])
        roles = self.report["roleHypotheses"]
        names = {"Origin", "Distribution", "Selection", "Transit", "Isolation", "Access control"}
        self.assertEqual({r["role"] for r in roles}, names)
        counts = self.compact["roleValidationCounts"]
        self.assertEqual(set(counts), names)
        self.assertEqual(sum(sum(values.values()) for values in counts.values()), len(roles))
        self.assertTrue(all(values["corroborated"] >= 1 for values in counts.values()))
        for r in roles:
            for ptr in r["evidence"] + r["relatedSummaries"] + r["validation"]["evidence"]:
                self.assertTrue(resolve(self.report, ptr))
            for link in r["intentLinks"]:
                summary = resolve(self.report, link["summary"])
                source = (resolve(self.report, link["flow"])["result"]["flow"]["ingressNode"]
                          if "flow" in link else link["source"])
                for ptr in link["rows"]:
                    self.assertIn(ptr, summary["evidence"])
                    self.assertEqual(resolve(self.report, ptr)["node"].lower(), source)
            self.assertTrue(all((HERE / "snapshot" / file).is_file() for file in r["configFiles"]))
        self.assertGreater(len({r["role"] for r in roles if r["node"] == "edge"}), 1)

    def test_route_identity_and_policy_provenance(self):
        routes = self.facts["routes"]
        candidates = {(r["bgpStatus"], r["inMainRib"], r["inFib"], r["nextHop"]["ip"])
                      for r in routes if r["node"] == "edge" and r["attributes"]["network"] == "203.0.113.8/32"}
        self.assertEqual(candidates, {("BEST", True, True, "10.0.0.2"), ("BACKUP", False, False, "10.0.0.6")})
        self.assertTrue(any(r["bgpStatus"] == "BEST" and not r["inMainRib"] for r in routes))
        rejected = [e for e in self.facts["events"] if e["action"] == "rejected"]
        for direction, node, prefix, policy in [
            ("import", "edge", "203.0.113.9/32", "FROM-PRIMARY"),
            ("export", "primary", "203.0.113.10/32", "TO-EDGE"),
        ]:
            event, = [e for e in rejected if (e["direction"], e["node"], e["prefix"]) == (direction, node, prefix)]
            self.assertEqual(event["cause"], "policy")
            self.assertIn(policy, {d["name"] for d in event["policyDefinitions"] if d["lines"]})
        self.assertTrue(any(e["cause"] == "core_protocol" for e in rejected))
        policy = self.queries["conditional-import"]
        self.assertEqual((policy["kind"], policy["result"][0]["Action"]), ("policyTests", "DENY"))

    def test_packet_scope_filters(self):
        queries = self.queries
        self.assertEqual(queries["tcp-80"]["behavior"]["dispositions"], ["ACCEPTED"])
        for port, iface, acl, direction in [
            (443, "GigabitEthernet0/2", "GUEST", "INGRESS_FILTER"),
            (22, "GigabitEthernet0/0", "SERVICE-OUT", "EGRESS_FILTER"),
        ]:
            denial, = queries[f"tcp-{port}"]["result"]["denials"]
            self.assertEqual((denial["filter"], denial["iface"], denial["direction"]), (acl, iface, direction))
            self.assertEqual(denial["packet"]["dstPort"], port)
            self.assertIn(f"eq {port}", denial["rule"])

    def test_markdown_links_reference_intents_to_a_separate_device_roles_section(self):
        markdown = Path(self.compact["overview"]).read_text()
        self.assertEqual([s for s in markdown.splitlines() if s.startswith("# ")],
                         ["# Intent Summary", "# Device Roles"])
        intents, roles = markdown.split("\n# Device Roles\n")
        self.assertNotIn("Device evidence covers", intents)
        self.assertNotIn("Observed packet outcomes", intents)
        self.assertNotIn("**Access control**", intents)
        self.assertIn("**Access control**", roles)
        self.assertIn("Observed packet outcomes", roles)
        self.assertIn("Device evidence covers 0 of", roles)
        for entry in roles.split('<a id="roles-')[1:]:
            preview, details = entry.split("<details><summary>Role details and evidence</summary>")
            self.assertIn("**Key devices**", preview)
            self.assertEqual(preview.count("**Observation**"), 1)
            self.assertIn("Device evidence covers", preview)
            self.assertNotIn("**Access control**", preview)
            self.assertTrue(details.rstrip().endswith("</details>"))
        self.assertIn("**Key devices** None attributed", roles)
        headings = [f"## {s['intent']}" for s in self.report["summaries"]]
        for section in (intents, roles):
            self.assertEqual([line for line in section.splitlines() if line.startswith("## ")], headings)
        for i in range(1, len(headings) + 1):
            self.assertEqual(intents.count(f'id="intent-{i}"'), 1)
            self.assertEqual(intents.count(f"(#roles-{i})"), 1)
            self.assertEqual(roles.count(f'id="roles-{i}"'), 1)
            self.assertEqual(roles.count(f"(#intent-{i})"), 1)

    def test_intent_groups_and_packet_roles_have_scoped_links(self):
        self.assertNotIn("checks", self.report)
        self.assertNotIn("verdictCounts", self.compact)
        self.assertEqual(self.compact["intentRows"], 10)
        self.assertCountEqual((q["kind"] for q in self.facts["queries"]), ["flows"] * 7 + ["policyTests"])
        self.assertTrue(all(s["scope"]["source"] == "supplied CSV" for s in self.report["summaries"]))
        self.assertEqual(self.compact["input"]["configurationState"], "as_supplied")
        self.assertEqual(self.compact["benchmark"]["configurationState"], "supplied_reference")
        for i, summary in enumerate(self.report["summaries"]):
            for ref in summary["relatedRoles"]:
                self.assertIn(f"#/summaries/{i}", resolve(self.report, ref)["relatedSummaries"])
        groups = {(s["kind"], s["scope"]["sources"]): s for s in self.report["summaries"]}
        acl = [resolve(self.report, ref) for ref in groups["isolation", "broken_removed"]["relatedRoles"]]
        self.assertTrue(any(r["role"] == "Access control" and r["scope"]["flow"] == "tcp-443" for r in acl))
        self.assertEqual(groups["isolation", "broken_added"]["relatedRoles"], [])
        self.assertEqual(groups["waypointing", "intact"]["relatedRoles"], [])

    def test_waypoint_role_points_to_the_intermediate_step_on_its_ecmp_branch(self):
        with tempfile.TemporaryDirectory() as temp:
            specs = Path(temp) / "intents.csv"
            specs.write_text("predicate_type,node,prefix,waypoint,num_routes,sources\n"
                             "waypointing,FWL,11.1.1.0/31,A2,,intact\n")
            plan = Path(temp) / "probes.json"
            plan.write_text(json.dumps({"flows": [packet("lan", "fwl", "10.1.1.4", "11.1.1.1")]}))
            report = analyze(IBDP / "ospf-edge", queries_path=plan, specifications=specs)
        self.assertEqual(report["status"], "ok")
        summary, = report["summaries"]
        role_ref, = summary["relatedRoles"]
        role = resolve(report, role_ref)
        self.assertEqual((role["role"], role["node"], role["relatedSummaries"]), ("Transit", "a2", ["#/summaries/0"]))
        step, = role["evidence"]
        self.assertEqual(resolve(report, step)["action"], "TRANSMITTED")
        self.assertEqual(role["intentLinks"][0]["steps"], [step])
        flow, = report["evidence"]["queries"]
        self.assertEqual(flow["behavior"]["successfulNextHopCount"], 2)
        self.assertNotIn("a2", flow["behavior"]["waypoints"])

        trace = flow["result"]["traces"][role["scope"]["pathIndex"]]
        rewrite = {"type": "Transformation", "action": "TRANSFORMED",
                   "detail": {"flowDiffs": [{"fieldName": "srcIp"}]}}
        trace["hops"][0]["steps"].insert(0, rewrite)
        for field, expected_link in [("srcIp", True), ("dstIp", False)]:
            with self.subTest(field=field):
                rewrite["detail"]["flowDiffs"][0]["fieldName"] = field
                roles = role_hypotheses(report["evidence"], report["summaries"], report["benchmark"]["rows"])
                self.assertEqual(any(r["role"] == "Transit" and r["node"] == "a2" for r in roles),
                                 expected_link)
        trace["hops"][0]["steps"].pop(0)
        for disposition in ("DENIED_IN", "DELIVERED_TO_SUBNET", "EXITS_NETWORK"):
            with self.subTest(disposition=disposition):
                trace["disposition"] = disposition
                roles = role_hypotheses(report["evidence"], report["summaries"], report["benchmark"]["rows"])
                self.assertFalse(any(r["role"] == "Transit" and r["node"] == "a2" for r in roles))

    def test_partial_query_and_fatal_error_are_distinct(self):
        path = Path(self.temp.name) / "invalid-location.json"
        path.write_text(json.dumps({"flows": [packet("missing", "absent", "192.0.2.1", "203.0.113.8")]}))
        result = analyze(HERE / "snapshot", queries_path=path)
        self.assertEqual(result["status"], "partial")
        self.assertTrue(result["evidence"]["queries"][0]["error"])
        self.assertEqual(result["summaries"], [])
        failed = subprocess.run([sys.executable, "-m", "netx.tools.understand", str(path.parent / "absent")],
                                capture_output=True)
        self.assertNotEqual(failed.returncode, 0)
        self.assertEqual(json.loads(failed.stdout)["status"], "error")


class CornettoTests(unittest.TestCase):
    def test_sampled_mixed_snapshot_ingress_acl(self):
        snapshot = SCENARIO.parent / "scenario-199"
        node = "0_as65003_glasgow"
        interface = "GigabitEthernet0/1"
        flows = [packet(name, node, src, "10.181.0.2", interface=interface, protocol="ICMP")
                 for name, src in [("peer", "10.181.0.3"), ("filtered-subnet", "192.0.2.1")]]
        with tempfile.TemporaryDirectory() as directory:
            plan = Path(directory) / "queries.json"
            plan.write_text(json.dumps({"flows": flows}))
            report = analyze(snapshot, queries_path=plan)
        facts = report["evidence"]
        # The probes terminate at Glasgow's ingress. Other devices have separate parser diagnostics.
        self.assertEqual(facts["conversionStatus"][node], "PASSED")
        for filename in facts["files"][node]:
            self.assertEqual(facts["parseStatus"][filename], "PASSED")
        queries = {q["id"]: q for q in facts["queries"]}
        for name, disposition in [("peer", "ACCEPTED"), ("filtered-subnet", "DENIED_IN")]:
            query = queries[name]
            self.assertIsNone(query["error"])
            self.assertTrue(query["behavior"]["pathsComplete"])
            self.assertEqual(query["behavior"]["dispositions"], [disposition])
        self.assertEqual(queries["peer"]["result"]["denials"], [])
        denial, = queries["filtered-subnet"]["result"]["denials"]
        self.assertEqual((denial["node"], denial["iface"], denial["direction"], denial["filter"]),
                         (node, interface, "INGRESS_FILTER", "ACL_0_GigabitEthernet0_1"))
        self.assertIn("deny ip 192.0.2.0 0.0.0.255 any", denial["rule"])

    def test_real_snapshot_and_specs(self):
        specs = SCENARIO / "specifications/specifications_2pct.csv"
        report = analyze(SCENARIO, specifications=specs)
        self.assertEqual(len(report["benchmark"]["rows"]), 42)
        self.assertEqual(report["input"]["links"], 40)
        self.assertEqual(len(report["evidence"]["files"]), 20)
        self.assertEqual({s["kind"] for s in report["summaries"]}, {"isolation", "load_balancing"})
        self.assertEqual({q["kind"] for q in report["evidence"]["queries"]}, {"flows"})
        self.assertEqual(sum(len(s["evidence"]) for s in report["summaries"]), 42)
        for summary in report["summaries"]:
            for ref in summary["evidence"]:
                row = resolve(report, ref)
                self.assertEqual(row["sources"], summary["scope"]["sources"])
                self.assertIn(row["prefix"], summary["prefixes"])


if __name__ == "__main__":
    unittest.main()
