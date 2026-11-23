"""Scoped role attribution against controlled changes and concrete Cornetto observations."""

from copy import deepcopy
import json

from netx.tests.understand.protocol_cases import EDGE, NETX, ProtocolCase
from netx.tools.understand import analyze
from netx.tools.understand.details import resolve
from netx.tools.understand.overview import overview
from netx.tools.understand.roles import role_hypotheses
from netx.tools.understand.summaries import imported_properties, summarize


HERE = EDGE.parent
SERVICE = "203.0.113.8/32"


def matching(report, name, node, **scope):
    return [role for role in report["roleHypotheses"] if role["role"] == name and role["node"] == node
            and all(role["scope"].get(key) == value for key, value in scope.items())]


class RoleTests(ProtocolCase):
    @classmethod
    def setUpClass(cls):
        cls.flows = json.loads((HERE / "queries.json").read_text())["flows"]
        cls.baseline = analyze(EDGE, queries_path=HERE / "queries.json", specifications=HERE / "intents.csv")

    def variant(self, edit, flows=None):
        return self.simulate_report(EDGE, edits=[edit], flows=self.flows if flows is None else flows,
                                    specifications=HERE / "intents.csv")

    def test_each_role_has_a_scoped_second_observation(self):
        for name, node, scope, method in [
            ("Origin", "primary", {"protocol": "bgp", "prefix": SERVICE}, "origin_export_cross_check"),
            ("Distribution", "primary", {"action": "sent", "peer": "edge", "prefix": SERVICE},
             "peer_received_from_session"),
            ("Selection", "edge", {"prefix": SERVICE}, "installed_route_in_packet_lookup"),
            ("Transit", "edge", {"flow": "tcp-80"}, "next_hop_received_on_link"),
            ("Access control", "edge", {"flow": "tcp-443"}, "filter_step_and_acl_replay"),
            ("Isolation", "edge", {}, "paired_vrf_packet"),
        ]:
            with self.subTest(role=name):
                role, = matching(self.baseline, name, node, **scope)
                result = role["validation"]
                self.assertEqual((result["status"], result["method"]), ("corroborated", method))
                self.assertTrue(result["evidence"])
                self.assertTrue(role["intentLinks"])
        role, = matching(self.baseline, "Isolation", "edge")
        self.assertEqual((role["validation"]["deliveryVrf"], role["validation"]["noRouteVrf"]),
                         ("tenant", "default"))
        self.assertTrue(all(link["basis"] == "packet_scope" for link in role["intentLinks"]))

    def test_withdraw_advertisement_removes_origin_despite_connected_prefix(self):
        before = self.baseline
        after = self.variant(("primary.cfg", " network 203.0.113.8 mask 255.255.255.255\n", ""))
        self.assertTrue(matching(before, "Origin", "primary", prefix=SERVICE, protocol="bgp"))
        self.assertEqual(matching(after, "Origin", "primary", prefix=SERVICE, protocol="bgp"), [])
        self.assertEqual(matching(after, "Origin", "primary", prefix=SERVICE), [])
        self.assertTrue(any(r["inMainRib"] and r["protocol"] == "connected"
                            for r in self.routes(after["evidence"], "primary", SERVICE)))
        self.assertTrue(matching(after, "Origin", "secondary", prefix=SERVICE, protocol="bgp"))
        self.assertEqual(matching(after, "Selection", "edge", prefix=SERVICE), [])
        role, = matching(after, "Distribution", "secondary", peer="edge", prefix=SERVICE, action="sent")
        self.assertEqual(role["validation"]["status"], "corroborated")
        control, = matching(after, "Transit", "edge", flow="tcp-80")
        self.assertEqual(control["scope"]["interface"], "GigabitEthernet0/1")

    def test_export_policy_change_moves_prefix_to_receiver(self):
        prefix = "203.0.113.10/32"
        before, = matching(self.baseline, "Distribution", "primary", prefix=prefix, action="rejected")
        self.assertEqual(before["validation"]["status"], "observed")
        self.assertEqual({link["basis"] for link in before["intentLinks"]}, {"member_route_filter"})
        self.assertEqual({link["source"] for link in before["intentLinks"]}, {"edge"})
        after = self.variant(("primary.cfg", "route-map TO-EDGE deny 10", "route-map TO-EDGE permit 10"))
        self.assertEqual(matching(after, "Distribution", "primary", prefix=prefix, action="rejected"), [])
        sent, = matching(after, "Distribution", "primary", prefix=prefix, peer="edge", action="sent")
        self.assertEqual(sent["validation"]["method"], "peer_received_from_session")
        self.assertTrue(matching(after, "Distribution", "edge", prefix="203.0.113.9/32", action="rejected"))

    def test_acl_detachment_changes_one_boundary(self):
        after = self.variant(("edge.cfg", " ip access-group GUEST in\n", ""))
        self.assertEqual(matching(after, "Access control", "edge", flow="tcp-443"), [])
        transit, = matching(after, "Transit", "edge", flow="tcp-443")
        self.assertEqual(transit["validation"]["status"], "corroborated")
        control, = matching(after, "Access control", "edge", flow="tcp-22")
        self.assertEqual(control["scope"]["filter"], "SERVICE-OUT")

    def test_moving_interface_removes_domain_role(self):
        after = self.variant(("edge.cfg", " vrf forwarding tenant\n", ""),
                             flows=[q for q in self.flows if q["flow"].get("ingressVrf") != "tenant"])
        self.assertEqual(matching(after, "Isolation", "edge"), [])
        default = self.query(after["evidence"], "tenant-address-from-default")
        self.assertEqual(default["behavior"]["dispositions"], ["ACCEPTED"])

    def test_unmatched_evidence_cannot_upgrade_a_role(self):
        for change in ("different packet", "incomplete pair", "boundary exit", "wrong sender", "wrong link",
                       "different replay"):
            with self.subTest(change=change):
                facts = deepcopy(self.baseline["evidence"])
                if change in {"different packet", "incomplete pair", "boundary exit"}:
                    query = self.query(facts, "tenant-address-from-tenant")
                    if change == "different packet":
                        query["result"]["flow"]["dstPort"] += 1
                    elif change == "incomplete pair":
                        query["behavior"]["pathsComplete"] = False
                    else:
                        query["behavior"]["dispositions"] = ["EXITS_NETWORK"]
                        query["result"]["traces"][0]["disposition"] = "EXITS_NETWORK"
                    role, node, scope, expected = "Isolation", "edge", {}, "configured"
                elif change == "wrong sender":
                    for session in facts["bgpSessions"]:
                        if session["node"] == "primary":
                            session["localIp"] = "192.0.2.199"
                    role, node, scope, expected = "Distribution", "primary", {"prefix": SERVICE, "action": "sent"}, "observed"
                elif change == "wrong link":
                    facts["layer3Edges"] = []
                    role, node, scope, expected = "Transit", "edge", {"flow": "tcp-80"}, "observed"
                else:
                    self.query(facts, "tcp-443")["result"]["denials"][0]["packet"]["dstPort"] = 80
                    role, node, scope, expected = "Access control", "edge", {"flow": "tcp-443"}, "inconsistent"
                records = role_hypotheses(facts, [], [])
                result, = matching({"roleHypotheses": records}, role, node, **scope)
                self.assertEqual(result["validation"]["status"], expected)
                self.assertEqual(result["validation"]["evidence"], [])

    def test_member_source_exceptions_duplicates_and_role_grouping(self):
        facts = self.baseline["evidence"]
        def row(node, prefix):
            return dict(predicate_type="load_balancing", node=node, prefix=prefix, sources="intact", num_routes="2")

        rows = [row("edge", SERVICE), row("edge", SERVICE), row("secondary", "203.0.113.10/32")]
        summaries = summarize(imported_properties(rows, self.baseline["benchmark"]))
        roles = role_hypotheses(facts, summaries, rows)
        group, = summaries
        self.assertEqual(group["attributedRows"], 2)
        self.assertEqual(group["unattributedRows"], ["#/benchmark/rows/2"])
        origins = [g for g in group["deviceRoles"] if g["role"] == "Origin"]
        self.assertEqual({g["node"] for g in origins}, {"primary", "secondary"})
        self.assertTrue(all(g["prefixes"] == [SERVICE] and g["memberCount"] == 2 for g in origins))
        self.assertTrue(all(r["intentLinks"] for r in roles))
        self.assertFalse(any(r["role"] == "Transit" for r in roles))
        self.assertFalse(any(r["scope"].get("prefix") == "203.0.113.10/32" for r in roles))

        # The source has two VRFs. A CSV row alone cannot place the route in either.
        facts = {**facts, "queries": []}
        self.assertEqual(role_hypotheses(facts, summaries, rows), [])
        self.assertEqual(group["unattributedRows"], group["evidence"])

    def test_scenario_300_member_filter_and_exact_origins(self):
        scenario = NETX / "benchmarks/cornetto/cornetto-benchmark/main_dataset/scenario-300"
        if not scenario.exists():
            self.skipTest("Optional local scenario-300 is unavailable")
        report = analyze(scenario, specifications=scenario / "specifications/specifications_100pct.csv")
        self.assertEqual(report["status"], "ok")
        groups = {(s["kind"], s["scope"]["sources"]): s for s in report["summaries"]}
        customer = groups["reachability", "broken_removed"]
        self.assertEqual(customer["attributedRows"], 2)
        rejection, = customer["deviceRoles"]
        self.assertEqual((rejection["node"], rejection["role"]), ("r4", "Distribution"))
        self.assertIn("R4_OUT_TO_C1", rejection["contributions"][0]["description"])
        self.assertEqual({tuple(o["dispositions"]) for o in customer["packetObservations"]}, {("NO_ROUTE",)})
        self.assertEqual({(r["node"], r["scope"]["prefix"]) for r in report["roleHypotheses"]
                          if r["role"] == "Origin"},
                         {("isp1", "192.0.2.0/24"), ("isp1", "198.51.100.0/24"), ("isp2", "203.0.113.0/24")})
        for label, prefixes, hops in [
            ("broken_removed", ["192.0.2.0/24", "198.51.100.0/24"], ["192.18.4.2"]),
            ("intact", ["203.0.113.0/24"], ["192.18.4.2", "192.18.4.6"]),
        ]:
            with self.subTest(reference=label):
                balance = groups["load_balancing", label]
                self.assertEqual(balance["prefixes"], prefixes)
                self.assertEqual({(d["node"], d["role"]) for d in balance["deviceRoles"]},
                                 {("r4", "Selection"), ("r2", "Distribution"), ("r3", "Distribution")})
                selection, = [d for d in balance["deviceRoles"] if d["role"] == "Selection"]
                choice, = selection["contributions"]
                self.assertEqual(choice["prefixes"], prefixes)
                self.assertCountEqual([h["ip"] for h in choice["conditions"]["installedNextHops"]], hops)
                exports, = [g for g in balance["responsibilityGroups"] if g["action"] == "advertise"]
                self.assertEqual(exports["conditions"]["peer"], "r4")
                self.assertEqual({m["node"] for m in exports["members"]}, {"r2", "r3"})
                self.assertEqual(len({m["localConditions"]["policy"] for m in exports["members"]}), 2)
                self.assertEqual(exports["validationCounts"], {"corroborated": 2 * len(prefixes)})
                self.assertEqual(exports["basePrefixes"], prefixes)
                self.assertEqual(exports["prefixExceptions"], {})
        self.assertEqual(groups["isolation", "intact"]["attributedRows"], 1)
        observations = [line for line in overview(report).splitlines() if line.startswith("**Observation**")]
        self.assertEqual(len(observations), len(report["summaries"]))
        self.assertIn("**Observation** `r4` installed 1 next hop for `192.0.2.0/24`, `198.51.100.0/24`.", observations)
        self.assertIn("**Observation** `r4` installed 2 next hops for `203.0.113.0/24`.", observations)
        self.assertIn("**Observation** `r4` filtered BGP imports from `customer1` for `172.16.0.0/12`.",
                      observations)
        for query in report["evidence"]["queries"]:
            self.assertTrue(query["id"].startswith("intent-"))

    def test_scenario_085_selection_and_waypoint_link_to_exact_input_rows(self):
        snapshot = NETX / "benchmarks/cornetto/cornetto-benchmark/main_dataset/scenario-085"
        report = analyze(snapshot, queries_path=HERE / "scenario_085_role_queries.json",
                         specifications=snapshot / "specifications/specifications_100pct.csv")
        self.assertEqual(report["status"], "ok")
        self.assertEqual(report["input"]["configurationState"], "fault_injected")
        self.assertEqual(report["benchmark"]["configurationState"], "golden_vs_faulty")
        self.assertEqual(report["evidence"]["configurationState"], "fault_injected")
        self.assertTrue(all(r["configurationState"] == "fault_injected" for r in report["roleHypotheses"]))
        boone = "36_as65010_boone"
        role, = matching(report, "Selection", boone, prefix="10.200.60.0/24")
        self.assertEqual(role["scope"]["basis"], "cross_protocol")
        self.assertEqual(role["validation"]["status"], "corroborated")
        routes = [resolve(report, ref) for ref in role["evidence"]]
        self.assertCountEqual([(r["protocol"], r["bgpStatus"], r["inFib"]) for r in routes],
                              [("ibgp", "BEST", False), ("ospfE2", None, True)])
        lookup, = role["validation"]["evidence"]
        self.assertEqual(resolve(report, lookup)["protocol"], "ospfE2")
        self.assertEqual({resolve(report, ptr)["line"] for link in role["intentLinks"] for ptr in link["rows"]},
                         {20526})
        waypoint, = matching(report, "Transit", "85_as65007_none", flow="orangeburg-waypoint")
        member, = [link for link in waypoint["intentLinks"] if link["basis"] == "observed_waypoint"]
        self.assertEqual([resolve(report, ptr)["line"] for ptr in member["rows"]], [64])
        self.assertEqual(waypoint["validation"]["method"], "next_hop_received_on_link")
        self.assertEqual(matching(report, "Transit", boone, flow="boone-service"), [])
        endpoint = "34_as65002_high-point"
        self.assertFalse(matching(report, "Origin", endpoint, protocol="connected"))
        observations = [o for summary in report["summaries"] for o in summary["endpointObservations"]
                        if o["node"] == endpoint and any(resolve(report, r)["line"] == 20789 for r in o["rows"])]
        observation, = observations
        self.assertEqual(resolve(report, observation["step"])["action"], "ACCEPTED")
        self.assertEqual(matching(report, "Transit", endpoint, flow="boone-service"), [])
