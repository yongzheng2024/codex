"""OSPF path cost, areas, redistribution and local route filtering."""

from netx.tests.understand.protocol_cases import IBDP, RESOURCES, ProtocolCase, packet


AREAS = IBDP / "ospf-distribute-lists"


class OspfTests(ProtocolCase):
    def test_route_types_distribute_lists_and_downstream_forwarding(self):
        facts = self.simulate(AREAS, flows=[
            packet("inside", "r2", "192.168.12.2", "2.2.2.2"),
            packet("downstream-filtered", "r3", "192.168.13.2", "1.1.1.1"),
        ])
        for node, prefix, protocol, metric, hop in [
            ("r2", "2.2.2.0/24", "ospf", 11, "192.168.12.1"),
            ("r3", "1.1.1.0/24", "ospfIA", 12, "192.168.13.1"),
            ("r2", "192.168.16.0/24", "ospfE1", 21, "192.168.12.1"),
            ("r2", "192.168.9.0/24", "ospfE2", 20, "192.168.13.2"),
        ]:
            with self.subTest(node=node, prefix=prefix):
                r, = self.routes(facts, node, prefix)
                self.assertEqual((r["protocol"], r["attributes"]["metric"], r["nextHop"]["ip"],
                                  r["inMainRib"], r["inFib"]), (protocol, metric, hop, True, True))
        for node, prefix in [("r2", "1.1.1.0/24"), ("r2", "192.168.15.0/24"),
                             ("r2", "192.168.10.0/24"), ("r3", "2.2.2.0/24")]:
            self.assertEqual(self.routes(facts, node, prefix), [], (node, prefix))
        self.assert_paths(facts, "inside", ("ACCEPTED", "r2", "r1"))
        self.assert_paths(facts, "downstream-filtered", ("NO_ROUTE", "r3", "r2"))
        self.assertEqual(self.query(facts, "downstream-filtered")["result"]["denials"], [])

    def test_area_mismatch_preserves_connected_forwarding(self):
        facts = self.simulate(AREAS, edits=[
            ("r3", "192.168.13.0 0.0.0.255 area 1", "192.168.13.0 0.0.0.255 area 2"),
        ], flows=[
            packet("remote", "r3", "192.168.13.2", "1.1.1.1"),
            packet("neighbor", "r3", "192.168.13.2", "192.168.13.1"),
        ])
        self.assertEqual(self.routes(facts, "r3", "1.1.1.0/24"), [])
        self.assertEqual(self.routes(facts, "r2", "192.168.9.0/24"), [])
        self.assert_paths(facts, "remote", ("NO_ROUTE", "r3"))
        self.assert_paths(facts, "neighbor", ("ACCEPTED", "r3", "r2"))

    def test_cost_change_breaks_ecmp(self):
        for raised_cost in (False, True):
            with self.subTest(raised_cost=raised_cost):
                interface = "interface FastEthernet0/0\n"
                edits = [("A1", interface, interface + " ip ospf cost 20\n")] if raised_cost else []
                report = self.simulate_report(IBDP / "ospf-edge", edits=edits, flows=[
                    packet("lan", "fwl", "10.1.1.4", "11.1.1.1"),
                ])
                facts = report["evidence"]
                selections = [r for r in report["roleHypotheses"] if r["role"] == "Selection"
                              and r["node"] == "fwl" and r["scope"]["prefix"] == "11.1.1.0/31"]
                if raised_cost:
                    self.assertEqual(selections, [])
                else:
                    selection, = selections
                    self.assertEqual(selection["scope"]["basis"], "installed_multipath")
                    self.assertEqual(selection["validation"]["status"], "corroborated")
                targets = {"10.1.1.2"} if raised_cost else {"10.1.1.1", "10.1.1.2"}
                self.assertCountEqual(
                    [(r["protocol"], r["attributes"]["metric"], r["nextHop"]["ip"], r["inFib"])
                     for r in self.routes(facts, "fwl", "11.1.1.0/31")],
                    [("ospf", 2, hop, True) for hop in targets],
                )
                expected = [("ACCEPTED", "fwl", "a2", "a1")]
                if not raised_cost:
                    expected.append(("ACCEPTED", "fwl", "a1"))
                self.assert_paths(facts, "lan", *expected)
                self.assertEqual(self.query(facts, "lan")["behavior"]["successfulNextHopCount"], len(targets))
                default, = self.routes(facts, "a2", "0.0.0.0/0")
                self.assertEqual((default["protocol"], default["nextHop"]["ip"]), ("ospfE2", "10.1.1.4"))

    def test_ebgp_redistributed_into_ospf_with_external_metric(self):
        fixture = RESOURCES / "grammar/frr/snapshots/ospf-bgp-redist-set-metric"
        report = self.simulate_report(fixture, flows=[packet("to-origin", "frr-listener", "5.5.5.5", "10.2.2.2")])
        facts = report["evidence"]
        prefix = "10.2.2.2/32"
        roles = [(r["node"], r["role"]) for r in report["roleHypotheses"] if r["scope"].get("prefix") == prefix]
        self.assertIn(("frr-originator", "Origin"), roles)
        self.assertNotIn(("frr-redistributor", "Origin"), roles)
        self.assertIn(("frr-redistributor", "Distribution"), roles)
        bgp, = self.routes(facts, "frr-redistributor", prefix)
        ospf, = self.routes(facts, "frr-listener", prefix)
        self.assertEqual((bgp["protocol"], bgp["nextHop"]["ip"], bgp["inFib"]), ("bgp", "10.1.1.1", True))
        self.assertEqual((ospf["protocol"], ospf["attributes"]["metric"], ospf["nextHop"]["ip"], ospf["inFib"]),
                         ("ospfE2", 10000, "10.1.1.2", True))
        self.assert_paths(facts, "to-origin", ("NULL_ROUTED", "frr-listener", "frr-redistributor", "frr-originator"))
