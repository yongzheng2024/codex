"""IS-IS level compatibility, area boundaries, interface metrics and export policy."""

from netx.tests.understand.protocol_cases import RESOURCES, ProtocolCase, packet


SNAPSHOT = RESOURCES / "grammar/juniper/testrigs/isis-redist"
LOOPBACK = "172.16.9.7/32"
REMOTE = packet("loopback", "r1", "172.16.3.5", "172.16.9.7")
LINK = packet("neighbor", "r1", "10.0.0.38", "10.0.0.37")
OTHER_AREA = ("r2", "49.0002.", "49.0003.")
TRANSIT = "interface ge-0/0/1.0;"


def single_level(r1, r2):
    edits = []
    for node, level in [("r1", r1), ("r2", r2)]:
        edits.append((node, "    isis {\n", f"    isis {{\n        level {3 - level} disable;\n"))
        edits.append((node, "interface lo0.0;", "interface lo0.0 { passive; }"))
    return edits


class IsisTests(ProtocolCase):
    def test_l1_internal_and_policy_redistributed_routes(self):
        report = self.simulate_report(SNAPSHOT, edits=single_level(1, 1), flows=[
            REMOTE, packet("redistributed", "r1", "172.16.3.5", "5.6.7.9"),
            packet("excluded", "r1", "172.16.3.5", "2.2.2.1"),
        ])
        facts = report["evidence"]
        self.assertEqual({r["node"] for r in report["roleHypotheses"] if r["role"] == "Origin"
                          and r["scope"]["prefix"] == LOOPBACK}, {"r2"})
        for prefix, protocol in [(LOOPBACK, "isisL1"), ("5.6.7.8/30", "isisEL1")]:
            route, = self.routes(facts, "r1", prefix)
            self.assertEqual((route["protocol"], route["attributes"]["metric"], route["nextHop"]["ip"],
                              route["inMainRib"], route["inFib"]), (protocol, 10, "10.0.0.37", True, True))
        for origin, peer, prefix in [("r2", "r1", "2.2.2.0/30"), ("r1", "r2", "1.2.3.4/30")]:
            static, = self.routes(facts, origin, prefix)
            self.assertEqual(static["protocol"], "static")
            self.assertEqual(self.routes(facts, peer, prefix), [])
        self.assert_paths(facts, "loopback", ("ACCEPTED", "r1", "r2"))
        self.assert_paths(facts, "redistributed", ("NULL_ROUTED", "r1", "r2"))
        self.assert_paths(facts, "excluded", ("NO_ROUTE", "r1"))

    def test_l2_crosses_areas_with_directional_metric(self):
        facts = self.simulate(SNAPSHOT, edits=[
            *single_level(2, 2), OTHER_AREA, ("r1", TRANSIT, "interface ge-0/0/1.0 { level 2 metric 37; }"),
        ], flows=[REMOTE])
        for node, prefix, hop, cost in [("r1", LOOPBACK, "10.0.0.37", 37),
                                        ("r2", "172.16.3.5/32", "10.0.0.38", 10)]:
            route, = self.routes(facts, node, prefix)
            self.assertEqual((route["protocol"], route["nextHop"]["ip"], route["attributes"]["metric"],
                              route["inFib"]), ("isisL2", hop, cost, True))
        self.assert_paths(facts, "loopback", ("ACCEPTED", "r1", "r2"))

    def test_incompatible_or_passive_neighbors_keep_connected_delivery(self):
        for condition, edits in [
            ("different L1 areas", [*single_level(1, 1), OTHER_AREA]),
            ("no common level", single_level(1, 2)),
            ("passive transit interface", [*single_level(1, 1),
                                           ("r2", TRANSIT, "interface ge-0/0/1.0 { passive; }")]),
        ]:
            with self.subTest(condition=condition):
                facts = self.simulate(SNAPSHOT, edits=edits, flows=[REMOTE, LINK])
                self.assertEqual(self.routes(facts, "r1", LOOPBACK), [])
                self.assertEqual(self.routes(facts, "r2", "172.16.3.5/32"), [])
                self.assert_paths(facts, "loopback", ("NO_ROUTE", "r1"))
                self.assert_paths(facts, "neighbor", ("ACCEPTED", "r1", "r2"))
