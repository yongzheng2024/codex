"""Probe ordered IPv4 ACLs with concrete packets and forwarding traces."""

from netx.tests.understand.protocol_cases import EDGE, IBDP, ProtocolCase, packet
from netx.tools.understand.details import resolve


GUEST = "GigabitEthernet0/2"
SERVICE = "203.0.113.8"
ORIGINAL = """ permit tcp any host 203.0.113.8 eq 80
 deny tcp any host 203.0.113.8 eq 443
 permit ip any any"""
ALLOW = " permit tcp host 192.0.2.2 host 203.0.113.8 eq 80"
DENY = " deny tcp any host 203.0.113.8 eq 80"
UDP = " permit udp any host 203.0.113.8 range 10000 10002"
ICMP = " permit icmp any any echo"


def guest(name, protocol, port=80, *, src="192.0.2.2", dst=SERVICE):
    return packet(name, "edge", src, dst, interface=GUEST, protocol=protocol, port=port)


class AclTests(ProtocolCase):
    def test_first_match_port_boundaries_and_implicit_deny(self):
        edits = [("edge.cfg", ORIGINAL, "\n".join([ALLOW, DENY, UDP, ICMP]))]
        facts = self.simulate(EDGE, edits=edits, flows=[
            guest("exception", "TCP"), guest("explicit", "TCP", src="192.0.2.3"), guest("implicit", "TCP", 443),
            guest("echo", "ICMP"), guest("unrouted", "ICMP", dst="198.18.0.1"),
            *(guest(f"udp-{port}", "UDP", port) for port in (9999, 10000, 10001, 10002, 10003)),
        ])
        for name in ("exception", "echo", "udp-10000", "udp-10001", "udp-10002"):
            self.assert_paths(facts, name, ("ACCEPTED", "edge", "primary"))
            self.assertEqual(self.query(facts, name)["result"]["denials"], [])
        for name in ("explicit", "implicit", "udp-9999", "udp-10003"):
            with self.subTest(flow=name):
                self.assert_paths(facts, name, ("DENIED_IN", "edge"))
                denial, = self.query(facts, name)["result"]["denials"]
                self.assertEqual((denial["node"], denial["iface"], denial["filter"], denial["direction"]),
                                 ("edge", GUEST, "GUEST", "INGRESS_FILTER"))
                self.assertEqual(denial["ruleIndex"], 1 if name == "explicit" else None)
                if name == "explicit":
                    self.assertIn(DENY.strip(), denial["rule"])
                else:
                    self.assertEqual(denial["rule"], "implicit deny")
        self.assert_paths(facts, "unrouted", ("NO_ROUTE", "edge"))
        self.assertEqual(self.query(facts, "unrouted")["result"]["denials"], [])

    def test_reordering_shadows_the_exception(self):
        facts = self.simulate(EDGE, edits=[("edge.cfg", ORIGINAL, "\n".join([DENY, ALLOW, UDP, ICMP]))],
                              flows=[guest("shadowed", "TCP")])
        self.assert_paths(facts, "shadowed", ("DENIED_IN", "edge"))
        denial, = self.query(facts, "shadowed")["result"]["denials"]
        self.assertEqual(denial["ruleIndex"], 0)
        self.assertIn(DENY.strip(), denial["rule"])

    def test_egress_denial_uses_the_translated_source(self):
        edits = [
            ("edge.cfg", " ip access-group GUEST in", " ip nat inside\n ip access-group GUEST in"),
            ("edge.cfg", " ip access-group SERVICE-OUT out", " ip nat outside\n ip access-group SERVICE-OUT out"),
            ("edge.cfg", "ip access-list extended SERVICE-OUT",
             "ip nat inside source static 192.0.2.2 198.51.100.22\n!\nip access-list extended SERVICE-OUT"),
            ("edge.cfg", "deny tcp any host 203.0.113.8 eq 22", "deny tcp host 198.51.100.22 host 203.0.113.8 eq 22"),
        ]
        report = self.simulate_report(EDGE, edits=edits, flows=[
            guest("translated", "TCP", 22), guest("other-source", "TCP", 22, src="192.0.2.3"),
        ])
        facts = report["evidence"]
        role, = [r for r in report["roleHypotheses"] if r["role"] == "Access control"]
        step, = role["validation"]["evidence"]
        self.assertEqual(resolve(report, step)["detail"]["flow"]["srcIp"], "198.51.100.22")
        self.assert_paths(facts, "translated", ("DENIED_OUT", "edge"))
        result = self.query(facts, "translated")["result"]
        denial, = result["denials"]
        self.assertEqual((result["flow"]["srcIp"], denial["packet"]["srcIp"]), ("192.0.2.2", "198.51.100.22"))
        self.assertEqual((denial["iface"], denial["direction"], denial["filter"], denial["ruleIndex"]),
                         ("GigabitEthernet0/0", "EGRESS_FILTER", "SERVICE-OUT", 0))
        self.assert_paths(facts, "other-source", ("ACCEPTED", "edge", "primary"))

    def test_acl_denies_only_one_ecmp_branch(self):
        edits = [
            ("A2", "interface GigabitEthernet1/0\n", "interface GigabitEthernet1/0\n ip access-group BRANCH in\n"),
            ("A2", "router ospf 1", "ip access-list extended BRANCH\n deny tcp any host 11.1.1.1 eq 443\n"
                                    " permit ip any any\n!\nrouter ospf 1"),
        ]
        flow = packet("two-branches", "fwl", "10.1.1.4", "11.1.1.1", protocol="TCP", port=443)
        report = self.simulate_report(IBDP / "ospf-edge", edits=edits, flows=[flow])
        facts = report["evidence"]
        self.assert_paths(facts, "two-branches", ("ACCEPTED", "fwl", "a1"), ("DENIED_IN", "fwl", "a2"))
        query = self.query(facts, "two-branches")
        self.assertIs(query["behavior"]["reachable"], True)
        self.assertEqual(query["behavior"]["successfulNextHopCount"], 1)
        result = query["result"]
        denial, = result["denials"]
        role, = [r for r in report["roleHypotheses"] if r["role"] == "Access control"]
        step, = role["validation"]["evidence"]
        self.assertEqual(role["scope"]["pathIndex"], denial["pathIndex"])
        self.assertIn(f"/traces/{denial['pathIndex']}/", step)
        self.assertEqual(resolve(report, step)["action"], "DENIED")
        self.assertEqual((denial["node"], denial["filter"], denial["iface"]), ("a2", "BRANCH", "GigabitEthernet1/0"))
        self.assertEqual(result["traces"][denial["pathIndex"]]["disposition"], "DENIED_IN")
