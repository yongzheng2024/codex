"""BGP selection, session loss and route reflection in the converged data plane."""

import shutil
import tempfile
from pathlib import Path

from netx.tests.understand.protocol_cases import EDGE, IBDP, ProtocolCase, packet
from netx.tools.understand import NETX, analyze


SERVICE = "203.0.113.8/32"
RR = IBDP / "testrigs/rr-rib-failure"
REFLECTED = "5.5.5.5/32"


class EbgpTests(ProtocolCase):
    def test_speclens_multipath_export_applies_policy_to_each_installed_path(self):
        scenario = NETX / "benchmarks/cornetto/cornetto-benchmark/main_dataset/scenario-300"
        if not scenario.exists():
            self.skipTest("Optional local scenario-300 is unavailable")
        prefix = "203.0.113.0/24"
        with tempfile.TemporaryDirectory(prefix="netx-multipath-export-") as directory:
            snapshot = shutil.copytree(scenario, Path(directory) / "scenario-300")
            config = snapshot / "final_configs/configs/r4.cfg"
            original = config.read_text()
            for policy in ("deny_comm1", "deny_both", "permit_both"):
                with self.subTest(policy=policy):
                    modified = original
                    if policy == "deny_both":
                        modified = modified.replace(
                            "route-map R4_OUT_TO_C1 permit 100",
                            "route-map R4_OUT_TO_C1 deny 20\n  match community comm2\n!\n"
                            "route-map R4_OUT_TO_C1 permit 100")
                    elif policy == "permit_both":
                        modified = modified.replace("  neighbor as700 route-map R4_OUT_TO_C1 out\n", "")
                    config.write_text(modified)
                    report = analyze(snapshot)
                    self.assertEqual(report["status"], "ok", report["gaps"])
                    self.assertEqual(report["simulation"]["bgpMultipathExport"], "speclens_compatible")
                    facts = report["evidence"]
                    paths = [r for r in self.routes(facts, "r4", prefix) if r["inMainRib"]]
                    self.assertEqual({r["nextHop"]["ip"] for r in paths}, {"192.18.4.2", "192.18.4.6"})
                    candidates = self.routes(facts, "customer1", prefix)
                    received = [r for r in candidates if r["inMainRib"]]
                    if policy == "deny_both":
                        self.assertEqual(received, [])
                    elif policy == "deny_comm1":
                        route, = received
                        self.assertEqual(route["attributes"]["communities"], ["100:300"])
                        self.assertEqual(route["nextHop"]["ip"], "192.18.7.2")
                        events = [e for e in facts["events"] if e["node"] == "r4"
                                  and e["peer"] == "customer1" and e["prefix"] == prefix
                                  and e["direction"] == "export"]
                        self.assertEqual({e["action"] for e in events}, {"sent", "rejected"})
                    else:
                        self.assertEqual({tuple(r["attributes"]["communities"]) for r in candidates},
                                         {("100:200",), ("100:300",)})
                        self.assertEqual(len({r["attributes"]["pathId"] for r in candidates}), 2)
                        self.assertEqual(len(received), 1)  # Both paths have the same next hop here.

    def test_local_preference_and_as_path_length(self):
        prepend = ("primary.cfg", "route-map TO-EDGE permit 20\n",
                   "route-map TO-EDGE permit 20\n set as-path prepend 65001 65001\n")
        for local_pref, winner in [(200, "primary"), (100, "secondary")]:
            with self.subTest(local_pref=local_pref):
                edits = [prepend]
                if local_pref == 100:
                    edits.append(("edge.cfg", "set local-preference 200", "set local-preference 100"))
                flow = packet("service", "edge", "10.0.0.1", "203.0.113.8")
                facts = self.simulate(EDGE, edits=edits, flows=[flow])
                routes = self.routes(facts, "edge", SERVICE)
                self.assertEqual(len(routes), 2)
                by_hop = {r["nextHop"]["ip"]: r for r in routes}
                for peer, hop, pref, path in [
                    ("primary", "10.0.0.2", local_pref, [65001, 65001, 65001]),
                    ("secondary", "10.0.0.6", 100, [65002]),
                ]:
                    route = by_hop[hop]
                    self.assertEqual(route["attributes"]["localPreference"], pref)
                    self.assertEqual([s["asns"] for s in route["attributes"]["asPath"]], [[asn] for asn in path])
                    selected = peer == winner
                    self.assertEqual((route["bgpStatus"], route["inMainRib"], route["inFib"]),
                                     ("BEST" if selected else "BACKUP", selected, selected))
                self.assert_paths(facts, "service", ("ACCEPTED", "edge", winner))

    def test_remote_as_mismatch_promotes_backup_while_link_still_forwards(self):
        edit = ("edge.cfg", "10.0.0.2 remote-as 65001", "10.0.0.2 remote-as 65099")
        facts = self.simulate(EDGE, edits=[edit], flows=[
            packet("service", "edge", "10.0.0.1", "203.0.113.8"),
            packet("link", "edge", "10.0.0.1", "10.0.0.2"),
        ])
        route, = self.routes(facts, "edge", SERVICE)
        self.assertEqual((route["nextHop"]["ip"], route["bgpStatus"], route["inMainRib"], route["inFib"]),
                         ("10.0.0.6", "BEST", True, True))
        self.assert_paths(facts, "service", ("ACCEPTED", "edge", "secondary"))
        self.assert_paths(facts, "link", ("ACCEPTED", "edge", "primary"))
        self.assertFalse(any(e["node"] == "edge" and e["peer"] == "primary" and e["direction"] == "import"
                             for e in facts["events"]))


class IbgpTests(ProtocolCase):
    def test_ebgp_to_ibgp_next_hop_self(self):
        # Secondary becomes an internal router with no route to the external peering subnet.
        peer = " neighbor 10.0.0.6 remote-as 65000"
        edits = [
            ("edge.cfg", " neighbor 10.0.0.6 remote-as 65002", peer),
            ("secondary.cfg", "router bgp 65002", "router bgp 65000"),
            ("secondary.cfg", "ip address 203.0.113.8", "ip address 203.0.113.11"),
            ("secondary.cfg", " network 203.0.113.8 mask 255.255.255.255\n", ""),
        ]
        flow = packet("to-primary", "secondary", "10.0.0.6", "203.0.113.8")
        for next_hop_self in (False, True):
            with self.subTest(next_hop_self=next_hop_self):
                rewrite = [("edge.cfg", peer, peer + "\n neighbor 10.0.0.6 next-hop-self")] if next_hop_self else []
                facts = self.simulate(EDGE, edits=edits + rewrite, flows=[flow])
                self.assertTrue(any((e["node"], e["peer"], e["prefix"], e["action"]) ==
                                    ("edge", "secondary", SERVICE, "sent") for e in facts["events"]))
                installed = [r for r in self.routes(facts, "secondary", SERVICE) if r["inMainRib"]]
                if next_hop_self:
                    route, = installed
                    self.assertEqual((route["protocol"], route["nextHop"]["ip"], route["inFib"]),
                                     ("ibgp", "10.0.0.5", True))
                    self.assert_paths(facts, "to-primary", ("ACCEPTED", "secondary", "edge", "primary"))
                else:
                    self.assertEqual(installed, [])
                    self.assert_paths(facts, "to-primary", ("NO_ROUTE", "secondary"))

    def test_reflection_and_split_horizon(self):
        disable_clients = [
            ("r2", f"  neighbor {ip} route-reflector-client\n", "") for ip in ["1.1.1.1", "3.3.3.3"]
        ]
        for reflects in (True, False):
            with self.subTest(reflects=reflects):
                report = self.simulate_report(RR, edits=[] if reflects else disable_clients, flows=[
                    packet("client", "r3", "3.3.3.3", "5.5.5.5"),
                ])
                facts = report["evidence"]
                roles = [r for r in report["roleHypotheses"] if r["node"] == "r2"
                         and r["scope"].get("prefix") == REFLECTED]
                self.assertFalse(any(r["role"] == "Origin" for r in roles))
                selection, = [r for r in roles if r["role"] == "Selection"]
                self.assertEqual(selection["scope"]["basis"], "cross_protocol")
                advertisements = [r for r in roles if r["role"] == "Distribution"
                                  and r["scope"]["peer"] == "r3" and r["scope"]["action"] == "sent"]
                self.assertEqual(bool(advertisements), reflects)
                if reflects:
                    self.assertEqual(advertisements[0]["validation"]["method"], "peer_received_from_session")
                rib = {(r["protocol"], r["bgpStatus"], r["inMainRib"], r["inFib"])
                       for r in self.routes(facts, "r2", REFLECTED)}
                self.assertEqual(rib, {("static", None, True, True), ("ibgp", "BEST", False, False)})
                sent = any((e["node"], e["peer"], e["action"], e["prefix"]) == ("r2", "r3", "sent", REFLECTED)
                           for e in facts["events"])
                self.assertEqual(sent, reflects)
                received = self.routes(facts, "r3", REFLECTED)
                if reflects:
                    route, = received
                    self.assertEqual((route["protocol"], route["nextHop"]["ip"], route["inFib"]),
                                     ("ibgp", "10.13.0.1", True))
                    self.assert_paths(facts, "client", ("NULL_ROUTED", "r3", "r1"))
                else:
                    self.assertEqual(received, [])
                    self.assert_paths(facts, "client", ("NO_ROUTE", "r3"))
