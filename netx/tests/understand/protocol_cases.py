"""Run controlled configuration variants through the public NetX analyzer."""

import json
from pathlib import Path
import shutil
import tempfile
import unittest

from netx.tools.understand import NETX, analyze


EDGE = Path(__file__).resolve().parent / "snapshot"
RESOURCES = NETX / "simulators/batfish/projects/batfish/src/test/resources/org/batfish"
IBDP = RESOURCES / "dataplane/ibdp"


def packet(name, node, src, dst, *, interface=None, protocol="UDP", port=33434):
    flow = {
        "ingressNode": node, "srcIp": src, "dstIp": dst, "ipProtocol": protocol, "packetLength": 64,
    }
    if interface:
        flow["ingressInterface"] = interface
    else:
        flow["ingressVrf"] = "default"
    if protocol in {"TCP", "UDP"}:
        flow.update(srcPort=50000, dstPort=port)
    elif protocol == "ICMP":
        flow.update(icmpVar=8, icmpCode=0)
    return {"id": name, "flow": flow}


class ProtocolCase(unittest.TestCase):
    def simulate(self, snapshot, *, edits=(), flows=()):
        return self.simulate_report(snapshot, edits=edits, flows=flows)["evidence"]

    def simulate_report(self, snapshot, *, edits=(), flows=(), specifications=None):
        """Apply exact edits to a private copy and require a complete simulation."""
        with tempfile.TemporaryDirectory(prefix="netx-protocol-case-") as directory:
            temp = Path(directory)
            if edits:
                snapshot = shutil.copytree(snapshot, temp / "snapshot")
            for filename, original, replacement in edits:
                path = snapshot / "configs" / filename
                config = path.read_text()
                self.assertEqual(config.count(original), 1, f"Fixture drift in {filename}: {original!r}")
                path.write_text(config.replace(original, replacement))
            plan = temp / "queries.json"
            plan.write_text(json.dumps({"flows": flows}))
            report = analyze(snapshot, queries_path=plan, specifications=specifications)
        self.assertEqual(report["status"], "ok", report["gaps"])
        self.assertCountEqual([q["id"] for q in report["evidence"]["queries"]],
                              [q["id"] for q in flows])
        return report

    @staticmethod
    def routes(facts, node, prefix):
        return [r for r in facts["routes"] if r["node"] == node and r["vrf"] == "default"
                and r["attributes"]["network"] == prefix]

    @staticmethod
    def query(facts, name):
        query, = [q for q in facts["queries"] if q["id"] == name]
        return query

    def assert_paths(self, facts, name, *expected):
        """Compare the disposition and device sequence of every returned trace."""
        result = self.query(facts, name)["result"]
        paths = [(trace["disposition"], *(h["node"]["name"] for h in trace["hops"]))
                 for trace in result["traces"]]
        self.assertEqual(result["totalPaths"], len(paths))
        self.assertCountEqual(paths, expected)
