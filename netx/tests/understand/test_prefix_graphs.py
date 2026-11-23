"""Regression cases for the boundary between prefix predicates and concrete packets."""

from collections import Counter
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock

from netx.tools.understand import NETX, analyze
from netx.tools.understand.prefix_graphs import compare_graphs

PREFIX = "10.181.0.40/31"
SCENARIO = NETX / "benchmarks/cornetto/cornetto-benchmark/main_dataset/scenario-194"


def row(kind, node, prefix=PREFIX, *, waypoint="", routes="", label="intact"):
    return dict(predicate_type=kind, node=node, prefix=prefix, waypoint=waypoint, num_routes=routes, sources=label)


def action(node, action, target=None, prefix=PREFIX):
    return {"Node": node, "Action": action, "Prefix": prefix, "Next_Hop_Interface": None, "Next_Hop_IP": target}


def tables(actions):
    return {"forwarding": actions, "layer1": [],
            "ipOwners": [{"IP": f"10.0.0.{i}", "Node": {"name": n}}
                         for i, n in enumerate(("source", "left", "right", "end"), start=1)]}


class PrefixGraphTests(unittest.TestCase):
    def test_subnet_endpoint_blocked_edge_and_absent_device(self):
        data = tables([action("source", "forwarded", "10.0.0.2"), action("left", "delivered_to_subnet"),
                       action("left", "forwarded", "10.0.0.4"), action("left", "forwarded_blocked_incoming_filter"),
                       action("end", "accepted")])
        rows = [row("isolation", "source"), row("reachability", "source", label="broken_removed"),
                row("isolation", "end", label="broken_added"), row("isolation", "missing", label="unknown"),
                row("isolation", "source")]
        faulty = compare_graphs(data, rows, "fault_injected", ["partial parse"])
        self.assertEqual([r["presence"] for r in faulty["rows"]], ["present", "absent", "absent", "absent", "present"])
        self.assertEqual(faulty["counts"], {"matches": 3, "differs": 1, "unspecified": 1})
        self.assertEqual(faulty["modelStatus"], "partial")
        golden = compare_graphs(data, rows, "original_correct", [])
        self.assertEqual(golden["rows"][1]["agreement"], "differs")
        self.assertEqual(golden["rows"][2]["agreement"], "matches")

    def test_layer1_precedence_accepting_waypoint_and_exact_ecmp(self):
        data = tables([action("source", "forwarded", "10.0.0.2"), action("source", "forwarded", "10.0.0.3"),
                       action("left", "forwarded", "10.0.0.4"), action("right", "forwarded", "10.0.0.4"),
                       action("end", "accepted")])
        rows = [row("waypointing", "source", waypoint=w) for w in ("end", "left", "source")]
        rows.extend(row("load_balancing", "source", routes=n) for n in ("2", "3"))
        self.assertEqual([r["presence"] for r in compare_graphs(data, rows, "fault_injected", [])["rows"]],
                         ["present", "absent", "absent", "present", "absent"])
        data["forwarding"][0]["Next_Hop_Interface"] = "Ethernet0"
        data["layer1"] = [{"Interface": {"hostname": "source", "interface": "Ethernet0"},
                           "Remote_Interface": {"hostname": "right", "interface": "Ethernet1"}}]
        self.assertEqual(compare_graphs(data, rows, "fault_injected", [])["rows"][3]["presence"], "absent")

    def test_scorer_emits_only_representative_of_identical_graphs(self):
        other = "192.0.2.0/24"
        data = tables([action("source", "forwarded", "10.0.0.2", prefix=p) for p in (PREFIX, other)])
        rows = [row("isolation", "source", prefix=p) for p in (PREFIX, other, "198.51.100.0/24")]
        observed = compare_graphs(data, rows, "fault_injected", [])["rows"]
        self.assertEqual([r["representativePrefix"] for r in observed], [PREFIX, PREFIX, None])
        self.assertEqual([r["presence"] for r in observed], ["present", "absent", "absent"])


class ScorerInputsTests(unittest.TestCase):
    def test_benchmark_links_are_scoped_to_device_analysis(self):
        scenario = SCENARIO.with_name("scenario-100")
        report = analyze(scenario, specifications=scenario / "specifications/specifications_10pct.csv",
                         specification_lines={516, 517})
        self.assertTrue(report["input"]["topology"].endswith("/data_and_metrics/topology.json"))
        graph = report["predicateComparison"]
        self.assertEqual((graph["engine"], graph["topology"]), ("ibdp", "snapshot_inputs"))
        self.assertEqual(graph["counts"], {"matches": 2})
        self.assertEqual([r["presence"] for r in graph["rows"]], ["present", "present"])


class Scenario194Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = analyze(SCENARIO, specifications=SCENARIO / "specifications/specifications_10pct.csv")

    def test_isolation_and_accepted_probe_coexist(self):
        graph = self.report["predicateComparison"]
        self.assertEqual(graph["counts"], {"matches": 271})
        self.assertEqual(graph["rows"][0]["presence"], "present")
        q = next(q for q in self.report["evidence"]["queries"] if q["id"] == "intent-1")
        self.assertEqual(q["result"]["flow"]["dstIp"], "10.181.0.40")
        self.assertIn("ACCEPTED", q["behavior"]["dispositions"])

    @unittest.skipUnless(os.getenv("CORNETTO_REFERENCE_JAR"), "requires the Cornetto scorer bundle")
    def test_against_original_engine_and_question(self):
        from pybatfish.datamodel.answer import TableAnswer
        from netx.benchmarks.cornetto.src.utils.evaluation_utils.forwarding_analysis.extract_forwarding_predicates import (
            extract_forwarding_predicates,
        )
        from netx.benchmarks.cornetto.src.utils.evaluation_utils.newer_spec_evaluator import read_specification_from_csv

        jar = Path(os.environ["CORNETTO_REFERENCE_JAR"]).resolve()
        with tempfile.TemporaryDirectory() as tmp:
            temp = Path(tmp)
            source = Path(__file__).parent / "reference/CornettoReference.java"
            result = temp / "tables.json"
            java = Path(os.environ["JAVA_HOME"]) / "bin/java" if "JAVA_HOME" in os.environ else "java"
            subprocess.run([java, "-cp", jar, source, SCENARIO / "final_configs", temp / "work", result], check=True)
            control = json.loads(result.read_text())

        def keys(rows):
            return Counter((r["Node"]["name"] if isinstance(r["Node"], dict) else r["Node"],
                            r["VRF"], r["Prefix"], r["Action"], r.get("Next_Hop_IP"), r.get("Next_Hop_Interface"))
                           for r in rows)
        self.assertEqual(keys(control["forwarding"]["rows"]), keys(self.report["evidence"]["cornettoTables"]["forwarding"]))
        answers = {key: TableAnswer({"answerElements": [value]}) for key, value in control.items()}
        # Supply the three real answers to the online extractor without starting an HTTP service.
        session = Mock()
        session.q.ipOwners.return_value.answer.return_value = answers["ipOwners"]
        session.q.layer1Edges.return_value.answer.return_value = answers["layer1"]
        observed = set(extract_forwarding_predicates(answers["forwarding"].frame(), bf=session).all())
        reference = read_specification_from_csv(str(SCENARIO / "specifications/specifications_10pct.csv"))
        expected = ["present" if p in observed else "absent" for p in reference]
        self.assertEqual(expected, [r["presence"] for r in self.report["predicateComparison"]["rows"]])
