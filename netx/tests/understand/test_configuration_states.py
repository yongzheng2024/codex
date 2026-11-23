"""Reference predicates and simulated behavior retain their own configuration state."""

import json
from pathlib import Path
import shutil
import tempfile
import unittest

from netx.tests.understand.protocol_cases import EDGE, packet
from netx.tools.understand import analyze
from netx.tools.understand.compact import compact
from netx.tools.understand.inputs import prepare_snapshot, read_specs, reference_input, reference_matches_snapshot
from netx.tools.understand.summaries import reference_presences


class ConfigurationStateTests(unittest.TestCase):
    def test_reference_polarity(self):
        for label, expected, faulty in [
            ("intact", "present", "present"), ("broken_removed", "present", "absent"),
            ("broken_added", "absent", "present"), ("broken_removed|intact", "present", "absent"),
            ("broken_added|intact", "absent", "present"), ("unrecognized", "unspecified", "unspecified"),
            ("intact|unrecognized", "unspecified", "unspecified"),
            ("broken_added|broken_removed", "unspecified", "unspecified"),
        ]:
            with self.subTest(label=label):
                self.assertEqual(reference_presences(label), (expected, faulty))

    def test_predicate_requires_its_own_parameters(self):
        with tempfile.TemporaryDirectory() as directory:
            specs = Path(directory) / "specifications.csv"
            header = "predicate_type,node,prefix,waypoint,num_routes,sources\n"
            for predicate, parameters, message in [
                ("waypointing", ",", "waypointing requires a waypoint router"),
                ("load_balancing", ",1", "num_routes must be at least 2"),
                ("reachability", "gw,", "waypoint is only used for waypointing"),
                ("isolation", ",2", "num_routes is only used for load_balancing"),
            ]:
                with self.subTest(predicate=predicate):
                    specs.write_text(f"{header}{predicate},edge,203.0.113.8/32,{parameters},intact\n")
                    with self.assertRaisesRegex(ValueError, f":2 {message}"):
                        read_specs(specs)

    def test_standalone_inputs_have_independent_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            path = temp / "final_configs"
            (path / "configs").mkdir(parents=True)
            (path / "layer1_topology.json").write_text('{"edges":[]}')
            self.assertEqual(prepare_snapshot(path, temp)[1]["configurationState"], "as_supplied")
            self.assertEqual(reference_input(EDGE.parent / "intents.csv")["configurationState"], "supplied_reference")
            self.assertIsNone(reference_input(None)["configurationState"])

    def test_cornetto_topology_is_staged_for_either_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scenario = root / "scenario-001"
            topology = scenario / "data_and_metrics/topology.json"
            topology.parent.mkdir(parents=True)
            topology.write_text(json.dumps({
                "nodes": [{"id": "1", "hostname": "edge"}, {"id": "2", "hostname": "core"}],
                "links": [{"interfaces": [{"node": "1", "name": "Eth0"}, {"node": "2", "name": "Eth1"}]}],
            }))
            for snapshot in ("initial_configs", "final_configs"):
                (scenario / snapshot / "configs").mkdir(parents=True)
            for snapshot, state in [("initial_configs", "original_correct"), ("final_configs", "fault_injected")]:
                temp = root / snapshot
                staged, provenance = prepare_snapshot(scenario / snapshot, temp)
                self.assertEqual(provenance["configurationState"], state)
                self.assertEqual(provenance["topology"], str(topology))
                self.assertEqual(len(json.loads((staged / "batfish/layer1_topology.json").read_text())["edges"]), 2)

    def test_fault_changes_observations_while_reference_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            scenario = temp / "scenario-001"
            initial = shutil.copytree(EDGE, scenario / "initial_configs")
            final = shutil.copytree(EDGE, scenario / "final_configs")
            config = final / "configs/edge.cfg"
            config.write_text(config.read_text().replace(" permit tcp any host 203.0.113.8 eq 80",
                                                        " deny ip any host 203.0.113.8"))
            specs = scenario / "specifications/specifications_20pct.csv"
            specs.parent.mkdir()
            specs.write_text("predicate_type,node,prefix,waypoint,num_routes,sources\n"
                             "reachability,edge,203.0.113.9/32,,,intact\n"
                             "reachability,edge,203.0.113.8/32,,,broken_removed\n"
                             "isolation,edge,203.0.113.8/32,,,broken_added\n")
            plan = temp / "flows.json"
            plan.write_text(json.dumps({"flows": [packet("web", "edge", "192.0.2.2", "203.0.113.8",
                                                         interface="GigabitEthernet0/2", protocol="TCP", port=80)]}))
            original = analyze(initial, specifications=specs, specification_lines={3, 4}, queries_path=plan)
            faulty = analyze(scenario, specifications=specs, specification_lines={3, 4}, queries_path=plan)
            self.assertEqual(prepare_snapshot(final, temp)[1], faulty["input"])
            self.assertEqual(original["benchmark"], faulty["benchmark"])
            self.assertEqual([row["line"] for row in faulty["benchmark"]["rows"]], [3, 4])
            for report, state, disposition in [(original, "original_correct", "ACCEPTED"),
                                               (faulty, "fault_injected", "DENIED_IN")]:
                self.assertEqual(report["status"], "ok")
                self.assertEqual(report["input"]["configurationState"], state)
                self.assertEqual(report["evidence"]["configurationState"], state)
                self.assertTrue(all(r["configurationState"] == state for r in report["roleHypotheses"]))
                self.assertEqual(report["evidence"]["queries"][0]["behavior"]["dispositions"], [disposition])
                overview = compact(report, temp / "result.json")
                self.assertEqual(overview["input"]["configurationState"], state)
                self.assertEqual(overview["benchmark"]["configurationState"], "golden_vs_faulty")
                self.assertEqual(overview["benchmark"]["nominalSamplePercent"], 20)
                self.assertEqual((overview["benchmark"]["rowsInFile"], overview["intentRows"]), (3, 2))
                self.assertEqual({(s["kind"], s["scope"]["expectedPresence"], s["scope"]["faultyPresence"])
                                  for s in overview["summaries"]},
                                 {("reachability", "present", "absent"), ("isolation", "absent", "present")})
            denial, = [r for r in faulty["roleHypotheses"] if r["role"] == "Access control"]
            self.assertEqual(denial["validation"]["status"], "corroborated")
            self.assertEqual({link["expectedPresence"] for link in denial["intentLinks"]}, {"present", "absent"})
            self.assertFalse(any(r["role"] == "Access control" for r in original["roleHypotheses"]))

            other = shutil.copytree(scenario, temp / "other" / scenario.name)
            copied = other / specs.relative_to(scenario)
            self.assertTrue(reference_matches_snapshot(reference_input(copied), faulty["input"]))
            different_id = other.rename(other.with_name("scenario-002"))
            self.assertFalse(reference_matches_snapshot(reference_input(different_id / specs.relative_to(scenario)),
                                                        faulty["input"]))
            different_id.rename(other)
            copied.write_text(copied.read_text().replace("broken_removed", "intact"))
            mismatched = analyze(scenario, specifications=copied,
                                 specification_lines={3, 4}, queries_path=plan)
            self.assertEqual(mismatched["status"], "partial")
            self.assertTrue(any("could not be matched to snapshot" in gap for gap in mismatched["gaps"]))
            self.assertEqual(len(mismatched["benchmark"]["rows"]), 2)
            self.assertEqual(mismatched["roleHypotheses"], [])
            self.assertTrue(all(not s["relatedRoles"] for s in mismatched["summaries"]))
