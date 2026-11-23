# Repairing the NetX Understand tool

## 1. Goal

Use this guide when an Understand run fails, reports incomplete evidence, or produces a conclusion that appears inconsistent with its inputs. A fault in the simulated network can be a valid test input. A tool repair needs a claim about how Understand should read, model, link or report that input. [Understand design and role boundaries](develop_understand.md)

Keep the reference and the observation identifiable throughout the investigation. A Cornetto row and its `sources` label describe predicate presence in the golden and faulty forwarding graphs. Batfish facts from `final_configs/` describe the fault-injected snapshot under the recorded simulator version and settings. Device roles are inferences from those facts. [Cornetto predicate semantics](benchmarks/cornetto/cornetto-benchmark/README.md)

Current Understand runs evaluate the selected CSV on the same local Batfish convergence that supplies role evidence. Each row in `intentEvaluation.rows` records the observed presence and the repair target. The historical comparisons below concern the separate Cornetto scorer. [Current evaluation](tools/understand/README.md#reading-the-evidence)

## 2. Historical cases from the first 20-scenario run

The run used seed `20261123`, every row of each selected `specifications_10pct.csv`, and the default ICMP probes. All 20 scenarios produced reports. Thirteen returned `ok` and seven returned `partial`. The local evidence bundle is `netx/runs/understand-random20-20261123-mclsl3y4/`. Its manifest records the draw order and input hashes. The observations below can also be investigated from the repository fixtures.

- **Isolation and accepted packets.** Of 916 probed rows whose reference records isolation as present in the faulty state, 877 had an accepted trace to the original destination address. In scenario-194, CSV line 2 records isolation from `0_as65002_0` to `10.181.0.40/31`. Probe `intent-1` reached `10.181.0.40`. Both historical graph scorers found the isolation predicate on this snapshot. The current endpoint check reports isolation absent for the accepted probe. The connected route terminates at `delivered_to_subnet` in the prefix graph while the ICMP packet reaches the interface. The packet observation remains relevant to that flow. [Reference row](benchmarks/cornetto/cornetto-benchmark/main_dataset/scenario-194/specifications/specifications_10pct.csv#L2) · [Predicate extractor](benchmarks/cornetto/src/utils/evaluation_utils/forwarding_analysis/predicates.py)
- **Partial configuration models.** Batfish flagged `is-type level-1-2` in 39 files across four scenarios. Three other scenarios each contained an OSPF `network` statement ending at `area`. Preserve the original line and parser diagnostic. Compare each syntax family with a known control and check which adjacency or route, if any, changes. [IS-IS input, line 74](benchmarks/cornetto/cornetto-benchmark/main_dataset/scenario-041/final_configs/configs/34_as65008_Tijuana.cfg#L74) · [OSPF input, line 106](benchmarks/cornetto/cornetto-benchmark/main_dataset/scenario-230/final_configs/configs/0_as65003_23-8.cfg#L106)
- **Sparse role attribution.** Of 10,156 reference rows, 138 had a linked device role. Nine scenarios had zero attributed rows, including four with status `ok`. For an unassigned row, check whether a probe or routing fact covers it, whether that evidence meets a role rule, and whether the qualifying action links back to the row. In scenario-100 all 22 waypoint rows had probes reporting `DENIED_IN`. Those probes supply no accepted branch through the named waypoint. [Role rules](develop_understand.md#c-boundaries-of-the-six-device-roles) · [Member linking](tools/understand/role_intents.py)

### Which Batfish implements the reference?

The original Config2Spec distribution pins Batfish commit `73946b2f1bdea5f1146e4db4f2586e071da752df` and patches it for Minesweeper. Its forwarding engine attaches a connected route to the sink. The Cornetto scoring code calls a custom `forwardingBehaviorTable` question and feeds its answers, layer-1 edges and IP owners into a Python graph extractor. Only the `accepted` action produces an edge to the prefix vertex. Both builds inspected for the scoring comparison report `0.36.0`, although their Java APIs differ. The release string does not identify a source revision. The scorer image establishes a reproducible comparison point. The exact image used when publishing the CSVs remains unverified. [Config2Spec setup](simulators/config2spec/batfish_interface/README.md) · [Original sink construction](simulators/config2spec/config2spec/dataplane/batfish_engine.py) · [Cornetto image](benchmarks/cornetto/scripts/batfish_setup/pull_and_run_container.sh) · [Scoring entry point](benchmarks/cornetto/src/utils/evaluation_utils/newer_spec_evaluator.py)

For an engine comparison, pass the same snapshot directory to both engines and compare graph-relevant forwarding columns before comparing CSV membership. Record external layer-1 topology and BGP export separately. In scenario-100, adding the benchmark topology to the scorer input changes 12 waypoint results in the 10% sample. The standalone graph audit uses the supplied snapshot. The current NetX evaluation uses the physical topology with its role evidence. [Executable reference control](tests/understand/README.md#cornetto-reference-control)

The compatibility rules are marked with `NOTE: Cornetto` in Java and Python. The
engine choice and question port live in the NetX Batfish adapter. Snapshot selection,
graph representatives and reference polarity live in Understand.
Run `rg 'NOTE: Cornetto' netx/simulators/batfish/projects/netx netx/tools netx/benchmarks/cornetto/src/utils/evaluation_utils/forwarding_analysis`
to locate these decisions when updating the scorer.

### Alignment results for the original draw

On the same 20 fault-injected scenarios and complete 10% samples, the port and pinned scorer produced identical multisets of 43,367 forwarding rows across the six compared columns (device, VRF, prefix, action, next-hop interface and next-hop IP). They agreed on all 10,156 CSV membership queries. Both graphs contained isolation for all 877 rows with an accepted packet witness. Introducing the external topology during the comparison produced 17 differences from the CSV across scenarios 026, 097 and 100. Using the original snapshot reduced this to one difference. The role pass linked the same 138 reference rows. Seven snapshots still carried parser diagnostics.

- **Scenario-097, original 10% sample, line 50.** The published CSV records `broken_added` reachability from `1_as65005_wartburg` to `10.180.0.1/32`. Both engines and a replay using the original Cornetto Python extractor report it absent from the faulty snapshot. The prefix graph contains an accepting router, `0_as65002_gainesboro`. The source has no forwarding row for this exact prefix and no incident device edge in that graph. The historical mining environment and golden snapshot would help explain the published label. [Retrieve the original sample](benchmarks/cornetto/cornetto-benchmark/README.md#netx-reconciliation)
- **Scenario-300.** This local regression fixture sits outside the published draw. NetX and the pinned scorer agree on every supplied predicate. For the faulty snapshot the 10% CSV agrees on 3 of 9 rows, and the 100% CSV agrees on 5 of 12. Keep the fixture targets available to the summarizer and record the observed differences. [Fixture status](benchmarks/cornetto/cornetto-benchmark/README.md) · [Full sample](benchmarks/cornetto/cornetto-benchmark/main_dataset/scenario-300/specifications/specifications_100pct.csv)

### All 231 published scenarios

The counts in this section refer to the original published CSVs at repository
revision `da6221cf7d1b2c8f2cc6f9b390d0dcea96b983d0`. The working benchmark
includes subsequent label corrections. [Local dataset changes](benchmarks/cornetto/cornetto-benchmark/README.md#netx-reconciliation)

NetX and Cornetto's pinned scorer agreed on all 2,013,925 distinct scenario-specific predicates in the 1,611 published CSV files. The summaries for all 5,098,630 row occurrences expanded to their original source sets, parameters, scopes and row pointers. The two engines also agreed on the six graph-relevant columns of all 1,041,254 forwarding rows, preserving duplicates. Scenarios 094 and 095 supply samples through 20%. The other 229 supply a 100% sample. [Reproduction command](tests/understand/README.md#cornetto-reference-control)

For the supplied faulty snapshots, 5,093,453 row occurrences matched the published labels. The other 5,177 occurred in 211 files across 45 scenarios. The same predicate can appear at several sampling percentages.

- All 4,787,212 `intact` rows were present and all 288,361 rows labeled solely `broken_removed` were absent.
- Of 22,123 `broken_added` rows, 4,243 were absent in both scorers. These represent 1,735 distinct predicates. For example, line 3 of the original 100% sample for scenario-051 labels isolation from Tampa to `10.180.0.65/32` as added. The graph has an edge from Tampa to Miami, which accepts that prefix. [Retrieve the original sample](benchmarks/cornetto/cornetto-benchmark/README.md#netx-reconciliation)
- All 934 `broken_removed|intact` rows were present in both scorers. They represent 445 distinct predicates. Cornetto's label parser gives the broken tag precedence. These rows therefore disagree with its faulty-state expectation even though their golden target also requires presence. [Scorer label parser](benchmarks/cornetto/src/utils/evaluation_utils/newer_spec_evaluator.py)

The difference first appears between the published faulty-state labels and the replayed graph membership. An independent replay of the unmodified Cornetto Python extractor agreed on all 2,013,925 predicates. Of the 231 snapshots, 96 have model diagnostics. On copies of scenarios 051, 079 and 097, removing the 47 unrecognized explicit dual-level IS-IS statements left the forwarding, IP-owner and layer-1 tables identical. Each affected process already started at the dual-level default. This control tests that warning on those three snapshots. [Cisco IS-IS initialization](simulators/batfish/projects/batfish/src/main/java/org/batfish/grammar/cisco/CiscoControlPlaneExtractor.java#L3278)

For 1,427 of the 2,180 discrepant predicates, the source was outside the device graph for the specified prefix. Cornetto enumerates sources from graph vertices, so it emits no predicate for those source/prefix pairs. Adding the external physical topology in the 45 affected cases brought three predicates in scenario-134 into agreement, left 2,177 discrepancies in place and introduced 12,220 across previously agreeing predicates. Preserve the snapshot boundary when reproducing a score.

The 231 scenarios supply no golden snapshot, and the exact mining environment used to publish the labels is unverified. The reconciled CSVs retain single labels for predicates present in either state. Rows absent in both states are preserved in the original revision and the audit ledger. The local full-run directory is `netx/runs/understand-231-K2htZ3/`. Its `files.csv` covers every sample and `reconciliation.csv.gz` maps each disagreement to the physical CSV line, published states and the two observations. Device roles require separate validation against routing and packet evidence.

## 3. Reproduce one observation

Start with one row, warning or failed command. For the isolation example, run from the repository root after building the adapter. [Build instructions](tools/understand/README.md#run-the-three-router-example)

```sh
scenario=netx/benchmarks/cornetto/cornetto-benchmark/main_dataset/scenario-194
python3 -m netx.tools.understand "$scenario" \
  --specifications "$scenario/specifications/specifications_10pct.csv" --mode compact
```

Use the returned `details` path to open `result.json`. In the recorded run, `#/benchmark/rows/0` contains CSV line 2, and `#/evidence/queries/0/result/traces/0` contains the accepting branch. In a new run, locate the row by its source line and the probe by its ID before comparing pointers. For an execution failure, capture the exit code, stderr and last completed step even if the tool produced no report.

Use the following fields to record a new case. A second developer should be able to replay the observation using the record.

- **Replay** — scenario, snapshot state, input files or hashes, code revision, Batfish version, simulation settings and CLI command. For a batch, retain the seed and selected scenario IDs.
- **Expected behavior and basis** — the exact predicate, role rule or output contract and its source.
- **Observed behavior** — CSV or configuration line, device and VRF, relevant prefix or packet, report pointer and status or diagnostic.
- **Open question** — the smallest comparison that would distinguish the plausible explanations. Record the decision after that comparison.

## 4. Locate the first discrepancy

1. **Input and summary.** Reconstruct the source set for the affected prefix from `baseNodes` and its exceptions. Check the predicate parameters, raw status, original CSV lines and duplicate rows. If the saved summary already differs from the input, the discrepancy can be reproduced without a simulator run. [Input handling](tools/understand/inputs.py) · [Summarization](tools/understand/summaries.py)
2. **Simulation.** Inspect parser and conversion diagnostics for the device, then the route, policy event or trace for the same VRF and prefix. For a packet, record its ingress, destination, disposition and branch. Complete trace enumeration covers the branches for those headers. A claim about every path in the prefix graph needs graph-level evidence. [Batfish adapter](simulators/batfish/projects/netx/) · [Report diagnostics](tools/understand/report.py)
3. **Role and presentation.** Follow a contribution's `intentLinks` to the assignment, source rows and validation evidence. Check that the device, action and scope agree. A row with insufficient evidence belongs in `unattributedRows`. If the full JSON is correct, compare the compact output and the Markdown observation against that same record. [Role validation](tools/understand/role_validation.py) · [Responsibility grouping](tools/understand/responsibilities.py) · [Overview renderer](tools/understand/overview.py)

## 5. Verify a repair

For a confirmed defect, put a regression case in `netx/tests/understand/`. Demonstrate the failing assertion before the change and the expected result afterward. Include a nearby control, such as a second peer whose export should still succeed or a row that should still have no device owner. Keep the benchmark input fixed. Use a separate fixture for any configuration variation. [Test fixtures and protocol suites](tests/understand/README.md)

Rerun the affected scenario with the original inputs and probe settings. Compare the changed row, warning or role link, then check its control. For shared grouping changes, repeat the affected cases from the saved draw and verify exact row expansion and evidence pointers. For NetX-specific simulation changes, use the adapter hooks and run the corresponding ordinary Batfish tests as a control. Report how many scenarios completed, how many reference rows a probe covered and how many had role evidence, each with its denominator.

Close a defect with the before-and-after evidence and regression test. If the comparison establishes expected behavior, record the rule that explains it. If required evidence is still missing, leave the case open and name the missing observation.
