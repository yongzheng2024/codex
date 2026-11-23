# Snapshot understanding tests

Run from the repository root. Build the adapter once before running the Python
suite. The historical Cornetto graph tests also use pandas and NetworkX.

```sh
(cd netx/simulators/batfish && bazelisk build //projects/netx:snapshot_facts)
python3 -m pip install -r netx/tests/understand/requirements.txt
python3 -m unittest discover -s netx/tests -v
```

To check the default Batfish engine and traceroute behavior, run the vendored
suites from the Batfish workspace.

```sh
cd netx/simulators/batfish
bazelisk test //projects/batfish/src/test/java/org/batfish/dataplane/ibdp:tests \
  //projects/batfish/src/test/java/org/batfish/dataplane/traceroute:tests
```

## Cornetto reference control

The historical dataset-audit tests cover source membership, endpoint acceptance, waypoint dominance, exact ECMP fanout, equivalent-prefix representatives and both reference states. The native scenario-194 test checks that an accepted packet contradicts isolation for that probe.

To run the independent control, install the Cornetto pybatfish client for decoding the original question answers, use a compatible JDK (tested with JDK 25), and export the bundle from the scorer image. From the repository root:

```sh
image=iprotogeros/batfish-allione@sha256:333119e3ccd448d0d096973f1002552c580d0daefc90a0331f84cef7a656ff47
control_dir=$(mktemp -d)
docker run --rm --network none --entrypoint cat "$image" /allinone-bundle.jar > "$control_dir/cornetto.jar"
export CORNETTO_REFERENCE_JAR="$control_dir/cornetto.jar"
python3 -m unittest netx.tests.understand.test_prefix_graphs -v
```

The test launches the bundle's own data plane and three questions, compares the forwarding rows as a multiset and checks predicate membership for every row of the 10% sample. The expected SHA-256 of the exported bundle is `887666d1b64a6783332e2a4a547733df1e5d9a552e5b0cc93db9c7bdf2863233`. Set `JAVA_HOME` to select the JDK.

To check every available sampling percentage in one scenario, run the audit from the
repository root with the same reference bundle. It computes one native data plane
and one reference data plane, expands each CSV's summaries and checks every row.

```sh
python3 -m netx.tests.understand.audit_specifications \
  netx/benchmarks/cornetto/cornetto-benchmark/main_dataset/scenario-097 \
  --reference-jar "$CORNETTO_REFERENCE_JAR" --output netx/runs/audit-scenario-097
```

`comparison.json` records per-file counts, hashes, model gaps and forwarding-table
differences. `differences.csv.gz` identifies the sample and physical CSV line for
each disagreement, including repeats of a predicate across files.

To repeat the audit for the entire published dataset with Bash, set the reference
bundle as above and use a separate output directory for each scenario.

```sh
(
  set -e
  dataset=netx/benchmarks/cornetto/cornetto-benchmark/main_dataset
  mkdir -p netx/runs
  audit_dir=$(mktemp -d netx/runs/audit-published-XXXXXX)
  for id in $(seq -w 1 231); do
    python3 -m netx.tests.understand.audit_specifications "$dataset/scenario-$id" \
      --reference-jar "$CORNETTO_REFERENCE_JAR" --output "$audit_dir/scenario-$id"
  done
)
```

## Protocol coverage

The role tests check all six responsibilities against a snapshot with known
configuration and packet outcomes. Withdrawing a BGP network statement removes that publisher from the summary
while its connected route and the other independent publisher persist. Permitting an export adds
a receiver-side learned route. Detaching an ingress ACL changes HTTPS forwarding
while the egress SSH denial persists. Moving a tenant interface to the default
VRF removes the multi-VRF role. Additional cases change one header, session
address, link or ACL replay to check how the reported evidence level responds.
[Role tests](test_roles.py)

Scenario-085 has two repeatable probes selected from its full intent file.
The Boone probe exercises cross-protocol selection for `10.200.60.0/24`.
It also reaches the accepting router High Point, the waypoint on CSV line
20,789, through the intermediate Lexington, the waypoint on line 20,788.
High Point contributes an endpoint observation. The Orangeburg probe observes the intermediate device from the waypoint
predicate on CSV line 64 on a successful trace branch. Run both from the
repository root.

```sh
scenario=netx/benchmarks/cornetto/cornetto-benchmark/main_dataset/scenario-085
python3 -m netx.tools.understand "$scenario" \
  --specifications "$scenario/specifications/specifications_100pct.csv" \
  --queries netx/tests/understand/scenario_085_role_queries.json --mode compact
```

The protocol tests run the public Python analyzer against Cisco IOS, Junos and
FRR snapshots. Configuration variants use temporary copies. Expected next hops,
metrics, filter matches and packet dispositions come from the topology and the
configured policies. Comparing two independently converged snapshots tests the
forwarding effect of a configuration change.

- **BGP.** Two eBGP peers advertise the same prefix. Changing local preference
  reverses selection between different AS-path lengths. An incorrect remote AS
  promotes the backup while the peer's interface remains reachable. An iBGP
  client needs a resolvable next hop for an externally learned route. A reflector
  advertises an iBGP-best route even when a static route wins locally. Removing
  the client relationships suppresses that advertisement. [BGP tests](test_bgp.py)
- **OSPF.** The three-router area fixture checks intra-area, inter-area, E1 and
  E2 routes, exact costs and next hops. A local distribute list can leave a
  downstream packet without a route. An area mismatch removes learned routes.
  A cost increase reduces two forwarding paths to one. An FRR route map
  redistributes an eBGP route into OSPF with metric 10000. [OSPF tests](test_ospf.py)
- **IS-IS.** Junos L1 peers exchange loopbacks and selected static routes. L2
  peers in different areas exchange routes with asymmetric costs. Separate
  variants exercise different L1 areas, incompatible levels and a passive
  transit interface. Each negative case checks reachability of the directly
  connected neighbor as a control. [IS-IS tests](test_isis.py)
- **ACLs.** Tests cover first-match ordering, explicit and implicit deny, TCP,
  ICMP and both boundaries of a UDP port range. They check the source address
  after NAT at the egress filter, and a flow with one denied ECMP path and one successful path. A probe
  pair on Cornetto scenario-199 also exercises a real ingress attachment.
  [ACL tests](test_acl.py) and [Cornetto tests](test_understand.py)

The IGP cases establish what was installed and where a packet went. Explaining
which SPF candidate lost, which adjacency failed, or which IGP policy rejected
an advertisement still requires protocol-specific evidence from the simulator.

## Run the pipeline on sampled Cornetto scenarios

From the repository root, run the command below after building the adapter.
The published dataset contains scenarios 001 through 231. To exercise the
additional local fixture alongside the random sample, pass
`--include netx/benchmarks/cornetto/cornetto-benchmark/main_dataset/scenario-300`.

```sh
python3 -m netx.tests.understand.sample_cornetto --seed 300 --scenarios 3 --rows 5
```

The runner draws from sorted scenarios with at most 30 Cisco configuration
files and declarations for BGP, OSPF, IS-IS and an attached IPv4 ACL. For each
selected scenario it draws up to five intent rows across all available types from
`specifications_10pct.csv` by default. It passes their original CSV line numbers
to the analyzer so the report identifies the source file and the golden versus
faulty comparison. It prints a run directory containing
the original CSV line numbers, per-row summary links, role counts and full NetX
reports. Default flow probes use ICMP. The targeted ACL regression above uses
two explicit sources on the same interface.

Some mixed Cornetto snapshots use the Cisco command `is-type level-1-2`.
The vendored parser reports this spelling as unrecognized. Those snapshots
retain their diagnostics and have partial model coverage.
