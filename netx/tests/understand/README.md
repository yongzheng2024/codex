# Snapshot understanding tests

Run from the repository root. Build the adapter once before running the Python
suite. Discovery starts at the shared NetX test directory.

```sh
(cd netx/simulators/batfish && bazelisk build //projects/netx:snapshot_facts)
python3 -m unittest discover -s netx/tests -v
```

To check the default Batfish engine and traceroute behavior, run the vendored
suites from the Batfish workspace.

```sh
cd netx/simulators/batfish
bazelisk test //projects/batfish/src/test/java/org/batfish/dataplane/ibdp:tests \
  //projects/batfish/src/test/java/org/batfish/dataplane/traceroute:tests
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
