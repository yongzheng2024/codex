# Understand a network snapshot

NetX groups supplied forwarding predicates into summaries with exceptions. It uses
Batfish routing events, packet traces and routing domains to describe six scoped
device roles. Start at a summary to see its devices, their contributions, relevant
reference members, packet observations and rows still awaiting attribution.

The NetX plugin uses SpecLens-compatible BGP multipath export: each installed
multipath candidate is evaluated against the peer's export policy. It assigns
internal path IDs when needed to keep those candidates distinct at the receiver.
These IDs and this behavior do not imply that ADD-PATH was negotiated or that a
real device would send multiple paths. Ordinary Batfish's `ibdp` plugin retains
its default best-path export behavior. Reports identify the assumption as
`bgpMultipathExport: speclens_compatible`.

## Run the three-router example

Build the adapter in the vendored Batfish workspace. The Python entry point
requires Python 3.10 or newer. The Java adapter reads and simulates the snapshot locally. The default workflow needs the NetX Batfish build and the Python standard library.

```sh
(cd netx/simulators/batfish && bazelisk build //projects/netx:snapshot_facts)
python3 -m netx.tools.understand netx/tests/understand/snapshot \
  --specifications netx/tests/understand/intents.csv \
  --queries netx/tests/understand/queries.json --mode compact
```

For `203.0.113.8/32`, edge selects primary at local preference 200 and keeps
secondary at 100 as a backup. The selected route appears in its main RIB and FIB.
Edge rejects `203.0.113.9/32` on import. Primary rejects `203.0.113.10/32` on
export. The policy events point to the peer and available route-map definitions.

The guest interface on edge permits HTTP and denies HTTPS to the same address.
SSH reaches the egress filter, which denies the packet there. The example CSV
contains illustrative intents for this fixture. A summary covering the guest
traffic links to the Access control role and the observed denying rule.

Use the returned `result_id` and report pointers to inspect compact results.
Compact mode also writes a readable `summary.md` beside the JSON when a reference CSV is supplied.
Its **Intent Summary** section lists the reference predicates and their scope.
Each entry in **Device Roles** starts with key devices, one scoped observation
and row coverage. The preview prioritizes linked filters for reachability and
isolation, route selection for load balancing and transmission for waypointing.
Expand **Role details and evidence** to see all role groups, per-device scopes,
probe outcomes and rows awaiting evidence.
Array results support paging. The full report is stored under
`netx/runs/<result_id>/result.json`. Full mode writes the report to stdout.
Both modes execute the same queries.

```sh
python3 -m netx.tools.understand.details "$result_id" '#/evidence/events' --limit 5
python3 -m netx.tools.understand.details "$result_id" '#/summaries/0'
```

Python callers can use `netx.tools.understand.analyze(snapshot_path,
queries_path=..., specifications=...)` with `pathlib.Path`
inputs. Each call uses a private Batfish storage directory. The NetX subclass
of `IncrementalDataPlanePlugin` supplies a prefix tracer per device and VRF.
Only this adapter registers the subclass. The [test guide](../../tests/understand/README.md)
covers protocol regressions, upstream compatibility checks and Cornetto sampling.

## Query scope

A query file is a JSON object. Each query has an `id` unique within its section.
The [example query file](../../tests/understand/queries.json) specifies route prefixes, concrete flows and a conditional BGP policy test.

- **prefixes** selects exact IPv4 prefixes for RIB and BGP propagation evidence.
  Omitting the field includes all prefixes. Packet searches use their own scopes.
- **flows** supplies Batfish `Flow` objects. Choose an ingress VRF or an ingress
  interface and provide the packet headers, including length. Omitting the array
  samples up to 64 ICMP probes. With matched specifications, NetX selects distinct
  source and prefix pairs round-robin across summaries and uses a modeled address
  inside each prefix when available. It uses the first usable address otherwise.
  Source VRFs use their lowest active IPv4 address. Snapshot-only runs sample
  directed pairs of VRF endpoints. An empty array disables sampling.
- **policyTests** evaluates a supplied IPv4 BGP `route` using the Batfish
  `nodes` and `policies` specifiers and direction `IN` or `OUT`. These results
  are marked `conditional_policy_test`. The evaluator uses its default session
  context. Each answer includes the tested route, decision and available trace.

## Cornetto

Pass a Cornetto scenario directory to simulate its `final_configs` snapshot.
You can also pass `final_configs` directly or pass `initial_configs` when a
golden snapshot is available. The adapter uses native Batfish layer-1 input
when available and otherwise stages the scenario's physical links from
`data_and_metrics/topology.json`. Supply a specifications CSV explicitly to
include reference data. [Cornetto benchmark](../../benchmarks/cornetto/cornetto-benchmark/README.md)

```sh
scenario=netx/benchmarks/cornetto/cornetto-benchmark/main_dataset/scenario-006
python3 -m netx.tools.understand "$scenario" \
  --specifications "$scenario/specifications/specifications_2pct.csv" \
  --mode compact
```

To reproduce the two scenario-300 reports from the repository root, run
the same snapshot with each reference sample. Each invocation prints the
path to its Markdown overview and full JSON report. Git ignores these files
under `netx/runs/`. [Run output rules](../../runs/.gitignore)

```sh
scenario=netx/benchmarks/cornetto/cornetto-benchmark/main_dataset/scenario-300
for sample in 10pct 100pct; do
  python3 -m netx.tools.understand "$scenario" \
    --specifications "$scenario/specifications_${sample}.csv" --mode compact
done
```

The full and compact reports record the Cornetto CSV under `benchmark` with
`configurationState: golden_vs_faulty`. The simulated snapshot is recorded under
`input` as `fault_injected` for `final_configs` or `original_correct` for
`initial_configs`. Routes, filters, packet paths and device roles describe the
simulated snapshot. A standalone CSV has state `supplied_reference` and a
standalone snapshot has state `as_supplied`. For scenarios in separate
checkouts, NetX links roles to a reference when the scenario identifiers match
and the simulated scenario contains a byte-identical copy of the named CSV.
If the match fails, the report retains the summaries and records the gap.
For a published sample filename, `benchmark.nominalSamplePercent` gives its
percentage. `benchmark.rowsInFile` counts all rows in the input file.
`intentRows` in compact mode counts the rows selected for this analysis.

Each summary preserves the raw `sources` label. `expectedPresence` is the
predicate's target state after repair, and `faultyPresence` is the state implied
by the CSV for the fault-injected configuration. `intact` is present in both
states. `broken_added` is present in the faulty state and should be absent after
repair. `broken_removed` is absent in the faulty state and should be present
after repair. NetX interprets `broken_removed|intact` as `broken_removed`, the
same precedence Cornetto uses for scoring. An `isolation` row with
`broken_added` records unwanted isolation. Unrecognized labels have
`unspecified` presence in both states.

## Reading the evidence

- **Summaries.** Each group fixes the property kind, source label and parameters.
  The `waypoint` parameter names the required router. For load balancing,
  `numRoutes` gives the exact number of next-hop routers in Cornetto's
  forwarding graph at the source. Both parameters come from the CSV.
  For each prefix, apply its `remove` and `add` exceptions to `baseNodes` to
  reconstruct the exact source node set. `evidence` links to the original rows,
  including duplicates. Without a specifications CSV, the tool returns an empty
  summary list and the available simulation evidence and roles.
- **Intent checks.** Every supplied source/prefix pair is checked on the same NetX Batfish
  convergence that supplies device roles. The 64-flow limit applies only to detailed role traces.
  `intentEvaluation.rows` preserves CSV line numbers, repair targets, observed presence and
  evidence pointers. `result` compares presence with the repair target, including on candidate
  copies named `final_configs/`. `faultyReference` retains the original label interpretation.
  Default-VRF reachability means at least one modeled ICMP echo path is accepted at the original
  destination address. The destination is a modeled interface address inside the prefix, or its
  first usable address when there is none. Isolation means every path fails and the
  enumeration is conclusive. Waypointing requires the named router on every accepted path after the source,
  including the receiving router. At least one path must be accepted. Load balancing counts distinct resolved neighboring
  routers installed in the source FIB for the same destination, independently of delivery.
  A missing source, unresolved forwarding neighbor, inconclusive delivery, or partial model can
  yield `unknown`. These observations are scoped to the recorded destination and headers.
  The historical Cornetto scorer remains available to the standalone dataset audit.
- **Packet paths.** Each flow observation includes dispositions and up to 256
  paths, together with the total path count. NetX treats `ACCEPTED`,
  `DELIVERED_TO_SUBNET` and `EXITS_NETWORK` as successful. Complete,
  determinate traces identify the common intermediate nodes on successful paths
  and the number of distinct successful first hops for that packet. Both
  values are `null` when the path set is incomplete or indeterminate.
  Cornetto counts outgoing next hops in its prefix graph. The packet's
  `successfulNextHopCount` counts next hops on successful branches for its
  particular headers and ingress location.
- **Routes.** The simulator compares route objects across the BGP RIB, main RIB
  and FIB. A BGP-best route can lose to a different protocol in the main RIB.
  A backup is an accepted candidate. Failover requires a separate scenario.
  Prefix events record actual import or export processing during convergence.
  Batfish aggregates them by prefix, neighbor and policy. The tracer omits
  chronology, candidate attributes of the rejected advertisement and
  protocol-level export suppression before policy evaluation. An absent
  advertisement has unknown cause unless the model provides a corresponding event.
  Policy source lines identify configuration dependencies. Individual clause
  matches require a policy execution trace.
- **Packet filtering.** Denials retain the original flow and the packet seen at
  the filter stage, the interface, direction and ACL. Rule lookup uses the
  latter packet and the hop's input interface, including preceding header
  transformations. A null rule index with `implicit deny` denotes the default
  action. A packet denial describes that packet alone.
- **Responsibilities by summary.** Start with `responsibilityGroups` for actions
  shared across devices. For the view from one device, open its `deviceRoles` entry
  and inspect `actionGroups`. Both views link to the same contributions. Apply a
  member's `prefixExceptions` entry to `basePrefixes` to recover its reference
  prefixes. Follow the contribution's `intentLinks` for exact row and assignment
  evidence. The group counts each linked row once and each assignment once at its
  own validation level.
  `attributedRows` counts distinct input rows with a role link. `unattributedRows`
  retains every remaining member. Coverage measures evidence scope.
- **First advertisement.** A BGP Origin requires a live export of a locally sourced
  or generated prefix. The NetX tracer observes IPv4 advertisements before import,
  distinguishes self-originated and learned routes, and processes withdrawals and
  session resets. External OSPF and IS-IS can identify an advertiser through a remote
  installed route. A learned prefix redistributed at a protocol boundary contributes
  Distribution. Internal OSPF routes currently lack publisher identity. A receiving
  endpoint is an observation. Multiple independent publishers can each qualify.
- **Member evidence.** An exact source/prefix match links selection at the source,
  an advertisement learned there, or a policy rejection affecting that receiver.
  For multiple VRFs, a matching probe identifies the observed VRF. A load-balancing
  summary uses source selection and evidence from peers supplying its routes. A
  reachability summary can also include devices on concrete forwarding paths.
  Isolation links cover scoped route filtering, a packet ACL, or a paired VRF
  observation. These associations describe behavior in the supplied snapshot.
  A waypoint Transit link requires the named router to transmit on an accepting
  branch with the original destination preserved. Endpoint acceptances are listed
  under `endpointObservations`. `packetObservations` retains sampled outcomes.
- **Validation levels.** `configured` records populated VRFs. `observed`
  records a route, event or transmission with primary evidence only.
  `corroborated` records a second matching observation. For the Isolation
  role, inspect the two VRFs and the packet in the cited query pair. The
  result applies to that destination and those headers. An unmatched ACL
  replay produces `inconsistent` and a report gap. Role cross-checks use
  the current simulator. The [development guide](../../develop_understand.md)
  gives the assignment and cross-check for each role.
- **Completeness.** Unresolved queries, incomplete traces and model diagnostics
  produce `partial` with reasons. Fatal errors produce `error` and a nonzero
  CLI exit code. Simulation facts cover a single IPv4 snapshot.
