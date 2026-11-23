# Developing the NetX understand tool

## 1. Goal

Build one component that helps an LLM understand a network.

**Cornetto reference predicates → NetMiner-style intent summaries → device responsibilities grounded in Batfish evidence.** The six roles describe the actions devices take for specific intent members.

Cornetto provides two inputs. [Cornetto benchmark](benchmarks/cornetto/cornetto-benchmark/README.md)

1. The specifications CSV compares predicates mined from the golden and fault-injected configurations. Read each predicate with its `sources` label to recover its expected and fault-injected presence.
2. The benchmark publishes the fault-injected snapshot under `final_configs/`. NetX runs the vendored Batfish on those files when given a Cornetto scenario. The resulting routes, advertisements, ACL decisions and traces describe that snapshot. Inferring roles in the golden state requires evidence from the golden snapshot.

The result should connect **what the network does**, **which devices and policies contribute**, and **what responsibilities they appear to carry**.

This describes the conceptual flow, not a requirement to run both original systems sequentially. Inspect the existing tools and code before choosing interfaces or implementation details. Reuse available capabilities.

For this initial stage, focus on understanding the current configuration. Modular contracts, repair-space generation, and a broader repair framework are outside this document's scope.

For a failed run or a disputed result, follow the [Understand repair guide](repair_understand.md).

## 2. Three building blocks

### A. Summarize supplied intents

Config2Spec [1] combines data-plane analysis and control-plane verification to identify properties that hold under a specified failure model. NetMiner [2] improves mining efficiency and groups low-level properties into compact summaries with exceptions.

Read the supplied Cornetto rows and group reachability, isolation, waypointing and load balancing. The published NetMiner algorithm cannot mine isolation from a forwarding path. NetX can summarize isolation because Cornetto supplies the predicate rows. [NetMiner, Section IV-A](https://haolis.com/files/netminer-ton25-kang.pdf)

Preserve the predicate type, parameters, raw status and original rows. For each prefix, expansion of the base source set and its additions and removals must recover exactly the recorded sources, with every input row traceable, including duplicates. A removed member is an exception to that group's base set. A negative repair target requires an explicit reference status. The percentage in a sample filename is nominal. An omitted row has unknown membership in the full reference, and `100pct` contains all recorded reference rows for that scenario. [Benchmark format](benchmarks/cornetto/cornetto-benchmark/README.md)

Cornetto mines both the golden and faulty forwarding graphs. Keep the two presence values tied to that comparison. `intact` holds in both states. `broken_removed` holds in the golden state and should be restored. `broken_added` holds only in the faulty state and should be absent after repair. The scorer treats `broken_removed|intact` as broken with expected presence. NetX retains the original label and leaves unfamiliar or contradictory tags unspecified. When a candidate configuration changes, keep the selected reference rows and their targets fixed and recompute observations for the new snapshot. [Cornetto evaluator](benchmarks/cornetto/src/utils/evaluation_utils/newer_spec_evaluator.py) · [NetX label handling](tools/understand/summaries.py)

For example, line 208 of the scenario-007 2% sample records `broken_added` isolation from `7_as65007_columbia` to `10.181.0.0/30`. Repair should remove that isolation. The row enters the same summary and attribution pipeline as the other predicates. Assigning Access control, Isolation or Distribution to a device requires evidence of the corresponding action. [Scenario-007 sample](benchmarks/cornetto/cornetto-benchmark/main_dataset/scenario-007/specifications/specifications_2pct.csv)

A waypoint lies on every graph path from the source to the synthetic prefix destination. The source is excluded, and the accepting router can qualify. For a source that reaches the destination, `num_routes` counts distinct outgoing forwarding targets in Cornetto's prefix graph. NetX records what the sampled packet did and which next hops were installed. A verdict for either reference predicate requires its graph semantics. [Predicate extraction](benchmarks/cornetto/src/utils/evaluation_utils/forwarding_analysis/predicates.py)

Start with the current snapshot. Reuse existing failure-aware results when available, but do not require a new fault-tolerance engine for this component. State which scenarios each result covers.

### B. Supplement with Batfish facts

For Cornetto references, compute prefix membership on the supplied snapshot using ordinary Batfish `ibdp` and the scorer's graph rules. Keep the CSV label, the published presence for that snapshot and the observed membership individually visible. A device connected to the destination by an `accepted` edge reaches the prefix vertex. A `delivered_to_subnet` edge can terminate a connected route while a packet addressed to the router's interface reaches the router. Packet observations and role assignments use the physical links and BGP settings recorded in the device evidence run. [Implementation and output](tools/understand/README.md#reading-the-evidence)

Summaries alone do not explain route choices or filtering. Supplement them with the following facts, using existing Batfish simulation and analysis where supported.

| Fact | Information to expose | Main role connection |
|---|---|---|
| Selected and non-preferred routes | Candidate attributes, selected status, relevant next hops and installation state. | Selection |
| Blocked routes | Import/export rejection, device/peer, direction, policy, and available explanation. | Distribution |
| ACL-denied traffic | Packet class, device/interface, direction, denying ACL or rule when available. | Access control |
| Forwarding behavior | Relevant paths, delivery, drops, and next-hop outcomes. | Transit |
| Route/domain context | Route origin, propagation, VRF membership and route leaking where available. | Origin, Distribution, Isolation |

Keep three distinctions explicit:

- An accepted but non-best route differs from a policy-denied route.
- A route absent at a receiver is not automatically a rejected route.
- An ACL blocks packets; an import/export policy blocks route advertisements.

Batfish's BGP RIB can expose `BEST` and `BACKUP` [4]. BGP-best does not necessarily mean installed in the main RIB/FIB, and a backup candidate alone does not prove successful failover.

Policy testing can show how a supplied route would be processed [5]. Distinguish that **conditional result** from a route **actually reaching and being rejected at that stage in the simulation**. Inspect the existing integration for rejection evidence; do not assume an ordinary RIB query exposes it all. Missing facts should remain explicitly unavailable.

For ACLs, use forwarding and filter analysis to identify the device, interface, direction and rule that denied an observed packet [3].

### C. Boundaries of the six device roles

Each role describes an action by a device in one snapshot. In a report with a reference CSV, the action must link to at least one original row of an intent summary. A row with no matching action remains visible in the summary. For Cornetto's `final_configs/`, the role describes what the device did after fault injection. [Intent linking](tools/understand/role_intents.py) · [Benchmark states](benchmarks/cornetto/cornetto-benchmark/README.md#predicate-status)

#### Origin

Identify who introduced the advertised prefix into the modeled routing domain. For BGP, the device must export a locally sourced or generated prefix on a live session. A connected route can supply the prefix, but local installation or packet delivery alone leaves publication unproven. Two routers can independently originate the same prefix. “First” refers to the source of each advertisement within the domain, without imposing a time order on the routers. For external OSPF and IS-IS, attribution requires an identifiable advertiser and evidence of a local source or an IS-IS attached default. The current internal OSPF route records omit the advertiser. [Origin attribution](tools/understand/origins.py)

#### Distribution

Identify who propagated or filtered a route, for which prefix and toward or from which peer. A route reflector can distribute a learned prefix even when packet paths bypass it. An observed BGP send or a policy-attributed import/export rejection supports this role. A missing route at a peer or a hypothetical policy test leaves the actual event unknown. For external OSPF and IS-IS, an identified advertiser can receive Distribution when the evidence establishes propagation but leaves local origination unproven. [BGP attribution](tools/understand/roles.py) · [IGP attribution](tools/understand/origins.py)

#### Selection

Identify who chose among eligible routes or installed multiple next hops for one prefix in one VRF. NetX recognizes competing accepted BGP candidates, a learned BGP best outside the main RIB alongside an installed route from another protocol, and installed multipath. An accepted BGP backup participates in selection. An import rejection excludes a route from the receiver's candidates. An export rejection can withhold a route the sender already selected. Both rejections are Distribution actions. A single installed route alone gives insufficient evidence of a choice. [Selection rules](tools/understand/roles.py)

#### Transit

Identify who forwarded an observed packet. The trace must show the packet arriving from a preceding hop or entering through a supplied ingress interface, then leaving through an output interface on that branch. A FIB entry alone establishes a forwarding option. A locally originated probe has no incoming hop at its source, and a router that only accepts the packet is an endpoint. For a waypoint intent, the named intermediate router must transmit on a branch that reaches the original destination. [Transit attribution](tools/understand/roles.py) · [Waypoint and endpoint links](tools/understand/role_intents.py)

#### Isolation

Identify who maintains separate routing contexts on a device. Two VRFs populated by interfaces or configured leaks establish a `configured` role in the diagnostic inventory. Linking this role to an intent requires paired probes on that device with identical packet headers. All branches must end in modeled acceptance from one VRF and in a local `NO_ROUTE` from the other, with complete traces for both. The conclusion covers that packet and those two VRFs. [VRF validation](tools/understand/role_validation.py)

A Cornetto `isolation` row records an absence-of-reachability predicate. Its `sources` label gives its expected presence. To attribute a device action, check the mechanism. In scenario-300, `r4` rejects the import of `172.16.0.0/12` from `customer1`. That row links to Distribution. A lone failed probe would leave the mechanism unresolved. [Intent linking](tools/understand/role_intents.py) · [Scenario regression](tests/understand/test_roles.py)

#### Access control

Identify who denied a packet at an interface ACL. The role records the interface, direction, filter, matching rule or implicit deny, and the packet headers as seen at that filter, including prior address translation. Replay must agree with the denying step on the same trace branch to corroborate the assignment. An attached ACL, a permit, or a route-policy rejection alone cannot produce this role. A denial on one ECMP branch applies only to that branch. [ACL validation](tools/understand/role_validation.py) · [ACL boundary tests](tests/understand/test_acl.py)

The roles can coexist when each action has evidence in its own scope. In the regression fixture, `primary` originates `203.0.113.8/32` and also distributes it to `edge`. Removing the local BGP advertisement removes that Origin assignment even though the connected route remains. On `edge`, the HTTP probe demonstrates Transit and the denied HTTPS probe demonstrates Access control. [Role regression tests](tests/understand/test_roles.py)

## 3. Workflow and expected output

1. Read topology, configuration, supplied intents, and existing analysis results.
2. Group the supplied intents into summaries with exceptions and links to their original rows.
3. Retrieve relevant route and ACL facts from Batfish.
4. Apply reproducible attribution rules and cross-check each scoped role against a second observation where available. An LLM can use the resulting evidence to explain the responsibility.
5. Return an overview with links back to supporting policies and analysis results.

Each reference summary is the unit of attribution. Its exact source and prefix members scope the device responsibilities. Each device entry groups contributions by the members they explain. Rows awaiting attribution remain visible. A snapshot run without reference data provides a diagnostic inventory. An operator's original design and the behavior of an untested scenario require separate evidence.

A reference target specifies forwarding behavior. It may admit several allocations of device responsibility. Record the device, role, observed action, applicable conditions, linked reference rows and evidence for each assignment. A missing observation leaves a gap for the affected members. A proposed device owner would need a stated basis and a separate hypothesis. The same evidence can explain a contribution to desired behavior or an obstacle to it.

For each useful association, expose:

- The intent or behavioral summary.
- The relevant devices and roles, including their scope.
- Supporting configuration and execution facts.
- The scope of the observation and any gaps in the evidence.

For example, one prefix can involve three devices.

- Edge A distributes the customer prefix to Core B.
- Core B selects exit X and retains Y as a non-best candidate.
- Gateway G enforces access control by denying a guest packet at its ingress ACL.

These descriptions should point to evidence. They do not, by themselves, prove end-to-end reachability, failover, or isolation.

### Summarizing device responsibilities

Each intent summary exposes two views of its observed assignments. The grouping key uses the action and its structured conditions. The reference status and snapshot come from the enclosing summary and report. [Responsibility grouping](tools/understand/responsibilities.py) · [Overview renderer](tools/understand/overview.py)

- **Within a device**, `deviceRoles[].actionGroups` gathers compatible contributions. For BGP, a device can advertise different prefix sets to different peers. Each member retains its peer, peer address and local policy. If one peer receives two of three shared prefixes, its exception identifies the missing prefix. VRFs, direction, packet class, ACL and interface constrain the corresponding actions.
- **Across devices**, `responsibilityGroups` compares contributions within the same reference summary. BGP distribution requires matching action, direction, peer and VRF scopes. In scenario-300, R2 and R3 advertise prefixes to R4 through separate BGP sessions and export policies. The 100% sample places `192.0.2.0/24` and `198.51.100.0/24` in the `broken_removed` load-balancing summary and `203.0.113.0/24` in the `intact` summary. R4 installs one next hop for each of the first two prefixes and two next hops for the third. [Scenario regression](tests/understand/test_roles.py)

In both views, each member points to an exact device contribution. Its reference prefixes are the group's `basePrefixes` with that member's removals and additions applied. Its `intentLinks` point into the original assignments and identify the exact source rows, including duplicates, alongside the assignment's snapshot, evidence and validation. `validationCounts` counts distinct assignments at each level. `memberCount` counts distinct reference rows. Unattributed rows remain on the summary. [Round-trip tests](tests/understand/test_responsibilities.py)

For Origin, the overview lists the prefixes each device advertised from a local source. A packet probe may link a reference prefix to a covering advertisement. The overview then shows both the published prefix and the linked reference prefixes for that device.

### Evidence and validation of role assignments

Each report distinguishes the observation that produced a role from the cross-check recorded in its `validation` field. Both observations come from the simulated configuration. For Cornetto's `final_configs/`, a corroborated role describes a responsibility exercised after fault injection. A link to a reference intent identifies the relevant source and destination scope. Waypoint links cite transmission by the named intermediate router on a branch ending in modeled acceptance. A named destination router accepting the packet is recorded separately as an endpoint observation. The reference describes all graph paths that reach the prefix. Cornetto's mining engine and the vendored Batfish can differ in their modeling.

| Role | Assignment rule | Cross-check within the reported scope |
|---|---|---|
| Origin | A first advertisement of a locally sourced prefix. For BGP, capture self-originated exports before receiver import, process withdrawals, and retain active sessions. | Check the local route source or generated mechanism. A peer candidate can corroborate receipt. For external OSPF and IS-IS, require a remote route with an unambiguous advertiser and evidence of a local source or generated attached default. |
| Distribution | A peer-specific BGP send, a policy-attributed import/export rejection, or an identified IGP redistributor | For a numbered session, match the receiver's learned candidate by VRF, prefix and sender address. A traced rejection retains its policy and available source lines. |
| Selection | Multiple accepted BGP candidates with a best route, a learned BGP best outside the main RIB alongside an installed route from another protocol, or multiple installed next hops | Match an installed route to a concrete forwarding lookup on the same node, VRF, prefix, protocol, next hop, administrative cost and metric. |
| Transit | A packet entering on an interface or arriving from the preceding hop is transmitted | Match the output interface to the next hop's received interface on the same trace branch and a directed layer-3 edge. |
| Isolation | Two or more VRFs on the device have interface or route-leak context | Compare complete traces for identical packet headers originating in two VRFs on that device. Require a modeled destination to accept the packet from one VRF and a local no-route lookup in the other. Record the tested VRFs and both probes. |
| Access control | Replay of a specific packet at a denying interface ACL | Match the packet as seen at the filter, device, interface, direction and ACL to the denied step and disposition on the same path. |

`configured` records VRF structure. `observed` records a primary behavioral observation. `corroborated` adds the scoped cross-check described above. Two observations from the same simulator establish agreement within its model. Attribution coverage counts distinct reference rows with evidence for a device action. Evaluating whether the intent holds or whether that device uniquely caused a fault requires separate evidence. A disagreement between ACL replay evidence and its trace is marked `inconsistent` and reported as a gap if it reaches the report builder. The adapter itself raises an error when ACL replay returns a different decision.

The benchmark supplies intent rows. It supplies no independent device-role labels. The regression suite tests attribution by changing a single configuration element in a private snapshot, recomputing convergence, and checking which assignments change and which controls persist. These experiments run in the test suite. Each ordinary analysis uses one snapshot. [Role regression tests](tests/understand/test_roles.py)

## 4. Initial completion criteria

Use one small network to demonstrate that:

- Summaries preserve the underlying properties and exceptions.
- Best, non-best, policy-denied routes, and ACL-denied packets remain distinguishable.
- One device can carry several scoped roles.
- Role descriptions link to actual evidence, with conditional tests clearly identified.
- Supplied requirements, current behavior, and inferred responsibilities are not conflated.

Keep schemas, API names, storage choices, and algorithms open until the existing implementation is inspected. The immediate deliverable is a useful network-understanding component.

## References

1. Birkner et al. **Config2Spec: Mining Network Specifications from Network Configurations.** NSDI 2020. [Paper](https://files.sri.inf.ethz.ch/website/papers/nsdi20.pdf).
2. Kang et al. **Network Specification Mining With High Fidelity, Scalability, and Readability.** IEEE Transactions on Networking; online 2025, volume 34 (2026). [Paper](https://haolis.com/files/netminer-ton25-kang.pdf).
3. Batfish. [Packet Forwarding](https://batfish.readthedocs.io/en/latest/notebooks/forwarding.html).
4. Batfish. [Routing and Forwarding Tables](https://batfish.readthedocs.io/en/latest/notebooks/routingTables.html) · [BGP route statuses](https://batfish.readthedocs.io/en/latest/specifiers.html#bgp-route-status-specifier).
5. Batfish. [Routing Protocol Sessions and Policies](https://batfish.readthedocs.io/en/stable/notebooks/routingProtocols.html). Check capabilities against the installed backend.
