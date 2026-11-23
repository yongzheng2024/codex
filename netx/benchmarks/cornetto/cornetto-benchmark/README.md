---
license: mit
---

# Cornetto Benchmark

Cornetto evaluates LLM-driven network configuration repair. The main dataset
contains 231 synthetic misconfiguration scenarios on real-world topologies
with 20 to 754 nodes.

This checkout also includes `main_dataset/scenario-300/`, a NetX regression
fixture with 10% and 100% reference samples. The published scenarios are
numbered 001 through 231.

## How the dataset was built

1. Use each of the 27 fault types individually and select 50 combinations of
   up to eight faults to cover all feasible fault pairs. For each fault set,
   sample one topology from each of three size tiers in the Internet Topology Zoo.
2. Build a logical network plan with the protocol features and dependencies
   required by the selected faults. Render the healthy (`golden`) router
   configurations using a configuration grammar. Apply the faults to the
   logical plan and render the faulty configurations.
3. Simulate the golden and faulty data planes with Batfish. Use Config2Spec
   algorithms on per-prefix forwarding graphs to extract the predicates that
   describe each state's forwarding behavior.

The benchmark uses the same analysis to measure which violations a proposed
repair resolves and which regressions it introduces.
[Cornetto paper, Sections 3 and 4.2](https://arxiv.org/abs/2604.22513).

## Scenario files

Each scenario in `main_dataset/` contains these artifacts.

- `final_configs/configs/` holds the faulty router configurations.
- `data_and_metrics/topology.json` lists the routers and their physical links.
- `specifications/specifications_<N>pct.csv` uses `N` as the nominal sampling
  percentage. The `100pct` file contains all recorded reference rows,
  including behavior introduced by faults. Most scenarios ship with 2%, 5%,
  10%, 20%, 50%, 75%, and 100%. `scenario-094` and `scenario-095` ship with
  the 2%, 5%, 10%, and 20% samples.

## Forwarding intents

Each CSV row gives the intent type (`predicate_type`), the source router hostname
(`node`), and the destination IPv4 prefix in CIDR notation (`prefix`). The
extractor evaluates these predicates in the forwarding graph for that prefix.
An accepting router connects to a synthetic destination vertex in this graph.

- `reachability` means traffic from `node` can reach `prefix`.
- `isolation` means traffic from `node` cannot reach `prefix`.
- `waypointing` means the router named in `waypoint` lies on every graph path
  from `node` to the destination vertex. The source is excluded. The router
  that accepts the traffic can itself be the waypoint.
- `load_balancing` means traffic from `node` toward `prefix` uses multiple
  paths. The evaluator checks for exactly `num_routes` distinct next-hop
  routers at `node` in the forwarding graph. It counts outgoing forwarding
  targets at a source that can reach the destination vertex. Concrete packet
  traces may exercise fewer of those next hops. [Predicate extraction](../src/utils/evaluation_utils/forwarding_analysis/predicates.py)

Unused parameter values are blank.

## Predicate status

The `sources` column compares each predicate in the golden and faulty states.

- `intact` holds in both states. Losing it after repair counts as a regression.
- `broken_added` holds only in the faulty state. It should be absent after repair.
- `broken_removed` holds only in the golden state. It should be present after repair.

### NetX reconciliation

The working samples for scenarios 001–231 use the golden target from the
published row and faulty-state membership observed independently by NetX and
the pinned Cornetto scorer. The golden configurations were unavailable for replay.

- The published samples included 934 rows labeled `broken_removed|intact`.
  Their golden target is presence and both scorers observed presence on the
  faulty snapshot. These rows now carry the single label `intact`.
- Both scorers found 4,243 published `broken_added` rows absent on the faulty
  snapshot. Their published golden target is also absence. The three labels
  describe predicates present in at least one state, so these rows were removed
  from every sample in which they occurred. They no longer contribute to repair
  or regression scoring. The remaining 17,880 `broken_added` rows retain their label.

The 1,611 corrected CSVs contain 5,094,387 rows. Sampling percentages in the
filenames refer to the original draw. To retrieve a sample with its original
line numbers, run the following from the repository root. [Audit and scorer details](../../../repair_understand.md#all-231-published-scenarios)

```sh
git show da6221cf7d1b2c8f2cc6f9b390d0dcea96b983d0:netx/benchmarks/cornetto/cornetto-benchmark/main_dataset/scenario-051/specifications/specifications_100pct.csv
```
