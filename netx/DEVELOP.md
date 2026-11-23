# Developing NetX

NetX is a network management and repair agent built on Codex. The directory
layout is in place. The `netx` CLI, MCP server, and benchmark runner are planned.

## Directory layout

```text
netx/
  agent/                     Agent instructions, MCP configuration, output mode
  tools/<tool>/              One implementation per network operation
  tests/<tool>/              Test cases, fixtures and benchmark checks per tool
  mcp/                       Tool registration, input validation, dispatch
  simulators/batfish/        Batfish source and NetX simulator integration
  simulators/speclens/       SpecLens verifier with its Batfish and Minesweeper fork
  benchmarks/cornetto/       Cornetto source, benchmark data, and scoring
  benchmarks/CloudOpsBench/  Cloud operations tasks, checks, and reference solutions
  runs/<run-id>/             Local experiment records, ignored by Git
```

Track simulator sources, benchmarks, and datasets as ordinary files in the
root Git repository. Keep each project's license and notices alongside its
source. Record the source revision when importing updates.

The initial import used these revisions.

- Cornetto at `21641495fb6485c1d6d61d44597a58d87ed29de2`
- CloudOpsBench at `5644a96962f937534290a767a0e5cecf8e0b2df2`

## Snapshot understanding

The snapshot understanding tool summarizes supplied forwarding predicates,
collects forwarding and routing evidence from the vendored Batfish engine, and
returns scoped device roles. Its three-router example exercises backup routes,
import/export rejections and interface ACLs. [Tool guide](tools/understand/README.md) ·
[Understand development guide](develop_understand.md) ·
[Cornetto benchmark](benchmarks/cornetto/cornetto-benchmark/README.md)

## SpecLens verification and configuration explanations

The local verifier uses revision `c86869812443cac2cc406576241d52b82d0c7b03`
from the upstream `speclens` branch. Its runner reads `configs/` and
`properties.json` from a work directory under `benchmarks/` or `user-study/`.
[Local setup and dependencies](simulators/speclens/README.md) ·
[Upstream revision](https://github.com/declarative-systems-lab/batfish/tree/c86869812443cac2cc406576241d52b82d0c7b03)

From the repository root, run the bundled ECMP reachability example with
the verifier's own Batfish and Minesweeper build.

```bash
cd netx/simulators/speclens
python3 run_benchmark.py --community --property 1 user-study/userstudy_task1
```

The standard workflow writes one `smts/smt_output_*/` directory per property.
It includes per-router checks in `3_consistency_check/` and line- and
field-level constraints in `4_subspec/`. The checkout includes a saved run
for this fixture. [Example input](simulators/speclens/user-study/userstudy_task1/properties.json) ·
[Saved output](simulators/speclens/smts/smt_output_0000/)

Batfish snapshot queries report which routes, advertisements, and forwarding
actions a scenario produces. SpecLens takes a network property and derives
conditions on routers, configuration lines, and fields that suffice to
preserve it under the verification model. For example, a config reference can
identify every neighbor using a prefix-list. SpecLens can then explain what a
prefix-list field must preserve for a particular reachability property.

The proposed `explain_property` tool would expose the full workflow in one call.

- **Input.** A snapshot ID and one property in the runner's format. Start with
  IPv4 reachability, for example
  `{"type":"reachability","ingressNodeRegex":"r3","finalNodeRegex":"isp2","dstIps":["203.0.113.0/24"]}`.
- **Output.** Return the property, engine revision and modeling assumptions,
  verification verdict, and per-router consistency checks. For a verified
  property with consistent encodings, include the router, line, and field
  subspecifications, preserving every alternative and its logical grouping.
  Retain the original symbolic identifiers and attach config file locations
  where the mapping is known.
- **Incomplete evidence.** Distinguish a verified violation from a runner
  failure, timeout, or inconsistent encoding. Report any available
  counterexample for a violated property. Mark explanations as partial when a
  required consistency check or model feature is unavailable.

For the BGP and ACL milestone, start with the routing-policy fixture above.
The current property reader accepts `reachability`, ingress and final node
patterns, destination IPs, and an optional `negate` flag. It does not pass IP
protocol or transport ports to the verifier. Use NetX FIB* for the TCP/80
permit and TCP/443 deny case until the SpecLens input path carries those
fields and the two outcomes have been tested.
[Property reader](simulators/speclens/projects/allinone/src/test/java/org/batfish/allinone/smt/MinesweeperPropertyRunner.java)

## Tool contracts

**How Codex handles MCP tools.** Codex exposes the tool name, description, and
input JSON Schema to the model. On a direct function call, the model supplies
JSON arguments. Codex pairs the result with the request using `call_id`. For
ordinary MCP data, Codex serializes `structuredContent` as JSON text, adds a
timing header, and applies an output budget. Plain text is also supported.
[Tool definition](../codex-rs/tools/src/responses_api.rs#L32) ·
[MCP result conversion](../codex-rs/protocol/src/models.rs#L2488) ·
[Direct call output](../codex-rs/core/src/tools/context.rs#L211)

**Inputs.** Give each tool one operation. Describe what it reads or changes.
Define required fields, types, and accepted values in MCP `inputSchema`, and
validate them in the handler. For example, `reachability` takes a snapshot ID,
a source router, and a destination IP address. The decoded arguments look like this.

```json
{"snapshot":"s1","src":"r1","dst":"192.0.2.9"}
```

**Outputs.** For network queries, return a JSON object in MCP `structuredContent`.
Select `full` or `compact` at session startup. Both modes use the same tool
name, inputs, defaults, and execution. `full` returns the complete result.
`compact` returns the verdict, the evidence needed to interpret it, and a
run-scoped `result_id` for details. This example identifies where routing failed.

```json
{"status":"ok","reachable":false,"reason":"no_route","node":"r2","result_id":"r17"}
```

`status` describes the query. Here it succeeded and found no route. Use
`partial` for incomplete evidence. On execution failure, return `error` with
a short reason and set MCP `isError` to true. Omit
`reachable` when the verdict is unknown. Keep full traces in the run store.
Expose details by field or page through `result_id`, and apply the same
compact view to any text fallback. Test both modes on the same snapshot,
including failure and partial-result cases.

## Benchmark runs

Start each session with the task, tool entry points, and snapshot ID. Let the
model discover topology and configuration on demand. Keep reference answers,
scoring code, and full traces outside the agent's accessible workspace and tools.

Run each case in a fresh session per mode. Fix the snapshot, model, instructions,
and tool budget. Record the case ID, component versions, mode, tool arguments,
full results, and model-visible outputs. Compare pass rate, total input tokens,
and tool calls per case.

## Build and upstream updates

From the repository root, build the existing Codex CLI with
`bazelisk build //codex-rs/cli:codex`.

The planned `//codex-rs/cli:netx` target shares Codex startup logic and loads
the settings in `netx/agent/`. Define the binary in both 
[Cargo](../codex-rs/cli/Cargo.toml)
and [Bazel](../codex-rs/cli/BUILD.bazel).

Once the target exists, build it with `bazelisk build //codex-rs/cli:netx`.
Check that interactive `netx` and `netx exec` expose the same domain tools.
To sync the fork, merge `upstream/main` into the NetX branch, build both CLI
targets, run the tool tests, and run one Cornetto case in both output modes.
