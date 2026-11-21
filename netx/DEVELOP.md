# Developing NetX

NetX is a network management and repair agent built on Codex. The directory
layout is in place. The `netx` CLI, MCP server, and benchmark runner are planned.

## Directory layout

```text
netx/
  agent/                     Agent instructions, MCP configuration, output mode
  tools/<tool>/              One implementation per network operation
  tools/<tool>/tests/        Test cases for both output modes
  mcp/                       Tool registration, input validation, dispatch
  simulators/batfish/        Batfish source and NetX simulator integration
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
