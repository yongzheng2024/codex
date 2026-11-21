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

## Tool outputs

Register each tool once, with the same name, input schema, and defaults in both
modes. Select the mode at session startup. Each call executes the operation once.

- `full` returns the complete result.
- `compact` returns the answer, essential evidence, and a run-scoped `result_id`
  for fetching details by field or page.

For example, a compact `reachability(snapshot, src, dst)` result identifies
the router that had no route to the destination.

```json
{"reachable": false, "reason": "no_route", "node": "r2", "result_id": "r17"}
```

Test both modes against the same snapshot. Give failed and incomplete queries
distinct statuses. Reserve `reachable: false` for a confirmed negative result.

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
