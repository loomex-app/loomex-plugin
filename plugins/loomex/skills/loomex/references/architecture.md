# Architecture and lifetimes

Codex talks over stdio to the bundled `loomex-mcp` adapter. The adapter talks to
the per-user Loomex Runner over an owner-restricted Unix domain socket on macOS
and Linux. The Runner communicates outbound with the Loomex backend and executes
approved local capabilities inside explicit workspace bindings. This release's
local-control and packaging contract supports macOS and Linux.

The MCP adapter belongs to the Codex process lifetime. The Runner and backend do
not. Once a run is accepted, closing Codex does not cancel it. On the next Codex
session, use `loomex_run_get` or `loomex_run_wait` and query the human and
approval inboxes to recover its latest durable state.

The adapter uses two local routes. Setup, authentication, organization/project
selection, workspace binding, and Runner control call the bundled `loomex`
bootstrap executable, so first use works before a service socket or credential
exists. Workflow/run/HITL/approval calls use the authenticated durable-service
socket. Status, diagnostics, and logs prefer that socket and may fall back to
the bootstrap executable when the service is unavailable. Neither route moves
workflow execution into the Codex process.

The boundary is important: Codex cannot present a question or notification
while it is closed. Human requests remain pending. The Tauri client is another
supported surface for the same durable request; it is not replaced by this
plugin.

The Runner owns device identity, credentials, reconnect and replay, heartbeat,
cancellation, path containment, symlink defense, policy, and audit. The plugin
must not duplicate or bypass these controls.

For `loomex.plugin-agent-task/v2`, the Runner also owns executable discovery,
capability probing, exact/automatic/ordered model resolution, process
lifecycle, output repair, session checkpoints, and typed redacted errors.
Codex sees only the safe MCP control surface and passes `requestId` plus an
idempotency key from the operation's correct domain; it never receives
authority to supply arbitrary prompts, commands, paths, model arguments,
environment values, or credentials. The canonical local executors are
`codex_cli` for `open_ai`,
`claude_cli` for `anthropic`, and `agy_cli` for `google`.

Backend-owned v2 processes cross the durable RunnerJob boundary. MCP does not
spawn or signal those local processes. An authenticated user may authorize a
successor or cancellation through MCP, but Backend creates the successor job or
adds the cancellation directive. The daemon leases or atomically reclaims the
job, durably reserves a cancellation directive before signaling, acknowledges
it with runner authentication, and submits terminal truth under the current
lease fence. Control `operationIdempotencyKey` values are separate from task,
process-attempt, and delivery idempotency keys.

The runner manifest always uses
`agentAdvertisementSchemaVersion:
"loomex.runner-agent-advertisement/v1"` and explicitly includes
`agentRuntimeV2Enabled`, `legacyAgentTasks.mode`, and `capabilities`. Its
fail-closed matrix is:

| v2 enabled | Legacy mode | Agent advertisement |
| --- | --- | --- |
| `true` | `drain_only` | `agent.runtime.v2`, `agent.task.v1.drain`, and a valid `agentRuntimes` snapshot |
| `true` | `disabled` | `agent.runtime.v2` and valid `agentRuntimes`; drain capability omitted |
| `false` | `drain_only` | only `agent.task.v1.drain`; v2 capability and `agentRuntimes` omitted |
| `false` | `disabled` | both agent capabilities and `agentRuntimes` omitted |

An omitted capability is not the same as a `false` capability, and an omitted
`agentRuntimes` field is not JSON `null`; the latter representations are
invalid in a disabled mode. Unknown advertisement or capability snapshot
schemas, unknown legacy modes, missing `legacyAgentTasks`, inconsistent
capability presence, and invalid snapshots all fail closed. This agent
advertisement remains inside `runner.v1`; it does not introduce a runner
transport v2.

A management transport error leaves the remote execution state unknown. The
plugin re-reads that state by execution ID; it does not infer durability or
cancellation from the error and does not restart a healthy Runner to force a
reconnect.
