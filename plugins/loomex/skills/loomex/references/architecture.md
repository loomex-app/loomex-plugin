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

A management transport error leaves the remote execution state unknown. The
plugin re-reads that state by execution ID; it does not infer durability or
cancellation from the error and does not restart a healthy Runner to force a
reconnect.
