# Workflows and durable runs

## Discover

Use `loomex_workflow_list` with the selected organization filters. Use
`loomex_workflow_show` before a run when names collide, inputs are missing, or
local capabilities and approval points need explanation. Pass `workflowId`;
pass optional `version` when the user selected a particular immutable version.
If `version` is omitted, report the version returned by Loomex rather than
claiming one was selected. Do not guess workflow IDs, versions, or schema fields.
The plugin workflow list is intentionally scoped to `plugin` execution-model
workflows. Workflows configured for `app` or `server` execution belong to the
Tauri app or backend surfaces and should not be shown as plugin options.

Any Loomex tool error is a hard stop for the requested work. Report its exact
code/message and do not use shell, file edits, direct provider commands, or an
ad-hoc implementation as a fallback. Only Loomex recovery or diagnostic tools
may be called after the error.

## Start

Before `loomex_workflow_run`, confirm:

- workflow ID/version;
- selected organization, execution scope, and the execution-local workspace path;
- supplied inputs, especially secrets or environment names;
- declared local capabilities and known approval points.

Call it with required `workflowId`, `workspacePath`, and `idempotencyKey`. Its
optional public fields are `inputs`, `version`, and `sessionId`. Reuse the same
idempotency key only when safely retrying the same request; use a new key for an
intentional new run. Include `version`
only for a deliberately selected workflow version. Include `sessionId` only
when a real Loomex/Codex session ID is already available; never fabricate one
from a task title, run ID, or local process. Use the returned execution ID for
all later calls. A submitted or queued response is not completion.

## Follow and reconnect

Use `loomex_run_wait` for bounded server-side waiting. Preserve the cursor or
sequence it returns and send it back as `afterSequence` so repeated waits do not
replay old events. Keep these bounded waits in the same task while the run is
non-terminal; a queued or running provider job must not be reported as a
completed interaction or as a reason for the user to say “continue”.
`timeoutSeconds` is optional and is capped by the tool schema.
Provide short progress updates for long runs. If the connection or Codex
restarts, call `loomex_run_get` with the run ID, then resume waiting from the
returned state.

`MANAGEMENT_HTTP_FAILED` and other retryable wait/transport failures mean that
the latest run state is unknown. They do not prove that the durable run was
preserved, cancelled, or failed. Keep the authoritative execution ID and:

1. call `loomex_run_get` for that execution;
2. if the request still has a retryable transport failure, make a small bounded
   number of status attempts with short pauses rather than an unbounded loop;
3. when a non-terminal state is returned, resume bounded `loomex_run_wait`
   calls from the returned sequence and refresh the human and approval inboxes;
4. when a terminal state is returned, report that exact server state and stop
   waiting.

Do not restart the Runner merely because a management request failed three
times. First call `loomex_runner_status`, and use `loomex_runner_doctor` when
status is inconclusive. Recommend a restart only when those authoritative
checks show the local service is unhealthy. A healthy Runner owns reconnect and
replay and should be allowed to recover without a disruptive lifecycle change.
Runner control still requires the impact preview and confirmation described in
[runner-operations.md](runner-operations.md).

Terminal states are `succeeded`, `failed`, and `cancelled`; use the actual
structured state returned by the server. Waiting for plugin agent execution,
human input, or approval is non-terminal. Route those states through the
corresponding inbox tools.

## Plugin agent tasks

Plugin workflows pause AI/person nodes on the server and emit a plugin agent
task. Use `loomex_agent_task_list` scoped by `executionId` after a wait reports
pending plugin agent work, or after reconnect when a plugin run is waiting.

Each task includes an `agentTask` object. Request `status: "pending"` when
dispatching work; `status: "all"` may include resolved historical tasks and
must not be used to infer the active provider route. Read its `prompt`, `input`, `schemas`,
`sessionDirective`, `providerExecution`, `runnerExecution`, and `instructions` before doing
anything. `resolvedProvider` and `resolvedModel` are the execution contract;
`requestedProvider` and `requestedModel` preserve the workflow selection. The
server is the source of truth for sub-agent continuity. Provider routing and
the explicit command/fallback policy are defined in
[plugin-agent-providers.md](plugin-agent-providers.md).

For AI workflow creation, discover the hidden system workflow with
`loomex_workflow_list(systemKey="workflow_builder")`, inspect it with
`loomex_workflow_show`, and start it through the normal `loomex_workflow_run`
contract with the user's request verbatim in `inputs.prompt`. Continue that
execution with bounded `loomex_run_wait` calls and dispatch every `plugin_agent`
request through the normal `loomex_agent_task_respond` contract. The system
workflow owns clarification, designer, reviewer, and repair loops. When the
execution is completed, call `loomex_workflow_create_finalize` with the
returned `builderSession.id` and a fresh idempotency key. Finalization performs
canonical validation and persists the user Workflow; the returned draft alone
is never a saved Workflow.

`agentTask.prompt` is already the immutable provider-ready prompt. It includes
the allowed resolved node input and schema context selected by Backend. Use
`promptTemplate`, `promptContext`, `input`, and `schemas` for audit only; never
reconstruct, extend, or replace the final prompt on the Plugin host.

For a Codex sub-agent, pass only that exact prompt string to the sub-agent.
Never add execution metadata, workspace instructions, a reconstructed task or
answers, or a hand-written output contract. When the sub-agent writes directly
to the selected Runner workspace, leave optional file-list fields out of the
submitted node output unless the node schema requires them; the workspace is
the source of truth for those edits.

For a non-Codex provider, Backend already owns the terminal hand-off from
`agentTask.runnerExecution.jobId` to the durable workflow resume queue. Do not
execute `providerExecution.argv` in Codex or with a shell command, and do not
submit its successful Runner output with `loomex_agent_task_respond`. You may
read the exact `runnerExecution.jobId` for progress, but Backend advances the
workflow after the Runner reports a terminal result. This is internal work,
not a user decision: do not end the Codex task or expose the plugin-agent task
to the user. Continue bounded waits until a real human request/approval or a
terminal run state is returned.

Obey `sessionDirective.action` exactly:

- `spawn`: create a new sub-agent in the AI host currently running the Loomex
  plugin. Return its actual opaque ID with `agentSession.action` set to
  `spawned`. When `previousSessionId` is present, the new ID must differ.
- `resume`: resume the exact sub-agent named by `sessionDirective.sessionId`.
  Return that same ID with `agentSession.action` set to `resumed`. Never spawn a
  replacement if that session cannot be resumed.

For `resume_per_node`, keep the sub-agent available while the workflow remains
non-terminal because a later loop visit may resume it. For `new_each_run`, each
loop visit receives `spawn` and must use a distinct session. The directive's
`visit` and `continuityKey` are server-owned correlation fields; do not alter or
derive session policy locally.

For the Codex route or an explicit Codex fallback, submit exactly one structured
response with `loomex_agent_task_respond`:

- completed spawn: include the actual provider/model in both the response and
  session, for example
  `{"status":"completed","output":{...},"provider":"claude","model":"claude-sonnet","agentSession":{"id":"actual-id","host":"codex","action":"spawned","provider":"claude","model":"claude-sonnet"}}`
- completed resume: use the same exact provider/model and the server-selected
  session ID, with `agentSession.action` set to `resumed`.
- plugin host cannot perform the directed action:
  `{"status":"unavailable","error":{"code":"PLUGIN_AGENT_PROVIDER_NOT_INSTALLED","message":"...","provider":"claude","model":"claude-sonnet"}}`
- failed local execution:
  `{"status":"failed","error":{"code":"PLUGIN_AGENT_FAILED","message":"...","provider":"...","model":"..."}}`

The `output` object must match the task's output schema when one is present.
Never fabricate an AI result or a session ID. The server will reject a missing,
reused, provider-mismatched, model-mismatched, or continuity-mismatched session
and prevent the execution from advancing rather than losing continuity.

Only a real pending human-input form or approval request requires a user
decision. Continue waiting through Runner-provider work and Codex sub-agent
work; never close the task merely because an AI node is still executing. If the
host itself is unable to execute a directed Codex task, submit its structured
`unavailable`/`failed` response so the server can make the execution terminal
instead of leaving it indefinitely paused.

A dispatch timeout is a terminal backend result when `loomex_run_get` reports
the run as `failed`: the job was not leased within the dispatch grace period.
Restarting the Runner cannot continue that same terminal execution; a new run
requires a new user request and idempotency key. Do not confuse a retryable
management transport failure with this authoritative terminal result.

`loomex_run_list` currently requires `workflowId`; it cannot enumerate every run
in a organization. When the user lacks both execution ID and workflow ID, resolve the
workflow first with `loomex_workflow_list`. Then call `loomex_run_list` with the
required `workflowId` and optional `status`, `cursor`, and `limit`, and let the
user choose when multiple runs still match. Do not send an organization context or an empty
workflow ID to this tool.

## Cancel

Before `loomex_run_cancel`, explain which run will be cancelled and whether a
local action is currently executing. Cancellation may be cooperative. Report
`cancellation_requested` separately from terminal `cancelled` and continue
waiting when the user needs confirmation. Call it with required `executionId`,
a non-empty audit `reason`, and `idempotencyKey`. Reuse the key only to retry
that same cancellation request with the same reason.
