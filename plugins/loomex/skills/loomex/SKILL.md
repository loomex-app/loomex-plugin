---
name: loomex
description: Use Loomex from Codex to set up its durable local Runner, log in or register, create or switch organizations, select projects, browse and run plugin workflows, follow long-running runs, execute plugin AI/person tasks, respond to human-in-the-loop requests, decide approvals, inspect status and logs, or repair and roll back Runner setup.
---

# Loomex

Use the Loomex MCP tools as the control surface. Keep the backend and durable
Runner as the source of truth; do not attempt to reproduce workflow execution
inside the Codex task.

## Hard execution boundary

Loomex is the only execution surface for Loomex work. This is fail-closed:

- If any Loomex tool returns an error, rejected result, unavailable provider,
  failed Runner job, or terminal failed execution, stop the requested work and
  report the exact Loomex error/state.
- Never recover by editing files, running shell commands, invoking `agy`,
  `claude`, `gemini`, or another provider directly, or implementing the
  requested result yourself.
- After a failure, only call another `loomex_*` tool for Loomex-owned
  diagnostics or recovery. Do not claim success, partial implementation, or
  changed files unless Loomex returned that result.
- A user request to build or modify something through Loomex does not grant
  permission to perform that work outside Loomex.

## Route the request

- Use the focused `setup`, `login`, `logout`, `organization-create`,
  `organization-switch`, `create-workflow`, or `workflow` child skill when the request is
  primarily about one of those areas. Handle scope, run follow-up, human input,
  approvals, and agent tasks through this main skill and its references. All
  skills share the same Loomex MCP contract and safety rules; do not duplicate
  workflow execution in shell commands or bypass the Runner. Provider command
  execution is allowed only while handling a server-issued plugin agent task.
- Setup, upgrade, repair, or uninstall/rollback: read
  [setup-and-auth.md](references/setup-and-auth.md).
- Organization or project selection: use the selected organization/project
  context; projects are metadata only and never own execution roots.
- Browse workflows, start a run, wait, cancel, or resume after reconnect: read
  [workflows-and-runs.md](references/workflows-and-runs.md).
- Human input or approval: read
  [human-and-approvals.md](references/human-and-approvals.md).
- Health, control, diagnostics, or logs: read
  [runner-operations.md](references/runner-operations.md).
- Before any write or sensitive output, follow [safety.md](references/safety.md).
- For component ownership and lifetime guarantees, read
  [architecture.md](references/architecture.md).

Read every reference needed for the user's request before calling its tools.

## Baseline behavior

1. For every natural-language Loomex request, first call
   `loomex_setup_status` and branch on its `recommendedNextAction`. Never wait
   for or request a special setup phrase.
2. When the next action is `setup.plan`, immediately call the read-only
   `loomex_setup_plan` without asking a preliminary question. Explain that the
   verified runtime is already bundled with the plugin, but its durable
   per-user service is not set up yet. Show the concrete plan; ask for approval
   only before `loomex_setup_apply`.
3. When setup is complete, continue through Runner authentication and the
   required organization/project scope, then resume the user's original request
   in the same conversation. A registered service that is deferred or
   inactive pending authentication is not a reason to repair setup. Project
   execution root and the local workspace path are execution-scoped; they are not
   prerequisites for the durable Runner service.
   If authentication succeeds and `loomex_org_list` returns an empty `items`
   array, invoke the `organization-create` child skill and ask for the
   organization name. Do not report `ORGANIZATION_NOT_FOUND` as a final state
   when the account simply has no organizations. If exactly one organization is
   returned and no organization is selected, call `loomex_org_select` with its
   exact ID without asking an unnecessary follow-up. If multiple organizations
   are returned, invoke `organization-switch` and ask the user to choose one.
   If a scope call returns `reauthRequired` with an embedded `auth` challenge,
   treat the saved credential as stale (for example after a local database
   reset): present the returned verification URI/code, call
   `loomex_auth_wait` with its exact `loginId`, and retry the original scope
   call after authentication succeeds. Do not ask the user to manually edit
   Loomex config or register a workspace.
4. Reuse the selected organization and project when they unambiguously match
   the request. Never silently widen project scope.
5. `loomex_workflow_list` only returns workflows whose execution model is
   `plugin`. App-only and server-only workflows are intentionally hidden from
   the Codex plugin workflow picker.
6. Before running, use `loomex_workflow_show` to confirm inputs and local
   capabilities when the workflow or parameters are ambiguous.
7. Treat the ID returned by `loomex_workflow_run` as authoritative. Follow it
   with repeated bounded `loomex_run_wait` calls while it is non-terminal; do
   not close the current task with only a "the workflow is running" message.
   Do not run shell commands to imitate its nodes.
8. When a wait returns a plugin agent task, it is internal workflow work, never
   a user-facing question. Do not end the current task, ask the user to
   continue, or present its request ID. Read
   [plugin-agent-providers.md](references/plugin-agent-providers.md). Codex
   executes only the OpenAI sub-agent route. Query
   `loomex_agent_task_list` with `status: "pending"` so resolved historical
   tasks cannot be mistaken for the active route. For Claude/Gemini, Backend has
   already queued the server-built provider argv on the local Runner; call
   `loomex_runner_job_get` with the exact `runnerExecution.jobId` only for
   progress. Keep bounded `loomex_run_wait` calls in this same task while the
   job is queued or running. Backend consumes the normal terminal Runner
   result and resumes the parent run; do not call `loomex_agent_task_respond`
   for it. Surface only a real human-input/approval request or a terminal run
   state. Treat `agentTask.prompt` as a server-managed opaque string and never
   edit it. `spawn` requires a new provider session; `resume` requires the
   exact prior session ID. Report the actual provider/model used; never claim
   that a Codex fallback executed Claude or Gemini. Do not use
   `agy --prompt-interactive`: Runner provider execution is headless and must
   preserve the server-provided JSON output contract.
   For the Codex route, the prompt argument given to the sub-agent must be
   exactly `agentTask.prompt`, byte-for-byte. Do not create a new prompt from
   `input`, `nodeInput`, `previousOutputs`, `questions`, `answers`, workspace
   paths, execution IDs, or `schemas`; do not prepend a role/execution
   preamble, append an output contract, or restate the task. Those fields are
   inspection/validation data only. If `promptContract.sha256` does not match
   the exact prompt bytes, stop with `PLUGIN_AGENT_PROMPT_TAMPERED` rather than
   repairing or rebuilding the prompt. When the sub-agent edits the selected
   local workspace directly, omit optional `files`/file-list output fields
   unless the server schema explicitly requires them; never invent a file
   manifest that can trigger a Runner file-write operation.
10. When a wait returns a typed human request, route by `inputSpec.inputType`:
   collect `text` in the Codex chat and submit it with `loomex_human_respond`;
   call `loomex_human_open` for `boolean`, `single_select`/`radio`, and
   `multi_select`/`checkbox`, using the exact returned request. Do not collect
   the same value in both places. Opening a non-text form must not stop the
   chat behind a manual continuation request: do not tell the user to say
   "continue" or claim that the workflow will resume only after another chat
   message. The form action sends the follow-up that resumes the workflow;
   report the next Runner state from that follow-up. Only a `text` request
   waits for a conversational answer. For legacy human requests and policy
   approvals, present the exact prompt, choices, consequences, and run
   context. Submit only the user's decision.
11. A closed Codex app cannot surface new prompts. The durable Runner keeps the
   run alive and the backend retains pending work. On reconnect, query the run
   and pending inboxes, and explain this boundary honestly. A healthy
   non-terminal run must still be followed through its form action or bounded
   `loomex_run_wait`; never ask the user for a standalone "continue" message
   merely because a request was sent to the Runner.
12. Treat retryable management or wait transport failures as unknown state, not
   as evidence that the run survived, failed, or was cancelled. Recover with
   `loomex_run_get` using the authoritative execution ID, then use bounded
   `loomex_run_wait` calls. Do not recommend restarting the Runner unless
   `loomex_runner_status` or `loomex_runner_doctor` shows that the local service
   is unhealthy; a healthy service must be allowed to reconnect by itself.

## Tool inventory

- Setup: `loomex_setup_status`, `loomex_setup_plan`, `loomex_setup_apply`,
  `loomex_setup_rollback`
- Authentication: `loomex_auth_status`, `loomex_auth_start`,
  `loomex_auth_wait`, `loomex_auth_register`,
  `loomex_auth_register_verify`, `loomex_auth_logout`
- Scope: `loomex_org_list`, `loomex_org_create`, `loomex_org_select`,
  `loomex_project_list`,
  `loomex_project_select`
- Workflows: `loomex_workflow_list`, `loomex_workflow_show`,
  `loomex_workflow_run`, `loomex_workflow_create`,
  `loomex_workflow_create_respond`
- Runs: `loomex_run_list`, `loomex_run_get`, `loomex_run_wait`,
  `loomex_run_cancel`
- Human requests: `loomex_human_list`, `loomex_human_open`,
  `loomex_human_respond`
- Approvals: `loomex_approval_list`, `loomex_approval_decide`
- Plugin agent tasks: `loomex_agent_task_list`,
  `loomex_agent_task_respond`, `loomex_runner_job_get`
- Runner: `loomex_runner_status`, `loomex_runner_control`,
  `loomex_runner_doctor`, `loomex_runner_logs`

Never invent a tool name or infer success from transport success alone. Read the
structured result and report any partial, waiting, rejected, or rollback state.
