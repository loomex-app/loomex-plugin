---
name: workflow
description: Use when a user asks to list, inspect, compare, or start a Loomex workflow with an execution-local workspace path.
---

# Workflow

Browse and start only Loomex workflows with execution model `plugin`. Read [workflows-and-runs.md](../loomex/references/workflows-and-runs.md) before running.

## Fail closed

Loomex is the only execution surface. If setup, authentication, binding,
workflow start, wait, Runner, provider, human-input, or resume handling fails,
stop and report the exact error/state. Never use shell commands, file editing,
direct provider CLIs, or a locally implemented fallback to imitate or replace
the workflow. After failure, only another `loomex_*` diagnostic or recovery
tool is allowed.

## Workflow

- Call `loomex_setup_status` first, then ensure auth, organization/project scope, and an active project binding are ready. The binding has no filesystem path.
- Use `loomex_workflow_list` to discover workflows. Do not show or run app-only or server-only workflows through the Codex plugin.
- `loomex_workflow_list` renders a searchable ChatGPT UI table when supported. Use the table for browsing, then call `loomex_workflow_show` when the user needs details or when a workflow choice is ambiguous.
- Use `loomex_workflow_show` when a workflow name collides, inputs are unclear, a version is selected, or local capabilities/approval points need explanation.
- Before `loomex_workflow_run`, confirm workflow ID/version, selected project,
  binding, the exact local workspace path for this execution, inputs,
  capabilities, and known approval points. Use a fresh `idempotencyKey` for a
  new run.
- `loomex_workflow_run` requires the canonical local `workspacePath` for that
  execution. The binding does not provide or own this path.
- Treat the returned execution ID and status as authoritative. A queued or submitted response is not completion; continue with bounded `loomex_run_wait` calls and recover uncertain state with `loomex_run_get`.
- Keep the current task open while the execution is non-terminal. Do not return
  a final "the workflow is running" message after one wait: continue the
  bounded wait/poll cycle in this task until the run reaches a terminal state,
  requires human input, or an explicit unrecoverable error is returned. A
  provider job that is queued or running is not a reason to close the task.
- Never pass credentials, tokens, or unrelated environment variables as inputs.
  Never execute workflow nodes with shell commands. The only permitted local
  command execution is the provider command explicitly required by a pending
  `plugin_agent` task; follow
  [plugin-agent-providers.md](../loomex/references/plugin-agent-providers.md).

If run input is ambiguous, stop and ask rather than guessing IDs, versions, or schema fields.
