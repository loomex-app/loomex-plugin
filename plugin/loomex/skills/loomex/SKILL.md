---
name: loomex
description: Use Loomex from Codex to set up its durable local Runner, authenticate, select organizations and projects, bind local workspaces, browse and run plugin workflows, follow long-running runs, execute plugin AI/person tasks, respond to human-in-the-loop requests, decide approvals, inspect status and logs, or repair and roll back Runner setup.
---

# Loomex

Use the Loomex MCP tools as the control surface. Keep the backend and durable
Runner as the source of truth; do not attempt to reproduce workflow execution
inside the Codex task.

## Route the request

- Use the focused child skill when the request is primarily about one area:
  `setup`, `scope`, `workflow`, `runs`, or `human`. The child skills share this
  skill's Loomex MCP contract and safety rules; do not duplicate execution in
  shell commands or bypass the Runner.
- Setup, upgrade, repair, or uninstall/rollback: read
  [setup-and-auth.md](references/setup-and-auth.md).
- Organization, project, or local workspace binding: read
  [workspace-binding.md](references/workspace-binding.md).
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
3. When the next action is `binding.create` because the configured Runner does
   not match the authenticated Runner, do not mutate local state silently. Read
   the selected scope and bindings, show the exact project and workspace repair,
   obtain confirmation, then call `loomex_binding_create`; its exact-binding
   reconciliation is safe after an uncertain prior create response.
4. When setup is complete, continue through authentication, required
   organization/project scope, and workspace binding, then resume the user's
   original request in the same conversation. A registered service that is
   deferred or inactive pending auth/binding is not a reason to repair setup.
5. Reuse the selected organization, project, and existing binding when they
   unambiguously match the current workspace. Never silently widen a binding.
6. `loomex_workflow_list` only returns workflows whose execution model is
   `plugin`. App-only and server-only workflows are intentionally hidden from
   the Codex plugin workflow picker.
7. Before running, use `loomex_workflow_show` to confirm inputs and local
   capabilities when the workflow or parameters are ambiguous.
8. Treat the ID returned by `loomex_workflow_run` as authoritative. Follow it
   with `loomex_run_wait`; do not run shell commands to imitate its nodes.
9. When a wait returns a plugin agent task, execute it on the local plugin host
   according to its server-managed `agentTask.sessionDirective`, then submit
   the result and actual `agentSession` with `loomex_agent_task_respond`.
   `spawn` requires a new sub-agent; `resume` requires the exact prior session
   ID and must never fall back to a replacement. Do not let the server AI
   substitute for this work.
10. When a wait returns a typed human request, call `loomex_human_open` with
   the exact returned request so Codex opens the interactive side panel; do not
   ask for the same values again in chat. For legacy human requests and policy
   approvals, present the exact prompt, choices, consequences, and run context.
   Submit only the user's decision.
11. A closed Codex app cannot surface new prompts. The durable Runner keeps the
   run alive and the backend retains pending work. On reconnect, query the run
   and pending inboxes, and explain this boundary honestly.
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
  `loomex_auth_wait`, `loomex_auth_logout`
- Scope: `loomex_org_list`, `loomex_org_select`, `loomex_project_list`,
  `loomex_project_select`
- Bindings: `loomex_binding_list`, `loomex_binding_create`,
  `loomex_binding_revoke`
- Workflows: `loomex_workflow_list`, `loomex_workflow_show`,
  `loomex_workflow_run`
- Runs: `loomex_run_list`, `loomex_run_get`, `loomex_run_wait`,
  `loomex_run_cancel`
- Human requests: `loomex_human_list`, `loomex_human_open`,
  `loomex_human_respond`
- Approvals: `loomex_approval_list`, `loomex_approval_decide`
- Plugin agent tasks: `loomex_agent_task_list`,
  `loomex_agent_task_respond`
- Runner: `loomex_runner_status`, `loomex_runner_control`,
  `loomex_runner_doctor`, `loomex_runner_logs`

Never invent a tool name or infer success from transport success alone. Read the
structured result and report any partial, waiting, rejected, or rollback state.
