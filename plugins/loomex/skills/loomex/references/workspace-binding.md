# Organization, project, and execution workspace

Use `loomex_org_list` and `loomex_project_list` to resolve scope. Project listing
accepts optional `organizationId`. If there is exactly one valid choice it may
be selected; otherwise show concise choices and ask the user. Persist an explicit
selection with `loomex_org_select(organizationId)` or
`loomex_project_select(projectId)` only after the choice is clear.

Binding records are not Runner installation state. The durable Runner can
start with only Runner authentication; the local path and execution scope are
selected independently for each execution.

Before creating an execution scope, call `loomex_binding_list` and inspect the
selected project and Runner. It accepts optional `projectId` and `status`
(`active`, `revoked`, or `all`). Reuse only a scope that belongs to the current
execution; never persist a workspace path on a binding.

For `loomex_binding_create`:

1. Show the organization, project, runner, and allowed capability summary.
2. Obtain confirmation because the binding grants the runner access to the
   selected project.
3. Submit the selected Loomex project as `projectId`.

`workspacePath` belongs only to `loomex_workflow_run` and is required for every
execution. Do not send `localRootPath` or `workspaceRoot` in binding requests
or infer the execution path from a binding response.

Never bind the home directory, filesystem root, a broad workspace collection,
or a symlink-resolved parent merely for convenience. The Runner performs the
authoritative containment and symlink checks; report its rejection as-is.

`loomex_binding_revoke` prevents future work for that binding and may affect
queued runs. Show the affected project/binding and any run context already known
before asking for confirmation; do not claim the revoke tool has a separate
preview mode. After explicit user confirmation, call it with the exact
`projectId`, exact `bindingId`, and `confirm: true`. The required `confirm` field
is an API guard, not a substitute for obtaining the user's decision first.
