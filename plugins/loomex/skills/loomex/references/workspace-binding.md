# Organization, project, and workspace binding

Use `loomex_org_list` and `loomex_project_list` to resolve scope. Project listing
accepts optional `organizationId`. If there is exactly one valid choice it may
be selected; otherwise show concise choices and ask the user. Persist an explicit
selection with `loomex_org_select(organizationId)` or
`loomex_project_select(projectId)` only after the choice is clear.

Before creating a binding, call `loomex_binding_list` and compare canonical
paths. It accepts optional `projectId` and `status` (`active`, `revoked`, or
`all`). Reuse an exact binding to the selected project. Do not create duplicates
or infer that a parent directory should be bound.

For `loomex_binding_create`:

1. Resolve the requested workspace root to a canonical absolute path.
2. Show the local root, organization, project, and allowed capability summary.
3. Obtain confirmation because the binding grants workflow access to that root.
4. Submit the canonical root as `workspacePath`, the selected Loomex project as
   `projectId`.

`workspacePath` is the public MCP field. Do not send the Runner's internal
`localRootPath` field or infer a path from the Codex process working directory
when the user identified another workspace.

Never bind the home directory, filesystem root, a broad workspace collection,
or a symlink-resolved parent merely for convenience. The Runner performs the
authoritative containment and symlink checks; report its rejection as-is.

`loomex_binding_revoke` prevents future work for that binding and may affect
queued runs. Show the affected project/binding and any run context already known
before asking for confirmation; do not claim the revoke tool has a separate
preview mode. After explicit user confirmation, call it with the exact
`projectId`, exact `bindingId`, and `confirm: true`. The required `confirm` field
is an API guard, not a substitute for obtaining the user's decision first.
