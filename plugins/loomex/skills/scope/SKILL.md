---
name: scope
description: Use when a user asks to change the active Loomex organization or project, inspect scope, bind a local workspace, or revoke an existing workspace binding.
---

# Scope

Manage the selected Loomex organization, project, and explicit local workspace binding. Read [workspace-binding.md](../loomex/references/workspace-binding.md) before binding changes.

## Workflow

- Call `loomex_setup_status` first. Complete authentication before scope selection when required.
- Resolve organizations with `loomex_org_list`; if multiple choices exist, show concise names and IDs and ask the user to choose. Persist only an explicit choice with `loomex_org_select`.
- Resolve projects with `loomex_project_list`, passing `organizationId` when needed. Persist only an explicit choice with `loomex_project_select`.
- These list tools render a ChatGPT UI table when the host supports Apps SDK UI. Use the rendered rows for orientation, but treat IDs returned in the tool result as authoritative; a row's Select action is still an explicit user choice.
- Treat changing organization/project as a state change. Report the selected scope and refresh bindings after a selection change.
- Before creating a binding, call `loomex_binding_list`, compare canonical paths, and reuse an exact active binding instead of creating a duplicate.
- Before `loomex_binding_create`, show canonical workspace path, organization, project, and capabilities, then obtain confirmation. Never bind home, filesystem root, or a broad parent directory.
- Before `loomex_binding_revoke`, show exact project, binding, and known run impact; obtain confirmation and pass exact IDs with `confirm: true`.

Never infer a project from a parent directory or silently widen a binding. Preserve exact IDs returned by Loomex.
