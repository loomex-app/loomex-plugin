---
name: workflow
description: Use when a user asks to list, inspect, compare, or start a Loomex workflow in an explicitly bound local workspace.
---

# Workflow

Browse and start only Loomex workflows with execution model `plugin`. Read [workflows-and-runs.md](../loomex/references/workflows-and-runs.md) before running.

## Workflow

- Call `loomex_setup_status` first, then ensure auth, organization/project scope, and an exact active workspace binding are ready.
- Use `loomex_workflow_list` to discover workflows. Do not show or run app-only or server-only workflows through the Codex plugin.
- `loomex_workflow_list` renders a searchable ChatGPT UI table when supported. Use the table for browsing, then call `loomex_workflow_show` when the user needs details or when a workflow choice is ambiguous.
- Use `loomex_workflow_show` when a workflow name collides, inputs are unclear, a version is selected, or local capabilities/approval points need explanation.
- Before `loomex_workflow_run`, confirm workflow ID/version, selected project, exact binding, inputs, capabilities, and known approval points. Use a fresh `idempotencyKey` for a new run.
- Treat the returned execution ID and status as authoritative. A queued or submitted response is not completion; hand off follow-up to the `runs` skill.
- Never pass credentials, tokens, or unrelated environment variables as inputs. Never execute workflow nodes with shell commands.

If run input is ambiguous, stop and ask rather than guessing IDs, versions, or schema fields.
