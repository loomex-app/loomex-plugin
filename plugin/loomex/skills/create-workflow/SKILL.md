---
name: create-workflow
description: Use when a user asks Codex to create and save a Loomex workflow with AI.
---

# Create and save a workflow with AI

Use this skill when the user wants Loomex to turn a natural-language request
into a saved Workflow. Creation is itself a hidden, organization-scoped
Loomex Workflow; it is not a separate server-side AI execution path.

## Rules

- First verify that the user supplied an actual workflow description. A bare
  skill invocation, a `/create-workflow` command, a plugin/skill reference,
  or a message that only says “create a workflow” is not a workflow request.
  In that case ask the user to describe the workflow they want and stop before
  calling any Loomex tool. Never pass the skill path, skill invocation, or
  another control message as `inputs.prompt`.
- Loomex is the only control surface. If setup, authentication, organization
  scope, Runner, execution, agent dispatch, validation, or finalization fails,
  stop and report the exact error. Never use shell commands, file edits,
  provider CLIs, or a fallback implementation.
- Call `loomex_setup_status` first and complete authentication and organization
  selection before starting creation.
- Discover the hidden seeded workflow through `loomex_workflow_list` with
  `systemKey: "workflow_builder"`, then inspect that exact id with
  `loomex_workflow_show`. This system workflow is the only create-workflow
  implementation; it is never shown in the ordinary user workflow list.
- Start that exact workflow with the normal `loomex_workflow_run` contract. Put
  the user's request verbatim in `inputs.prompt`. Do not rewrite, summarize,
  translate, or augment it. Omit `workspacePath` for this internal system run;
  Loomex allocates a fresh execution-local workspace.
- Continue with bounded `loomex_run_wait` calls for that exact execution until
  Loomex returns a real `plugin_agent` task or a terminal state. Internal agent
  and reviewer requests are not human questions. Follow the normal Codex
  dispatch contract: rely on the Plugin runtime's native verification of
  `agentTask.promptContract.sha256`, pass `agentTask.prompt` byte-for-byte as
  the only sub-agent prompt, and obey its
  `sessionDirective` exactly. Submit the actual response through the normal
  `loomex_agent_task_respond` path with the exact execution/request id.
- For builder agent tasks, pass `agentTask.referenceContext` separately as
  read-only context and preserve `agentTask.guideAudit` in the response
  metadata. Never append, summarize, translate, or merge guide content into
  `agentTask.prompt`.
- If the builder returns a Human Input request, route it by its exact
  `inputSpec.inputType`: use `loomex_human_respond` only for `text`; use
  `loomex_human_open` for `radio`, `checkbox`, `boolean`, `single_select`, or
  `multi_select`. Never answer a typed form with `optionId`, `selected`, or a
  hand-built `otherText` payload, and never ask the user to provide radio
  answers in chat. The side-panel form must render the server-provided
  questions and submit canonical `value`/`values` fields for the same request.
- The seeded workflow owns designer/reviewer prompts and the repair loop. Do not
  construct a prompt, add an output suffix, locally validate, repair, or alter
  the agent result.
- The Backend is authoritative for package validation. Pass the canonical flat
  graph through create, finalize, and edit/validation calls unchanged; do not
  calculate a local package allowance or silently trim a graph. The server
  counts every entry in `nodes`, including `start`, `end`, and other system
  nodes. Exactly the package maximum is accepted; the first node beyond it is
  rejected with the server's package-limit error.
- When the execution reaches `completed`, call
  `loomex_workflow_create_finalize` once with the returned
  `builderSession.id` and a fresh idempotency key. The server performs canonical validation,
  imports the valid definition, publishes version one, and returns the saved
  Workflow.
- If finalization returns `WORKFLOW_BUILDER_OUTPUT_INVALID`, stop and report the
  server's validation errors. Do not paste the JSON into the UI or claim that a
  Workflow was saved.
- If any workflow, execution, person, memory, or duration operation returns a
  package hard-limit error, stop and report its exact stable error code/message
  and structured `details` (`metric`, `current`, `requested`, `limit`, and
  `period` when supplied). Never turn that response into a success or retry it
  unless the server marks it retryable.
- On success, report the returned saved Workflow id/name and execution id. The
  returned `workflowDraft` is audit data; it is not a replacement for the
  persisted Workflow.

## Tool sequence

```text
loomex_setup_status
loomex_workflow_list(systemKey="workflow_builder")
loomex_workflow_show(workflowId=<system workflow id>, version="active")
loomex_workflow_run(
  workflowId=<system workflow id>,
  inputs={"prompt": <verbatim user request>},
  idempotencyKey=<fresh>,
)
loomex_run_wait(executionId=<returned execution.id>, ...)
loomex_agent_task_respond(...)       # only when run.wait exposes plugin_agent
loomex_run_wait(...)                  # repeat until terminal
loomex_workflow_create_finalize(
  sessionId=<returned builderSession.id>,
  idempotencyKey=<fresh>,
)
```

Do not call `loomex_workflow_create` or the old
`loomex_workflow_create_respond` builder-draft flow for a new request. They
remain only for inspecting legacy sessions during migration.
