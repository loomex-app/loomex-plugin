---
name: create-workflow
description: Use when a user asks Codex to create and save a Loomex workflow with AI.
---

# Create and save a workflow with AI

Use this skill when the user wants Loomex to turn a natural-language request
into a saved Workflow. Creation is itself a hidden, organization-scoped
Loomex Workflow; it is not a separate server-side AI execution path.

## Rules

- Loomex is the only control surface. If setup, authentication, organization
  scope, Runner, execution, agent dispatch, validation, or finalization fails,
  stop and report the exact error. Never use shell commands, file edits,
  provider CLIs, or a fallback implementation.
- Call `loomex_setup_status` first and complete authentication and organization
  selection before starting creation.
- Call `loomex_workflow_create` exactly once with the user's request verbatim in
  `prompt`. Do not rewrite, summarize, translate, or augment it.
- The tool starts a normal plugin execution of the hidden seeded workflow and
  returns `execution.id` plus `builderSession.id`. The hidden workflow is not
  returned by workflow discovery and must not be shown as a user workflow.
- Continue with bounded `loomex_run_wait` calls for that exact execution until
  Loomex returns a real `plugin_agent` task or a terminal state. Internal agent
  and reviewer requests are not human questions. Follow the normal Codex
  dispatch contract: verify `agentTask.promptContract.sha256`, pass
  `agentTask.prompt` byte-for-byte as the only sub-agent prompt, and obey its
  `sessionDirective` exactly. Submit the actual response through the normal
  `loomex_agent_task_respond` path with the exact execution/request id.
- The seeded workflow owns designer/reviewer prompts and the repair loop. Do not
  construct a prompt, add an output suffix, locally validate, repair, or alter
  the agent result.
- When the execution reaches `completed`, call
  `loomex_workflow_create_finalize` once with the returned builder session id
  and a fresh idempotency key. The server performs canonical validation,
  imports the valid definition, publishes version one, and returns the saved
  Workflow.
- If finalization returns `WORKFLOW_BUILDER_OUTPUT_INVALID`, stop and report the
  server's validation errors. Do not paste the JSON into the UI or claim that a
  Workflow was saved.
- On success, report the returned saved Workflow id/name and execution id. The
  returned `workflowDraft` is audit data; it is not a replacement for the
  persisted Workflow.

## Tool sequence

```text
loomex_setup_status
loomex_workflow_create(prompt=<verbatim user request>, idempotencyKey=<fresh>)
loomex_run_wait(executionId=<returned execution.id>, ...)
loomex_agent_task_respond(...)       # only when run.wait exposes plugin_agent
loomex_run_wait(...)                  # repeat until terminal
loomex_workflow_create_finalize(
  sessionId=<returned builderSession.id>,
  idempotencyKey=<fresh>,
)
```

Do not call the old `loomex_workflow_create_respond` builder-draft flow for a
new request. It remains only for inspecting legacy sessions during migration.
