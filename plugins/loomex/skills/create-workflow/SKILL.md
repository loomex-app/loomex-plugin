---
name: create-workflow
description: Use when a user asks Codex to design a Loomex workflow with AI and return a validated workflow JSON draft.
---

# Create a workflow with AI

Use this skill when the user wants Loomex to design a workflow from a natural-language description. This is a design session, not execution of a saved workflow. The result is a validated JSON draft and an auditable builder session; it is not a Workflow record and must not be run automatically.

## Rules

- Loomex is the only control surface. If setup, authentication, organization scope, Runner, the builder API, sub-agent dispatch, or validation fails, stop and report the exact error.
- Call `loomex_setup_status` first. Complete authentication and organization selection before calling `loomex_workflow_create`.
- Do not require an execution root or local workspace path for workflow creation. Creation is organization-scoped and produces JSON only.
- Call `loomex_workflow_create` with the user's request verbatim in `prompt`. Do not rewrite, summarize, translate, or augment the user's request.
- When the result contains `agentTask`, treat it as internal work. Verify `agentTask.promptContract.sha256` against the exact UTF-8 bytes of `agentTask.prompt`.
- Follow `agentTask.sessionDirective` exactly: spawn a new Codex sub-agent for `spawn`; resume the exact session id for `resume`. Use the server-selected `resolvedModel` and reasoning effort.
- Give the sub-agent exactly `agentTask.prompt` as its only prompt. Do not add an execution preamble, role, workspace path, output suffix, validation instructions, or any other text.
- The sub-agent must return the JSON object required by the server contract. It must not edit files, use shell commands, call `agy`, call `claude`, or implement the workflow elsewhere.
- Submit the sub-agent result using `loomex_workflow_create_respond` with the exact builder session id and a fresh idempotency key. Include the actual sub-agent session object with `id`, `host`, `action`, `provider`, and `model`.
- If the response contains another `agentTask` and `validationErrors`, resume the same sub-agent session and submit the repaired JSON. Never spawn a replacement for a repair attempt.
- Repeat only until the server returns `status: completed`, `status: failed`, or the server's maximum-attempt error. Do not locally validate, repair, or fabricate a workflow after a server failure.
- On completion, show the returned `workflowDraft` JSON and explain that it is not saved as a formal Workflow until the user explicitly imports/saves it through a supported flow.

## Response contract

The sub-agent response sent to `loomex_workflow_create_respond` must be:

```json
{
  "status": "completed",
  "provider": "codex",
  "model": "<server-selected resolvedModel>",
  "agentSession": {
    "id": "<actual sub-agent session id>",
    "host": "current_plugin_host",
    "action": "spawned or resumed",
    "provider": "codex",
    "model": "<server-selected resolvedModel>"
  },
  "output": {
    "name": "short workflow name",
    "workflow": {
      "nodes": [],
      "transitions": [],
      "settings": {}
    },
    "rationale": "brief implementation note",
    "warnings": []
  }
}
```

Do not add a manual prompt around the sub-agent output. The Backend owns the canonical prompt, validation, repair instructions, attempt log, and final session record.
