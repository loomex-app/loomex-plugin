---
name: human
description: Use when a Loomex run needs human input, a policy approval, or a plugin-host agent task to be listed, answered, or decided.
---

# Human

Handle durable human requests and policy approvals as separate inboxes. Read [human-and-approvals.md](../loomex/references/human-and-approvals.md) before responding.

## Workflow

- Call `loomex_setup_status` first. Refresh the relevant inbox and run state before submitting a mutable response.
- For human input, use `loomex_human_list` with known `executionId` or `workflowId`, preserve `nextCursor`, and inspect the exact request schema.
- If a typed `inputSpec` is present, call `loomex_human_open` with the exact request and let the rendered side-panel form collect answers. Do not ask for those same typed values in chat.
- For legacy free-form requests, present the exact prompt, choices/schema, request ID, context, and deadline; submit only the user's answer through the public `response` field of `loomex_human_respond`.
- For policy approvals, use `loomex_approval_list`, explain target, side effects, consequences, and choices, then call `loomex_approval_decide` with exact `approvalId` and `approve` or `reject`. Never auto-approve.
- For plugin agent tasks, read instructions and session directive, execute only on the local plugin host, and submit exactly one structured response. Never fabricate output or replace an unresumable session.
- If Codex was closed, refresh both inboxes and the run before acting; the Tauri app may have resolved the request concurrently.

Never answer a human request or approval from model preference, prior context, or assumption.
