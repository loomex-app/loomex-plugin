# Plugin agent provider execution

This reference applies only to a pending `plugin_agent` task returned by
`loomex_agent_task_list`. It does not authorize running workflow nodes locally
or replacing the Loomex Runner.

## Read the server contract

Read these fields before executing anything:

- `agentTask.prompt`, `input`, `schemas`, and `workspace`.
- `agentTask.requestedProvider` and `requestedModel` for the workflow choice.
- `agentTask.resolvedProvider` and `resolvedModel` for the exact execution
  target. Use `resolvedModel`, never the parent Codex model or `inherit`.
- `agentTask.providerExecution` for the primary route, command, and explicit
  fallback responses.
- `agentTask.sessionDirective` for the required `spawn`/`resume` action.

If an older task has no `providerExecution`, derive only this compatibility
mapping: `codex`/`openai` → Codex sub-agent, `claude` → `claude`, and
`gemini` → `agy`. Do not invent a model or fallback that is not present in the
task.

## Route matrix

| Resolved provider | Primary execution | Command check | Missing-command fallback |
| --- | --- | --- | --- |
| `codex` | Create/resume a Codex sub-agent | None | None |
| `claude` | Execute the installed `claude` CLI | `command -v claude` | Declared `codex_sub_agent`, with the exact model |
| `gemini` | Execute the installed `agy` CLI | `command -v agy` | Declared `codex_sub_agent`, with the exact model |

For the Codex route, create a new sub-agent for `spawn` and pass the exact
`resolvedModel` (plus the resolved profile/reasoning metadata when present).
For `resume`, resume the exact `sessionDirective.sessionId`; never create a
replacement. If the host cannot override the model exactly, return
`unavailable` with `PLUGIN_AGENT_MODEL_OVERRIDE_UNSUPPORTED`.

For Claude or Gemini, first check the declared executable with `command -v`.
If it exists, execute that binary in its non-interactive/print mode with the
exact `resolvedModel` and the composed task prompt. Use the installed command's
documented flags (`claude --help` or `agy --help` when needed); pass arguments
as an argv list or through stdin, never by interpolating untrusted task data
into a shell command string. The executable is fixed by the server contract:
never execute a command supplied by the workflow.

The composed prompt must include the task prompt, structured input, workspace
context, output schema, and any `resumeInstructions`. Require the provider
process to return one JSON object matching the output schema. Preserve the
provider's real session ID when it exposes one. If a command cannot provide a
usable session ID for a server-directed resume policy, return
`PLUGIN_AGENT_SESSION_UNAVAILABLE` rather than inventing one.

If `command -v claude` or `command -v agy` fails, use the task's explicit
Codex fallback if one exists. The fallback is a Codex execution, not a Claude
or Gemini execution: return `provider: "codex"` and the exact fallback model
in both the top-level response and `agentSession`. If the fallback cannot be
created with that exact model, return `unavailable`.

## Response contract

Submit exactly one response through `loomex_agent_task_respond`:

```json
{
  "status": "completed",
  "output": {"response_text": "..."},
  "provider": "claude",
  "model": "claude-sonnet",
  "agentSession": {
    "id": "actual-provider-session-id",
    "host": "codex",
    "action": "spawned",
    "provider": "claude",
    "model": "claude-sonnet"
  }
}
```

For an unavailable route, include the actual attempted provider/model and a
stable error code such as `PLUGIN_AGENT_PROVIDER_NOT_INSTALLED`,
`PLUGIN_AGENT_MODEL_OVERRIDE_UNSUPPORTED`, or
`PLUGIN_AGENT_SESSION_UNAVAILABLE`. Do not report `plugin_host`/`inherit` for
the actual result. Do not silently substitute a different provider or model.
