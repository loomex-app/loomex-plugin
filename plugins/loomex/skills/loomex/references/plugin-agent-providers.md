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
- `agentTask.providerExecution` for the primary route, the server-built
  executable argv, output extraction contract, and explicit fallback responses.
- `agentTask.sessionDirective` for the required `spawn`/`resume` action.
- `agentTask.runnerWorkspacePath` for the exact local workspace path sent by the
  Plugin and echoed by Backend. This is the only valid provider process `cwd`.

If an older task has no `providerExecution`, derive only this compatibility
mapping: `codex`/`openai` → Codex sub-agent, `claude` → `claude`, and
`gemini` → `agy`. Do not invent a model or fallback that is not present in the
task.

The server execution workspace and the local runner workspace are different
hosts. Use `agentTask.runnerWorkspacePath` exactly as returned by Backend for
the provider process `cwd`. Never substitute `agentTask.workspace.absolutePath`,
the current Codex directory, or another locally selected directory. If the
echoed path is missing or inaccessible, return `unavailable` with
`PLUGIN_AGENT_WORKSPACE_UNAVAILABLE`; do not silently fall back.

## Route matrix

| Resolved provider | Primary execution | Command check | Missing-command fallback |
| --- | --- | --- | --- |
| `codex` | Create/resume a Codex sub-agent | None | None |
| `claude` | Execute the installed `claude` CLI | `command -v claude` | Declared `codex_sub_agent`, with the exact model |
| `gemini` | Execute the installed `agy` CLI | `command -v agy` | Declared `codex_sub_agent`, with the exact model |

For the Codex route, create a new sub-agent for `spawn` and pass the exact `resolvedModel`
plus the exact `providerExecution.reasoningEffort` and
`codexProfile` when present. Never inherit the parent host model or effort.
For `resume`, resume the exact `sessionDirective.sessionId`; never create a
replacement. If the host cannot override the model exactly, return
`unavailable` with `PLUGIN_AGENT_MODEL_OVERRIDE_UNSUPPORTED`.

For Claude or Gemini, first check the declared executable with `command -v`.
If it exists, execute the exact `providerExecution.argv` array produced by the
Backend, in `providerExecution.cwd`. Do not reconstruct, reorder, quote,
remove, or append arguments. The executable is fixed by the server contract:
never execute a command supplied by the workflow. `commandLine` is for audit
display only; use `argv` for execution and never interpolate it into a shell
string.

When `providerExecution.reasoningEffort` is present, pass that exact value to
the provider route. Do not infer a different effort from the host model or
replace a server-resolved provider model with a base model.

The server prompt is an opaque payload. Forward `agentTask.prompt` verbatim:
do not paraphrase, translate, summarize, reorder, sanitize, add a preamble or
append a suffix. Do not put structured input, workspace context, output schema,
or `resumeInstructions` into the prompt text. Pass those values through their
separate provider-native/structured-output transport fields. Verify the
server-provided `promptContract.sha256` against the exact UTF-8 prompt bytes
before execution; if it does not match, return `PLUGIN_AGENT_PROMPT_TAMPERED`.

For AGY 1.1.8, the installed CLI advertises the following headless options.
The prompt must be supplied to the `-p`/`--prompt` flag. Do not run bare
`--print` and do not append the prompt as an undocumented positional argument;
the former executes with no prompt and the latter can terminate with a generic
provider error.

The Backend-generated AGY argv has this exact shape (the `--effort` pair is
present when `providerExecution.reasoningEffort` is present):

```text
agy -p <agentTask.prompt> --output-format json --model <resolvedModel> \
  [--effort <reasoning-effort>] --dangerously-skip-permissions \
  --json-schema <output-schema>
```

The canonical executable form is `providerExecution.argv`, not this display
form. `--dangerously-skip-permissions` is part of the server-owned provider
command so AGY can run headlessly without waiting for a permission prompt. It
must not be removed or replaced with a different permission mode.
For a `resume` directive, Backend places `--conversation <sessionId>` before
`-p` in that same argv; use it exactly and return the same session ID.

Use `--json-schema` only when it is present in `agy --help`; otherwise keep the
prompt unchanged, request JSON through the provider's supported mechanism, and
validate the parsed result locally. A non-zero exit, empty output, invalid JSON,
or schema mismatch is `PLUGIN_AGENT_FAILED`; do not retry by rewriting the
prompt or by allowing unrelated workspace exploration. Include the exit status
and sanitized provider stderr in the failure message when available so the
actual provider failure is diagnosable.

For AGY, parse stdout as the provider JSON envelope. When
`providerExecution.structuredOutput.responsePath` is
`response.structured_output`, use exactly that nested object as the response
`output`; do not return the whole AGY envelope, its textual `response`, usage,
or metadata. The Backend validates that object against
`providerExecution.structuredOutput.schema` and the workflow node output
schema. If the path is missing or is not an object, return
`PLUGIN_AGENT_FAILED` with the provider envelope and stderr details.

AGY does not guarantee that the JSON response contains a conversation ID. For
`spawn`, capture the workspace-keyed conversation ID created by the command
from AGY's documented cache at
`~/.gemini/antigravity-cli/cache/last_conversations.json`; compare it with the
snapshot taken before execution and require a new non-empty ID. For `resume`,
pass the exact server session ID with `--conversation <sessionId>` before the
`-p` flag and return that same ID. If no usable ID is exposed, return
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
  "output": {"questions": []},
  "provider": "gemini",
  "model": "gemini-3.5-flash-medium",
  "agentSession": {
    "id": "actual-provider-session-id",
    "host": "codex",
    "action": "spawned",
    "provider": "gemini",
    "model": "gemini-3.5-flash-medium"
  }
}
```

For an unavailable route, include the actual attempted provider/model and a
stable error code such as `PLUGIN_AGENT_PROVIDER_NOT_INSTALLED`,
`PLUGIN_AGENT_MODEL_OVERRIDE_UNSUPPORTED`, or
`PLUGIN_AGENT_SESSION_UNAVAILABLE`. Do not report `plugin_host`/`inherit` for
the actual result. Do not silently substitute a different provider or model.
