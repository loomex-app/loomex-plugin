# Plugin agent provider execution

This reference applies only to a pending `plugin_agent` task returned by
`loomex_agent_task_list`. It does not authorize running workflow nodes locally
or replacing the Loomex Runner.

Provider failure is fail-closed. A 401/403, missing CLI, non-zero exit, invalid
output, timeout, unavailable Runner, or schema mismatch must become the exact
declared `failed`/`unavailable` result for the Loomex agent task. Never edit the
workspace, run a provider CLI outside the declared route, invent output, or
continue the workflow manually after that failure.

## Read the server contract

Read these fields before executing anything:

- `agentTask.prompt`, `promptTemplate`, `promptContext`, `input`, `schemas`, and
  `workspace`.
- `agentTask.requestedProvider` and `requestedModel` for the workflow choice.
- `agentTask.resolvedProvider` and `resolvedModel` for the exact execution
  target. Use `resolvedModel`, never the parent Codex model or `inherit`.
- `agentTask.providerExecution` for the primary route, the server-built
  executable argv, output extraction contract, and explicit fallback responses.
- `agentTask.runnerExecution` for the Runner job id, terminal result contract,
  provider, and model. For Claude/Gemini this is the only execution route.
- `agentTask.sessionDirective` for the required `spawn`/`resume` action.
- `agentTask.runnerWorkspacePath` for the exact local workspace path sent by the
  Plugin and echoed by Backend. This is the only valid provider process `cwd`.

If an older task has no `providerExecution`, derive only this compatibility
mapping: `codex`/`openai` → Codex sub-agent, and `claude`/`gemini` → the
declared Runner command job. Do not invent a model or fallback that is not
present in the task.

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
| `claude` | Backend completes the selected Runner job | Runner executes `claude` | Declared `codex_sub_agent`, with the exact model |
| `gemini` | Backend completes the selected Runner job | Runner executes `agy` | Declared `codex_sub_agent`, with the exact model |

For the Codex route, create a new sub-agent for `spawn` and pass the exact `resolvedModel`
plus the exact `providerExecution.reasoningEffort` and
`codexProfile` when present. Give that sub-agent the exact compiled
`agentTask.prompt`; never inherit the parent host model, effort, or prompt.
For `resume`, resume the exact `sessionDirective.sessionId`; never create a
replacement. If the host cannot override the model exactly, return
`unavailable` with `PLUGIN_AGENT_MODEL_OVERRIDE_UNSUPPORTED`.

For Claude or Gemini, do not execute a process in Codex and do not run
`command -v` locally. Backend queues the exact `providerExecution.argv` array
as a Runner `shell.exec` job and returns its opaque `runnerExecution.jobId`.
The Backend is the terminal-result consumer: it parses the Runner result,
validates the schema and workspace scope, and creates the durable workflow
resume delivery itself. Do not call `loomex_agent_task_respond` for a normal
Runner terminal result, and do not use the human request id as a job id.
`commandLine` is for audit display only. The Runner is the only process executor.

You may inspect a provider job with `loomex_runner_job_get` using exactly
`runnerExecution.jobId` for progress reporting, but never make workflow
continuation depend on a Codex chat polling it. Keep following the run with
bounded `loomex_run_wait` calls. A pause is actionable only when the server
returns a real human-input or approval request; a queued/running provider job
is not a request for the user to say “continue”. Do not end the Codex task at
this point: keep bounded waits running until Loomex returns a real human-input
or approval request, or a terminal execution state.

When `providerExecution.reasoningEffort` is present, pass that exact value to
the provider route. Do not infer a different effort from the host model or
replace a server-resolved provider model with a base model.

`agentTask.prompt` is the Backend-compiled, provider-ready prompt. It contains
the workflow-authored prompt unchanged between markers plus a canonical
`loomex.provider-context/v1` JSON envelope with the resolved `nodeInput`, input
and output schemas, and selected workspace scope. `promptTemplate` and
`promptContext` are audit fields only; never rebuild `agentTask.prompt` from
them, from `input`, or from `schemas`.

Forward `agentTask.prompt` verbatim for every route: do not paraphrase,
translate, summarize, reorder, sanitize, add a preamble or append a suffix.
Do not add workflow inputs, previous outputs, workspace context, output schema,
or `resumeInstructions`: Backend decides which resolved node inputs may reach
the provider and has already compiled them into the immutable prompt. Verify the
server-provided `promptContract.sha256` against the exact UTF-8 prompt bytes
before execution; if it does not match, return `PLUGIN_AGENT_PROMPT_TAMPERED`.

For Codex specifically, the sub-agent's prompt parameter has exactly one
source: `agentTask.prompt`. It must not contain a hand-written message such as
an execution/workspace preamble, `Task: ...`, `Clarification answers: ...`, or
an `Output contract ...` suffix. Never substitute `promptTemplate`,
`promptContext`, `input`, `schemas`, or any value derived from them. Do not
repair an empty-looking or malformed server prompt locally; report the prompt
tamper/unavailable condition and let Backend fix the task payload.

For AGY 1.1.8, the Runner-installed CLI advertises the following headless options.
The compiled prompt must be supplied to the `-p`/`--prompt` flag.
Do not run bare `--print`; do not append the prompt as an undocumented
positional argument. The former executes with no prompt and the latter can
terminate with a generic provider error.

The Backend-generated AGY argv has this exact shape. The model is always the
base model identifier; the optional `--effort` pair carries the independent
reasoning selection:

```text
agy -p <agentTask.prompt> --add-dir <runnerWorkspacePath> \
  --output-format json --model <resolvedModel> \
  [--effort <reasoning-effort>] --dangerously-skip-permissions \
  --json-schema <output-schema>
```

The canonical executable form is `providerExecution.argv`, not this display
form. `--dangerously-skip-permissions` is part of the server-owned provider
command so AGY can run headlessly without waiting for a permission prompt. It
must not be removed or replaced with a different permission mode. The
server-owned `--add-dir` value is the exact `runnerWorkspacePath`; it gives AGY
the execution root as its workspace and must not be replaced or
omitted.
Do not add AGY's `--sandbox` flag: AGY may redirect edits into its own scratch
directory instead of the selected Runner workspace. For both AGY and Claude,
`runnerExecution.workspaceScope=provider_write_confined` requires the Runner to
apply its native process-level write sandbox before starting the provider. The
provider and all of its child processes can write only in the selected execution root,
apart from the provider's own narrow runtime-state directory needed for
credentials and conversation metadata (`.gemini/antigravity-cli` for AGY and
`.claude` for Claude). AGY's `.gemini/antigravity-cli/scratch` tree is
explicitly denied because it is an AGY-created project workspace, not runtime
state. No other user project path is writable; if the native sandbox is
unavailable, the Runner fails closed. Backend still validates every declared
`changed_files` path as a separate result-contract check.
For a `resume` directive, Backend places `--conversation <sessionId>` before
`-p` in that same argv; use it exactly and return the same session ID.

The Runner owns command availability and execution. A non-zero exit, empty
output, invalid JSON, or schema mismatch is `PLUGIN_AGENT_FAILED`; do not retry
by rewriting the prompt or by allowing unrelated workspace exploration. Include
the exit status and sanitized Runner/provider stderr in the failure message when
available.

Backend parses AGY/Claude stdout as the provider JSON envelope and follows the
server-declared compatible structured-output paths. AGY accepts both
`response.structured_output` and root `structured_output` because successful
AGY turns can emit either envelope shape; Claude uses root `structured_output`.
It uses exactly that object as the node output; it never returns the whole
provider envelope, textual `response`, usage, or metadata. Backend validates it against
`providerExecution.structuredOutput.schema` and the workflow node output
schema. If the path is missing or is not an object, Backend fails the agent
node with the Runner/provider diagnostics instead of leaving the workflow
waiting.

For `spawn`, use the provider conversation id in the terminal AGY/Claude JSON
envelope. For `resume`, Backend already placed the exact session id in
`providerExecution.argv`; return that same id. If no usable provider id is
exposed, return `PLUGIN_AGENT_SESSION_UNAVAILABLE` rather than inventing one.

If `runnerExecution.status` is `unavailable`, use the task's explicit Codex
fallback if one exists. The fallback is a Codex execution, not a Claude or
Gemini execution: return `provider: "codex"` and the exact fallback model in
both the top-level response and `agentSession`. If the fallback cannot be
created with that exact model, return `unavailable`.

## Response contract

This section applies to the Codex route and an explicit declared Codex fallback
only. Claude/Gemini Runner jobs are responded to automatically by Backend.

Submit exactly one response through `loomex_agent_task_respond`:

```json
{
  "status": "completed",
  "output": {"questions": []},
  "provider": "gemini",
  "model": "gemini-3.6-flash",
  "reasoningEffort": "medium",
  "agentSession": {
    "id": "actual-provider-session-id",
    "host": "codex",
    "action": "spawned",
    "provider": "gemini",
    "model": "gemini-3.6-flash",
    "reasoningEffort": "medium"
  }
}
```

For an unavailable route, include the actual attempted provider/model and a
stable error code such as `PLUGIN_AGENT_PROVIDER_NOT_INSTALLED`,
`PLUGIN_AGENT_MODEL_OVERRIDE_UNSUPPORTED`, or
`PLUGIN_AGENT_SESSION_UNAVAILABLE`. Do not report `plugin_host`/`inherit` for
the actual result. Do not silently substitute a different provider or model.
