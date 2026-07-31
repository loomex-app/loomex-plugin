# Changelog

## 0.1.55

- Keep pending Codex sub-agent tasks visible when resolved Gemini/Claude Runner
  tasks are also present in the agent inbox.
- Route `run_wait` by the resolved provider instead of treating every
  `plugin_agent` request as durable Runner work.
- Tell the Codex host to query pending agent tasks before dispatching a
  provider-specific sub-agent.

## 0.1.54

- Automatically recover stale local management and Runner credentials by
  clearing the rejected profile scope and starting device authentication again.
- Keep Plugin bindings pathless; execution-local workspace paths are supplied
  only when a workflow execution starts.

## 0.1.53

- Fail closed when Loomex setup, workflow, Runner, provider, or agent-task
  operations fail; direct shell, file edits, provider CLIs, and ad-hoc fallback
  implementations are explicitly prohibited.
- Add a hard-stop MCP error message and preserve the exact Loomex error state.

## 0.1.52

- Make AGY use the selected Runner workspace with its supported `--add-dir` argument.
- Deny AGY's scratch workspace at the process boundary so it cannot escape the selected binding.

## 0.1.51

- Confine Claude and AGY provider processes to the selected Runner workspace at the OS process boundary, with only their dedicated runtime state writable outside it.
- Remove AGY's scratch-directory sandbox flag so workflow changes are applied in the selected workspace.

## 0.1.50

- Accept both successful AGY structured-output envelope shapes before validating and resuming the provider node.
- Mark Claude/Gemini plugin-agent work as internal in the MCP contract and workflow skill, keeping the chat in bounded follow-up until a real human decision or terminal result.

## 0.1.49

- Let Backend consume terminal Claude/Gemini Runner results, validate the provider structured output and workspace scope, and enqueue the durable workflow resume without requiring a Codex chat to submit it.
- Document that only real human input or approval pauses require a user decision; provider execution remains a non-terminal run state.

## 0.1.48

- Treat `agentTask.prompt` as the Backend-compiled provider prompt, carrying the resolved node input, input/output schemas, and binding workspace scope.
- Require Codex sub-agents to receive that exact compiled prompt while Claude and Gemini continue to execute the immutable Runner argv.

## 0.1.47

- Execute Runner `shell.exec` jobs in their explicitly declared, binding-contained working directory.
- Preserve the provider command working directory from Backend through the Runner job payload.

## 0.1.46

- Keep the durable Runner control session fresh while provider commands run, so a long-running Gemini or Claude command can renew its lease and submit its terminal result.

## 0.1.45

- Fix PostgreSQL-compatible Runner job leasing and stale pre-start job recovery.
- Preserve safe `HOME`/`PATH` settings for provider CLIs running under launchd or systemd.
- Keep retryable runner job-control validation failures from stopping the Runner service.

## 0.1.44

- Keep workflow tasks open while non-terminal Runner jobs are executing.
- Poll durable Runner jobs until terminal completion and preserve provider output handoff.

## 0.1.43

- Dispatch Claude and Gemini provider commands through the local Runner and let Codex watch the durable Runner job.
- Add the `loomex_runner_job_get` MCP tool for provider-job polling and structured output handoff.
- Keep provider command argv and workflow prompts server-built and unchanged through plugin execution.

## 0.1.42

- Build provider-specific command argv on the Backend and execute it unchanged on the Plugin host.
- Run AGY headlessly with the mapped model, effort, JSON schema, and structured-output extraction contract.
- Validate plugin-agent output against the workflow node schema before resuming execution.

## 0.1.41

- Forward the exact local binding workspace path through `workflow.run` and the Backend plugin-agent task.
- Use the echoed runner workspace as the provider working directory and fail closed when it is unavailable.

## 0.1.40

- Invoke AGY headless prompts with its documented `-p` flag and preserve the exact workflow prompt.
- Recover AGY conversation IDs from its workspace cache for strict plugin-agent session continuity.
- Surface provider exit status and sanitized stderr when a local provider fails.

## 0.1.39

- Forward plugin agent prompts verbatim without mixing schemas or workspace context into the prompt.
- Route AGY with the resolved model and fail closed when structured output or prompt integrity is invalid.
- Preserve exact provider effort and Codex profile metadata for sub-agent execution.
- Publish the 0.1.39 package through the standard main-branch release provenance gate.

## 0.1.38

- Route plugin agent tasks by the workflow-selected provider and resolved model.
- Execute Claude through `claude`, Gemini through `agy`, and use an explicit
  Codex fallback only when the provider command is unavailable.
- Validate actual provider, model, and agent-session continuity in Backend.

## 0.1.37

- Remove the standalone Runs, Human, and Scope sub-skills from the Codex plugin.
- Route run follow-up, human input, approvals, and scope handling through the main Loomex skill.
- Keep focused Setup and Workflow sub-skills with explicit run continuation guidance.

## 0.1.36

- Restore human-input form progress and submitted review state after reopening the same Codex chat.
- Preserve workflow action state within its originating Codex chat without leaking it into other chats.
- Keep custom `Other` drafts persistent without interrupting input focus.

## 0.1.31

- Release the verified Codex package with durable widget-state handling.
- Keep `Other` drafts visible across widget rerenders.
- Restore checkbox and radio selections after reopening the chat form.
- Persist human-input form state through the Codex widget-state bridge.

## 0.1.30

- Persist form progress and submitted workflow actions across widget reloads.
- Advance typed choice forms automatically while keeping `Other` available for custom text.
- Keep non-text human input in the interactive form and resume the workflow without a manual continue message.
- Route batch boolean `false` answers through the configured workflow branch.

## 0.1.29

- Render typed human-input forms directly from human request list results.
- Move the workflow Run action to the first table column.

## 0.1.28

- Keep choice inputs stable when selecting Other and preserve submitted human-input reviews across widget remounts.
- Apply reliable widget shell spacing and disable the form after submission.
- Preserve false Boolean routing for legacy human approval conditions.

## 0.1.27

- Increase widget frame spacing for Codex display scaling.
- Hide human-input actions after a successful submission.
- Keep the Other answer field visible while it is selected.

## 0.1.26

- Improve widget spacing and disable human-input controls after submission.
- Send boolean responses in the server-compatible single-answer shape.
- Add a Run action to the workflow list that resumes execution in Codex.

## 0.1.25

- Add responsive outer padding to human-input forms and list/table widgets.

## 0.1.24

- Render typed human-input forms through the standard MCP Apps tool-result bridge.
- Keep text requests in Codex chat and make the form render tool visible to the app host.

## 0.1.23

- Recognize `radio` and `checkbox` human-input types and render their interactive form.
- Keep `text` human-input requests in the Codex chat.

## 0.1.22

- Route typed text human-input requests through the Codex chat.
- Keep boolean, radio, and checkbox requests in the interactive side-panel form.
- Publish the updated plugin and native runtime artifacts.
## 0.1.28

- Keep choice inputs stable when selecting Other and preserve submitted human-input reviews across widget remounts.
- Apply reliable widget shell spacing and disable the form after submission.
- Preserve false Boolean routing for legacy human approval conditions.
