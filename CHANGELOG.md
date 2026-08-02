# Changelog

## 0.1.70

- Harden workflow builder guide contracts for Human Input batch answers and
  condition branch identifiers.

## 0.1.69

- Require a real natural-language workflow description before starting the
  hidden workflow builder; skill invocations and skill references are no
  longer sent as workflow prompts.

## 0.1.68

- Add a verified, role-aware workflow builder Guide Pack with read-only
  reference context and guide audit metadata.
- Preserve Backend-owned workflow builder prompts byte-for-byte while exposing
  catalog-guided context to Clarifier, Designer, and Reviewer tasks.

## 0.1.67

- Verify server-owned agent prompts in the native Plugin runtime with SHA-256
  before exposing Codex tasks, preventing manual hash implementation in Codex.
- Return a deterministic `PLUGIN_AGENT_PROMPT_TAMPERED` error when prompt bytes
  do not match the server-provided contract.

## 0.1.66

- Restore the canonical workflow-builder entry Human Input node.
- Route typed Human Input requests through the interactive side-panel form and
  reject manual radio payload construction in the Plugin guidance.

## 0.1.65

- Run AI workflow creation through the hidden system workflow using the normal
  workflow execution contract, including clarification, review, and repair.
- Add the reviewer workflow-validation MCP tool and accept valid JSON-string
  agent outputs before Backend schema validation.
- Include the live workflow node catalog in the clarification, designer, and
  reviewer agent context.

## 0.1.64

- Run AI workflow creation through the hidden, editable Loomex system workflow.
- Dispatch designer and reviewer nodes through the normal Plugin agent contract,
  validate the repaired workflow on the Backend, and persist the resulting
  Workflow automatically.
- Add explicit finalization support and keep the system builder hidden from
  user workflow discovery.

## 0.1.63

- Harden AI workflow-builder dispatch so repair attempts resume the exact
  sub-agent session and never create a replacement.

## 0.1.62

- Allow `loomex_workflow_create` descriptions up to 20,000 characters, matching
  the Backend workflow-builder contract while preserving verbatim forwarding.

## 0.1.61

- Remove Project from the plugin MCP surface, runner protocol, organization
  context, skills, and release tests.
- Keep organization selection multi-organization while making execution roots
  the only execution-local binding.

## 0.1.60

- Remove persistent project/workspace binding from the Plugin Runner contract.
- Scope Runner authentication to the organization and require the execution
  workspace root on each workflow run.
- Remove the legacy binding transport, bind command, and Runner config migration.

## 0.1.59

- Align the Codex marketplace discovery smoke test with the current 36-tool
  MCP surface so the release package can complete its final validation.

## 0.1.58

- Refresh release validation for the expanded 39-tool MCP contract.
- Keep package assembly fixtures aligned with the current immutable runtime
  version.

## 0.1.57

- Add guided Login, Logout, organization creation, and organization switching
  skills with automatic Runner scope recovery.
- Clear stale local account and organization scope before authentication and
  preserve organization creation even when the local Runner service needs repair.
- Add MCP operations for registration, organization creation, and scope changes.

## 0.1.56

- Make Codex sub-agent dispatch explicitly prompt-opaque: only the exact
  Backend-provided `agentTask.prompt` may be sent to the sub-agent.
- Prevent prompt reconstruction from task inputs, clarification answers,
  workspace metadata, or output-contract text.
- Keep optional file manifests out of direct local-workspace Codex results so
  they do not enter the incompatible Runner file-write path.

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
