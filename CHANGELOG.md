# Changelog

## 0.2.1

- Refresh local agent executable discovery during verified installer updates.
- Launch JavaScript-based Codex CLIs with their trusted local Node runtime when
  the Runner service has a minimal launchd PATH.
- Improve installer diagnostics and local runtime setup guidance.

## 0.2.0

- Add the durable local agent runtime for exact, automatic, and explicitly
  ordered model selection through `codex_cli`, `claude_cli`, and `agy_cli`.
- Add runtime status, execute, resume, cancel, and checkpoint MCP tools while
  retaining the legacy v1 task list/respond compatibility path.
- Add typed, redacted model/provider/session remediation and user-approved
  canonical executable discovery that never trusts Backend paths or daemon
  `PATH`.
- Keep the Runner transport at `runner.v1` while mirroring the shared
  `loomex-protocol` v0.2.0 contracts.
- Require published authoritative protocol v0.2.0 provenance before any
  production or tag release.

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
