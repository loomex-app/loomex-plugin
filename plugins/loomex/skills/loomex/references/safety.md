# Safety rules

- Treat setup, logout, selection changes, binding creation/revocation, workflow
  start, cancellation, human responses, approvals, and Runner control as state
  changes. Preview their exact target and obtain required user confirmation.
- Never broaden a local binding to make an operation pass. Never bypass Runner
  policy, path containment, or symlink protections with direct shell or file
  tools.
- Do not pass credentials, API keys, tokens, or unrelated environment variables
  as workflow inputs. Use Loomex's credential facilities when the schema calls
  for a secret reference.
- Preserve run, request, approval, setup transaction, organization, project, and
  binding IDs from tool output. Do not manufacture or substitute IDs.
- Distinguish accepted, queued, waiting, cancellation requested, rolled back,
  and terminal results. Transport success alone is not operation success.
- Keep logs and outputs scoped and redacted. Ask before revealing sensitive
  local paths or content the user did not request.
- The Tauri app and Codex may act concurrently. Refresh a mutable request before
  a response or approval to avoid stale decisions.
