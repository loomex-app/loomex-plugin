# Safety rules

- Treat setup, logout, selection changes, workflow
  start, cancellation, human responses, approvals, and Runner control as state
  changes. Preview their exact target and obtain required user confirmation.
- Never broaden an execution root to make an operation pass. Never bypass
  Runner path containment or symlink protections with direct shell or file
  tools.
- Do not pass credentials, API keys, tokens, or unrelated environment variables
  as workflow inputs. Use Loomex's credential facilities when the schema calls
  for a secret reference.
- Preserve run, request, approval, setup transaction, organization, organization, and
  execution-root IDs from tool output. Do not manufacture or substitute IDs.
- Distinguish accepted, queued, waiting, cancellation requested, rolled back,
  and terminal results. Transport success alone is not operation success.
- Keep logs and outputs scoped and redacted. Ask before revealing sensitive
  local paths or content the user did not request.
- When a scope request is rejected with an authentication-invalid result, the
  Plugin may automatically clear only the rejected profile's local
  credentials/scope and start a replacement device-auth flow. It must not
  attempt remote revocation as part of that recovery; present the returned
  verification URI/code and wait for the user to complete authentication.
- The Tauri app and Codex may act concurrently. Refresh a mutable request before
  a response or approval to avoid stale decisions.
