---
name: setup
description: Use when a user asks to install, update, repair, roll back, start, stop, or authenticate the Loomex Runner, or when a Loomex request needs first-use setup.
---

# Setup

Use Loomex MCP setup and authentication tools. Read [setup-and-auth.md](../loomex/references/setup-and-auth.md) before state-changing setup or auth work.

## Workflow

- For every Loomex request, call `loomex_setup_status` first.
- If `recommendedNextAction` is `setup.plan`, immediately call the read-only `loomex_setup_plan`, explain the exact plan, and ask for confirmation only before `loomex_setup_apply`.
- Apply only with the returned `planId`, exact `channel`, exact `installService`, and `confirm: true`.
- If the action is `auth.status`, do not reinstall. Check `loomex_auth_status`; when needed, start device auth, show the exact verification URI and code, then wait serially with the returned `loginId`.
- Treat `package.error`, `unsupported`, identity mismatch, retryable errors, pending, and rollback states as distinct structured outcomes.
- Logout, Runner lifecycle changes, and rollback require explicit confirmation. Never print credentials or manually modify runtime/service state.

Never tell the user to type a setup phrase or use direct `loomex login`. Resume the original request after setup/auth succeeds.
