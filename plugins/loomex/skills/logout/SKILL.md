---
name: logout
description: Use when the user explicitly asks to sign out of Loomex or clear the active Loomex account from this device.
---

# Logout

Confirm that the user wants to sign out, then call `loomex_auth_logout` with
`confirm: true`. Report the structured result only after it returns.

Logout removes the local user and Runner credentials, clears the selected
organization/project and execution scope, and stops the local Runner when
needed. It does not delete the remote Loomex account, organizations, projects,
workflows, or executions. Never print credential contents or use shell commands.
