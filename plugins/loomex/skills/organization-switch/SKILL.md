---
name: organization-switch
description: Use when the user asks to change the active Loomex organization or when multiple organizations are available.
---

# Switch organization

Call `loomex_org_list` and show the available organization names and IDs. If
there is exactly one organization and no organization was requested, select it
automatically. Otherwise ask the user to choose when the request does not
identify one unambiguously. Then call `loomex_org_select` with the exact
selected `organizationId`.

Organization selection clears the execution scope and reboots the
organization-scoped Runner authentication when needed. It does not create a
workspace path. Never change scope through config files or shell commands.
