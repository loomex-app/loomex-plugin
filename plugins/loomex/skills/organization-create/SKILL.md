---
name: organization-create
description: Use when an authenticated Loomex account has no organization or the user asks to create one.
---

# Create an organization

Call `loomex_setup_status`, then `loomex_auth_status`. If the user is not
authenticated, route to the `login` skill first.

Ask for an organization name if it was not provided. The slug is optional and
must be passed only when the user supplied one. Call `loomex_org_create` with
the exact name and optional slug.

The tool creates and selects the organization, clears execution context, and
bootstraps the organization-scoped local Runner. It does not create a
workspace path. After success, continue the original request. If the tool
fails, stop and report its exact structured error.
