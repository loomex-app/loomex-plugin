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
workspace path. After success, continue the original request.

The result separates setup phases. `setupStatus: "runner_ready"` means the
organization and local Runner are ready. `setupStatus: "runner_pending"` or
`"pending_reconciliation"` is recoverable: preserve the returned organization
and retry the setup action, not the entire login flow. A bootstrap timeout is
not proof that organization creation failed; the plugin reconciles the
authenticated user's organizations by the exact server slug before allowing
another create. Never issue a blind duplicate create or ask the user to log
out and sign in again solely because Runner bootstrap timed out.

For a terminal validation or authorization error, stop and report its exact
structured error.
