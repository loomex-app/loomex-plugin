---
name: login
description: Use when the user asks to sign in to Loomex, register a new Loomex account, or continue after authentication has completed.
---

# Login and registration

Use only Loomex MCP tools. Never inspect or edit credential files, call the
backend directly, or ask the user to run a CLI command.

## Existing account

1. Call `loomex_setup_status`, then `loomex_auth_status`.
2. If unauthenticated, call `loomex_auth_start`, show its exact verification
   URI and code, then call `loomex_auth_wait` with the exact returned `loginId`.
3. After success, call `loomex_org_list`. If it returns no organizations, use
   the `organization-create` skill. If it returns multiple organizations, use
   `organization-switch`.

## New account

1. Ask for the email, first name, last name, password, and password confirmation
   when they were not provided.
2. Call `loomex_auth_register` with those exact values.
3. Show the returned verification state and ask the user for the email code.
4. Call `loomex_auth_register_verify` with the exact `challengeId`, email, and
   code. Then use `organization-create` because a new account has no
   organization yet.

Never expose access tokens or passwords. A successful login does not imply that
an organization, organization, or execution workspace is selected.
