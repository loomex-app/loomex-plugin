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

1. Collect the email, first name, and last name in the conversation only when
   needed. Never ask for, accept, repeat, or summarize a password or password
   confirmation in Codex chat.
2. Open the host's secure credential-entry UI and let that UI call
   `loomex_auth_register` directly. Keep password fields outside model context,
   transcript, prompt, and tool-result content; the model receives only the
   redacted registration state or error code.
3. Show the returned verification state and ask for the email code. Treat the
   code as sensitive too: use the secure UI when the host provides it, and never
   include it in a progress message or tool-result summary.
4. Call `loomex_auth_register_verify` from the secure UI with the exact
   `challengeId`, email, and code. Then use `organization-create` because a new
   account has no organization yet.

The secure credential UI is one-shot: clear password, confirmation, and
verification-code fields after submit, cancel, logout, timeout, or failure.
Never store them in localStorage, widget state, prompt state, or any durable
credential file owned by the plugin. Never expose access tokens or passwords. A
successful login does not imply that an organization, organization, or
execution workspace is selected.
