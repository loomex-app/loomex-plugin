---
name: login
description: Use when the user asks to sign in to Loomex, register a new Loomex account, recover a password, or continue after authentication has completed.
---

# Workspace authentication

Use only Loomex MCP tools. Never inspect or edit credential files, call the
backend directly, or ask the user to run a CLI command.

1. Call `loomex_setup_status`, then `loomex_auth_status`. If setup is ready and
   the user is not authenticated, call `loomex_auth_login` with no arguments to
   open the secure credential-entry UI for the secure Loomex workspace form. The form follows the workspace
   Login.tsx conventions: dark animated/glass layout, Loomex branding, clear
   field hierarchy, loading/error feedback, and six-digit OTP inputs.
2. Let the secure form collect email and password. Never ask for, accept,
   repeat, or summarize a password or confirmation in Codex chat. The form
   calls `loomex_auth_login` directly. An existing account signs in; an email
   that is not already an active account starts the registration OTP branch.
   A wrong password is a terminal login error on the same page and must never
   retry registration.
3. For a registration challenge, keep the returned `challengeId`, expiry, and
   resend metadata only as redacted UI state. The form collects the email code
   in a secure field and calls `loomex_auth_register_verify`. Handle invalid,
   expired, replayed, rate-limited, and cooldown responses without creating a
   new registration attempt automatically.
4. Use the form's `Forgot password?` action for recovery. It calls
   `loomex_auth_password_forgot` with the email, then collects the reset code,
   new password, and confirmation in the secure UI and calls
   `loomex_auth_password_reset`. A successful reset returns to the login form;
   it must not auto-select or create an organization.
5. After successful login or registration verification, call
   `loomex_org_list`. If it returns no organizations, use
   `organization-create`; if it returns multiple organizations, use
   `organization-switch`; if it returns exactly one and no scope is selected,
   select that exact organization. Preserve the existing organization and
   Runner bootstrap behavior.

Authentication values are one-shot and memory-only. The secure UI clears email,
password, confirmation, and OTP fields after submit, cancel, timeout, backend
failure, or logout. Passwords, OTPs, challenge secrets, and access tokens must
   stay outside model context and never enter model-visible results, transcript, prompt, localStorage, widget
   Never store them in localStorage, widget state, or any durable state.
state, logs, or durable plugin files. Only redacted status, `nextAction`, and
non-sensitive challenge metadata may be shown to the model.
