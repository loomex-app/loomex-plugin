# Setup and authentication

## Inspect

For every Loomex request, call `loomex_setup_status` first and obey its
`recommendedNextAction`. Never tell the user to type a setup phrase. The status
separates the verified runtime bundled in the plugin (`bundledRuntime`) from the
installed runtime and registered per-user service (`durableRuntime`).

If `recommendedNextAction` is `setup.plan`, immediately call the read-only
`loomex_setup_plan`; do not ask whether setup should be started. Its public
optional fields are `version`, `channel` (`stable` or `beta`), and
`installService`. Report:

- whether this is install, update, or repair;
- the version and stable per-user install path;
- the service mechanism and actions;
- migrations, restarts, and rollback availability;
- any running executions that affect timing.

## Apply

Ask the user to approve the concrete plan only before `loomex_setup_apply`. Call it
with the returned `planId`, exact returned `channel` and `installService`, and
`confirm: true`; never invent, alter, or reuse a plan ID. These fields are bound
to the plan, so changing either option requires generating and reviewing a new
plan. When `installService` is false, apply installs the verified runtime but
does not register, start, or restart a service.
Setup is a persistent local change even though it is per-user. Do not request
admin rights, install system-wide, or copy binaries manually. The tool verifies
the bundled release, installs atomically, health-checks the candidate, then
switches the active version.

On a first install before authentication and workspace binding are complete,
the per-user service is registered with deferred start. Authentication and
binding remain available through the bundled bootstrap; completing the binding
activates and health-checks the installed service. Rollback follows the same
readiness rule: an installed but not-yet-ready service remains deferred, and a
failed activation restores the prior runtime pointer or returns an explicit
recoverable partial-state error.

If apply fails, preserve its structured error. Use `loomex_setup_rollback` only
after the user selects an installed prior version and approves the change. Call
it with that exact `targetVersion` and `confirm: true`. Do not describe a
rollback as successful until the returned health state is healthy.

The initial setup call must finish before the user closes Codex. After the
service is healthy, long-running workflow execution no longer depends on Codex.

If `recommendedNextAction` is `auth.status`, do not create another setup plan,
even when the registered service is inactive or deferred while authentication
or binding is incomplete. Continue with authentication, organization/project
scope, and workspace binding below, then resume the original Loomex request.
If the action is `binding.create` with reason `runner_identity_mismatch`, treat
it as an explicit binding repair, not a setup reinstall or automatic identity
rewrite. Read the current organization, project, and bindings; show the exact
workspace and authenticated-Runner repair; obtain confirmation; then call
`loomex_binding_create`. Do not restart the Runner merely to conceal the
identity mismatch.
If the action is `unsupported`, report the structured reason and do not attempt
setup. If it is `package.error`, report `bundledRuntime.error`; do not misreport
a malformed or unavailable package as an unsupported platform.

## Authenticate

Call `loomex_auth_status`. If unauthenticated, call `loomex_auth_start`, show the
verification URL and user code exactly, and then call `loomex_auth_wait` with
the returned `loginId` and, optionally, `timeoutSeconds`. `loomex_auth_start`
accepts optional `serverUrl` only when the user intentionally selected a Loomex
server. A timeout means the login is still incomplete, not rejected; keep the
login ID and offer to wait again.

`loomex_auth_wait` is a state-changing operation: a successful poll consumes
the device authorization and stores the returned credential locally. Do not
issue concurrent waits for the same login ID.

If `loomex_auth_wait` returns an error, surface its exact structured `code`,
`message`, and `retryable` fields. Retry `loomex_auth_wait` with the same login
ID only when `retryable` is `true`, and keep retries serial. When it is `false`,
stop and report the error and its remediation. Never recommend or run direct
`loomex login` as a fallback: it bypasses the MCP authentication flow and its
structured safety contract.

`loomex_auth_logout` removes Loomex credentials from this device and is a
sensitive state change. Confirm the user's intent before calling it, then pass
`confirm: true`. Never print tokens or credential-store material.
