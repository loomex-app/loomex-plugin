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

On a first install before Runner authentication is complete, the per-user
service is registered with deferred start. Completing Runner authentication
activates and health-checks the installed service; organization scope and execution
workspace are not service-readiness prerequisites. Rollback follows the same
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
is incomplete. Continue with authentication and organization scope,
then resume the original Loomex request. Runner authentication is independent
from organization scope; the filesystem workspace and execution root are selected
when that execution starts.
If `loomex_org_list` or another scope call returns a successful response with
`reauthRequired: true` and an embedded `auth` challenge, the Plugin has already
cleared stale local credentials and started a replacement device flow. Show the
returned verification URI/code, call `loomex_auth_wait` with the exact returned
`loginId`, and retry the failed scope call after authentication succeeds. Do not
ask the user to edit config, register a workspace, or manually delete tokens.
If the authenticated Runner identity is stale or mismatched, re-bootstrap the
Runner credential through the setup/auth flow. Do not create a organization scope
record or persist a workspace merely to make the service start.
If the action is `unsupported`, report the structured reason and do not attempt
setup. If it is `package.error`, report `bundledRuntime.error`; do not misreport
a malformed or unavailable package as an unsupported platform.

## Complete first-use readiness gate

The main `loomex` skill runs this sequence before showing the post-auth
capability catalog or resuming a natural-language request:

1. `loomex_setup_status` must be followed by the exact returned action. Read
   `loomex_setup_plan` when recommended, and call `loomex_setup_apply` only
   after confirmation with the exact `planId`, `channel`, and `installService`.
   Setup failure or cancellation is a stopped gate, not a guide state.
2. `loomex_auth_status` must show account authentication. An unauthenticated
   account routes to the existing `login` child skill and its secure
   `loomex_auth_login`/register UI. Do not ask the model-visible conversation
   for credentials. Once account auth is complete, use
   `loomex_auth_start` and `loomex_auth_wait` serially for Runner device auth;
   preserve the exact `loginId` returned by `loomex_auth_start`.
3. Call `loomex_org_list` after authentication. An empty `items` array goes to
   `organization-create`; one organization is selected with its exact
   `organizationId`; multiple organizations go to `organization-switch` and
   require the user's choice. Organization scope is not ready until the
   structured health state is `runner_ready`.
4. `runner_pending` and `pending_reconciliation` are recoverable, not success:
   preserve the returned organization/action identifiers and retry the same
   setup action serially. A timeout is unknown state; reconcile before another
   create or login. A non-retryable setup, auth, organization, or Runner error
   stops the gate and reports its exact `code`, `message`, and `retryable` value.

Only after all four stages succeed may the main skill present
`references/capability-guide.md`. It presents the eight catalog entries in the
current conversation language, keeps technical names unchanged, and then
records the non-sensitive plugin marker `loomex.first-use.capability-guide.v1`.
The marker is a host/plugin-supported boolean/version marker only; it must not
contain a token, password, OTP, challenge, credential, organization secret, or
transcript. If it is already present, skip the catalog and resume the original
request. Failure, cancellation, pending state, or an unsuccessful retry never
records the marker.

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
