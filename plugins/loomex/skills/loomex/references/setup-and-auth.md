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

## Refresh local agent executables

Codex and other GUI-launched applications commonly inherit a smaller `PATH`
than the user's interactive terminal. The durable Runner deliberately never
searches its service `PATH`, and neither the Backend nor an MCP/plugin-control
request may supply an executable path. A CLI installed or moved after Loomex
setup therefore requires an explicit local refresh from a terminal owned by the
user.

`loomex_setup_apply` creates an initial executable snapshot only when
`agent-executables.json` does not exist. A repeated setup/apply, repair, or
plugin-control call preserves the existing file and never refreshes or
overwrites it from that process's `PATH`. After the initial snapshot, only the
local interactive refresh command below may change executable discovery.

If a typed runtime error reports `executor_version_unverified`, follow its
ordered remediation exactly: `upgrade_executor`, then
`refresh_executor_discovery`. The upgrade happens through the selected
executor's trusted user-local installer or package manager, under the user's
control. Loomex does not accept or construct a remote upgrade command, and
Backend, workflow, MCP, model output, and daemon state cannot choose an
installer or executable path. Do not skip directly to refresh: refreshing an
unchanged incompatible binary cannot establish compatibility.

After the user confirms the local upgrade completed, run the refresh command
below. Then call `loomex_agent_runtime_status` and wait for the next heartbeat
before retrying the blocked task. Do not claim success from the installer exit
alone; the new executable must pass the safe local probe.

Ask the user to review and run the local interactive command:

```bash
loomex setup agents refresh --confirm
```

This captures only the `PATH` of that user-invoked process and considers the
closed allowlist `codex`, `claude`, and `agy`. It does not inspect the daemon's
environment and never treats a legacy Gemini executable as `agy`. The
`--confirm` flag approves the local discovery and private persistence; it is
not authorization for the Backend to select paths.

When the executable is outside that interactive `PATH`, the user may approve
one exact provider/path pair:

```bash
loomex setup agents refresh --confirm \
  --provider codex|claude|agy \
  --path ABSOLUTE_CANONICAL_PATH
```

`--provider` and `--path` must appear together; otherwise the command returns
the typed `AGENT_EXECUTABLE_REFRESH_PATH_PAIR_REQUIRED` error. The path must be
local, absolute, canonical, a regular executable file, and have the expected
allowlisted filename. Do not obtain it from workflow input, Backend metadata,
an MCP tool argument, a model suggestion, or logs. Do not use
`--non-interactive`, edit the file manually, expose persisted paths, or ask the
user to paste them into the chat.

The command validates and merges the approved snapshot, atomically persists a
private sibling of `config.toml` at `~/.loomex/agent-executables.json`, and
returns only redacted provider status. No Runner restart is required: execution
and status reload the persisted configuration, and missing executors are not
cached. After refresh, call `loomex_agent_runtime_status` to force a fresh safe
probe, then wait for the next Runner heartbeat to publish the updated readiness
before retrying the blocked task. If the service is inactive, complete its
normal authenticated binding/start flow first; never restart a healthy service
merely to refresh executable discovery.

## Configure the agent runtime cutover

Config v3 has two root-level cutover fields:

```toml
configVersion = 3
agentRuntimeV2Enabled = true
legacyAgentTaskMode = "drain_only"
```

`agentRuntimeV2Enabled` accepts only `true` or `false` and defaults to `true`.
`legacyAgentTaskMode` accepts only `"drain_only"` or `"disabled"` and defaults
to `"drain_only"`. Config v1/v2 migration uses the same safe defaults: accept
new v2 work while draining only already-issued v1 tasks. `drain_only` is a
migration posture, not permission for Backend to emit new v1 tasks.

Change one value only when the user deliberately selects a cutover or rollback:

```bash
loomex config set agentRuntimeV2Enabled false
loomex config set legacyAgentTaskMode disabled
```

The commands persist config but do not alter the already-running daemon.
Cutover values are read at daemon start. Their structured result therefore has
`serviceRestartRequired: true` and
`nextAction: "restart_runner_service"`. After either command:

1. call `loomex_runner_status` and show active local executions and restart
   impact;
2. obtain explicit confirmation;
3. call `loomex_runner_control` with `action: "restart"` and `confirm: true`;
4. call `loomex_runner_status` again and wait for the new Runner
   session/heartbeat before relying on advertisement or task enforcement.

Do not claim the new cutover state from config-file persistence alone. This
restart requirement is intentionally different from executable discovery:
`loomex setup agents refresh --confirm` reloads per operation and does not
require a restart.

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
