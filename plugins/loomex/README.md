# Loomex for Codex

The Loomex plugin makes Codex a conversational client for Loomex. It can browse
workflows, bind a selected project to the local Runner, start and follow durable
runs, and surface human requests and approval decisions. A binding identifies a
project Runner only; each execution supplies its own local workspace path.

## User experience

Official macOS and Linux release packages include both the `loomex-mcp` adapter
and the matching, verified Loomex Runner runtime. No special setup prompt is
needed: any natural Loomex request makes Codex check setup status first. When
the durable per-user service is missing, Codex automatically prepares and shows
the read-only setup plan, asks for approval only before applying it, then guides
authentication, scope selection, and project binding before resuming the
original request. There is no separate Runner download in the normal
installation flow.

## Install from the Loomex marketplace

The normal installation is one command on macOS and Linux:

```bash
curl -fsSL https://github.com/loomex-app/loomex-plugin/releases/latest/download/install-codex.sh | sh
```

To install or upgrade to an exact plugin version:

```bash
curl -fsSL https://github.com/loomex-app/loomex-plugin/releases/download/v0.1.56/install-codex.sh | sh
```

The `0.1.56` release keeps pending Codex sub-agent tasks separate from
resolved Gemini/Claude Runner tasks and routes `run_wait` by the resolved
provider. It also makes Loomex automatically recover rejected local
management credentials and fail closed on workflow/tool/provider errors:
it never falls back to direct shell/file/provider execution. It also keeps AGY
using the selected Runner workspace and blocks
its scratch workspace from escaping that boundary.

The old `loomex-app/runner` URL is retained only for historical releases. New
releases and upgrades come from `loomex-app/loomex-plugin`; running the command
again is sufficient and preserves the existing Codex marketplace state on
failure.

GitHub selects the latest stable, non-prerelease release. That release's version
is embedded in the downloaded script, which then uses version-specific asset
URLs authenticated by Sigstore. It obtains a temporary pinned Cosign binary and
verifies its pinned SHA-256, downloads an official Sigstore trusted-root
snapshot from a pinned commit and verifies its SHA-256, and verifies the
versioned installer, marketplace provenance, and marketplace ZIP before any
Codex change. It does not install Cosign
globally, modify Loomex credentials/backend configuration, bypass macOS
quarantine, or use insecure Sigstore options.

Release CI refuses to overwrite same-version assets, but a repository
administrator can still change GitHub tags or release assets unless GitHub's
immutable-release and tag-protection controls are enabled. Installation trust
therefore comes from verification of the exact workflow/tag Sigstore identity,
not from treating a GitHub tag or asset name as inherently immutable.

The `curl | sh` convenience path necessarily trusts GitHub TLS for the bootstrap
script itself. For high-assurance installation, download `install-codex.sh` and
`install-codex.sh.sigstore.json` from the same release, verify the script with
Cosign against the exact workflow/tag identity below, and then run the verified
file. Each release also publishes a complete Codex marketplace snapshot,
provenance, and `loomex-install-marketplace-<version>.sh`, each with a keyless
Sigstore bundle. The normal installer installs the verified ZIP as a local,
versioned marketplace snapshot, so it does not depend on Codex cloning GitHub
during installation.

The lower-level verified installer opens the versioned installer twice before
verification, confirms both descriptors identify the same file,
verifies one descriptor against the pinned GitHub issuer/workflow/tag identity,
and executes the other descriptor without reopening the pathname:

```bash
sh -eu -c '
version=$1
installer="loomex-install-marketplace-$version.sh"
test -f "$installer" && test ! -L "$installer"
test -f "$installer.sigstore.json" && test ! -L "$installer.sigstore.json"
exec 3< "$installer"
exec 4< "$installer"
test /dev/fd/3 -ef /dev/fd/4
cosign verify-blob \
  --bundle "$installer.sigstore.json" \
  --certificate-identity "https://github.com/loomex-app/loomex-plugin/.github/workflows/codex-plugin-release.yml@refs/tags/v$version" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  /dev/fd/3
archive="loomex-codex-marketplace-$version.zip"
test -f "$archive" && test ! -L "$archive"
exec sh /dev/fd/4 "$version" "$archive"
' sh <release-version>
```

Only the marketplace ZIP whose SHA-256 is bound by the verified provenance is
used for the normal installation. The provenance also binds the exact
40-character marketplace commit and Git tree used to produce that ZIP; those
content-addressed identifiers cannot move. Do not substitute the
`codex-plugin-marketplace-v<version>` publication branch, a tag, or another
symbolic ref to select installation bytes: those names can be moved. The
installer registers the verified local snapshot, then installs the adapter,
Runner, and `loomex-core`-based runtime together; users do not install a
separate native package. Start a new Codex task after installing or upgrading so
the new MCP tools are loaded.

For an offline/local install, first verify
`loomex-codex-marketplace-<version>.zip.sigstore.json` with the same pinned
issuer and workflow identity. Then run the verified
`loomex-install-marketplace-<version>.sh` with the version and ZIP path; it will
verify the ZIP digest against signed provenance, extract it into the user's
local data directory, register that local marketplace, and install
`loomex@loomex`.

Run the one-command installer again to upgrade. It inspects the existing Codex
marketplace and plugin state, does nothing when the same verified local snapshot
is already installed, and otherwise replaces the marketplace with the newly
verified local snapshot. It then runs the bundled Runner's transaction-safe setup
update, including service health-check and rollback, so the durable Runner
matches the installed plugin release. If any upgrade step fails, it restores the previous
checkout by its captured exact commit—or the previous local marketplace path—and
restores whether the plugin was installed. A
pre-existing sparse or disabled Loomex installation is rejected before any
change because the current Codex CLI cannot reproduce that state safely.

The release job keyless-signs and verifies the marketplace ZIP and provenance
with Sigstore/Fulcio and records the bundles in Sigstore's transparency log,
recreates the exact Git tree, rejects any commit mismatch, and only then
publishes it. The signed provenance binds the release version, archive SHA-256,
Git tree, repository, and exact commit. The trust anchor is the pinned GitHub
OIDC issuer plus exact repository/workflow/tag identity shown above—not a public
key downloaded beside the release assets.

The offline/local path verifies the marketplace ZIP's `.sigstore.json` bundle
with the same issuer and workflow identity before handing it to the installer.
Both paths avoid trusting a mutable branch or co-located replacement key to
select installation bytes.

Typical prompts:

- `Show my Loomex workflows.`
- `Bind this repository to Loomex and run release-review.`
- `Wait for run 123 and show me any human requests.`
- `Show pending Loomex approvals.`

Typed Human Input requests are routed by input type. `boolean`,
`single_select`/`radio`, and `multi_select`/`checkbox` requests open as an interactive Codex
side panel and submit directly to the durable request. `text` requests are
answered in the Codex chat and submitted with `loomex_human_respond`. Legacy
human requests remain available through the chat-based response flow.

Every tool publishes a tool-specific `outputSchema` and returns the same
discriminated structured envelope. Successful calls have
`{schemaVersion: "loomex.mcp/v1", ok: true, tool, data, meta}`; failed calls
have `{schemaVersion: "loomex.mcp/v1", ok: false, tool, error, meta}`. The
`data` schema is specific to the selected tool (runs, workflows, approvals,
logs, and so on), while entity objects allow additive backend fields so a
compatible server upgrade does not break Codex. The adapter validates runtime
responses before exposing them as `structuredContent`.

Setup changes are explicit. `loomex_setup_plan` returns the exact paths and
service action before `loomex_setup_apply` makes persistent per-user changes.
System-wide installation and administrator access are not required.

## Durable execution and the closed-Codex boundary

`loomex-mcp` is an adapter, not the execution engine. Before the service exists,
it routes setup, authentication, scope, binding, and service-control operations
through the bundled `loomex` bootstrap command. Workflow execution and live run
operations use the authenticated local-control socket of the durable service;
read-only status, diagnostics, and logs can fall back to the bootstrap command
when that socket is unavailable.

Long-running work is owned by the durable Loomex backend and the headless Runner
service. Closing or restarting Codex therefore does not cancel an accepted run.
Run state, human requests, approvals, and logs remain available after
reconnection.

Codex cannot display a new question while the Codex application is closed. A
pending request remains durable and appears when the plugin reconnects; the
Tauri app may also be used to answer it. The initial setup operation itself must
finish before Codex is closed so that the Runner service has been installed.

## Local workspace safety

Loomex operates only inside an explicit execution workspace. Binding creation
associates a project with a Runner and never stores a filesystem path. The
canonical `workspacePath` is supplied by `loomex_workflow_run` for every
execution and is carried through the server job payload to the Runner. The
Runner owns path containment, symlink escape prevention, execution policy,
cancellation, and audit logging. Codex approval prompts complement, but do not
replace, those Runner controls.

## Source and release packages

This source tree intentionally contains no unsigned or placeholder executable.
CI builds each native `loomex-mcp` adapter and matching `loomex` runtime,
verifies both, writes their sizes and SHA-256 digests into
`packaging/runtime-manifest.json`, and then assembles the macOS/Linux plugin
archive. See [packaging/README.md](packaging/README.md).

To use a source checkout while developing, set `LOOMEX_MCP_BINARY` to an
absolute path to a locally built adapter and set
`LOOMEX_ALLOW_DEVELOPMENT_BINARY=1`. Keep the matching `loomex` executable next
to that adapter, or set `LOOMEX_RUNNER_BINARY` to its absolute path. Release
packages never need these variables.
The dependency-free `/bin/sh` launcher used by packaged macOS/Linux releases
ignores development overrides whenever a release runtime manifest is present.

## Development validation

From this plugin directory:

```bash
node --test tests/*.test.mjs
node scripts/validate-package.mjs
python3 /path/to/plugin-creator/scripts/validate_plugin.py .
python3 /path/to/skill-creator/scripts/quick_validate.py skills/loomex
```

Release assembly must additionally pass:

```bash
node scripts/validate-package.mjs --release
```

That mode requires a real native executable and a complete digest manifest.

Before publishing a release, verify the assembled marketplace through the real
Codex install and app-server paths:

```bash
python3 ../../scripts/codex_mcp_discovery_smoke.py \
  --marketplace-root ../../dist/marketplace
```

This release-mode smoke installs `loomex@loomex` into a temporary, isolated
`CODEX_HOME`, exercising the marketplace, plugin cache, `.mcp.json`, launcher,
runtime manifest, platform selection, and checksum verification. It starts no
model turn and calls no Loomex tool. It asserts the installed and MCP-advertised
versions match the assembled manifest, and that Codex sees exactly 33 tools,
including setup, workflow discovery, and plugin agent-task tools.

For a faster development-only check before assembling all native targets, pass
`--loomex-mcp /absolute/path/to/loomex-mcp --expected-version <version>`. That
mode verifies MCP discovery but intentionally does not cover plugin packaging.
