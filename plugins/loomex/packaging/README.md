# Native package assembly

The repository stores no pretend executable and no made-up signature. CI builds
the real `loomex-mcp` adapter and matching `loomex` Runner for every macOS/Linux
entry in `targets.json` and provides both artifacts to the assembler.

The native executables intentionally carry no OS-vendor signature. In
particular, macOS binaries are not Developer ID signed and are not notarized.
Every native `signing.json` and the assembled runtime manifest records the
binaries as `unsigned` with method `none`; the production package state is
`unsigned-release`, not a platform-signing claim. macOS Gatekeeper may therefore
warn or block on first launch after download.

`codex_plugin_assemble.py` copies both binaries into each target directory,
writes their sizes and lower-case SHA-256 digests into
`runtime-manifest.json`, and runs:

```bash
node scripts/validate-package.mjs --release
```

Only the assembled archive contains `bin/` and the generated runtime manifest.
Source validation deliberately succeeds without them. At launch, the adapter
rejects symlinks, unsupported targets, missing executability, path escapes,
absent manifests, and digest mismatches. Development overrides remain limited
to source checkouts and cannot replace packaged release bytes.

The archive is one install for users: it includes every supported
macOS/Linux MCP adapter and Runner pair. The first `loomex_setup_apply` installs the durable
per-user Runner from the checksum-verified artifact for the current target; it
does not ask the user to obtain a second installer.

## Marketplace integrity and publication

Assembly creates `loomex-codex-marketplace-<version>.zip`, its versioned
installer, the stable `install-codex.sh` bootstrap, and a companion provenance
document. The provenance binds all of the following:

- the plugin version, archive name, and archive SHA-256;
- the canonical content-addressed Git tree and orphan commit;
- the exact source release SHA, `v*` tag, `main` base, and PR number;
- the explicit unsigned/unnotarized native-binary state; and
- the SHA-256 plus keyless Sigstore release-integrity contract.

Production keyless-signs the plugin archive, marketplace archive, provenance,
versioned installer, and stable bootstrap with Cosign using GitHub's short-lived
OIDC token. Verification
pins `https://token.actions.githubusercontent.com` and the exact workflow
identity. No Loomex private signing key or Apple credential is stored.

The publication job reconstructs the orphan marketplace commit from the
verified archive and refuses to replace an existing publication ref. The
version branch is only a discoverability pointer: normal installation must
verify provenance first and install the marketplace ZIP whose SHA-256 is bound
by that provenance. The provenance still records the exact 40-character
`marketplace.commit` for reconstruction and audit, but the user-facing
installer registers a verified local snapshot so it is not vulnerable to Codex's
Git clone timeout. The online and offline installers both fail closed before
mutation if provenance or Sigstore verification fails.

The user-facing URL is
`https://github.com/loomex-app/loomex-plugin/releases/latest/download/install-codex.sh`.
The bootstrap embeds the selected release version, downloads subsequent assets
only from that version tag, and uses a checksum-pinned Cosign binary plus a
checksum-pinned official Sigstore trusted root. This avoids dependency on the
Sigstore TUF CDN during installation. The convenience `curl | sh` path still
trusts GitHub TLS for the bootstrap itself; its separately published Sigstore
bundle supports a two-step high-assurance verification path.

Release assets disable overwrite. Immediately before each external write, CI
resolves the live remote version tag and requires it to peel to the gated
release SHA. A moved, deleted, or recreated tag fails closed. Repository rules
should additionally forbid updating or deleting `v*` tags and enable immutable
GitHub Releases.

Linux binaries are built on Ubuntu 22.04, reject symbols newer than GLIBC 2.35,
and execute ARM64 smoke tests under QEMU before packaging.

## Production release gate

A `v*` tag or production manual run must resolve to a commit satisfying every
condition below:

- exactly two parents;
- exact `merge_commit_sha` of one merged GitHub PR into `main`;
- GitHub's standard `Merge pull request #... from ...` subject;
- second parent equal to the PR's exact head SHA; and
- still reachable from the matching remote base branch.

PR approval is not part of this release gate. The provenance job does not read
PR reviews and the production Environment must not configure a
`required_reviewers` protection rule.

The provenance job still fails closed unless the
`codex-plugin-production` Environment:

- disables administrator bypass (`can_admins_bypass` is exactly `false`);
- uses custom deployment policies; and
- exclusively permits the `main` branch and tag policy `v*`.

Malformed, missing, broadened, additional, truncated, or inconsistently
paginated policy data blocks release. `sign-release-archive`,
`publish-marketplace`, and `publish-release-assets` all reference that
Environment, so GitHub enforces its branch/tag/admin controls on the release
jobs themselves. The Environment needs no secrets: Cosign uses the job's
short-lived OIDC token.

The checkout uses `persist-credentials: false`. Reachability is proven through
the authenticated GitHub Compare API using a read-only `GITHUB_TOKEN`; the gate
performs no network `git fetch` and writes no authorization header or credential
helper into Git configuration.
