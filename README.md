# loomex-plugin

Loomex Codex plugin and its MCP/plugin runtime.

This repository owns plugin skills, marketplace manifests, MCP stdio startup,
plugin-native binaries, checksums, provenance, and discovery smoke tests. It
does not build or package the Tauri desktop application.

The current migration snapshot keeps the existing runtime core while the
stable shared contracts move to `loomex-protocol`.

## Default profile

The canonical production profile uses the Loomex application URL:

```toml
configVersion = 2
selectedProfile = "default"

[profiles."default"]
serverUrl = "https://loomex.app"
```

## Protocol mirror

`crates/loomex-protocol` is a byte-for-byte, checked-in mirror of the
authoritative `loomex-protocol` v0.2.0 source. The workspace continues to
advertise the `runner.v1` transport; agent task schema v2 does not change the
runner transport version. The path dependency keeps local builds and release
packaging deterministic even before the protocol crate is published.

Refresh and verify the mirror from a sibling checkout:

```bash
python3 scripts/protocol_mirror.py sync --source ../loomex-protocol
python3 scripts/protocol_mirror.py check --source ../loomex-protocol
```

CI runs `python3 scripts/protocol_mirror.py check` using the checked-in
`protocol-source.lock.json` hashes and therefore does not require the source
repository or a package registry.

Protocol v0.2.0 publication provenance remains blocked until the authoritative
contract is committed on its own repository, merged, and tagged `v0.2.0`.
After that tag exists, rerun the sync command from a clean checkout at the tag
so the lock records the immutable commit and tag before publishing or switching
consumers to a registry dependency.
