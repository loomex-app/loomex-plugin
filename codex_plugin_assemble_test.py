#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

from codex_plugin_assemble import (
    MARKETPLACE_COMMIT_EPOCH,
    SUPPORTED_TARGETS as ASSEMBLER_TARGETS,
    marketplace_commit,
)
from codex_plugin_validate import (
    SUPPORTED_TARGETS as VALIDATOR_TARGETS,
    validate_marketplace_archive,
    validate_marketplace_provenance,
    validate_runtime_integrity,
    validate_tree,
)


ROOT = Path(__file__).resolve().parent
ASSEMBLER = ROOT / "codex_plugin_assemble.py"


def native_test_header(target: str) -> bytes:
    if target.startswith("linux-"):
        header = bytearray(64)
        header[:7] = b"\x7fELF\x02\x01\x01"
        header[16:18] = (3).to_bytes(2, "little")
        machine = 62 if target == "linux-x64" else 183
        header[18:20] = machine.to_bytes(2, "little")
        header[20:24] = (1).to_bytes(4, "little")
        header[52:54] = (64).to_bytes(2, "little")
        return bytes(header)
    header = bytearray(32)
    header[:4] = b"\xcf\xfa\xed\xfe"
    cpu_type = 0x01000007 if target == "darwin-x64" else 0x0100000C
    header[4:8] = cpu_type.to_bytes(4, "little")
    header[12:16] = (2).to_bytes(4, "little")
    return bytes(header)


class SourcePluginContractTest(unittest.TestCase):
    @staticmethod
    def write_artifacts(root: Path) -> None:
        for target in ASSEMBLER_TARGETS:
            directory = root / target
            directory.mkdir(parents=True)
            runtime = directory / "loomex"
            mcp = directory / "loomex-mcp"
            runtime.write_bytes(f"runtime-{target}".encode())
            mcp.write_bytes(f"mcp-{target}".encode())
            runtime.chmod(0o755)
            mcp.chmod(0o755)
            (directory / "signing.json").write_text(json.dumps({
                "schemaVersion": 1,
                "target": target,
                "status": "unsigned",
                "method": "none",
                "binaries": {
                    "loomex": {"sha256": hashlib.sha256(runtime.read_bytes()).hexdigest()},
                    "loomex-mcp": {"sha256": hashlib.sha256(mcp.read_bytes()).hexdigest()},
                },
            }))

    @staticmethod
    def write_installer_provenance(
        root: Path,
        version: str,
        commit: str,
        archive_name: str | None = None,
        archive_sha256: str | None = None,
    ) -> Path:
        document = {
            "schemaVersion": 1,
            "pluginVersion": version,
            "marketplace": {
                "repository": "loomex-app/runner",
                "gitObjectFormat": "sha1",
                "commit": commit,
            },
        }
        if archive_name is not None and archive_sha256 is not None:
            document["archive"] = {
                "name": archive_name,
                "sha256": archive_sha256,
            }
        provenance = root / f"loomex-codex-marketplace-{version}.provenance.json"
        provenance.write_text(
            json.dumps(document) + "\n",
            encoding="utf-8",
        )
        (root / f"{provenance.name}.sigstore.json").write_text(
            "{}\n", encoding="utf-8"
        )
        return provenance

    @staticmethod
    def write_installer_marketplace_archive(root: Path, version: str) -> Path:
        archive_path = root / f"loomex-codex-marketplace-{version}.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr(
                ".agents/plugins/marketplace.json",
                json.dumps(
                    {
                        "name": "loomex",
                        "plugins": [
                            {
                                "name": "loomex",
                                "source": {"source": "local", "path": "./plugins/loomex"},
                            }
                        ],
                    }
                ),
            )
            archive.writestr(
                "plugins/loomex/.codex-plugin/plugin.json",
                json.dumps({"name": "loomex", "version": version}),
            )
            executable = zipfile.ZipInfo("plugins/loomex/bin/darwin-arm64/loomex-mcp")
            executable.create_system = 3
            executable.external_attr = (stat.S_IFREG | 0o755) << 16
            archive.writestr(executable, b"#!/bin/sh\n")
        return archive_path

    @staticmethod
    def write_stateful_installer_stubs(root: Path, state: dict) -> tuple[dict, Path, Path]:
        binaries = root / "bin"
        binaries.mkdir()
        checkout = Path(state["root"])
        checkout.mkdir(parents=True)
        initial_marketplace = state.get("marketplace")
        if (
            initial_marketplace is not None
            and initial_marketplace.get("kind", "git") == "git"
            and state.get("metadata_present", True)
            and "last_revision" not in state
        ):
            state["last_revision"] = initial_marketplace["commit"]
        if (
            initial_marketplace is not None
            and initial_marketplace.get("kind", "git") == "git"
            and state.get("metadata_present", True)
        ):
            (checkout / ".codex-marketplace-install.json").write_text(
                json.dumps(
                    {
                        "source_type": "git",
                        "source": initial_marketplace["source"],
                        "ref_name": initial_marketplace["ref"],
                        "sparse_paths": initial_marketplace.get("sparse_paths", []),
                        "revision": initial_marketplace["commit"],
                    }
                ),
                encoding="utf-8",
            )
        state_path = root / "codex-state.json"
        state_path.write_text(json.dumps(state), encoding="utf-8")
        log = root / "codex.log"
        codex_home = root / "codex-home"
        codex_home.mkdir()

        def write_config() -> None:
            marketplace = state.get("marketplace")
            lines = []
            if marketplace is not None:
                if marketplace.get("kind") == "local":
                    return
                lines.extend(
                    [
                        "[marketplaces.loomex]",
                        'last_updated = "2026-07-21T00:00:00Z"',
                    ]
                )
                if state.get("last_revision") is not None:
                    lines.append(f'last_revision = {json.dumps(state["last_revision"])}')
                lines.extend(
                    [
                        'source_type = "git"',
                        f'source = {json.dumps(marketplace["source"])}',
                        f'ref = {json.dumps(marketplace["ref"])}',
                    ]
                )
                if marketplace.get("sparse_paths"):
                    lines.append(
                        f'sparse_paths = {json.dumps(marketplace["sparse_paths"])}'
                    )
            (codex_home / "config.toml").write_text(
                "\n".join(lines) + ("\n" if lines else ""), encoding="utf-8"
            )

        write_config()

        codex = binaries / "codex"
        codex.write_text(
            """#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

state_path = os.environ["CODEX_STUB_STATE"]
with open(state_path, encoding="utf-8") as handle:
    state = json.load(handle)
args = [arg for arg in sys.argv[1:] if arg != "--json"]
with open(os.environ["CALL_LOG"], "a", encoding="utf-8") as handle:
    handle.write(" ".join(args) + "\\n")

def save():
    with open(state_path, "w", encoding="utf-8") as handle:
        json.dump(state, handle)
    config = Path(os.environ["CODEX_HOME"]) / "config.toml"
    marketplace = state.get("marketplace")
    lines = []
    if marketplace is not None:
        if marketplace.get("kind") == "local":
            config.write_text("", encoding="utf-8")
            return
        lines.extend(["[marketplaces.loomex]", 'last_updated = "2026-07-21T00:00:00Z"'])
        if state.get("last_revision") is not None:
            lines.append("last_revision = " + json.dumps(state["last_revision"]))
        lines.extend([
            'source_type = "git"',
            "source = " + json.dumps(marketplace["source"]),
            "ref = " + json.dumps(marketplace["ref"]),
        ])
        if marketplace.get("sparse_paths"):
            lines.append("sparse_paths = " + json.dumps(marketplace["sparse_paths"]))
    config.write_text("\\n".join(lines) + ("\\n" if lines else ""), encoding="utf-8")

def metadata_path():
    return Path(state["root"]) / ".codex-marketplace-install.json"

marketplace = state.get("marketplace")
if args == ["plugin", "marketplace", "list"]:
    entries = []
    if marketplace is not None:
        entries.append({
            "name": "loomex",
            "root": state["root"],
            "marketplaceSource": {
                "sourceType": marketplace.get("kind", "git"),
                "source": marketplace["source"],
            },
        })
    print(json.dumps({"marketplaces": entries}))
elif args == ["plugin", "list", "--available"]:
    installed = []
    available = []
    if marketplace is not None:
        entry = {
            "pluginId": "loomex@loomex",
            "name": "loomex",
            "marketplaceName": "loomex",
            "installed": bool(state.get("plugin_installed")),
            "enabled": bool(state.get("plugin_installed")),
        }
        (installed if entry["installed"] else available).append(entry)
    print(json.dumps({"installed": installed, "available": available}))
elif args[:3] == ["plugin", "marketplace", "add"]:
    source = args[3]
    if len(args) == 4:
        state["root"] = source
        state["marketplace"] = {"kind": "local", "source": source}
        state["last_revision"] = None
        state["plugin_installed"] = False
        save()
        print(json.dumps({"marketplaceName": "loomex", "installedRoot": state["root"], "alreadyAdded": False}))
        sys.exit(0)
    if args[4:5] != ["--ref"] or len(args) != 6:
        sys.exit(31)
    commit = args[5]
    if source == "loomex-app/runner":
        source = "https://github.com/loomex-app/runner.git"
    state["marketplace"] = {"source": source, "ref": commit, "commit": commit}
    state["last_revision"] = None
    state["plugin_installed"] = False
    metadata_path().unlink(missing_ok=True)
    save()
    print(json.dumps({
        "marketplaceName": "loomex",
        "installedRoot": state["root"],
        "alreadyAdded": False,
    }))
elif args == ["plugin", "marketplace", "upgrade", "loomex"]:
    if marketplace is None:
        sys.exit(37)
    if marketplace["ref"] == state.get("fail_upgrade_ref"):
        metadata_path().write_text('{"source_type":"git","source":"https://evil.invalid/repo"}', encoding="utf-8")
        sys.exit(38)
    state["last_revision"] = marketplace["commit"]
    save()
    metadata_path().write_text(json.dumps({
        "source_type": "git",
        "source": marketplace["source"],
        "ref_name": marketplace["ref"],
        "sparse_paths": [],
        "revision": marketplace["commit"],
    }), encoding="utf-8")
    print(json.dumps({
        "selectedMarketplaces": ["loomex"],
        "upgradedRoots": [state["root"]],
        "errors": [],
    }))
elif args == ["plugin", "marketplace", "remove", "loomex"]:
    state["marketplace"] = None
    state["last_revision"] = None
    state["plugin_installed"] = False
    metadata_path().unlink(missing_ok=True)
    save()
    print("{}")
elif args == ["plugin", "add", "loomex@loomex"]:
    if marketplace is None:
        sys.exit(32)
    if "fail_plugin_add_ref" in state and marketplace.get("ref") == state.get("fail_plugin_add_ref"):
        print("injected plugin add failure", file=sys.stderr)
        sys.exit(33)
    state["plugin_installed"] = True
    save()
    print("{}")
elif args == ["plugin", "remove", "loomex@loomex"]:
    state["plugin_installed"] = False
    save()
    print("{}")
else:
    print("unexpected codex stub arguments: " + repr(args), file=sys.stderr)
    sys.exit(34)
""",
            encoding="utf-8",
        )
        codex.chmod(0o755)

        git = binaries / "git"
        git.write_text(
            """#!/usr/bin/env python3
import json
import os
import sys
with open(os.environ["CODEX_STUB_STATE"], encoding="utf-8") as handle:
    marketplace = json.load(handle)["marketplace"]
if marketplace is None:
    sys.exit(35)
if sys.argv[-3:] == ["rev-parse", "--verify", "HEAD^{commit}"]:
    print(marketplace["commit"])
elif sys.argv[-3:] == ["remote", "get-url", "origin"]:
    print(marketplace["source"])
elif sys.argv[-3:] == ["rev-parse", "--git-path", "info/sparse-checkout"]:
    print(".git/info/sparse-checkout")
elif sys.argv[-3:] == ["config", "--bool", "core.sparseCheckout"]:
    print("true" if marketplace.get("sparse_paths") else "false")
elif sys.argv[-3:] == ["config", "--bool", "core.sparseCheckoutCone"]:
    print("true" if marketplace.get("sparse_paths") else "false")
else:
    sys.exit(36)
""",
            encoding="utf-8",
        )
        git.chmod(0o755)

        cosign = binaries / "cosign"
        cosign.write_text(
            "#!/bin/sh\n"
            "if test -n \"${ORIGINAL_PROVENANCE:-}\"; then\n"
            "  printf '%s' \"$REPLACEMENT_DOCUMENT\" > \"$ORIGINAL_PROVENANCE\"\n"
            "fi\n",
            encoding="utf-8",
        )
        cosign.chmod(0o755)
        (binaries / "python3").symlink_to(sys.executable)

        environment = os.environ.copy()
        environment.update(
            {
                "PATH": f"{binaries}:/bin:/usr/bin",
                "CALL_LOG": str(log),
                "CODEX_STUB_STATE": str(state_path),
                "CODEX_HOME": str(codex_home),
            }
        )
        return environment, state_path, log

    def test_all_packaging_components_share_the_unix_target_matrix(self) -> None:
        targets = json.loads(
            (ROOT / "plugin/loomex/packaging/targets.json").read_text(encoding="utf-8")
        )["artifacts"]
        expected = {
            "darwin-arm64",
            "darwin-x64",
            "linux-arm64",
            "linux-x64",
        }
        self.assertEqual(set(targets), expected)
        self.assertEqual(ASSEMBLER_TARGETS, expected)
        self.assertEqual(VALIDATOR_TARGETS, expected)

    def test_codex_0_144_6_marketplace_list_json_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            checkout = root / "checkout"
            source = "https://github.com/loomex-app/runner.git"
            environment, _state_path, _log = self.write_stateful_installer_stubs(
                root,
                {
                    "root": str(checkout),
                    "marketplace": {
                        "source": source,
                        "ref": "a" * 40,
                        "commit": "a" * 40,
                    },
                    "plugin_installed": True,
                },
            )
            result = subprocess.run(
                ["codex", "plugin", "marketplace", "list", "--json"],
                env=environment,
                text=True,
                capture_output=True,
                check=True,
            )
            self.assertEqual(
                json.loads(result.stdout),
                {
                    "marketplaces": [
                        {
                            "name": "loomex",
                            "root": str(checkout),
                            "marketplaceSource": {
                                "sourceType": "git",
                                "source": source,
                            },
                        }
                    ]
                },
            )
            config = (root / "codex-home/config.toml").read_text(encoding="utf-8")
            self.assertIn("[marketplaces.loomex]", config)
            self.assertIn('source_type = "git"', config)
            self.assertIn(f"source = {json.dumps(source)}", config)
            self.assertIn(f'ref = {json.dumps("a" * 40)}', config)
            self.assertIn(f'last_revision = {json.dumps("a" * 40)}', config)

    def test_skill_inventory_matches_mcp_definitions(self) -> None:
        rust = (ROOT / "crates/loomex-mcp/src/tools.rs").read_text(encoding="utf-8")
        skill = (ROOT / "plugin/loomex/skills/loomex/SKILL.md").read_text(
            encoding="utf-8"
        )
        implemented = set(re.findall(r'"(loomex_[a-z_]+)"', rust))
        advertised = set(re.findall(r"`(loomex_[a-z_]+)`", skill))
        self.assertEqual(len(implemented), 33)
        self.assertEqual(advertised, implemented)

    def test_auth_skill_forbids_direct_cli_fallback_and_obeys_retryability(self) -> None:
        guidance = (
            ROOT / "plugin/loomex/skills/loomex/references/setup-and-auth.md"
        ).read_text(encoding="utf-8")

        self.assertIn("surface its exact structured `code`", guidance)
        self.assertIn("only when `retryable` is `true`", guidance)
        self.assertIn("Never recommend or run direct\n`loomex login` as a fallback", guidance)
        self.assertIn("keep retries serial", guidance)

    def test_manifest_advertises_only_supported_product_capabilities(self) -> None:
        manifest = json.loads(
            (ROOT / "plugin/loomex/.codex-plugin/plugin.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(
            manifest["interface"]["capabilities"],
            [
                "Interactive",
                "Local workspace",
                "Long-running workflows",
                "Human-in-the-loop",
            ],
        )

    def test_install_docs_require_verified_local_archive_not_version_branch(self) -> None:
        readme = (ROOT / "plugin/loomex/README.md").read_text(encoding="utf-8")
        installer = (
            ROOT / "plugin/loomex/scripts/install-marketplace.sh"
        ).read_text(encoding="utf-8")
        packaging = (ROOT / "plugin/loomex/packaging/README.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("exec sh /dev/fd/4 \"$version\" \"$archive\"", readme)
        self.assertIn('"--ref", commit', installer)
        self.assertIn("install_local_archive", installer)
        self.assertIn("marketplace archive digest does not match verified provenance", installer)
        self.assertIn("40-character marketplace commit", readme)
        self.assertIn("verified local snapshot", readme)
        self.assertIn("https://token.actions.githubusercontent.com", installer)
        self.assertIn(
            "https://github.com/loomex-app/runner/.github/workflows/codex-plugin-release.yml@refs/tags/v$version",
            installer,
        )
        self.assertLess(
            installer.index("cosign verify-blob"),
            installer.index('marketplace_commit = marketplace["commit"]'),
        )
        self.assertNotIn(
            "--ref codex-plugin-marketplace-v<version>",
            readme,
        )
        self.assertIn("Git clone timeout", packaging)
        self.assertIn("verify provenance first and install the marketplace ZIP", packaging)

    def test_stable_installer_is_stream_safe_and_uses_pinned_trust(self) -> None:
        installer_path = ROOT / "plugin/loomex/scripts/install-codex.sh"
        installer = installer_path.read_text(encoding="utf-8")
        self.assertEqual(installer.count("@LOOMEX_RELEASE_VERSION@"), 1)
        self.assertTrue(installer.rstrip().endswith('main "$@"'))
        self.assertIn("main() {", installer)
        self.assertIn("releases/download/v$version", installer)
        self.assertNotIn("api.github.com/repos", installer)
        self.assertIn("--proto '=https'", installer)
        self.assertIn("--tlsv1.2", installer)
        self.assertIn("--progress-bar", installer)
        self.assertIn("--continue-at -", installer)
        self.assertIn("Download of $label was interrupted; retrying", installer)
        self.assertIn("Reusing verified Cosign verifier from cache", installer)
        self.assertIn('cosign_cache_dir="$cache_root/loomex/cosign/$cosign_version"', installer)
        self.assertIn('test ! -L "$cosign_cached"', installer)
        self.assertIn('step "Verifying signed release assets"', installer)
        self.assertIn("cosign_version=\"3.1.2\"", installer)
        self.assertIn("sigstore_root_commit=\"a394944ec0ec1dd5e8ba50471e9ded37d88b5daa\"", installer)
        self.assertIn("--trusted-root \"$trusted_root\"", installer)
        self.assertEqual(installer.count("cosign_sha256="), 4)
        self.assertIn("marketplace_archive=\"loomex-codex-marketplace-$version.zip\"", installer)
        self.assertGreaterEqual(installer.count('"$cosign_bin" verify-blob'), 3)
        self.assertLess(
            installer.index('"$cosign_bin" verify-blob'),
            installer.index('"./$installer" "$version" "$temporary/$marketplace_archive"'),
        )
        for unsafe in ("--insecure", "--insecure-ignore-tlog", "xattr", "spctl", "sudo"):
            self.assertNotIn(unsafe, installer)

        rendered = installer.replace("@LOOMEX_RELEASE_VERSION@", "0.1.8")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            complete = root / "install-codex.sh"
            complete.write_text(rendered, encoding="utf-8")
            syntax = subprocess.run(
                ["sh", "-n", str(complete)], text=True, capture_output=True
            )
            self.assertEqual(syntax.returncode, 0, syntax.stderr)

            # Simulate a stream that ends after the function definition but
            # before the final invocation: no prerequisite or network command
            # is allowed to run.
            partial = root / "partial.sh"
            partial.write_text(rendered.rsplit('main "$@"', 1)[0], encoding="utf-8")
            result = subprocess.run(
                ["sh", str(partial)], text=True, capture_output=True
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_release_workflow_signs_and_enforces_exact_marketplace_commit(self) -> None:
        workflow = (
            ROOT / ".github/workflows/codex-plugin-release.yml"
        ).read_text(encoding="utf-8")
        self.assertIn(".provenance.json.sigstore.json", workflow)
        self.assertIn(
            '--bundle "${{ needs.assemble.outputs.marketplace-provenance }}.sigstore.json"',
            workflow,
        )
        self.assertIn("id-token: write", workflow)
        self.assertIn(
            '--certificate-oidc-issuer "https://token.actions.githubusercontent.com"',
            workflow,
        )
        self.assertNotIn("COSIGN_PRIVATE_KEY", workflow)
        action_refs = re.findall(r"uses:\s*[^@\s]+@([^\s#]+)", workflow)
        self.assertTrue(action_refs)
        self.assertTrue(
            all(re.fullmatch(r"[0-9a-f]{40}", ref) for ref in action_refs),
            action_refs,
        )
        self.assertIn('test "$actual_tree" = "$expected_tree"', workflow)
        self.assertIn('test "$actual_commit" = "$expected_commit"', workflow)
        self.assertIn("refusing to replace it", workflow)
        self.assertNotIn("--ref codex-plugin-marketplace-v", workflow)
        marketplace_job = workflow.index("\n  publish-marketplace:")
        release_assets_job = workflow.index("\n  publish-release-assets:")
        release_action = workflow.index("uses: softprops/action-gh-release@")
        self.assertLess(marketplace_job, release_assets_job)
        self.assertLess(release_assets_job, release_action)
        self.assertIn(
            "needs: [release-provenance, assemble, sign-release-archive, publish-marketplace]",
            workflow,
        )
        self.assertIn("overwrite_files: false", workflow)
        self.assertIn(
            "refusing to replace existing same-version release assets",
            workflow,
        )
        self.assertIn(
            "Install this release with the verified local-snapshot installer",
            workflow,
        )
        self.assertIn(
            "releases/download/v${{ needs.assemble.outputs.version }}/install-codex.sh",
            workflow,
        )
        self.assertNotIn("codex plugin marketplace add loomex-app/runner --ref", workflow)
        self.assertIn("marketplace-installer", workflow)
        self.assertIn("MARKETPLACE_INSTALLER", workflow)
        self.assertIn("stable-installer: ${{ steps.metadata.outputs.stable-installer }}", workflow)
        self.assertIn('stable_installer="install-codex.sh"', workflow)
        self.assertIn("STABLE_INSTALLER", workflow)
        self.assertIn("make_latest: true", workflow)
        self.assertGreaterEqual(workflow.count("stable-installer"), 10)
        self.assertEqual(workflow.count("live_release_sha="), 2)
        self.assertEqual(
            workflow.count(
                'test "$live_release_sha" = "${{ needs.release-provenance.outputs.release-sha }}"'
            ),
            2,
        )

    def test_installer_stops_before_parsing_or_codex_when_cosign_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binaries = root / "bin"
            binaries.mkdir()
            log = root / "calls.log"
            for name, status in (("cosign", 41), ("python3", 0), ("codex", 0)):
                stub = binaries / name
                stub.write_text(
                    "#!/bin/sh\n"
                    f"printf '%s\\n' {name} >> \"$CALL_LOG\"\n"
                    f"exit {status}\n",
                    encoding="utf-8",
                )
                stub.chmod(0o755)
            version = "9.8.7"
            (root / f"loomex-codex-marketplace-{version}.provenance.json").write_text(
                "{}\n", encoding="utf-8"
            )
            (root / f"loomex-codex-marketplace-{version}.provenance.json.sigstore.json").write_text(
                "{}\n", encoding="utf-8"
            )
            environment = os.environ.copy()
            environment["PATH"] = f"{binaries}:/bin:/usr/bin"
            environment["CALL_LOG"] = str(log)
            result = subprocess.run(
                [str(ROOT / "plugin/loomex/scripts/install-marketplace.sh"), version],
                cwd=root,
                env=environment,
                text=True,
                capture_output=True,
            )
            self.assertEqual(result.returncode, 41)
            self.assertEqual(log.read_text(encoding="utf-8"), "cosign\n")

    def test_installer_parses_verified_inode_when_original_is_swapped(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            version = "9.8.7"
            trusted_commit = "1" * 40
            replacement_commit = "2" * 40
            provenance = self.write_installer_provenance(
                root, version, trusted_commit
            )

            def document(commit: str) -> str:
                return json.dumps(
                    {
                        "schemaVersion": 1,
                        "pluginVersion": version,
                        "marketplace": {
                            "repository": "loomex-app/runner",
                            "gitObjectFormat": "sha1",
                            "commit": commit,
                        },
                    }
                ) + "\n"

            environment, state_path, log = self.write_stateful_installer_stubs(
                root,
                {
                    "root": str(root / "checkout"),
                    "marketplace": None,
                    "plugin_installed": False,
                },
            )
            environment.update(
                {
                    "ORIGINAL_PROVENANCE": str(provenance),
                    "REPLACEMENT_DOCUMENT": document(replacement_commit),
                }
            )
            result = subprocess.run(
                [str(ROOT / "plugin/loomex/scripts/install-marketplace.sh"), version],
                cwd=root,
                env=environment,
                text=True,
                capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            calls = log.read_text(encoding="utf-8")
            self.assertIn(
                f"plugin marketplace add loomex-app/runner --ref {trusted_commit}",
                calls,
            )
            self.assertNotIn(replacement_commit, calls)
            installed_state = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertEqual(installed_state["marketplace"]["ref"], trusted_commit)
            self.assertTrue(installed_state["plugin_installed"])
            self.assertEqual(
                json.loads(provenance.read_text(encoding="utf-8"))["marketplace"]["commit"],
                replacement_commit,
            )

    def test_installer_local_archive_install_avoids_codex_git_upgrade(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            version = "1.0.0"
            commit = "a" * 40
            archive = self.write_installer_marketplace_archive(root, version)
            self.write_installer_provenance(
                root,
                version,
                commit,
                archive.name,
                hashlib.sha256(archive.read_bytes()).hexdigest(),
            )
            environment, state_path, log = self.write_stateful_installer_stubs(
                root,
                {
                    "root": str(root / "checkout"),
                    "marketplace": None,
                    "plugin_installed": False,
                },
            )
            data_home = root / "data-home"
            environment["XDG_DATA_HOME"] = str(data_home)

            result = subprocess.run(
                [
                    str(ROOT / "plugin/loomex/scripts/install-marketplace.sh"),
                    version,
                    str(archive),
                ],
                cwd=root,
                env=environment,
                text=True,
                capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            calls = log.read_text(encoding="utf-8")
            self.assertIn(
                f"plugin marketplace add {data_home / 'loomex-codex-marketplace' / version}",
                calls,
            )
            self.assertIn("plugin add loomex@loomex", calls)
            self.assertNotIn("plugin marketplace upgrade", calls)
            self.assertNotIn("--ref", calls)
            installed_state = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertEqual(installed_state["marketplace"]["kind"], "local")
            self.assertTrue(installed_state["plugin_installed"])
            marker = (
                data_home
                / "loomex-codex-marketplace"
                / version
                / ".loomex-codex-release.json"
            )
            self.assertEqual(
                json.loads(marker.read_text(encoding="utf-8"))["marketplaceCommit"],
                commit,
            )
            installed_mcp = (
                data_home
                / "loomex-codex-marketplace"
                / version
                / "plugins/loomex/bin/darwin-arm64/loomex-mcp"
            )
            self.assertNotEqual(installed_mcp.stat().st_mode & stat.S_IXUSR, 0)

    def test_installer_exact_ref_first_install_idempotency_and_upgrade(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            old_commit = "a" * 40
            new_commit = "b" * 40
            environment, state_path, log = self.write_stateful_installer_stubs(
                root,
                {
                    "root": str(root / "checkout"),
                    "marketplace": None,
                    "plugin_installed": False,
                },
            )

            self.write_installer_provenance(root, "1.0.0", old_commit)
            first = subprocess.run(
                [str(ROOT / "plugin/loomex/scripts/install-marketplace.sh"), "1.0.0"],
                cwd=root,
                env=environment,
                text=True,
                capture_output=True,
            )
            self.assertEqual(first.returncode, 0, first.stderr)
            state = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertEqual(state["marketplace"]["ref"], old_commit)
            self.assertEqual(state["marketplace"]["commit"], old_commit)
            self.assertTrue(state["plugin_installed"])

            log_before_idempotent = log.read_text(encoding="utf-8")
            second = subprocess.run(
                [str(ROOT / "plugin/loomex/scripts/install-marketplace.sh"), "1.0.0"],
                cwd=root,
                env=environment,
                text=True,
                capture_output=True,
            )
            self.assertEqual(second.returncode, 0, second.stderr)
            idempotent_calls = log.read_text(encoding="utf-8")[
                len(log_before_idempotent):
            ]
            self.assertNotIn("plugin marketplace add", idempotent_calls)
            self.assertNotIn("plugin marketplace remove", idempotent_calls)
            self.assertNotIn("plugin marketplace upgrade", idempotent_calls)
            self.assertNotIn("plugin add", idempotent_calls)
            self.assertNotIn("plugin remove", idempotent_calls)

            self.write_installer_provenance(root, "1.1.0", new_commit)
            upgrade = subprocess.run(
                [str(ROOT / "plugin/loomex/scripts/install-marketplace.sh"), "1.1.0"],
                cwd=root,
                env=environment,
                text=True,
                capture_output=True,
            )
            self.assertEqual(upgrade.returncode, 0, upgrade.stderr)
            state = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertEqual(state["marketplace"]["ref"], new_commit)
            self.assertEqual(state["marketplace"]["commit"], new_commit)
            self.assertTrue(state["plugin_installed"])
            calls = log.read_text(encoding="utf-8")
            self.assertIn("plugin remove loomex@loomex", calls)
            self.assertIn("plugin marketplace remove loomex", calls)
            self.assertIn(
                f"plugin marketplace add https://github.com/loomex-app/runner.git --ref {new_commit}",
                calls,
            )
            self.assertIn("plugin marketplace upgrade loomex", calls)
            metadata = json.loads(
                (root / "checkout/.codex-marketplace-install.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(metadata["ref_name"], new_commit)
            self.assertEqual(metadata["revision"], new_commit)
            self.assertEqual(metadata["sparse_paths"], [])

    def test_installer_rewrites_same_sha_when_activation_metadata_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            commit = "9" * 40
            source = "https://github.com/loomex-app/runner.git"
            environment, state_path, log = self.write_stateful_installer_stubs(
                root,
                {
                    "root": str(root / "checkout"),
                    "marketplace": {
                        "source": source,
                        "ref": commit,
                        "commit": commit,
                    },
                    "last_revision": commit,
                    "metadata_present": False,
                    "plugin_installed": True,
                },
            )
            self.write_installer_provenance(root, "1.2.0", commit)

            result = subprocess.run(
                [str(ROOT / "plugin/loomex/scripts/install-marketplace.sh"), "1.2.0"],
                cwd=root,
                env=environment,
                text=True,
                capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            calls = log.read_text(encoding="utf-8")
            self.assertIn("plugin marketplace remove loomex", calls)
            self.assertIn(f"plugin marketplace add {source} --ref {commit}", calls)
            self.assertIn("plugin marketplace upgrade loomex", calls)
            metadata = json.loads(
                (root / "checkout/.codex-marketplace-install.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(metadata["ref_name"], commit)
            self.assertEqual(metadata["revision"], commit)
            self.assertTrue(
                json.loads(state_path.read_text(encoding="utf-8"))["plugin_installed"]
            )

    def test_installer_rejects_config_source_disagreement_before_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            commit = "8" * 40
            source = "https://github.com/loomex-app/runner.git"
            environment, _state_path, log = self.write_stateful_installer_stubs(
                root,
                {
                    "root": str(root / "checkout"),
                    "marketplace": {
                        "source": source,
                        "ref": commit,
                        "commit": commit,
                    },
                    "plugin_installed": True,
                },
            )
            config_path = root / "codex-home/config.toml"
            config_path.write_text(
                config_path.read_text(encoding="utf-8").replace(
                    source, "https://github.com/loomex-app/not-runner.git"
                ),
                encoding="utf-8",
            )
            self.write_installer_provenance(root, "1.3.0", commit)

            result = subprocess.run(
                [str(ROOT / "plugin/loomex/scripts/install-marketplace.sh"), "1.3.0"],
                cwd=root,
                env=environment,
                text=True,
                capture_output=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("config and marketplace list disagree", result.stderr)
            calls = log.read_text(encoding="utf-8")
            self.assertNotIn("plugin marketplace add", calls)
            self.assertNotIn("plugin marketplace remove", calls)
            self.assertNotIn("plugin add", calls)
            self.assertNotIn("plugin remove", calls)

    def test_installer_failure_rolls_back_exact_commit_and_plugin_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            old_commit = "c" * 40
            new_commit = "d" * 40
            old_source = "https://github.com/loomex-app/runner.git"
            environment, state_path, log = self.write_stateful_installer_stubs(
                root,
                {
                    "root": str(root / "checkout"),
                    "marketplace": {
                        "source": old_source,
                        "ref": "mutable-old-tag",
                        "commit": old_commit,
                    },
                    "plugin_installed": True,
                    "fail_plugin_add_ref": new_commit,
                },
            )
            self.write_installer_provenance(root, "2.0.0", new_commit)

            result = subprocess.run(
                [str(ROOT / "plugin/loomex/scripts/install-marketplace.sh"), "2.0.0"],
                cwd=root,
                env=environment,
                text=True,
                capture_output=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("prior state was restored", result.stderr)
            state = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertEqual(
                state["marketplace"],
                {"source": old_source, "ref": old_commit, "commit": old_commit},
            )
            self.assertTrue(state["plugin_installed"])
            calls = log.read_text(encoding="utf-8")
            self.assertIn(
                f"plugin marketplace add {old_source} --ref {new_commit}", calls
            )
            self.assertIn(
                f"plugin marketplace add {old_source} --ref {old_commit}", calls
            )
            self.assertNotIn("--ref mutable-old-tag", calls)

    def test_installer_upgrades_legacy_local_marketplace_to_exact_git_ref(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            checkout = root / "legacy-local-marketplace"
            new_commit = "5" * 40
            environment, state_path, log = self.write_stateful_installer_stubs(
                root,
                {
                    "root": str(checkout),
                    "marketplace": {
                        "kind": "local",
                        "source": str(checkout),
                    },
                    "plugin_installed": True,
                },
            )
            self.write_installer_provenance(root, "2.0.1", new_commit)

            result = subprocess.run(
                [str(ROOT / "plugin/loomex/scripts/install-marketplace.sh"), "2.0.1"],
                cwd=root,
                env=environment,
                text=True,
                capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            state = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertEqual(state["marketplace"]["ref"], new_commit)
            self.assertTrue(state["plugin_installed"])
            calls = log.read_text(encoding="utf-8")
            self.assertIn("plugin marketplace remove loomex", calls)
            self.assertIn(
                f"plugin marketplace add loomex-app/runner --ref {new_commit}", calls
            )

    def test_installer_failure_restores_legacy_local_marketplace(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            checkout = root / "legacy-local-marketplace"
            new_commit = "6" * 40
            environment, state_path, log = self.write_stateful_installer_stubs(
                root,
                {
                    "root": str(checkout),
                    "marketplace": {
                        "kind": "local",
                        "source": str(checkout),
                    },
                    "plugin_installed": True,
                    "fail_plugin_add_ref": new_commit,
                },
            )
            self.write_installer_provenance(root, "2.0.2", new_commit)

            result = subprocess.run(
                [str(ROOT / "plugin/loomex/scripts/install-marketplace.sh"), "2.0.2"],
                cwd=root,
                env=environment,
                text=True,
                capture_output=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("prior state was restored", result.stderr)
            state = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertEqual(
                state["marketplace"],
                {"kind": "local", "source": str(checkout)},
            )
            self.assertTrue(state["plugin_installed"])
            self.assertIn(
                f"plugin marketplace add {checkout}",
                log.read_text(encoding="utf-8"),
            )

    def test_installer_failure_preserves_previously_uninstalled_plugin(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            old_commit = "1" * 40
            new_commit = "2" * 40
            old_source = "https://github.com/loomex-app/runner.git"
            environment, state_path, _log = self.write_stateful_installer_stubs(
                root,
                {
                    "root": str(root / "checkout"),
                    "marketplace": {
                        "source": old_source,
                        "ref": old_commit,
                        "commit": old_commit,
                    },
                    "plugin_installed": False,
                    "fail_plugin_add_ref": new_commit,
                },
            )
            self.write_installer_provenance(root, "2.1.0", new_commit)

            result = subprocess.run(
                [str(ROOT / "plugin/loomex/scripts/install-marketplace.sh"), "2.1.0"],
                cwd=root,
                env=environment,
                text=True,
                capture_output=True,
            )
            self.assertNotEqual(result.returncode, 0)
            state = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertEqual(
                state["marketplace"],
                {"source": old_source, "ref": old_commit, "commit": old_commit},
            )
            self.assertFalse(state["plugin_installed"])

    def test_installer_rolls_back_malformed_metadata_from_failed_upgrade(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            old_commit = "3" * 40
            new_commit = "4" * 40
            source = "https://github.com/loomex-app/runner.git"
            environment, state_path, _log = self.write_stateful_installer_stubs(
                root,
                {
                    "root": str(root / "checkout"),
                    "marketplace": {
                        "source": source,
                        "ref": old_commit,
                        "commit": old_commit,
                    },
                    "plugin_installed": True,
                    "fail_upgrade_ref": new_commit,
                },
            )
            self.write_installer_provenance(root, "2.2.0", new_commit)

            result = subprocess.run(
                [str(ROOT / "plugin/loomex/scripts/install-marketplace.sh"), "2.2.0"],
                cwd=root,
                env=environment,
                text=True,
                capture_output=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("prior state was restored", result.stderr)
            state = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertEqual(state["marketplace"]["commit"], old_commit)
            self.assertTrue(state["plugin_installed"])
            metadata = json.loads(
                (root / "checkout/.codex-marketplace-install.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(metadata["ref_name"], old_commit)
            self.assertEqual(metadata["revision"], old_commit)

    def test_installer_rejects_sparse_prior_state_before_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            old_commit = "e" * 40
            new_commit = "f" * 40
            environment, _state_path, log = self.write_stateful_installer_stubs(
                root,
                {
                    "root": str(root / "checkout"),
                    "marketplace": {
                        "source": "https://github.com/loomex-app/runner.git",
                        "ref": old_commit,
                        "commit": old_commit,
                        "sparse_paths": ["plugins/loomex"],
                    },
                    "plugin_installed": True,
                },
            )
            self.write_installer_provenance(root, "3.0.0", new_commit)

            result = subprocess.run(
                [str(ROOT / "plugin/loomex/scripts/install-marketplace.sh"), "3.0.0"],
                cwd=root,
                env=environment,
                text=True,
                capture_output=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("cannot safely preserve a sparse", result.stderr)
            calls = log.read_text(encoding="utf-8")
            self.assertNotIn("plugin marketplace add", calls)
            self.assertNotIn("plugin marketplace remove", calls)
            self.assertNotIn("plugin add", calls)
            self.assertNotIn("plugin remove", calls)

    def test_installer_detects_sparse_file_independently_of_config_flags(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            commit = "7" * 40
            environment, _state_path, log = self.write_stateful_installer_stubs(
                root,
                {
                    "root": str(root / "checkout"),
                    "marketplace": {
                        "source": "https://github.com/loomex-app/runner.git",
                        "ref": commit,
                        "commit": commit,
                    },
                    "plugin_installed": True,
                },
            )
            sparse_file = root / "checkout/.git/info/sparse-checkout"
            sparse_file.parent.mkdir(parents=True)
            sparse_file.write_text("/.agents/plugins/\n", encoding="utf-8")
            self.write_installer_provenance(root, "3.1.0", "6" * 40)

            result = subprocess.run(
                [str(ROOT / "plugin/loomex/scripts/install-marketplace.sh"), "3.1.0"],
                cwd=root,
                env=environment,
                text=True,
                capture_output=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("cannot safely preserve a sparse", result.stderr)
            calls = log.read_text(encoding="utf-8")
            self.assertNotIn("plugin marketplace add", calls)
            self.assertNotIn("plugin marketplace remove", calls)

    def test_real_source_assembles_and_passes_release_validation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temp = Path(temporary)
            artifacts = temp / "artifacts"
            for target in (
                "darwin-arm64",
                "darwin-x64",
                "linux-arm64",
                "linux-x64",
            ):
                directory = artifacts / target
                directory.mkdir(parents=True)
                runtime = directory / "loomex"
                mcp = directory / "loomex-mcp"
                runtime.write_bytes(f"runtime-{target}".encode())
                mcp.write_bytes(f"mcp-{target}".encode())
                runtime.chmod(0o755)
                mcp.chmod(0o755)
                (directory / "signing.json").write_text(
                    json.dumps({
                        "schemaVersion": 1,
                        "target": target,
                        "status": "unsigned",
                        "method": "none",
                        "binaries": {
                            "loomex": {"sha256": hashlib.sha256(runtime.read_bytes()).hexdigest()},
                            "loomex-mcp": {"sha256": hashlib.sha256(mcp.read_bytes()).hexdigest()},
                        },
                    }),
                    encoding="utf-8",
                )

            plugin = temp / "dist/loomex"
            result = subprocess.run(
                [
                    "python3",
                    str(ASSEMBLER),
                    "--plugin-source",
                    str(ROOT / "plugin/loomex"),
                    "--artifacts-root",
                    str(artifacts),
                    "--output-root",
                    str(temp / "dist"),
                    "--archive",
                    str(temp / "loomex.zip"),
                    "--marketplace-archive",
                    str(temp / "loomex-marketplace.zip"),
                    "--marketplace-provenance",
                    str(temp / "loomex-marketplace.provenance.json"),
                    "--marketplace-installer",
                    str(temp / "loomex-install-marketplace.sh"),
                    "--version",
                    "0.1.21",
                ],
                text=True,
                capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            release = subprocess.run(
                ["node", "scripts/validate-package.mjs", "--release"],
                cwd=plugin,
                text=True,
                capture_output=True,
            )
            self.assertEqual(release.returncode, 0, release.stderr)
            self.assertEqual(validate_runtime_integrity(plugin), [])

    def test_official_codex_cachebuster_keeps_base_runtime_version_installable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temp = Path(temporary)
            source = temp / "source"
            shutil.copytree(ROOT / "plugin/loomex", source)
            plugin_json = source / ".codex-plugin/plugin.json"
            plugin = json.loads(plugin_json.read_text())
            plugin["version"] = "0.1.21+codex.local-20260723-120000"
            plugin_json.write_text(json.dumps(plugin))
            artifacts = temp / "artifacts"
            self.write_artifacts(artifacts)
            result = subprocess.run([
                "python3", str(ASSEMBLER),
                "--plugin-source", str(source),
                "--artifacts-root", str(artifacts),
                "--output-root", str(temp / "dist"),
                "--archive", str(temp / "plugin.zip"),
                "--marketplace-archive", str(temp / "marketplace.zip"),
                "--marketplace-provenance", str(temp / "marketplace.provenance.json"),
                "--marketplace-installer", str(temp / "install-marketplace.sh"),
                "--version", plugin["version"],
            ], text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            manifest = json.loads((temp / "dist/loomex/packaging/runtime-manifest.json").read_text())
            self.assertEqual(manifest["pluginVersion"], plugin["version"])
            self.assertEqual(manifest["runtimeVersion"], "0.1.21")
            self.assertEqual(validate_runtime_integrity(temp / "dist/loomex"), [])


class AssemblePluginTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.temp = Path(self.temporary.name)
        self.source = self.temp / "source"
        (self.source / ".codex-plugin").mkdir(parents=True)
        (self.source / "packaging").mkdir()
        (self.source / "scripts").mkdir()
        (self.source / "scripts/install-marketplace.sh").write_text(
            "#!/bin/sh\nexit 0\n", encoding="utf-8"
        )
        (self.source / "scripts/install-marketplace.sh").chmod(0o755)
        (self.source / ".codex-plugin/plugin.json").write_text(
            json.dumps({"name": "loomex", "version": "9.8.7"}), encoding="utf-8"
        )
        targets = {
            "darwin-arm64": "bin/darwin-arm64/loomex-mcp",
            "darwin-x64": "bin/darwin-x64/loomex-mcp",
            "linux-arm64": "bin/linux-arm64/loomex-mcp",
            "linux-x64": "bin/linux-x64/loomex-mcp",
        }
        (self.source / "packaging/targets.json").write_text(
            json.dumps({
                "schemaVersion": 1,
                "linuxRuntimeContract": {"libc": "glibc", "minimumVersion": "2.35"},
                "artifacts": targets,
            }),
            encoding="utf-8",
        )
        (self.source / "packaging/runtime-manifest.template.json").write_text(
            json.dumps({
                "schemaVersion": 1,
                "pluginVersion": None,
                "runtimeVersion": "9.8.7",
                "channel": "stable",
                "distributionKind": "validation",
                "developmentOverridesAllowed": False,
                "linuxRuntimeContract": {"libc": "glibc", "minimumVersion": "2.35"},
                "artifacts": {},
            }),
            encoding="utf-8",
        )
        (self.source / "packaging/marketplace.template.json").write_text(
            json.dumps({
                "name": "loomex",
                "interface": {"displayName": "Loomex"},
                "plugins": [{
                    "name": "loomex",
                    "source": {"source": "local", "path": "./plugins/loomex"},
                    "policy": {"installation": "AVAILABLE", "authentication": "ON_USE"},
                    "category": "Productivity",
                }],
            }),
            encoding="utf-8",
        )
        self.artifacts = self.temp / "artifacts"
        for target in targets:
            directory = self.artifacts / target
            directory.mkdir(parents=True)
            header = native_test_header(target)
            (directory / "loomex").write_bytes(header + f"cli-{target}".encode())
            (directory / "loomex-mcp").write_bytes(
                header + f"mcp-{target}".encode()
            )
            self.write_signing_marker(target)

    def write_signing_marker(self, target: str) -> None:
        directory = self.artifacts / target
        runtime = directory / "loomex"
        mcp = directory / "loomex-mcp"
        payload = {
            "schemaVersion": 1,
            "target": target,
            "status": "unsigned",
            "method": "none",
            "binaries": {
                "loomex": {"sha256": hashlib.sha256(runtime.read_bytes()).hexdigest()},
                "loomex-mcp": {"sha256": hashlib.sha256(mcp.read_bytes()).hexdigest()},
            },
        }
        (directory / "signing.json").write_text(json.dumps(payload), encoding="utf-8")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def assemble(self, *extra: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "python3",
                str(ASSEMBLER),
                "--plugin-source",
                str(self.source),
                "--artifacts-root",
                str(self.artifacts),
                "--output-root",
                str(self.temp / "dist"),
                "--archive",
                str(self.temp / "loomex.zip"),
                "--marketplace-archive",
                str(self.temp / "loomex-marketplace.zip"),
                "--marketplace-provenance",
                str(self.temp / "loomex-marketplace.provenance.json"),
                "--marketplace-installer",
                str(self.temp / "loomex-install-marketplace.sh"),
                "--version",
                "9.8.7",
                *extra,
            ],
            text=True,
            capture_output=True,
        )

    def test_assembles_both_executables_with_digest_size_and_modes(self) -> None:
        result = self.assemble()
        self.assertEqual(result.returncode, 0, result.stderr)
        plugin = self.temp / "dist/loomex"
        manifest = json.loads((plugin / "packaging/runtime-manifest.json").read_text())
        for target, entry in manifest["artifacts"].items():
            for binary in (entry, entry["runtime"]):
                path = plugin / binary["path"]
                self.assertEqual(binary["size"], path.stat().st_size)
                self.assertEqual(binary["sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
            self.assertNotEqual((plugin / entry["path"]).stat().st_mode & 0o111, 0)
            self.assertNotEqual(
                (plugin / entry["runtime"]["path"]).stat().st_mode & 0o111, 0
            )

        with zipfile.ZipFile(self.temp / "loomex.zip") as archive:
            unix = archive.getinfo("loomex/bin/darwin-arm64/loomex-mcp")
            self.assertNotEqual((unix.external_attr >> 16) & stat.S_IXUSR, 0)
            self.assertIn("loomex/bin/linux-x64/loomex", archive.namelist())
        with zipfile.ZipFile(self.temp / "loomex-marketplace.zip") as archive:
            self.assertIn(".agents/plugins/marketplace.json", archive.namelist())
            self.assertIn("plugins/loomex/.codex-plugin/plugin.json", archive.namelist())
            self.assertIn("plugins/loomex/bin/linux-arm64/loomex-mcp", archive.namelist())
        provenance = json.loads(
            (self.temp / "loomex-marketplace.provenance.json").read_text(
                encoding="utf-8"
            )
        )
        installer = self.temp / "loomex-install-marketplace.sh"
        self.assertEqual(provenance["installer"]["name"], installer.name)
        self.assertEqual(
            provenance["installer"]["sha256"],
            hashlib.sha256(installer.read_bytes()).hexdigest(),
        )

    def test_rejects_source_inside_marketplace_output_before_mutation(self) -> None:
        output = self.temp / "collision-output"
        source = output / "marketplace"
        shutil.copytree(self.source, source)
        sentinel = source / "sentinel.txt"
        sentinel.write_text("must survive\n", encoding="utf-8")
        result = subprocess.run(
            [
                "python3",
                str(ASSEMBLER),
                "--plugin-source",
                str(source),
                "--artifacts-root",
                str(self.artifacts),
                "--output-root",
                str(output),
                "--archive",
                str(self.temp / "collision-plugin.zip"),
                "--marketplace-archive",
                str(self.temp / "collision-marketplace.zip"),
                "--marketplace-provenance",
                str(self.temp / "collision-provenance.json"),
                "--marketplace-installer",
                str(self.temp / "collision-installer.sh"),
                "--version",
                "9.8.7",
            ],
            text=True,
            capture_output=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must be completely disjoint", result.stderr)
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "must survive\n")

    def test_marketplace_provenance_matches_git_and_exact_archive(self) -> None:
        result = self.assemble()
        self.assertEqual(result.returncode, 0, result.stderr)
        marketplace = self.temp / "dist/marketplace"
        archive = self.temp / "loomex-marketplace.zip"
        provenance_path = self.temp / "loomex-marketplace.provenance.json"
        self.assertEqual(
            validate_marketplace_provenance(
                marketplace,
                archive,
                provenance_path,
                self.temp / "loomex-install-marketplace.sh",
            ),
            [],
        )
        provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
        expected_commit, expected_tree = marketplace_commit(marketplace, "9.8.7")
        self.assertEqual(provenance["marketplace"]["commit"], expected_commit)
        self.assertEqual(provenance["marketplace"]["tree"], expected_tree)
        self.assertEqual(
            provenance["archive"]["sha256"],
            hashlib.sha256(archive.read_bytes()).hexdigest(),
        )

        environment = os.environ.copy()
        environment.update(
            {
                "GIT_AUTHOR_NAME": "Loomex Release Bot",
                "GIT_AUTHOR_EMAIL": "release-bot@loomex.app",
                "GIT_COMMITTER_NAME": "Loomex Release Bot",
                "GIT_COMMITTER_EMAIL": "release-bot@loomex.app",
                "GIT_AUTHOR_DATE": f"{MARKETPLACE_COMMIT_EPOCH} +0000",
                "GIT_COMMITTER_DATE": f"{MARKETPLACE_COMMIT_EPOCH} +0000",
            }
        )
        subprocess.run(["git", "init", "-q", str(marketplace)], check=True)
        subprocess.run(
            ["git", "-C", str(marketplace), "-c", "core.autocrlf=false", "add", ".agents", "plugins"],
            check=True,
        )
        tree = subprocess.run(
            ["git", "-C", str(marketplace), "write-tree"],
            check=True,
            text=True,
            capture_output=True,
        ).stdout.strip()
        commit = subprocess.run(
            ["git", "-C", str(marketplace), "commit-tree", tree],
            input="Loomex Codex plugin 9.8.7\n",
            env=environment,
            check=True,
            text=True,
            capture_output=True,
        ).stdout.strip()
        self.assertEqual(tree, expected_tree)
        self.assertEqual(commit, expected_commit)

    def test_marketplace_provenance_rejects_tree_or_archive_tampering(self) -> None:
        result = self.assemble()
        self.assertEqual(result.returncode, 0, result.stderr)
        marketplace = self.temp / "dist/marketplace"
        archive = self.temp / "loomex-marketplace.zip"
        provenance_path = self.temp / "loomex-marketplace.provenance.json"
        manifest = marketplace / ".agents/plugins/marketplace.json"
        manifest.write_text(manifest.read_text(encoding="utf-8") + " ", encoding="utf-8")
        failures = validate_marketplace_provenance(
            marketplace,
            archive,
            provenance_path,
            self.temp / "loomex-install-marketplace.sh",
        )
        self.assertIn(
            "marketplace provenance is not bound to the exact Git tree and commit",
            failures,
        )
        self.assertIn(
            "marketplace archive bytes differ for .agents/plugins/marketplace.json",
            failures,
        )

        manifest.write_text(manifest.read_text(encoding="utf-8").rstrip(), encoding="utf-8")
        archive.write_bytes(archive.read_bytes() + b"tamper")
        failures = validate_marketplace_provenance(
            marketplace,
            archive,
            provenance_path,
            self.temp / "loomex-install-marketplace.sh",
        )
        self.assertIn("marketplace provenance archive digest differs", failures)

    def test_marketplace_archive_rejects_unsafe_directory_entry(self) -> None:
        result = self.assemble()
        self.assertEqual(result.returncode, 0, result.stderr)
        marketplace = self.temp / "dist/marketplace"
        archive = self.temp / "loomex-marketplace.zip"
        with zipfile.ZipFile(archive, "a") as package:
            entry = zipfile.ZipInfo("../../escape/")
            entry.create_system = 3
            entry.external_attr = (stat.S_IFDIR | 0o755) << 16
            package.writestr(entry, b"")
        failures = validate_marketplace_archive(marketplace, archive)
        self.assertIn(
            "marketplace archive contains a directory entry: ../../escape/",
            failures,
        )

    def test_marketplace_archive_rejects_setuid_mode(self) -> None:
        result = self.assemble()
        self.assertEqual(result.returncode, 0, result.stderr)
        marketplace = self.temp / "dist/marketplace"
        archive = self.temp / "loomex-marketplace.zip"
        rewritten = self.temp / "unsafe-mode.zip"
        with zipfile.ZipFile(archive) as source, zipfile.ZipFile(
            rewritten, "w"
        ) as destination:
            for info in source.infolist():
                data = source.read(info.filename)
                if info.filename == ".agents/plugins/marketplace.json":
                    info.external_attr = (stat.S_IFREG | 0o4755) << 16
                destination.writestr(info, data)
        failures = validate_marketplace_archive(marketplace, rewritten)
        self.assertIn(
            "marketplace archive path is unsafe: .agents/plugins/marketplace.json",
            failures,
        )

    def test_unsigned_release_requires_complete_source_provenance(self) -> None:
        result = self.assemble("--signing-state", "unsigned-release")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("require complete source release provenance", result.stderr)

    def test_unsigned_release_records_source_and_platform_limitations(self) -> None:
        result = self.assemble(
            "--signing-state", "unsigned-release",
            "--source-release-sha", "a" * 40,
            "--source-release-tag", "v9.8.7",
            "--source-release-base", "main",
            "--source-release-pr", "42",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        runtime = json.loads(
            (self.temp / "dist/loomex/packaging/runtime-manifest.json").read_text()
        )
        self.assertEqual(runtime["distributionKind"], "release")
        self.assertEqual(runtime["packageSigningState"], "unsigned-release")
        for entry in runtime["artifacts"].values():
            self.assertEqual(entry["platformSignature"]["status"], "unsigned")
            self.assertEqual(entry["platformSignature"]["method"], "none")
        provenance = json.loads(
            (self.temp / "loomex-marketplace.provenance.json").read_text()
        )
        self.assertEqual(
            provenance["sourceRelease"],
            {"sha": "a" * 40, "tag": "v9.8.7", "base": "main", "pullRequest": 42},
        )
        self.assertEqual(
            provenance["nativeBinaries"],
            {"platformSigning": "unsigned", "appleNotarization": "none"},
        )

    def test_validation_package_rejects_source_release_claims(self) -> None:
        result = self.assemble(
            "--source-release-sha", "a" * 40,
            "--source-release-tag", "v9.8.7",
            "--source-release-base", "main",
            "--source-release-pr", "42",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("only valid for unsigned-release", result.stderr)

    def test_signing_evidence_is_bound_to_native_bytes(self) -> None:
        marker = json.loads((self.artifacts / "darwin-arm64/signing.json").read_text())
        marker["binaries"]["loomex"]["sha256"] = "0" * 64
        (self.artifacts / "darwin-arm64/signing.json").write_text(json.dumps(marker))
        result = self.assemble()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not bound to the native bytes", result.stderr)

    def test_rejects_symlinked_native_input(self) -> None:
        target = self.artifacts / "darwin-arm64/loomex-mcp"
        target.unlink()
        target.symlink_to(self.artifacts / "darwin-arm64/loomex")
        result = self.assemble()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("non-symlink", result.stderr)

    def test_rejects_target_path_escape(self) -> None:
        (self.source / "packaging/targets.json").write_text(
            json.dumps(
                {
                    "schemaVersion": 1,
                    "linuxRuntimeContract": {"libc": "glibc", "minimumVersion": "2.35"},
                    "artifacts": {"darwin-arm64": "../outside/loomex-mcp"},
                }
            ),
            encoding="utf-8",
        )
        result = self.assemble()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must install below", result.stderr)

    def test_rejects_windows_until_local_control_transport_exists(self) -> None:
        (self.source / "packaging/targets.json").write_text(
            json.dumps(
                {
                    "schemaVersion": 1,
                    "linuxRuntimeContract": {"libc": "glibc", "minimumVersion": "2.35"},
                    "artifacts": {
                        "win32-x64": "bin/win32-x64/loomex-mcp.exe",
                    },
                }
            ),
            encoding="utf-8",
        )
        windows = self.artifacts / "win32-x64"
        windows.mkdir()
        (windows / "loomex.exe").write_bytes(b"cli-windows")
        (windows / "loomex-mcp.exe").write_bytes(b"mcp-windows")
        result = self.assemble()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unsupported package target", result.stderr)

    def test_safety_scan_reports_secrets_and_machine_paths_without_echoing_values(self) -> None:
        package = self.temp / "unsafe-package"
        package.mkdir()
        unsafe = package / "settings.txt"
        unsafe.write_text(
            "workspace=/Users/example/private/repo\n"
            "token=ghp_abcdefghijklmnopqrstuvwxyz123456\n",
            encoding="utf-8",
        )
        failures = validate_tree(package)
        self.assertIn("macOS user path detected in settings.txt", failures)
        self.assertIn("GitHub token detected in settings.txt", failures)
        self.assertTrue(all("example/private" not in failure for failure in failures))

    def test_nul_byte_cannot_bypass_secret_scan_outside_known_native_paths(self) -> None:
        package = self.temp / "nul-bypass"
        package.mkdir()
        (package / "notes.dat").write_bytes(
            b"\0token=ghp_abcdefghijklmnopqrstuvwxyz123456\n"
        )
        self.assertIn("GitHub token detected in notes.dat", validate_tree(package))

    def test_marketplace_native_payload_is_format_checked_and_safety_scanned(self) -> None:
        package = self.temp / "marketplace"
        native = package / "plugins/loomex/bin/linux-x64/loomex-mcp"
        native.parent.mkdir(parents=True)
        native.write_bytes(
            native_test_header("linux-x64")
            + b"workspace=/home/example/private/repo\n"
            b"token=ghp_abcdefghijklmnopqrstuvwxyz123456\n"
        )
        native.chmod(0o755)

        failures = validate_tree(package)

        self.assertIn(
            "Linux user path detected in plugins/loomex/bin/linux-x64/loomex-mcp",
            failures,
        )
        self.assertIn(
            "GitHub token detected in plugins/loomex/bin/linux-x64/loomex-mcp",
            failures,
        )

    def test_known_native_payload_requires_executable_mode_and_target_magic(self) -> None:
        package = self.temp / "bad-native"
        native = package / "bin/darwin-arm64/loomex"
        native.parent.mkdir(parents=True)
        native.write_bytes(b"not a Mach-O executable")
        native.chmod(0o644)

        failures = validate_tree(package)

        self.assertIn("native payload is not executable: bin/darwin-arm64/loomex", failures)
        self.assertIn(
            "native payload does not have the expected executable format: bin/darwin-arm64/loomex",
            failures,
        )

    def test_known_native_payload_rejects_magic_only_and_cross_arch_headers(self) -> None:
        wrong_elf_class = bytearray(native_test_header("linux-x64"))
        wrong_elf_class[4] = 1
        wrong_elf_data = bytearray(native_test_header("linux-x64"))
        wrong_elf_data[5] = 2
        malformed_macho = bytearray(native_test_header("darwin-arm64"))
        malformed_macho[12:16] = (0).to_bytes(4, "little")
        cases = (
            ("linux-x64", b"\x7fELF", "magic-only ELF"),
            ("linux-x64", bytes(wrong_elf_class), "32-bit ELF"),
            ("linux-x64", bytes(wrong_elf_data), "big-endian ELF"),
            ("linux-x64", native_test_header("linux-arm64"), "cross-arch ELF"),
            ("darwin-arm64", b"\xcf\xfa\xed\xfe", "magic-only Mach-O"),
            ("darwin-arm64", bytes(malformed_macho), "non-executable Mach-O"),
            (
                "darwin-arm64",
                native_test_header("darwin-x64"),
                "cross-arch Mach-O",
            ),
        )
        for target, payload, label in cases:
            with self.subTest(label):
                package = self.temp / label.replace(" ", "-")
                native = package / f"bin/{target}/loomex"
                native.parent.mkdir(parents=True)
                native.write_bytes(payload)
                native.chmod(0o755)

                self.assertIn(
                    f"native payload does not have the expected executable format: bin/{target}/loomex",
                    validate_tree(package),
                )

    def test_runtime_integrity_validation_detects_cli_tampering(self) -> None:
        result = self.assemble()
        self.assertEqual(result.returncode, 0, result.stderr)
        plugin = self.temp / "dist/loomex"
        (plugin / "bin/darwin-arm64/loomex").write_bytes(b"tampered")
        failures = validate_runtime_integrity(plugin)
        self.assertIn("runtime manifest darwin-arm64 runtime size does not match", failures)
        self.assertIn("runtime manifest darwin-arm64 runtime digest does not match", failures)


if __name__ == "__main__":
    unittest.main()
