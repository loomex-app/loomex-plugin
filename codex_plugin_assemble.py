#!/usr/bin/env python3
"""Assemble the macOS/Linux Loomex Codex plugin release artifact.

Native binaries are inputs, never built by this script.  This keeps assembly
reproducible and makes the CI matrix responsible for proving that every
declared target really compiled.  The resulting zip preserves Unix executable
mode bits and contains a byte-level manifest for both executables.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import sys
import zipfile
from pathlib import Path
import re


PLUGIN_MANIFEST = Path(".codex-plugin/plugin.json")
TARGETS_MANIFEST = Path("packaging/targets.json")
RUNTIME_MANIFEST = Path("packaging/runtime-manifest.json")
RUNTIME_TEMPLATE = Path("packaging/runtime-manifest.template.json")
MARKETPLACE_TEMPLATE = Path("packaging/marketplace.template.json")
SOURCE_DATE = (1980, 1, 1, 0, 0, 0)
MARKETPLACE_REPOSITORY = "loomex-app/loomex-plugin"
MARKETPLACE_COMMIT_EPOCH = 946684800
MARKETPLACE_COMMIT_IDENTITY = "Loomex Release Bot <release-bot@loomex.app>"
SUPPORTED_TARGETS = {
    "darwin-arm64",
    "darwin-x64",
    "linux-arm64",
    "linux-x64",
}
SEMVER_RE = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)


class AssemblyError(RuntimeError):
    pass


def paths_overlap(left: Path, right: Path) -> bool:
    return (
        left == right
        or left.is_relative_to(right)
        or right.is_relative_to(left)
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plugin-source", type=Path, default=Path("plugin/loomex"))
    parser.add_argument("--artifacts-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--marketplace-archive", type=Path, required=True)
    parser.add_argument("--marketplace-provenance", type=Path, required=True)
    parser.add_argument("--marketplace-installer", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument(
        "--signing-state",
        choices=("unsigned-validation", "unsigned-release"),
        default="unsigned-validation",
        help="Describes unsigned native bytes for validation or a Sigstore release.",
    )
    parser.add_argument("--source-release-sha")
    parser.add_argument("--source-release-tag")
    parser.add_argument("--source-release-base")
    parser.add_argument("--source-release-pr")
    return parser.parse_args()


def read_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise AssemblyError(f"cannot read JSON {path}: {error}") from error
    if not isinstance(value, dict):
        raise AssemblyError(f"expected JSON object in {path}")
    return value


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def git_object_id(kind: str, payload: bytes) -> bytes:
    header = f"{kind} {len(payload)}\0".encode("ascii")
    return hashlib.sha1(header + payload).digest()


def _git_tree_object(root: Path) -> tuple[bytes, int]:
    entries: list[tuple[bytes, bytes]] = []
    for path in root.iterdir():
        name = os.fsencode(path.name)
        if b"\0" in name or b"/" in name:
            raise AssemblyError(f"marketplace path cannot be represented by Git: {path}")
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise AssemblyError(f"marketplace tree contains a symlink: {path}")
        if stat.S_ISDIR(info.st_mode):
            mode = b"40000"
            object_id, child_entries = _git_tree_object(path)
            # Git does not represent empty directories in a tree.
            if child_entries == 0:
                continue
            sort_name = name + b"/"
        elif stat.S_ISREG(info.st_mode):
            mode = b"100755" if info.st_mode & 0o111 else b"100644"
            object_id = git_object_id("blob", path.read_bytes())
            sort_name = name
        else:
            raise AssemblyError(f"marketplace tree contains a non-file entry: {path}")
        entries.append((sort_name, mode + b" " + name + b"\0" + object_id))
    payload = b"".join(entry for _, entry in sorted(entries, key=lambda item: item[0]))
    return git_object_id("tree", payload), len(entries)


def git_tree_id(root: Path) -> bytes:
    """Return the canonical Git SHA-1 tree ID without trusting local Git config."""
    return _git_tree_object(root)[0]


def marketplace_commit(root: Path, version: str) -> tuple[str, str]:
    tree = git_tree_id(root).hex()
    commit = (
        f"tree {tree}\n"
        f"author {MARKETPLACE_COMMIT_IDENTITY} {MARKETPLACE_COMMIT_EPOCH} +0000\n"
        f"committer {MARKETPLACE_COMMIT_IDENTITY} {MARKETPLACE_COMMIT_EPOCH} +0000\n"
        "\n"
        f"Loomex Codex plugin {version}\n"
    ).encode("utf-8")
    return git_object_id("commit", commit).hex(), tree


def write_marketplace_provenance(
    marketplace_root: Path,
    marketplace_archive: Path,
    marketplace_installer: Path,
    provenance_path: Path,
    version: str,
    source_release: dict[str, object] | None,
) -> dict:
    commit, tree = marketplace_commit(marketplace_root, version)
    value = {
        "schemaVersion": 1,
        "pluginVersion": version,
        "marketplace": {
            "name": "loomex",
            "repository": MARKETPLACE_REPOSITORY,
            "gitObjectFormat": "sha1",
            "commit": commit,
            "tree": tree,
            "commitEpoch": MARKETPLACE_COMMIT_EPOCH,
            "commitIdentity": MARKETPLACE_COMMIT_IDENTITY,
            "commitMessage": f"Loomex Codex plugin {version}",
        },
        "archive": {
            "name": marketplace_archive.name,
            "sha256": digest(marketplace_archive),
        },
        "installer": {
            "name": marketplace_installer.name,
            "sha256": digest(marketplace_installer),
        },
        "nativeBinaries": {
            "platformSigning": "unsigned",
            "appleNotarization": "none",
        },
        "releaseIntegrity": {
            "checksums": "sha256",
            "blobSignature": "sigstore-keyless-external",
        },
    }
    if source_release is not None:
        value["sourceRelease"] = source_release
    provenance_path.parent.mkdir(parents=True, exist_ok=True)
    provenance_path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return value


def ensure_plain_file(path: Path, description: str) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError as error:
        raise AssemblyError(f"missing {description}: {path}") from error
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise AssemblyError(f"{description} must be a regular non-symlink file: {path}")


def target_input_dir(root: Path, target: str) -> Path:
    candidates = (
        root / target,
        root / f"loomex-native-{target}",
        root / f"native-{target}",
    )
    for candidate in candidates:
        if candidate.is_dir() and not candidate.is_symlink():
            return candidate
    raise AssemblyError(
        f"missing native artifact directory for {target}; tried "
        + ", ".join(str(candidate) for candidate in candidates)
    )


def copy_plugin_source(source: Path, destination: Path) -> None:
    if source.is_symlink() or not source.is_dir():
        raise AssemblyError(f"plugin source must be a real directory: {source}")
    for entry in source.rglob("*"):
        if entry.is_symlink():
            raise AssemblyError(f"plugin source contains a symlink: {entry}")
    shutil.copytree(source, destination, symlinks=False)


def signature_metadata(
    input_dir: Path,
    target: str,
    cli_source: Path,
    mcp_source: Path,
    signing_state: str,
) -> dict:
    marker = input_dir / "signing.json"
    if marker.exists():
        ensure_plain_file(marker, "signing marker")
        metadata = read_json(marker)
    else:
        metadata = {"status": "unsigned", "method": "none"}

    if metadata.get("schemaVersion") != 1 or metadata.get("target") != target:
        raise AssemblyError(f"{target} signing evidence has an invalid schema or target")
    expected_status = "unsigned"
    if metadata.get("status") != expected_status:
        raise AssemblyError(
            f"{target} signing evidence status must be {expected_status!r}"
        )
    binaries = metadata.get("binaries")
    expected = {"loomex": digest(cli_source), "loomex-mcp": digest(mcp_source)}
    if not isinstance(binaries, dict) or any(
        not isinstance(binaries.get(name), dict)
        or binaries[name].get("sha256") != value
        for name, value in expected.items()
    ):
        raise AssemblyError(f"{target} signing evidence is not bound to the native bytes")
    return metadata


def add_native_artifacts(
    destination: Path,
    artifacts_root: Path,
    targets: dict[str, str],
    signing_state: str,
) -> dict[str, dict]:
    manifest_entries: dict[str, dict] = {}
    for target, mcp_relative in sorted(targets.items()):
        if not isinstance(target, str) or not isinstance(mcp_relative, str):
            raise AssemblyError("target names and artifact paths must be strings")
        if target not in SUPPORTED_TARGETS:
            raise AssemblyError(f"unsupported package target: {target!r}")
        input_dir = target_input_dir(artifacts_root, target)
        cli_name = "loomex"
        mcp_name = "loomex-mcp"
        cli_source = input_dir / cli_name
        mcp_source = input_dir / mcp_name
        ensure_plain_file(cli_source, f"{target} loomex executable")
        ensure_plain_file(mcp_source, f"{target} loomex-mcp executable")

        expected_mcp = Path(mcp_relative)
        if (
            expected_mcp.is_absolute()
            or ".." in expected_mcp.parts
            or expected_mcp.parent != Path("bin") / target
        ):
            raise AssemblyError(
                f"target {target} must install below its own bin/{target} directory"
            )
        if expected_mcp.name != mcp_name:
            raise AssemblyError(
                f"target {target} expects {expected_mcp.name}, not built file {mcp_name}"
            )
        target_dir = destination / expected_mcp.parent
        target_dir.mkdir(parents=True, exist_ok=True)
        cli_destination = target_dir / cli_name
        mcp_destination = target_dir / mcp_name
        shutil.copy2(cli_source, cli_destination)
        shutil.copy2(mcp_source, mcp_destination)
        cli_destination.chmod(0o755)
        mcp_destination.chmod(0o755)

        signature = signature_metadata(
            input_dir, target, cli_source, mcp_source, signing_state
        )
        (mcp_destination.with_name(mcp_destination.name + ".sha256")).write_text(
            digest(mcp_destination) + "\n", encoding="ascii"
        )
        (cli_destination.with_name(cli_destination.name + ".sha256")).write_text(
            digest(cli_destination) + "\n", encoding="ascii"
        )
        manifest_entries[target] = {
            # path/sha256 remain compatible with the plugin launcher's v1 contract.
            "path": expected_mcp.as_posix(),
            "sha256": digest(mcp_destination),
            "size": mcp_destination.stat().st_size,
            "platformSignature": signature,
            "runtime": {
                "path": cli_destination.relative_to(destination).as_posix(),
                "sha256": digest(cli_destination),
                "size": cli_destination.stat().st_size,
            },
        }
    return manifest_entries


def write_archive(plugin_dir: Path, archive: Path) -> None:
    archive.parent.mkdir(parents=True, exist_ok=True)
    temporary = archive.with_suffix(archive.suffix + ".tmp")
    if temporary.exists():
        temporary.unlink()
    with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zip_file:
        for path in sorted(plugin_dir.rglob("*"), key=lambda item: item.as_posix()):
            if not path.is_file():
                continue
            relative = Path(plugin_dir.name) / path.relative_to(plugin_dir)
            info = zipfile.ZipInfo(relative.as_posix(), SOURCE_DATE)
            mode = 0o755 if (path.stat().st_mode & 0o111) else 0o644
            info.external_attr = (stat.S_IFREG | mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            with path.open("rb") as source, zip_file.open(info, "w") as target:
                shutil.copyfileobj(source, target, length=1024 * 1024)
    os.replace(temporary, archive)


def write_marketplace_archive(marketplace_root: Path, archive: Path) -> None:
    archive.parent.mkdir(parents=True, exist_ok=True)
    temporary = archive.with_suffix(archive.suffix + ".tmp")
    if temporary.exists():
        temporary.unlink()
    with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zip_file:
        for path in sorted(marketplace_root.rglob("*"), key=lambda item: item.as_posix()):
            if not path.is_file():
                continue
            relative = path.relative_to(marketplace_root)
            info = zipfile.ZipInfo(relative.as_posix(), SOURCE_DATE)
            mode = 0o755 if (path.stat().st_mode & 0o111) else 0o644
            info.external_attr = (stat.S_IFREG | mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            with path.open("rb") as source, zip_file.open(info, "w") as target:
                shutil.copyfileobj(source, target, length=1024 * 1024)
    os.replace(temporary, archive)


def assemble(args: argparse.Namespace) -> Path:
    source = args.plugin_source.resolve()
    artifacts_root = args.artifacts_root.resolve()
    output_root = args.output_root.resolve()
    destination = output_root / "loomex"
    marketplace_root = output_root / "marketplace"
    archive = args.archive.resolve()
    marketplace_archive = args.marketplace_archive.resolve()
    marketplace_provenance = args.marketplace_provenance.resolve()
    marketplace_installer = args.marketplace_installer.resolve()
    if paths_overlap(source, output_root):
        raise AssemblyError("output root and plugin source must be completely disjoint")
    if paths_overlap(artifacts_root, output_root):
        raise AssemblyError("output root and native artifacts must be completely disjoint")
    if paths_overlap(destination, marketplace_root):
        raise AssemblyError("plugin and marketplace output trees must be disjoint")
    output_files = {
        "plugin archive": archive,
        "marketplace archive": marketplace_archive,
        "marketplace provenance": marketplace_provenance,
        "marketplace installer": marketplace_installer,
    }
    if len(set(output_files.values())) != len(output_files):
        raise AssemblyError("release output files must all be different")
    protected_trees = {
        "plugin source": source,
        "native artifacts": artifacts_root,
        "assembled plugin": destination,
        "assembled marketplace": marketplace_root,
    }
    for output_label, output_path in output_files.items():
        for tree_label, tree_path in protected_trees.items():
            if paths_overlap(output_path, tree_path):
                raise AssemblyError(
                    f"{output_label} and {tree_label} must be completely disjoint"
                )
    if archive == destination or archive.is_relative_to(destination):
        raise AssemblyError("archive must be outside the assembled plugin directory")

    plugin = read_json(source / PLUGIN_MANIFEST)
    if plugin.get("name") != "loomex":
        raise AssemblyError("plugin manifest name must be loomex")
    if plugin.get("version") != args.version:
        raise AssemblyError(
            f"requested version {args.version!r} differs from plugin version {plugin.get('version')!r}"
        )
    if SEMVER_RE.fullmatch(args.version) is None:
        raise AssemblyError("plugin version must be strict semver")
    source_values = (
        args.source_release_sha,
        args.source_release_tag,
        args.source_release_base,
        args.source_release_pr,
    )
    if args.signing_state == "unsigned-release" and any(value is None for value in source_values):
        raise AssemblyError("unsigned-release packages require complete source release provenance")
    if args.signing_state == "unsigned-validation" and any(value is not None for value in source_values):
        raise AssemblyError("source release provenance is only valid for unsigned-release packages")
    source_release = None
    if args.signing_state == "unsigned-release":
        if re.fullmatch(r"[0-9a-f]{40}", args.source_release_sha or "") is None:
            raise AssemblyError("source release SHA must be a full lowercase Git SHA")
        if re.fullmatch(r"v[0-9A-Za-z.+-]+", args.source_release_tag or "") is None:
            raise AssemblyError("source release tag must begin with v")
        if args.source_release_base not in {"stage", "main"}:
            raise AssemblyError("source release base must be stage or main")
        if re.fullmatch(r"[1-9][0-9]*", args.source_release_pr or "") is None:
            raise AssemblyError("source release PR must be a positive integer")
        source_release = {
            "sha": args.source_release_sha,
            "tag": args.source_release_tag,
            "base": args.source_release_base,
            "pullRequest": int(args.source_release_pr),
        }
    template = read_json(source / RUNTIME_TEMPLATE)
    marketplace = read_json(source / MARKETPLACE_TEMPLATE)
    plugins = marketplace.get("plugins")
    if (
        marketplace.get("name") != "loomex"
        or not isinstance(plugins, list)
        or len(plugins) != 1
        or plugins[0].get("name") != "loomex"
        or plugins[0].get("source")
        != {"source": "local", "path": "./plugins/loomex"}
        or plugins[0].get("policy")
        != {"installation": "AVAILABLE", "authentication": "ON_USE"}
    ):
        raise AssemblyError("marketplace template does not match the Codex marketplace contract")
    runtime_version = template.get("runtimeVersion")
    channel = template.get("channel")
    if not isinstance(runtime_version, str) or SEMVER_RE.fullmatch(runtime_version) is None:
        raise AssemblyError("runtime manifest template runtimeVersion must be strict semver")
    plugin_base = args.version.split("+", 1)[0]
    if runtime_version != plugin_base:
        raise AssemblyError(
            f"runtime version {runtime_version!r} differs from plugin base version {plugin_base!r}"
        )
    if channel not in {"stable", "beta"}:
        raise AssemblyError("runtime manifest template channel must be stable or beta")
    targets_document = read_json(source / TARGETS_MANIFEST)
    targets = targets_document.get("artifacts")
    if not isinstance(targets, dict) or not targets:
        raise AssemblyError("packaging/targets.json must declare at least one artifact")
    linux_contract = targets_document.get("linuxRuntimeContract")
    if linux_contract != {"libc": "glibc", "minimumVersion": "2.35"}:
        raise AssemblyError("packaging/targets.json must pin the GLIBC 2.35 runtime contract")
    if template.get("linuxRuntimeContract") != linux_contract:
        raise AssemblyError("runtime manifest template and target GLIBC contracts differ")
    if destination.exists():
        shutil.rmtree(destination)
    output_root.mkdir(parents=True, exist_ok=True)
    copy_plugin_source(source, destination)
    entries = add_native_artifacts(
        destination, artifacts_root, targets, args.signing_state
    )
    runtime_manifest = {
        "schemaVersion": 1,
        "pluginVersion": args.version,
        "runtimeVersion": runtime_version,
        "channel": channel,
        "distributionKind": "release" if args.signing_state == "unsigned-release" else "validation",
        "developmentOverridesAllowed": False,
        "linuxRuntimeContract": linux_contract,
        "packageSigningState": args.signing_state,
        "artifacts": entries,
    }
    manifest_path = destination / RUNTIME_MANIFEST
    manifest_path.write_text(
        json.dumps(runtime_manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    write_archive(destination, archive)
    if marketplace_root.exists():
        shutil.rmtree(marketplace_root)
    marketplace_manifest = marketplace_root / ".agents/plugins/marketplace.json"
    marketplace_manifest.parent.mkdir(parents=True, exist_ok=True)
    marketplace_manifest.write_text(
        json.dumps(marketplace, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    shutil.copytree(destination, marketplace_root / "plugins/loomex", symlinks=False)
    write_marketplace_archive(marketplace_root, marketplace_archive)
    installer_source = destination / "scripts/install-marketplace.sh"
    ensure_plain_file(installer_source, "marketplace installer")
    marketplace_installer.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(installer_source, marketplace_installer)
    marketplace_installer.chmod(0o755)
    write_marketplace_provenance(
        marketplace_root,
        marketplace_archive,
        marketplace_installer,
        marketplace_provenance,
        args.version,
        source_release,
    )
    return destination


def main() -> int:
    args = parse_args()
    try:
        destination = assemble(args)
    except AssemblyError as error:
        print(f"codex plugin assembly failed: {error}", file=sys.stderr)
        return 1
    print(f"assembled plugin directory: {destination}")
    print(f"archive: {args.archive.resolve()}")
    print(f"archive sha256: {digest(args.archive.resolve())}")
    print(f"marketplace archive: {args.marketplace_archive.resolve()}")
    print(f"marketplace archive sha256: {digest(args.marketplace_archive.resolve())}")
    print(f"marketplace provenance: {args.marketplace_provenance.resolve()}")
    print(f"marketplace installer: {args.marketplace_installer.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
