#!/usr/bin/env python3
"""Validate an assembled Loomex Codex plugin without leaking file contents."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import subprocess
import sys
import zipfile
from pathlib import Path

from codex_plugin_assemble import (
    AssemblyError,
    MARKETPLACE_COMMIT_EPOCH,
    MARKETPLACE_COMMIT_IDENTITY,
    MARKETPLACE_REPOSITORY,
    marketplace_commit,
)


SECRET_PATTERNS = {
    "private key": re.compile(rb"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"),
    "GitHub token": re.compile(rb"\bgh[oprsu]_[A-Za-z0-9_]{24,}\b"),
    "AWS access key": re.compile(rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "Slack token": re.compile(rb"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
}
MACHINE_PATH_PATTERNS = {
    "macOS user path": re.compile(rb"/Users/[A-Za-z0-9._-]+/"),
    "Linux user path": re.compile(rb"/home/[A-Za-z0-9._-]+/"),
    "Windows user path": re.compile(rb"[A-Za-z]:\\Users\\[^\\\r\n]+\\"),
}
FORBIDDEN_NAMES = {".env", "id_rsa", "id_ed25519", "credentials", "credentials.json"}
TEXT_SCAN_LIMIT = 4 * 1024 * 1024
NATIVE_SCAN_LIMIT = 128 * 1024 * 1024
SUPPORTED_TARGETS = {
    "darwin-arm64",
    "darwin-x64",
    "linux-arm64",
    "linux-x64",
}


def native_payload_target(relative: Path) -> str | None:
    """Return the target only for the two exact assembled plugin layouts."""
    parts = relative.parts
    if len(parts) == 3:
        prefix: tuple[str, ...] = ()
        bin_name, target, executable = parts
    elif len(parts) == 5:
        prefix = parts[:2]
        bin_name, target, executable = parts[2:]
    else:
        return None
    if (
        prefix not in {(), ("plugins", "loomex")}
        or bin_name != "bin"
        or target not in SUPPORTED_TARGETS
        or executable not in {"loomex", "loomex-mcp"}
    ):
        return None
    return target


def has_native_magic(prefix: bytes, target: str) -> bool:
    if target.startswith("linux-"):
        if len(prefix) < 64 or prefix[:4] != b"\x7fELF":
            return False
        # Release targets are 64-bit, little-endian ELF. Check the identifying
        # fields and the fixed-size ELF64 header so a magic-only blob cannot be
        # treated as a native executable.
        if prefix[4:7] != bytes((2, 1, 1)):
            return False
        machine = int.from_bytes(prefix[18:20], "little")
        expected_machine = 62 if target == "linux-x64" else 183
        return (
            int.from_bytes(prefix[16:18], "little") in {2, 3}
            and machine == expected_machine
            and int.from_bytes(prefix[20:24], "little") == 1
            and int.from_bytes(prefix[52:54], "little") == 64
        )

    if len(prefix) < 32:
        return False
    if prefix[:4] == b"\xcf\xfa\xed\xfe":
        byteorder = "little"
    elif prefix[:4] == b"\xfe\xed\xfa\xcf":
        byteorder = "big"
    else:
        return False
    cpu_type = int.from_bytes(prefix[4:8], byteorder)
    expected_cpu_type = 0x01000007 if target == "darwin-x64" else 0x0100000C
    file_type = int.from_bytes(prefix[12:16], byteorder)
    return cpu_type == expected_cpu_type and file_type == 2


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("plugin", type=Path)
    parser.add_argument(
        "--plugin-validator",
        type=Path,
        required=True,
        help="Path to the pinned official plugin-creator validate_plugin.py.",
    )
    parser.add_argument("--marketplace-root", type=Path)
    parser.add_argument("--marketplace-archive", type=Path)
    parser.add_argument("--marketplace-provenance", type=Path)
    parser.add_argument("--marketplace-installer", type=Path)
    return parser.parse_args()


def run(command: list[str], cwd: Path) -> None:
    printable = " ".join(command)
    print(f"+ {printable}")
    subprocess.run(command, cwd=cwd, check=True)


def validate_tree(root: Path) -> list[str]:
    failures: list[str] = []
    for path in root.rglob("*"):
        relative = path.relative_to(root)
        try:
            info = path.lstat()
        except OSError as error:
            failures.append(f"cannot inspect {relative}: {error}")
            continue
        if stat.S_ISLNK(info.st_mode):
            failures.append(f"symlink is not allowed: {relative}")
            continue
        if path.name in FORBIDDEN_NAMES or path.name.endswith((".pem", ".p12", ".pfx")):
            failures.append(f"secret-bearing filename is not allowed: {relative}")
        if not stat.S_ISREG(info.st_mode):
            continue
        try:
            with path.open("rb") as stream:
                prefix = stream.read(4096)
        except OSError as error:
            failures.append(f"cannot read {relative}: {error}")
            continue
        target = native_payload_target(relative)
        if target is not None:
            if (info.st_mode & 0o111) == 0:
                failures.append(f"native payload is not executable: {relative}")
            if not has_native_magic(prefix, target):
                failures.append(
                    f"native payload does not have the expected executable format: {relative}"
                )
                continue
            if info.st_size > NATIVE_SCAN_LIMIT:
                failures.append(f"native payload is too large to safety scan: {relative}")
                continue
        if info.st_size > TEXT_SCAN_LIMIT:
            if target is None:
                failures.append(
                    f"oversized non-binary file cannot be safety scanned: {relative}"
                )
                continue
        try:
            data = path.read_bytes()
        except OSError as error:
            failures.append(f"cannot read {relative}: {error}")
            continue
        for label, pattern in {**SECRET_PATTERNS, **MACHINE_PATH_PATTERNS}.items():
            if pattern.search(data):
                failures.append(f"{label} detected in {relative}")
    return failures


def read_json(path: Path, failures: list[str]) -> dict | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        failures.append(f"cannot read JSON {path.name}: {error}")
        return None
    if not isinstance(value, dict):
        failures.append(f"{path.name} must contain a JSON object")
        return None
    return value


def file_digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def validate_binary_entry(
    root: Path, target: str, entry: object, expected_path: str, label: str
) -> list[str]:
    failures: list[str] = []
    if not isinstance(entry, dict):
        return [f"runtime manifest {target} {label} entry must be an object"]
    if entry.get("path") != expected_path:
        failures.append(f"runtime manifest {target} {label} path is incorrect")
        return failures
    relative = Path(expected_path)
    if relative.is_absolute() or ".." in relative.parts:
        failures.append(f"runtime manifest {target} {label} path is unsafe")
        return failures
    path = root / relative
    try:
        info = path.lstat()
    except OSError as error:
        failures.append(f"cannot inspect {target} {label}: {error}")
        return failures
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        failures.append(f"{target} {label} must be a regular non-symlink file")
        return failures
    if (info.st_mode & 0o111) == 0:
        failures.append(f"{target} {label} is not executable")
    if entry.get("size") != info.st_size:
        failures.append(f"runtime manifest {target} {label} size does not match")
    expected_digest = entry.get("sha256")
    if not isinstance(expected_digest, str) or not re.fullmatch(r"[a-f0-9]{64}", expected_digest):
        failures.append(f"runtime manifest {target} {label} digest is invalid")
    elif file_digest(path) != expected_digest:
        failures.append(f"runtime manifest {target} {label} digest does not match")
    return failures


def validate_runtime_integrity(root: Path) -> list[str]:
    failures: list[str] = []
    plugin = read_json(root / ".codex-plugin/plugin.json", failures)
    targets = read_json(root / "packaging/targets.json", failures)
    manifest = read_json(root / "packaging/runtime-manifest.json", failures)
    if plugin is None or targets is None or manifest is None:
        return failures
    declared = targets.get("artifacts")
    entries = manifest.get("artifacts")
    if not isinstance(declared, dict) or not isinstance(entries, dict):
        return failures + ["target and runtime manifests must contain artifact objects"]
    if set(entries) != set(declared):
        failures.append("runtime manifest target set differs from packaging/targets.json")
        return failures
    if set(declared) != SUPPORTED_TARGETS:
        failures.append("packaging target set must contain exactly the supported macOS/Linux targets")
        return failures
    if manifest.get("pluginVersion") != plugin.get("version"):
        failures.append("runtime manifest pluginVersion differs from plugin.json")
    plugin_version = plugin.get("version")
    if (
        not isinstance(plugin_version, str)
        or manifest.get("runtimeVersion") != plugin_version.split("+", 1)[0]
    ):
        failures.append("runtime manifest runtimeVersion differs from plugin base version")
    expected_distribution = (
        "release"
        if manifest.get("packageSigningState") == "unsigned-release"
        else "validation"
    )
    if (
        manifest.get("distributionKind") != expected_distribution
        or manifest.get("developmentOverridesAllowed") is not False
    ):
        failures.append("distribution kind/signing state disagree or overrides are enabled")
    if manifest.get("linuxRuntimeContract") != {
        "libc": "glibc",
        "minimumVersion": "2.35",
    }:
        failures.append("runtime manifest must declare the GLIBC 2.35 contract")
    if manifest.get("packageSigningState") not in {"unsigned-validation", "unsigned-release"}:
        failures.append("runtime manifest packageSigningState is invalid")
    for target, mcp_path in sorted(declared.items()):
        if not isinstance(mcp_path, str):
            failures.append(f"declared MCP path for {target} is not a string")
            continue
        entry = entries[target]
        failures.extend(validate_binary_entry(root, target, entry, mcp_path, "MCP"))
        runtime_path = f"bin/{target}/loomex"
        runtime_entry = entry.get("runtime") if isinstance(entry, dict) else None
        failures.extend(
            validate_binary_entry(root, target, runtime_entry, runtime_path, "runtime")
        )
        if isinstance(entry, dict) and isinstance(runtime_entry, dict):
            for label, binary_entry in (("loomex-mcp", entry), ("loomex", runtime_entry)):
                sidecar = root / f"bin/{target}/{label}.sha256"
                try:
                    sidecar_digest = sidecar.read_text(encoding="ascii").strip()
                except OSError as error:
                    failures.append(f"cannot read {target} {label} checksum sidecar: {error}")
                else:
                    if sidecar_digest != binary_entry.get("sha256"):
                        failures.append(f"{target} {label} checksum sidecar does not match")
            signature = entry.get("platformSignature")
            if not isinstance(signature, dict):
                failures.append(f"runtime manifest {target} signing evidence is missing")
                continue
            if signature.get("schemaVersion") != 1 or signature.get("target") != target:
                failures.append(f"runtime manifest {target} signing evidence target is invalid")
            expected_status = "unsigned"
            if signature.get("status") != expected_status:
                failures.append(f"runtime manifest {target} signing evidence status is invalid")
            evidence_binaries = signature.get("binaries")
            if not isinstance(evidence_binaries, dict):
                failures.append(f"runtime manifest {target} signing evidence is not digest-bound")
            else:
                mcp_evidence = evidence_binaries.get("loomex-mcp")
                runtime_evidence = evidence_binaries.get("loomex")
                if not isinstance(mcp_evidence, dict) or mcp_evidence.get("sha256") != entry.get("sha256"):
                    failures.append(f"runtime manifest {target} MCP signing digest differs")
                if not isinstance(runtime_evidence, dict) or runtime_evidence.get("sha256") != runtime_entry.get("sha256"):
                    failures.append(f"runtime manifest {target} runtime signing digest differs")
    return failures


def validate_marketplace_archive(root: Path, archive: Path) -> list[str]:
    failures: list[str] = []
    expected = {
        path.relative_to(root).as_posix(): path
        for path in root.rglob("*")
        if path.is_file() and not path.is_symlink()
    }
    try:
        with zipfile.ZipFile(archive) as package:
            infos = package.infolist()
            names = [info.filename for info in infos if not info.is_dir()]
            if len(names) != len(set(names)):
                failures.append("marketplace archive contains duplicate paths")
            actual: dict[str, zipfile.ZipInfo] = {}
            for info in infos:
                if info.is_dir():
                    # The deterministic release archive contains files only.
                    # Rejecting all explicit directory records also prevents a
                    # traversal/special-mode record from bypassing the checks
                    # below merely because its name ends in a slash.
                    failures.append(
                        f"marketplace archive contains a directory entry: {info.filename}"
                    )
                    continue
                relative = Path(info.filename)
                mode = (info.external_attr >> 16) & 0o177777
                if (
                    relative.is_absolute()
                    or ".." in relative.parts
                    or "\\" in info.filename
                    or info.create_system != 3
                    or mode not in {
                        stat.S_IFREG | 0o644,
                        stat.S_IFREG | 0o755,
                    }
                ):
                    failures.append(f"marketplace archive path is unsafe: {info.filename}")
                    continue
                actual[info.filename] = info
            if set(actual) != set(expected):
                failures.append("marketplace archive file set differs from marketplace tree")
            for name in sorted(set(actual) & set(expected)):
                info = actual[name]
                path = expected[name]
                with package.open(info) as stream:
                    archive_digest = hashlib.sha256(stream.read()).hexdigest()
                if archive_digest != file_digest(path):
                    failures.append(f"marketplace archive bytes differ for {name}")
                archived_mode = (info.external_attr >> 16) & 0o177777
                tree_mode = stat.S_IFREG | (
                    0o755 if path.stat().st_mode & 0o111 else 0o644
                )
                if archived_mode != tree_mode:
                    failures.append(f"marketplace archive mode differs for {name}")
    except (OSError, zipfile.BadZipFile) as error:
        failures.append(f"cannot inspect marketplace archive: {error}")
    return failures


def validate_marketplace_provenance(
    root: Path, archive: Path, provenance_path: Path, installer_path: Path
) -> list[str]:
    failures = validate_tree(root)
    provenance = read_json(provenance_path, failures)
    marketplace = read_json(root / ".agents/plugins/marketplace.json", failures)
    plugin = read_json(root / "plugins/loomex/.codex-plugin/plugin.json", failures)
    runtime = read_json(root / "plugins/loomex/packaging/runtime-manifest.json", failures)
    if provenance is None or marketplace is None or plugin is None or runtime is None:
        return failures
    plugins = marketplace.get("plugins")
    if (
        marketplace.get("name") != "loomex"
        or not isinstance(plugins, list)
        or len(plugins) != 1
        or plugins[0].get("name") != "loomex"
        or plugins[0].get("source")
        != {"source": "local", "path": "./plugins/loomex"}
    ):
        failures.append("marketplace manifest does not select the bundled Loomex plugin")
    if provenance.get("schemaVersion") != 1:
        failures.append("marketplace provenance schemaVersion must be 1")
    if provenance.get("pluginVersion") != plugin.get("version"):
        failures.append("marketplace provenance pluginVersion differs from plugin")
    descriptor = provenance.get("marketplace")
    archive_descriptor = provenance.get("archive")
    installer_descriptor = provenance.get("installer")
    if provenance.get("nativeBinaries") != {
        "platformSigning": "unsigned",
        "appleNotarization": "none",
    }:
        failures.append("marketplace provenance must declare unsigned, unnotarized native binaries")
    if provenance.get("releaseIntegrity") != {
        "checksums": "sha256",
        "blobSignature": "sigstore-keyless-external",
    }:
        failures.append("marketplace provenance release integrity contract is invalid")
    source_release = provenance.get("sourceRelease")
    if source_release is not None and (
        not isinstance(source_release, dict)
        or re.fullmatch(r"[0-9a-f]{40}", str(source_release.get("sha", ""))) is None
        or re.fullmatch(r"v[0-9A-Za-z.+-]+", str(source_release.get("tag", ""))) is None
        or source_release.get("base") not in {"stage", "main"}
        or isinstance(source_release.get("pullRequest"), bool)
        or not isinstance(source_release.get("pullRequest"), int)
        or source_release["pullRequest"] <= 0
    ):
        failures.append("marketplace provenance source release identity is invalid")
    if runtime.get("packageSigningState") == "unsigned-release" and source_release is None:
        failures.append("release marketplace provenance must bind the source release identity")
    if runtime.get("packageSigningState") == "unsigned-validation" and source_release is not None:
        failures.append("validation marketplace provenance must not claim a source release identity")
    if not isinstance(descriptor, dict):
        failures.append("marketplace provenance descriptor is missing")
    else:
        try:
            expected_commit, expected_tree = marketplace_commit(
                root, str(plugin.get("version", ""))
            )
        except (AssemblyError, OSError) as error:
            failures.append(f"cannot compute marketplace Git identity: {error}")
        else:
            expected = {
                "name": "loomex",
                "repository": MARKETPLACE_REPOSITORY,
                "gitObjectFormat": "sha1",
                "commit": expected_commit,
                "tree": expected_tree,
                "commitEpoch": MARKETPLACE_COMMIT_EPOCH,
                "commitIdentity": MARKETPLACE_COMMIT_IDENTITY,
                "commitMessage": f"Loomex Codex plugin {plugin.get('version')}",
            }
            if descriptor != expected:
                failures.append("marketplace provenance is not bound to the exact Git tree and commit")
    if not isinstance(archive_descriptor, dict):
        failures.append("marketplace provenance archive descriptor is missing")
    else:
        if archive_descriptor.get("name") != archive.name:
            failures.append("marketplace provenance archive name differs")
        try:
            archive_digest = file_digest(archive)
        except OSError as error:
            failures.append(f"cannot digest marketplace archive: {error}")
        else:
            if archive_descriptor.get("sha256") != archive_digest:
                failures.append("marketplace provenance archive digest differs")
    failures.extend(validate_marketplace_archive(root, archive))
    bundled_installer = root / "plugins/loomex/scripts/install-marketplace.sh"
    if not isinstance(installer_descriptor, dict):
        failures.append("marketplace provenance installer descriptor is missing")
    else:
        if installer_descriptor.get("name") != installer_path.name:
            failures.append("marketplace provenance installer name differs")
        try:
            installer_digest = file_digest(installer_path)
            bundled_digest = file_digest(bundled_installer)
        except OSError as error:
            failures.append(f"cannot digest marketplace installer: {error}")
        else:
            if installer_descriptor.get("sha256") != installer_digest:
                failures.append("marketplace provenance installer digest differs")
            if installer_digest != bundled_digest:
                failures.append("release installer differs from bundled installer")
        try:
            installer_info = installer_path.lstat()
        except OSError as error:
            failures.append(f"cannot inspect marketplace installer: {error}")
        else:
            if (
                stat.S_ISLNK(installer_info.st_mode)
                or not stat.S_ISREG(installer_info.st_mode)
                or (installer_info.st_mode & 0o777) != 0o755
            ):
                failures.append("marketplace installer must be a regular 0755 file")
    return failures


def main() -> int:
    args = parse_args()
    root = args.plugin.resolve()
    if root.is_symlink() or not root.is_dir():
        print(f"plugin directory is invalid: {root}", file=sys.stderr)
        return 1
    failures = validate_tree(root)
    failures.extend(validate_runtime_integrity(root))
    marketplace_args = (
        args.marketplace_root,
        args.marketplace_archive,
        args.marketplace_provenance,
        args.marketplace_installer,
    )
    if any(value is not None for value in marketplace_args):
        if not all(value is not None for value in marketplace_args):
            failures.append(
                "marketplace root, archive, provenance, and installer must be provided together"
            )
        else:
            failures.extend(
                validate_marketplace_provenance(
                    args.marketplace_root.resolve(),
                    args.marketplace_archive.resolve(),
                    args.marketplace_provenance.resolve(),
                    args.marketplace_installer.resolve(),
                )
            )
    if failures:
        print("plugin safety validation failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    try:
        # Source-only tests intentionally assert that bin/ is absent, so the
        # assembled-package hook is the release validator rather than the
        # source test suite (which CI runs before native assembly).
        run(["node", "scripts/validate-package.mjs", "--release"], root)
        validator = args.plugin_validator.resolve()
        if not validator.is_file():
            raise RuntimeError(f"official plugin validator does not exist: {validator}")
        run([sys.executable, str(validator), str(root)], root)
    except (subprocess.CalledProcessError, RuntimeError) as error:
        print(f"plugin validator failed: {error}", file=sys.stderr)
        return 1
    print("assembled plugin safety and validator hooks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
