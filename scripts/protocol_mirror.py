#!/usr/bin/env python3
"""Synchronize and verify the checked-in loomex-protocol v0.2.0 mirror.

The plugin intentionally builds from a workspace path dependency so packaging
does not depend on crates.io availability.  This tool makes that vendored
source deterministic: the allowlisted files and their SHA-256 digests are
recorded in ``protocol-source.lock.json`` and checked in CI.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any


EXPECTED_PACKAGE = "loomex-protocol"
EXPECTED_VERSION = "0.2.0"
EXPECTED_TRANSPORT = "runner.v1"
LOCK_SCHEMA = "loomex.protocol-source-lock/v1"
SOURCE_REPOSITORY = "https://github.com/loomex-app/loomex-protocol"
ACCEPTED_SOURCE_REMOTES = {
    SOURCE_REPOSITORY,
    f"{SOURCE_REPOSITORY}.git",
    "git@github.com:loomex-app/loomex-protocol.git",
    "ssh://git@github.com/loomex-app/loomex-protocol.git",
}
MIRROR_RELATIVE_PATH = Path("crates/loomex-protocol")
LOCK_RELATIVE_PATH = Path("protocol-source.lock.json")
MANAGED_FILES = (
    "Cargo.toml",
    "README.md",
    "fixtures/agent_capabilities_v2.json",
    "fixtures/agent_error_v2.json",
    "fixtures/agent_error_provider_not_eligible_v2.json",
    "fixtures/agent_error_malformed_dispatch.json",
    "fixtures/agent_error_prestart_cancelled.json",
    "fixtures/agent_error_refresh_executor_discovery_v2.json",
    "fixtures/agent_error_runtime_v2_disabled.json",
    "fixtures/agent_error_upgrade_executor_v2.json",
    "fixtures/agent_execution_v2.json",
    "fixtures/agent_execution_v2_blocked_resumed.json",
    "fixtures/agent_execution_v2_dispatch_rejected.json",
    "fixtures/agent_execution_v2_fresh_after_remediation.json",
    "fixtures/agent_execution_v2_malformed_dispatch_rejected.json",
    "fixtures/agent_execution_v2_pre_session_blocked.json",
    "fixtures/agent_execution_v2_dispatch_cancelled.json",
    "fixtures/agent_process_dispatch_v2.json",
    "fixtures/agent_process_dispatch_v2_fresh_after_remediation.json",
    "fixtures/agent_process_dispatch_v2_jcs_edge.canonical",
    "fixtures/agent_process_dispatch_v2_jcs_edge.json",
    "fixtures/agent_process_dispatch_v2_resumed.json",
    "fixtures/agent_session_checkpoint_v2.json",
    "fixtures/agent_session_checkpoint_v2_auto_unresolved.json",
    "fixtures/agent_session_checkpoint_v2_ordered_fallback.json",
    "fixtures/agent_session_continuation_v2_auto_unresolved.json",
    "fixtures/agent_session_continuation_v2_ordered_fallback.json",
    "fixtures/agent_structured_output_schema_array_v1.json",
    "fixtures/agent_structured_output_schema_object_v1.json",
    "fixtures/agent_structured_output_schema_scalar_v1.json",
    "fixtures/agent_task_v2.json",
    "fixtures/agent_task_v2_ordered_fallback.json",
    "fixtures/agent_terminal_payload_limits_v1.json",
    "fixtures/runner_agent_advertisement_v1_disabled.json",
    "fixtures/runner_agent_advertisement_v1_drain_enabled.json",
    "fixtures/runner_identity_v1.json",
    "src/agent_runtime_v2.rs",
    "src/agent_terminal_v1.rs",
    "src/lib.rs",
    "src/runner_advertisement_v1.rs",
    "tests/fixture_contract.rs",
    "tests/public_surface.rs",
)


class MirrorError(RuntimeError):
    """Raised when the protocol mirror or its provenance is invalid."""


def sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def file_digests(root: Path) -> dict[str, str]:
    digests: dict[str, str] = {}
    for relative in MANAGED_FILES:
        path = root / relative
        if not path.is_file() or path.is_symlink():
            raise MirrorError(f"missing regular protocol source file: {path}")
        digests[relative] = sha256(path.read_bytes())
    return digests


def validate_mirror_inventory(root: Path) -> None:
    actual: set[str] = set()
    for path in root.rglob("*"):
        if path.is_symlink():
            raise MirrorError(f"protocol mirror must not contain symlinks: {path}")
        if path.is_file():
            actual.add(path.relative_to(root).as_posix())
    expected = set(MANAGED_FILES)
    if actual != expected:
        missing = sorted(expected - actual)
        unexpected = sorted(actual - expected)
        raise MirrorError(
            f"protocol mirror inventory differs; missing={missing}, unexpected={unexpected}"
        )


def tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for relative in MANAGED_FILES:
        payload = (root / relative).read_bytes()
        encoded_path = relative.encode("utf-8")
        digest.update(len(encoded_path).to_bytes(8, "big"))
        digest.update(encoded_path)
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    return digest.hexdigest()


def validate_protocol_source(root: Path) -> None:
    manifest_path = root / "Cargo.toml"
    try:
        manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise MirrorError(f"cannot read protocol manifest {manifest_path}: {error}") from error

    package = manifest.get("package", {})
    if package.get("name") != EXPECTED_PACKAGE:
        raise MirrorError(
            f"expected package {EXPECTED_PACKAGE!r}, got {package.get('name')!r}"
        )
    if package.get("version") != EXPECTED_VERSION:
        raise MirrorError(
            f"expected protocol version {EXPECTED_VERSION!r}, "
            f"got {package.get('version')!r}"
        )

    lib = (root / "src/lib.rs").read_text(encoding="utf-8")
    expected_declaration = f'pub const RUNNER_PROTOCOL_V1: &str = "{EXPECTED_TRANSPORT}";'
    if expected_declaration not in lib:
        raise MirrorError(
            f"protocol v{EXPECTED_VERSION} must retain transport {EXPECTED_TRANSPORT}"
        )
    file_digests(root)


def git_output(source: Path, *args: str) -> str | None:
    result = subprocess.run(
        ["git", "-C", str(source), *args],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def source_revision(source: Path) -> dict[str, Any]:
    head = git_output(source, "rev-parse", "HEAD")
    status = git_output(source, "status", "--porcelain", "--untracked-files=all")
    tags = git_output(source, "tag", "--points-at", "HEAD")
    remote = git_output(source, "remote", "get-url", "origin")
    repository_verified = remote in ACCEPTED_SOURCE_REMOTES
    matching_tag = next(
        (tag for tag in (tags or "").splitlines() if tag == f"v{EXPECTED_VERSION}"),
        None,
    )
    clean = status == ""
    published = bool(clean and head and matching_tag and repository_verified)
    return {
        "commit": head if published else None,
        "tag": matching_tag if published else None,
        "workingTreeBaseCommit": head,
        "workingTreeDirty": not clean,
        "repositoryVerified": repository_verified,
        "publicationStatus": "published" if published else "blocked",
        "publicationBlocker": (
            None
            if published
            else (
                "loomex-protocol v0.2.0 is not available from a clean, tagged, "
                "repository-verified source commit. Commit the authoritative "
                "contract, merge it, and create tag v0.2.0 before recording "
                "release provenance."
            )
        ),
    }


def build_lock(source: Path, mirror: Path) -> dict[str, Any]:
    return {
        "schemaVersion": LOCK_SCHEMA,
        "package": {
            "name": EXPECTED_PACKAGE,
            "version": EXPECTED_VERSION,
            "transportProtocol": EXPECTED_TRANSPORT,
        },
        "source": {
            "repository": SOURCE_REPOSITORY,
            **source_revision(source),
        },
        "mirror": {
            "path": MIRROR_RELATIVE_PATH.as_posix(),
            "treeSha256": tree_digest(mirror),
            "files": file_digests(mirror),
        },
    }


def write_lock(path: Path, value: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def sync(repo_root: Path, source: Path) -> None:
    validate_protocol_source(source)
    mirror = repo_root / MIRROR_RELATIVE_PATH
    mirror.mkdir(parents=True, exist_ok=True)

    for relative in MANAGED_FILES:
        source_path = source / relative
        destination = mirror / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source_path, destination)

    validate_mirror_inventory(mirror)
    validate_protocol_source(mirror)
    write_lock(repo_root / LOCK_RELATIVE_PATH, build_lock(source, mirror))


def load_lock(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise MirrorError(f"cannot read protocol lock {path}: {error}") from error
    if not isinstance(value, dict):
        raise MirrorError(f"protocol lock must contain a JSON object: {path}")
    return value


def validate_source_provenance(
    source_metadata: dict[str, Any], *, require_published: bool
) -> None:
    if source_metadata.get("repository") != SOURCE_REPOSITORY:
        raise MirrorError("protocol lock references an unexpected source repository")

    publication_status = source_metadata.get("publicationStatus")
    if publication_status == "blocked":
        if (
            source_metadata.get("commit") is not None
            or source_metadata.get("tag") is not None
            or not source_metadata.get("publicationBlocker")
        ):
            raise MirrorError("blocked protocol provenance must retain its commit/tag blocker")
        if require_published:
            raise MirrorError(
                "production release requires published authoritative "
                f"{EXPECTED_PACKAGE} v{EXPECTED_VERSION} provenance"
            )
        return

    if publication_status != "published":
        raise MirrorError(f"unexpected protocol publication status: {publication_status!r}")

    commit = source_metadata.get("commit")
    if (
        not isinstance(commit, str)
        or re.fullmatch(r"[0-9a-f]{40}", commit) is None
        or source_metadata.get("tag") != f"v{EXPECTED_VERSION}"
        or source_metadata.get("workingTreeBaseCommit") != commit
        or source_metadata.get("workingTreeDirty") is not False
        or source_metadata.get("repositoryVerified") is not True
        or source_metadata.get("publicationBlocker") is not None
    ):
        raise MirrorError(
            "published protocol provenance must name the exact clean "
            "repository-verified commit and v0.2.0 tag"
        )


def check(
    repo_root: Path,
    source: Path | None = None,
    *,
    require_published: bool = False,
) -> None:
    mirror = repo_root / MIRROR_RELATIVE_PATH
    validate_mirror_inventory(mirror)
    validate_protocol_source(mirror)
    lock = load_lock(repo_root / LOCK_RELATIVE_PATH)

    if lock.get("schemaVersion") != LOCK_SCHEMA:
        raise MirrorError(f"unexpected protocol lock schema: {lock.get('schemaVersion')!r}")
    expected_package = {
        "name": EXPECTED_PACKAGE,
        "version": EXPECTED_VERSION,
        "transportProtocol": EXPECTED_TRANSPORT,
    }
    if lock.get("package") != expected_package:
        raise MirrorError("protocol lock package identity does not match v0.2.0")

    locked_mirror = lock.get("mirror")
    if not isinstance(locked_mirror, dict):
        raise MirrorError("protocol lock is missing mirror metadata")
    actual_files = file_digests(mirror)
    if locked_mirror.get("files") != actual_files:
        raise MirrorError("protocol mirror file hashes differ from protocol-source.lock.json")
    actual_tree = tree_digest(mirror)
    if locked_mirror.get("treeSha256") != actual_tree:
        raise MirrorError("protocol mirror tree hash differs from protocol-source.lock.json")
    if locked_mirror.get("path") != MIRROR_RELATIVE_PATH.as_posix():
        raise MirrorError("protocol mirror path differs from the workspace path dependency")

    source_metadata = lock.get("source")
    if not isinstance(source_metadata, dict):
        raise MirrorError("protocol lock is missing source provenance")
    validate_source_provenance(
        source_metadata,
        require_published=require_published,
    )

    if source is not None:
        validate_protocol_source(source)
        if file_digests(source) != actual_files or tree_digest(source) != actual_tree:
            raise MirrorError("checked-in mirror has drifted from the supplied protocol source")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help=argparse.SUPPRESS,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    sync_parser = subparsers.add_parser("sync", help="mirror v0.2.0 from a source checkout")
    sync_parser.add_argument("--source", type=Path, required=True)

    check_parser = subparsers.add_parser("check", help="verify the checked-in mirror and lock")
    check_parser.add_argument(
        "--source",
        type=Path,
        help="also verify byte-for-byte parity with a source checkout",
    )
    check_parser.add_argument(
        "--require-published",
        action="store_true",
        help=(
            "fail unless the lock names the clean, repository-verified "
            "authoritative v0.2.0 tag and commit"
        ),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.command == "sync":
            sync(args.repo_root.resolve(), args.source.resolve())
        else:
            check(
                args.repo_root.resolve(),
                args.source.resolve() if args.source is not None else None,
                require_published=args.require_published,
            )
    except MirrorError as error:
        print(f"protocol mirror check failed: {error}", file=sys.stderr)
        return 1

    print(f"loomex-protocol {EXPECTED_VERSION} mirror {args.command} succeeded")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
