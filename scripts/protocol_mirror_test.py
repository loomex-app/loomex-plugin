#!/usr/bin/env python3
"""Tests for deterministic loomex-protocol mirroring and drift checks."""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from scripts import protocol_mirror


REPO_ROOT = Path(__file__).resolve().parents[1]


class ProtocolMirrorTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        mirror = self.root / protocol_mirror.MIRROR_RELATIVE_PATH
        for relative in protocol_mirror.MANAGED_FILES:
            source = REPO_ROOT / protocol_mirror.MIRROR_RELATIVE_PATH / relative
            destination = mirror / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
        shutil.copyfile(
            REPO_ROOT / protocol_mirror.LOCK_RELATIVE_PATH,
            self.root / protocol_mirror.LOCK_RELATIVE_PATH,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_checked_in_mirror_matches_lock(self) -> None:
        protocol_mirror.check(self.root)

    def test_sync_is_deterministic_without_git_or_a_registry(self) -> None:
        source_root = self.root / "standalone-source"
        shutil.copytree(
            self.root / protocol_mirror.MIRROR_RELATIVE_PATH,
            source_root,
        )
        destination_root = self.root / "destination"
        destination_root.mkdir()

        protocol_mirror.sync(destination_root, source_root)
        first_lock = (destination_root / protocol_mirror.LOCK_RELATIVE_PATH).read_bytes()
        protocol_mirror.sync(destination_root, source_root)
        second_lock = (destination_root / protocol_mirror.LOCK_RELATIVE_PATH).read_bytes()

        self.assertEqual(first_lock, second_lock)
        protocol_mirror.check(destination_root, source_root)

    def test_source_file_drift_is_rejected(self) -> None:
        source = self.root / protocol_mirror.MIRROR_RELATIVE_PATH / "src/lib.rs"
        source.write_text(
            source.read_text(encoding="utf-8") + "\n// unexpected drift\n",
            encoding="utf-8",
        )

        with self.assertRaisesRegex(protocol_mirror.MirrorError, "file hashes differ"):
            protocol_mirror.check(self.root)

    def test_lock_hash_drift_is_rejected(self) -> None:
        lock_path = self.root / protocol_mirror.LOCK_RELATIVE_PATH
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        lock["mirror"]["files"]["README.md"] = "0" * 64
        lock_path.write_text(json.dumps(lock), encoding="utf-8")

        with self.assertRaisesRegex(protocol_mirror.MirrorError, "file hashes differ"):
            protocol_mirror.check(self.root)

    def test_extra_mirror_file_is_rejected(self) -> None:
        extra = self.root / protocol_mirror.MIRROR_RELATIVE_PATH / "src/duplicate.rs"
        extra.write_text("// accidental duplicate\n", encoding="utf-8")

        with self.assertRaisesRegex(protocol_mirror.MirrorError, "inventory differs"):
            protocol_mirror.check(self.root)

    def test_blocked_provenance_must_keep_the_publication_blocker(self) -> None:
        lock_path = self.root / protocol_mirror.LOCK_RELATIVE_PATH
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        lock["source"].update(
            {
                "commit": None,
                "tag": None,
                "workingTreeDirty": True,
                "repositoryVerified": False,
                "publicationStatus": "blocked",
                "publicationBlocker": None,
            }
        )
        lock_path.write_text(json.dumps(lock), encoding="utf-8")

        with self.assertRaisesRegex(protocol_mirror.MirrorError, "commit/tag blocker"):
            protocol_mirror.check(self.root)

    def test_blocked_provenance_is_allowed_for_validation_but_not_release(self) -> None:
        lock_path = self.root / protocol_mirror.LOCK_RELATIVE_PATH
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        lock["source"].update(
            {
                "commit": None,
                "tag": None,
                "workingTreeDirty": True,
                "repositoryVerified": False,
                "publicationStatus": "blocked",
                "publicationBlocker": "test commit/tag blocker",
            }
        )
        lock_path.write_text(json.dumps(lock), encoding="utf-8")

        protocol_mirror.check(self.root)

        with self.assertRaisesRegex(
            protocol_mirror.MirrorError,
            "production release requires published authoritative",
        ):
            protocol_mirror.check(self.root, require_published=True)

    def test_release_gate_requires_exact_published_tag_and_commit(self) -> None:
        lock_path = self.root / protocol_mirror.LOCK_RELATIVE_PATH
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        commit = "a" * 40
        lock["source"].update(
            {
                "commit": commit,
                "tag": "v0.2.0",
                "workingTreeBaseCommit": commit,
                "workingTreeDirty": False,
                "repositoryVerified": True,
                "publicationStatus": "published",
                "publicationBlocker": None,
            }
        )
        lock_path.write_text(json.dumps(lock), encoding="utf-8")

        protocol_mirror.check(self.root, require_published=True)

        lock["source"]["commit"] = "not-a-commit"
        lock_path.write_text(json.dumps(lock), encoding="utf-8")
        with self.assertRaisesRegex(
            protocol_mirror.MirrorError,
            "exact clean repository-verified commit",
        ):
            protocol_mirror.check(self.root, require_published=True)

    def test_supplied_authoritative_source_must_match(self) -> None:
        source_root = self.root / "source"
        shutil.copytree(
            self.root / protocol_mirror.MIRROR_RELATIVE_PATH,
            source_root,
        )
        protocol_mirror.check(self.root, source_root)
        fixture = source_root / "fixtures/agent_error_v2.json"
        fixture.write_text(
            fixture.read_text(encoding="utf-8").replace(
                "model_not_available", "different_error"
            ),
            encoding="utf-8",
        )

        with self.assertRaisesRegex(protocol_mirror.MirrorError, "supplied protocol source"):
            protocol_mirror.check(self.root, source_root)


if __name__ == "__main__":
    unittest.main()
