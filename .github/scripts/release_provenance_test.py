import contextlib
import importlib.util
import io
import os
import re
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).with_name("release_provenance.py")
WORKFLOW_PATH = MODULE_PATH.parent.parent / "workflows/codex-plugin-release.yml"
SPEC = importlib.util.spec_from_file_location("release_provenance", MODULE_PATH)
assert SPEC and SPEC.loader
release_provenance = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release_provenance)


class ReleaseProvenanceTest(unittest.TestCase):
    @staticmethod
    def valid_environment(wait_timer: int = 0):
        return {
            "can_admins_bypass": False,
            "protection_rules": [
                {
                    "id": 2,
                    "node_id": "wait-rule-node",
                    "type": "wait_timer",
                    "wait_timer": wait_timer,
                },
                {
                    "id": 3,
                    "node_id": "branch-rule-node",
                    "type": "branch_policy",
                },
            ],
            "deployment_branch_policy": {
                "protected_branches": False,
                "custom_branch_policies": True,
            },
        }

    @staticmethod
    def valid_policies():
        return {
            "total_count": 3,
            "branch_policies": [
                {"id": 11, "node_id": "stage", "name": "stage", "type": "branch"},
                {"id": 12, "node_id": "main", "name": "main", "type": "branch"},
                {"id": 13, "node_id": "tag", "name": "v*", "type": "tag"},
            ],
        }

    def test_workflow_is_keyless_and_has_no_apple_or_review_gate(self) -> None:
        workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
        uses = re.findall(r"^\s*-?\s*uses:\s*([^\s#]+)", workflow, re.MULTILINE)
        self.assertTrue(uses)
        for action in uses:
            self.assertRegex(action, r"^[^@]+@[0-9a-f]{40}$")
        for forbidden in (
            "production-native:",
            "platform-signed",
            "require-platform-signatures",
            "MACOS_CERTIFICATE",
            "MACOS_SIGNING_IDENTITY",
            "APPLE_ID",
            "APPLE_TEAM_ID",
            "notarytool",
            "codesign",
            "required_reviewers",
            "pulls/{number}/reviews",
            "sigstore/cosign-installer",
        ):
            self.assertNotIn(forbidden, workflow)
        self.assertEqual(
            workflow.count("run: bash .github/scripts/install-cosign.sh"), 3
        )
        cosign_installer = (MODULE_PATH.parent / "install-cosign.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn('cosign_version="3.1.2"', cosign_installer)
        self.assertIn(
            'cosign_sha256="f7622ed3cf22e55e1ae6377c080979ff77a22da9981c11df222a2e444991e7cf"',
            cosign_installer,
        )
        self.assertIn("--proto '=https' --tlsv1.2", cosign_installer)
        self.assertLess(
            cosign_installer.index("sha256sum -c -"),
            cosign_installer.index('printf \'%s\\n\' "$install_dir" >>'),
        )
        signing = workflow[
            workflow.index("\n  sign-release-archive:") : workflow.index("\n  publish-marketplace:")
        ]
        self.assertIn("id-token: write", signing)
        self.assertIn("cosign sign-blob", signing)
        self.assertIn("cosign verify-blob", signing)
        self.assertIn("name: codex-plugin-production", signing)
        publish_marketplace = workflow[
            workflow.index("\n  publish-marketplace:") : workflow.index("\n  publish-release-assets:")
        ]
        publish_assets = workflow[workflow.index("\n  publish-release-assets:") :]
        self.assertIn("name: codex-plugin-production", publish_marketplace)
        self.assertIn("name: codex-plugin-production", publish_assets)
        self.assertIn("unsigned-platform", workflow)
        self.assertIn("unsigned-release", workflow)

    def test_environment_accepts_no_reviewer_rule_and_exact_policies(self) -> None:
        for wait in (0, 43_200):
            with mock.patch.object(
                release_provenance,
                "api_get",
                side_effect=[self.valid_environment(wait), self.valid_policies()],
            ):
                release_provenance.verify_environment()

    def test_environment_rejects_required_reviewer_rule(self) -> None:
        environment = self.valid_environment()
        environment["protection_rules"].append(
            {
                "id": 4,
                "node_id": "review",
                "type": "required_reviewers",
                "prevent_self_review": True,
                "reviewers": [{"type": "User", "reviewer": {"id": 1}}],
            }
        )
        with mock.patch.object(release_provenance, "api_get", return_value=environment):
            with self.assertRaisesRegex(SystemExit, "unsupported type"):
                release_provenance.verify_environment()

    def test_environment_rejects_weakened_branch_policy(self) -> None:
        policies = self.valid_policies()
        policies["branch_policies"][2]["name"] = "*"
        with mock.patch.object(
            release_provenance,
            "api_get",
            side_effect=[self.valid_environment(), policies],
        ):
            with self.assertRaisesRegex(SystemExit, "exclusively allow"):
                release_provenance.verify_environment()

    def test_environment_rejects_admin_bypass_and_missing_branch_rule(self) -> None:
        environment = self.valid_environment()
        environment["can_admins_bypass"] = True
        with mock.patch.object(release_provenance, "api_get", return_value=environment):
            with self.assertRaisesRegex(SystemExit, "disable administrator"):
                release_provenance.verify_environment()
        environment = self.valid_environment()
        environment["protection_rules"] = environment["protection_rules"][:1]
        with mock.patch.object(release_provenance, "api_get", return_value=environment):
            with self.assertRaisesRegex(SystemExit, "exactly one branch-policy"):
                release_provenance.verify_environment()

    def test_main_accepts_exact_standard_merge_without_review_api(self) -> None:
        release_sha = "1" * 40
        head_sha = "2" * 40
        parent = "3" * 40
        paths: list[str] = []

        def api(path: str):
            paths.append(path)
            if path == "environments/codex-plugin-production":
                return self.valid_environment()
            if path.startswith("environments/codex-plugin-production/deployment-branch-policies"):
                return self.valid_policies()
            if path.startswith(f"commits/{release_sha}/pulls"):
                return [{
                    "number": 42,
                    "merged_at": "2026-07-21T00:00:00Z",
                    "merge_commit_sha": release_sha,
                    "base": {"ref": "main"},
                    "head": {"sha": head_sha},
                    "user": {"login": "author"},
                }]
            if path == f"compare/{release_sha}...main":
                return {
                    "status": "identical",
                    "base_commit": {"sha": release_sha},
                    "merge_base_commit": {"sha": release_sha},
                }
            self.fail(f"unexpected API call: {path}")

        def git(*args: str):
            if args[0] == "rev-list":
                return f"{release_sha} {parent} {head_sha}"
            if args[0] == "show":
                return "Merge pull request #42 from loomex-app/feature/codex-plugin"
            self.fail(f"unexpected git call: {args}")

        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, {"RELEASE_SHA": release_sha}, clear=False), mock.patch.object(
            release_provenance, "api_get", side_effect=api
        ), mock.patch.object(release_provenance, "git", side_effect=git), contextlib.redirect_stdout(
            stdout
        ), contextlib.redirect_stderr(stderr):
            release_provenance.main()

        self.assertNotIn("/reviews", "\n".join(paths))
        self.assertEqual(
            stdout.getvalue().splitlines(),
            [
                "release-mode=true",
                f"release-sha={release_sha}",
                "release-base=main",
                "release-pr=42",
            ],
        )
        self.assertIn("as standard merge of PR #42 into main", stderr.getvalue())

    def test_main_rejects_non_merge_commit_before_api_access(self) -> None:
        release_sha = "1" * 40
        with mock.patch.dict(os.environ, {"RELEASE_SHA": release_sha}, clear=False), mock.patch.object(
            release_provenance, "git", return_value=f"{release_sha} {'2' * 40}"
        ), mock.patch.object(release_provenance, "api_get") as api:
            with self.assertRaisesRegex(SystemExit, "not a two-parent merge commit"):
                release_provenance.main()
        api.assert_not_called()

    def test_comparison_requires_exact_ancestry_evidence(self) -> None:
        sha = "1" * 40
        self.assertTrue(
            release_provenance.comparison_contains_release(
                {"status": "ahead", "base_commit": {"sha": sha}, "merge_base_commit": {"sha": sha}}, sha
            )
        )
        self.assertFalse(
            release_provenance.comparison_contains_release(
                {"status": "behind", "base_commit": {"sha": sha}, "merge_base_commit": {"sha": sha}}, sha
            )
        )


if __name__ == "__main__":
    unittest.main()
