#!/usr/bin/env python3
"""Fail-closed production release provenance verification."""

from __future__ import annotations

import json
import os
import re
import subprocess
import urllib.parse
import urllib.request
from collections.abc import Callable
from typing import Any


PAGE_SIZE = 100
ENVIRONMENT_NAME = "codex-plugin-production"
DOCUMENTED_RULE_TYPES = {"wait_timer", "branch_policy"}
RULE_VARIANT_FIELDS = {"wait_timer"}
REQUIRED_DEPLOYMENT_POLICIES = {
    ("stage", "branch"),
    ("main", "branch"),
    ("v*", "tag"),
}


def api_get(path: str) -> Any:
    repository = os.environ["GITHUB_REPOSITORY"]
    token = os.environ["GH_TOKEN"]
    request = urllib.request.Request(
        f"https://api.github.com/repos/{repository}/{path}",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(request) as response:
        return json.load(response)


def paginated_list(
    get_page: Callable[[str], Any], path: str
) -> list[dict[str, Any]]:
    """Read every page from a GitHub list endpoint without trusting Link parsing."""
    values: list[dict[str, Any]] = []
    page = 1
    separator = "&" if "?" in path else "?"
    while True:
        batch = get_page(
            f"{path}{separator}per_page={PAGE_SIZE}&page={page}"
        )
        if not isinstance(batch, list):
            raise SystemExit(f"GitHub API did not return a list for {path}")
        values.extend(batch)
        if len(batch) < PAGE_SIZE:
            return values
        page += 1


def paginated_branch_policies(
    get_page: Callable[[str], Any], path: str
) -> list[dict[str, Any]]:
    """Read an object-wrapped policy collection until total_count is satisfied."""
    policies: list[dict[str, Any]] = []
    expected_total: int | None = None
    page = 1
    separator = "&" if "?" in path else "?"
    while True:
        response = get_page(
            f"{path}{separator}per_page={PAGE_SIZE}&page={page}"
        )
        if not isinstance(response, dict):
            raise SystemExit("branch policy API response must be an object")
        total_count = response.get("total_count")
        batch = response.get("branch_policies")
        if (
            isinstance(total_count, bool)
            or not isinstance(total_count, int)
            or total_count < 0
        ):
            raise SystemExit("branch policy total_count must be a non-negative integer")
        if expected_total is None:
            expected_total = total_count
        elif total_count != expected_total:
            raise SystemExit("branch policy total_count changed between pages")
        if not isinstance(batch, list):
            raise SystemExit("branch_policies must be a list")
        if len(batch) > PAGE_SIZE:
            raise SystemExit("branch policy page exceeds requested page size")
        policies.extend(batch)
        if len(policies) > expected_total:
            raise SystemExit("branch policy pages exceed total_count")
        if len(policies) == expected_total:
            return policies
        if not batch or len(batch) < PAGE_SIZE:
            raise SystemExit("branch policy pages ended before total_count")
        page += 1


def comparison_contains_release(
    comparison: dict[str, Any], release_sha: str
) -> bool:
    """Return whether GitHub proves release_sha is an ancestor of the head ref."""
    base_commit = comparison.get("base_commit") or {}
    merge_base = comparison.get("merge_base_commit") or {}
    return (
        comparison.get("status") in {"ahead", "identical"}
        and base_commit.get("sha") == release_sha
        and merge_base.get("sha") == release_sha
    )


def require_positive_int(value: Any, description: str) -> int:
    """Return a JSON integer identifier, rejecting booleans and non-positive IDs."""
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise SystemExit(f"{description} must be a positive integer")
    return value


def require_nonempty_string(value: Any, description: str) -> str:
    """Return a non-empty JSON string without normalizing API evidence."""
    if not isinstance(value, str) or not value:
        raise SystemExit(f"{description} must be a non-empty string")
    return value


def validate_protection_rule(rule: dict[str, Any]) -> str:
    """Validate the complete documented shape of one environment rule."""
    rule_type = rule.get("type")
    if rule_type not in DOCUMENTED_RULE_TYPES:
        raise SystemExit(
            f"{ENVIRONMENT_NAME} protection rules contain a missing or unsupported type"
        )
    require_positive_int(rule.get("id"), f"{ENVIRONMENT_NAME} protection rule id")
    require_nonempty_string(
        rule.get("node_id"), f"{ENVIRONMENT_NAME} protection rule node_id"
    )

    permitted_variant_fields = {
        "wait_timer": {"wait_timer"},
        "branch_policy": set(),
    }[rule_type]
    disallowed = (RULE_VARIANT_FIELDS - permitted_variant_fields).intersection(rule)
    if disallowed:
        fields = ", ".join(sorted(disallowed))
        raise SystemExit(
            f"{ENVIRONMENT_NAME} {rule_type} rule contains fields from another "
            f"rule variant: {fields}"
        )

    if rule_type == "wait_timer":
        wait_timer = rule.get("wait_timer")
        if (
            isinstance(wait_timer, bool)
            or not isinstance(wait_timer, int)
            or not 0 <= wait_timer <= 43_200
        ):
            raise SystemExit(
                f"{ENVIRONMENT_NAME} wait_timer must be an integer from 0 to 43200"
            )
    return rule_type


def git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], text=True, capture_output=True, check=True
    ).stdout.strip()


def verify_environment() -> None:
    environment_name = ENVIRONMENT_NAME
    encoded_environment = urllib.parse.quote(environment_name, safe="")
    environment = api_get(f"environments/{encoded_environment}")
    if not isinstance(environment, dict):
        raise SystemExit(f"{environment_name} API response must be an object")
    if environment.get("can_admins_bypass") is not False:
        raise SystemExit(
            f"{environment_name} must disable administrator protection bypass"
        )
    protection_rules = environment.get("protection_rules")
    if not isinstance(protection_rules, list):
        raise SystemExit(
            f"{environment_name} protection_rules must be a list"
        )
    if not all(isinstance(rule, dict) for rule in protection_rules):
        raise SystemExit(
            f"{environment_name} protection rules must be objects"
        )
    rule_types = [validate_protection_rule(rule) for rule in protection_rules]
    rule_ids = [rule["id"] for rule in protection_rules]
    rule_node_ids = [rule["node_id"] for rule in protection_rules]
    if len(set(rule_ids)) != len(rule_ids) or len(set(rule_node_ids)) != len(
        rule_node_ids
    ):
        raise SystemExit(f"{environment_name} protection rules must be unique")
    for rule_type in DOCUMENTED_RULE_TYPES:
        if rule_types.count(rule_type) > 1:
            raise SystemExit(
                f"{environment_name} must not have duplicate {rule_type} rules"
            )
    deployment_policy = environment.get("deployment_branch_policy")
    if not isinstance(deployment_policy, dict):
        raise SystemExit(
            f"{environment_name} deployment_branch_policy must be an object"
        )
    if (
        deployment_policy.get("protected_branches") is not False
        or deployment_policy.get("custom_branch_policies") is not True
    ):
        raise SystemExit(
            f"{environment_name} must use custom branch and tag deployment policies"
        )
    branch_rules = [
        rule for rule in protection_rules if rule["type"] == "branch_policy"
    ]
    if len(branch_rules) != 1:
        raise SystemExit(
            f"{environment_name} must have exactly one branch-policy rule when "
            "custom branch policies are enabled"
        )
    policies = paginated_branch_policies(
        api_get,
        f"environments/{encoded_environment}/deployment-branch-policies",
    )
    if not all(isinstance(policy, dict) for policy in policies):
        raise SystemExit(
            f"{environment_name} branch policies must be objects"
        )
    policy_ids: set[int] = set()
    policy_node_ids: set[str] = set()
    configured_policies: list[tuple[str, str]] = []
    for policy in policies:
        policy_id = require_positive_int(
            policy.get("id"), f"{environment_name} branch policy id"
        )
        node_id = require_nonempty_string(
            policy.get("node_id"), f"{environment_name} branch policy node_id"
        )
        name = require_nonempty_string(
            policy.get("name"), f"{environment_name} branch policy name"
        )
        policy_type = policy.get("type")
        if policy_type not in {"branch", "tag"}:
            raise SystemExit(
                f"{environment_name} branch policy type must be branch or tag"
            )
        policy_tuple = (name, policy_type)
        if (
            policy_id in policy_ids
            or node_id in policy_node_ids
            or policy_tuple in configured_policies
        ):
            raise SystemExit(f"{environment_name} branch policies must be unique")
        policy_ids.add(policy_id)
        policy_node_ids.add(node_id)
        configured_policies.append(policy_tuple)
    if set(configured_policies) != REQUIRED_DEPLOYMENT_POLICIES:
        raise SystemExit(
            f"{environment_name} must exclusively allow branch policies "
            "stage/main and tag policy v*"
        )


def main() -> None:
    sha = os.environ["RELEASE_SHA"]
    parents = git("rev-list", "--parents", "-n", "1", sha).split()
    if len(parents) != 3:
        raise SystemExit(
            f"production release commit {sha} is not a two-parent merge commit"
        )

    verify_environment()
    pulls = paginated_list(api_get, f"commits/{sha}/pulls")
    candidates = [
        pull
        for pull in pulls
        if pull.get("merged_at")
        and pull.get("merge_commit_sha") == sha
        and pull.get("base", {}).get("ref") in {"stage", "main"}
    ]
    if len(candidates) != 1:
        raise SystemExit(
            "release commit must be the exact merge_commit_sha of one merged "
            "GitHub PR targeting stage or main"
        )

    pull = candidates[0]
    base = pull["base"]["ref"]
    number = pull["number"]
    head_sha = pull.get("head", {}).get("sha")
    if not isinstance(head_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", head_sha):
        raise SystemExit(f"PR #{number} does not expose a valid head SHA")
    if parents[2] != head_sha:
        raise SystemExit(
            f"release merge second parent {parents[2]} does not equal PR head {head_sha}"
        )
    encoded_base = urllib.parse.quote(base, safe="")
    comparison = api_get(f"compare/{sha}...{encoded_base}")
    if not comparison_contains_release(comparison, sha):
        raise SystemExit(f"release commit is not reachable from origin/{base}")

    subject = git("show", "-s", "--format=%s", sha)
    expected = re.compile(rf"^Merge pull request #{number} from .+")
    if not expected.fullmatch(subject):
        raise SystemExit(
            "release commit is not a standard GitHub PR merge commit: " + subject
        )

    print("release-mode=true")
    print(f"release-sha={sha}")
    print(f"release-base={base}")
    print(f"release-pr={number}")
    print(
        f"verified {sha} as standard merge of PR #{number} into {base}",
        file=os.sys.stderr,
    )


if __name__ == "__main__":
    main()
