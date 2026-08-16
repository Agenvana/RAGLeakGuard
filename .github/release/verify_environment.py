"""Require the exact protected GitHub environment contract for publication."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--response", type=Path, required=True)
    parser.add_argument("--branch-policies", type=Path, required=True)
    parser.add_argument(
        "--policy",
        type=Path,
        default=Path(".github/release/release-policy.json"),
    )
    args = parser.parse_args()
    document = json.loads(args.response.read_text(encoding="utf-8"))
    branch_document = json.loads(
        args.branch_policies.read_text(encoding="utf-8")
    )
    policy = json.loads(args.policy.read_text(encoding="utf-8"))
    publication = policy.get("publication")
    if not isinstance(publication, dict):
        raise RuntimeError("publication policy is absent")
    trusted_publisher = publication.get("trusted_publisher")
    deployment_policy = publication.get("deployment_branch_policy")
    if not isinstance(trusted_publisher, dict) or not isinstance(
        deployment_policy, dict
    ):
        raise RuntimeError("publication environment policy is incomplete")

    expected_environment = trusted_publisher.get("environment")
    if document.get("name") != expected_environment or expected_environment != "pypi":
        raise RuntimeError("the protected pypi environment is absent")
    rules = document.get("protection_rules")
    if not isinstance(rules, list):
        raise RuntimeError("environment protection evidence is absent")
    reviewer_rules = [rule for rule in rules if rule.get("type") == "required_reviewers"]
    if len(reviewer_rules) != 1:
        raise RuntimeError("the pypi environment lacks required reviewers")
    reviewer_rule = reviewer_rules[0]
    reviewers = reviewer_rule.get("reviewers")
    if not isinstance(reviewers, list) or not reviewers:
        raise RuntimeError("the pypi environment lacks required reviewers")
    if publication.get("prevent_self_review") is not True:
        raise RuntimeError("publication policy does not require reviewer separation")
    if reviewer_rule.get("prevent_self_review") is not True:
        raise RuntimeError("the pypi environment permits dispatcher self-review")
    for reviewer in reviewers:
        if reviewer.get("type") not in {"User", "Team"} or not isinstance(
            reviewer.get("reviewer"), dict
        ):
            raise RuntimeError("environment reviewer evidence is malformed")

    branch_rules = [rule for rule in rules if rule.get("type") == "branch_policy"]
    if len(branch_rules) != 1:
        raise RuntimeError("the pypi environment lacks a deployment branch policy")
    observed_policy = document.get("deployment_branch_policy")
    expected_policy = {
        "protected_branches": deployment_policy.get("protected_branches"),
        "custom_branch_policies": deployment_policy.get(
            "custom_branch_policies"
        ),
    }
    if expected_policy != {
        "protected_branches": False,
        "custom_branch_policies": True,
    }:
        raise RuntimeError("release policy does not require selected tags")
    if observed_policy != expected_policy:
        raise RuntimeError("environment deployment policy differs")

    policies = branch_document.get("branch_policies")
    if branch_document.get("total_count") != 1 or not isinstance(policies, list):
        raise RuntimeError("deployment tag policy evidence is incomplete")
    if len(policies) != 1:
        raise RuntimeError("the pypi environment must allow one exact tag only")
    required = deployment_policy.get("required_policy")
    if not isinstance(required, dict):
        raise RuntimeError("required deployment tag policy is absent")
    observed = {"name": policies[0].get("name"), "type": policies[0].get("type")}
    if observed != required or required != {"name": "v0.1.1", "type": "tag"}:
        raise RuntimeError("the pypi environment does not allow only exact tag v0.1.1")

    print("Exact protected pypi environment contract verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
