"""Require an existing protected GitHub environment before a publish job can start."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--response", type=Path, required=True)
    args = parser.parse_args()
    document = json.loads(args.response.read_text(encoding="utf-8"))
    if document.get("name") != "pypi":
        raise RuntimeError("the protected pypi environment is absent")
    rules = document.get("protection_rules")
    if not isinstance(rules, list):
        raise RuntimeError("environment protection evidence is absent")
    reviewer_rules = [rule for rule in rules if rule.get("type") == "required_reviewers"]
    if len(reviewer_rules) != 1 or not reviewer_rules[0].get("reviewers"):
        raise RuntimeError("the pypi environment lacks required reviewers")
    print("Existing protected pypi environment verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
