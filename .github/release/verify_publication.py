"""Validate reviewed bytes, evidence, tag, and commit without rebuilding."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path


def _git(*arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return result.stdout.strip()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dist", type=Path, required=True)
    parser.add_argument("--build-evidence", type=Path, required=True)
    parser.add_argument("--gate-evidence", type=Path, required=True)
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--expected-tag", required=True)
    parser.add_argument("--wheel-sha256", required=True)
    parser.add_argument("--sdist-sha256", required=True)
    parser.add_argument("--candidate-run-id", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--server-url", required=True)
    parser.add_argument("--workflow-ref", required=True)
    parser.add_argument("--workflow-sha", required=True)
    parser.add_argument("--policy-dir", type=Path, default=Path(".github/release"))
    args = parser.parse_args()

    policy = json.loads(
        (args.policy_dir / "release-policy.json").read_text(encoding="utf-8")
    )
    publication = policy.get("publication")
    if not isinstance(publication, dict):
        raise RuntimeError("publication policy is absent")
    trusted_publisher = publication.get("trusted_publisher")
    if trusted_publisher != {
        "repository": "Agenvana/RAGLeakGuard",
        "workflow": "publish-pypi.yml",
        "environment": "pypi",
    }:
        raise RuntimeError("trusted publisher tuple differs")

    if not re.fullmatch(r"[0-9a-f]{40}", args.expected_commit):
        raise RuntimeError("expected commit must be a full lowercase SHA-1")
    if args.expected_version != "0.1.1" or args.expected_tag != "v0.1.1":
        raise RuntimeError("only exact proposed version 0.1.1 is permitted")
    if not re.fullmatch(r"[0-9a-f]{64}", args.wheel_sha256):
        raise RuntimeError("wheel hash must be a full lowercase SHA-256")
    if not re.fullmatch(r"[0-9a-f]{64}", args.sdist_sha256):
        raise RuntimeError("sdist hash must be a full lowercase SHA-256")
    if not re.fullmatch(r"[1-9][0-9]*", args.candidate_run_id):
        raise RuntimeError("candidate run ID must be a positive decimal integer")
    if args.repository != trusted_publisher["repository"]:
        raise RuntimeError("publication repository differs")
    if args.server_url != "https://github.com":
        raise RuntimeError("publication server differs")
    expected_workflow_ref = (
        f"{args.repository}/{publication['workflow_path']}"
        f"@{publication['workflow_ref']}"
    )
    if args.workflow_ref != expected_workflow_ref:
        raise RuntimeError("publication workflow ref differs")
    if args.workflow_sha != args.expected_commit:
        raise RuntimeError("publication workflow commit differs")
    if _git("rev-parse", "HEAD") != args.expected_commit:
        raise RuntimeError("checked-out commit differs")
    tag_ref = f"refs/tags/{args.expected_tag}"
    if _git("cat-file", "-t", tag_ref) != "tag":
        raise RuntimeError("an annotated exact tag is required")
    if _git("rev-parse", f"{tag_ref}^{{commit}}") != args.expected_commit:
        raise RuntimeError("tag does not identify the reviewed commit")

    build = json.loads(args.build_evidence.read_text(encoding="utf-8"))
    gate = json.loads(args.gate_evidence.read_text(encoding="utf-8"))
    for document, status in (
        (build, "build-verified"),
        (gate, "ready-for-independent-review"),
    ):
        if document.get("schema") != 1 or document.get("status") != status:
            raise RuntimeError("candidate evidence is incomplete")
        if document.get("version") != args.expected_version:
            raise RuntimeError("candidate evidence version differs")
        if document.get("source_sha") != args.expected_commit:
            raise RuntimeError("candidate evidence commit differs")
    if gate.get("publication_authorized") is not False:
        raise RuntimeError("candidate evidence publication field differs")
    expected_run = f"{args.server_url}/{args.repository}/actions/runs/{args.candidate_run_id}"
    if gate.get("candidate_run") != expected_run:
        raise RuntimeError("gate evidence belongs to a different workflow run")
    expected_gates = {
        "artifact_install_wheel": "passed",
        "artifact_install_sdist": "passed",
        "base_matrix": "passed",
        "build_and_archive_inspection": "passed",
        "wp7c_private_matrix": "passed",
        "wp7d_public_matrix": "passed",
    }
    if gate.get("gates") != expected_gates:
        raise RuntimeError("candidate gate results are incomplete")

    material_paths = {
        "build_requirements_sha256": args.policy_dir / "build-requirements.txt",
        "release_policy_sha256": args.policy_dir / "release-policy.json",
        "test_constraints_sha256": args.policy_dir / "test-constraints.txt",
    }
    expected_materials = {name: _sha256(path) for name, path in material_paths.items()}
    if build.get("materials") != expected_materials:
        raise RuntimeError("candidate release inputs differ from the reviewed commit")

    wheel = args.dist / "ragleakguard-0.1.1-py3-none-any.whl"
    sdist = args.dist / "ragleakguard-0.1.1.tar.gz"
    if sorted(path.name for path in args.dist.iterdir() if path.is_file()) != sorted(
        (wheel.name, sdist.name)
    ):
        raise RuntimeError("publish directory contains unexpected files")
    observed = {wheel.name: _sha256(wheel), sdist.name: _sha256(sdist)}
    expected = {wheel.name: args.wheel_sha256, sdist.name: args.sdist_sha256}
    if observed != expected:
        raise RuntimeError("artifact input hashes differ")
    recorded = {item["filename"]: item["sha256"] for item in build["artifacts"]}
    if recorded != expected:
        raise RuntimeError("build evidence hashes differ")
    gate_recorded = {item["filename"]: item["sha256"] for item in gate["artifacts"]}
    if gate_recorded != expected:
        raise RuntimeError("gate evidence hashes differ")
    print("Exact reviewed artifacts, evidence, tag, commit, version, and hashes validated.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
