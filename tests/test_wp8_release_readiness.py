"""WP8 version, package, claim, candidate, and publication safeguards."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import ragleakguard


ROOT = Path(__file__).resolve().parents[1]
POLICY = json.loads(
    (ROOT / ".github" / "release" / "release-policy.json").read_text(
        encoding="utf-8"
    )
)
EXPECTED_VERSION = "0.1.1"
EXPECTED_ACTIONS = {
    "checkout": "11d5960a326750d5838078e36cf38b85af677262",
    "setup_python": "a26af69be951a213d495a4c3e4e4022e16d87065",
    "upload_artifact": "ea165f8d65b6e75b540449e92b4886f43607fa02",
    "download_artifact": "d3f86a106a0bac45b974a628896c90dbdf5c8093",
    "pypi_publish": "dc37677b2e1c63e2034f94d8a5b11f265b73ba33",
}


def _workflow(name):
    return (ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8")


def _action_refs(workflow):
    return re.findall(r"^\s*uses:\s*([^\s#]+)", workflow, re.MULTILINE)


def test_hatch_runtime_policy_notes_and_package_metadata_share_version():
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    project = pyproject.split("[project]", 1)[1].split("\n[", 1)[0]
    notes = (ROOT / "docs" / "releases" / "0.1.1.md").read_text(
        encoding="utf-8"
    )

    assert ragleakguard.__version__ == EXPECTED_VERSION
    assert POLICY["proposed_version"] == EXPECTED_VERSION
    assert 'dynamic = ["version"]' in project
    assert not re.search(r"^version\s*=", project, re.MULTILINE)
    assert '[tool.hatch.version]\npath = "src/ragleakguard/__init__.py"' in pyproject
    assert 'requires-python = ">=3.9,<3.13"' in pyproject
    assert 'requires = ["hatchling==1.27.0"]' in pyproject
    assert notes.startswith("# RAGLeakGuard 0.1.1 corrective release notes")
    assert "proposed corrective version; not published, tagged, or released" in notes


def test_finite_base_wp7c_and_unchanged_wp7d_matrices_are_exact():
    base = {
        (row["os"], row["platform"], row["python"])
        for row in POLICY["base_matrix"]
    }
    expected_base = {
        (os_name, platform, python)
        for os_name, platform in (
            ("ubuntu-24.04", "Linux-ext4"),
            ("macos-15", "macOS15-APFS"),
            ("windows-2025", "Windows-NTFS"),
        )
        for python in ("3.9", "3.10", "3.11", "3.12")
    }
    expected_wp7c = {
        (os_name, platform, python, chroma)
        for os_name, platform, python in (
            ("ubuntu-24.04", "Linux-ext4", "3.10"),
            ("ubuntu-24.04", "Linux-ext4", "3.11"),
            ("ubuntu-24.04", "Linux-ext4", "3.12"),
            ("macos-15", "macOS15-APFS", "3.12"),
            ("windows-2025", "Windows-NTFS", "3.12"),
        )
        for chroma in ("1.5.0", "1.5.9")
    }
    expected_wp7d = {
        ("ubuntu-24.04", "Linux-ext4", "3.10", "1.5.9"),
        ("ubuntu-24.04", "Linux-ext4", "3.11", "1.5.9"),
        ("ubuntu-24.04", "Linux-ext4", "3.12", "1.5.9"),
        ("macos-15", "macOS15-APFS", "3.12", "1.5.9"),
        ("windows-2025", "Windows-NTFS", "3.12", "1.5.9"),
    }
    wp7c = {
        (row["os"], row["platform"], row["python"], row["chroma"])
        for row in POLICY["wp7c_matrix"]
    }
    wp7d = {
        (row["os"], row["platform"], row["python"], row["chroma"])
        for row in POLICY["wp7d_matrix"]
    }

    assert POLICY["schema"] == 1
    assert POLICY["python_requires"] == ">=3.9,<3.13"
    assert POLICY["builder"] == {"os": "ubuntu-24.04", "python": "3.12.13"}
    assert POLICY["spacy_model"] == {
        "name": "en_core_web_sm",
        "version": "3.7.1",
        "url": (
            "https://github.com/explosion/spacy-models/releases/download/"
            "en_core_web_sm-3.7.1/en_core_web_sm-3.7.1-py3-none-any.whl"
        ),
        "sha256": "86cc141f63942d4b2c5fcee06630fd6f904788d2f0ab005cce45aadb8fb73889",
        "size": 12803381,
    }
    assert base == expected_base and len(POLICY["base_matrix"]) == 12
    assert wp7c == expected_wp7c and len(POLICY["wp7c_matrix"]) == 10
    assert wp7d == expected_wp7d and len(POLICY["wp7d_matrix"]) == 5
    assert POLICY["actions"] == EXPECTED_ACTIONS


def test_candidate_workflow_is_build_once_artifact_only_and_nonpublishing():
    workflow = _workflow("release-candidate.yml")
    refs = _action_refs(workflow)

    assert "pull_request:" in workflow and "workflow_dispatch:" in workflow
    assert workflow.count("python -m build --no-isolation --sdist --wheel") == 1
    assert "verify_candidate.py" in workflow
    assert "verify_installed.py" in workflow
    assert "install_spacy_model.py" in workflow
    assert "write_gate_manifest.py" in workflow
    assert "release-candidate-dist" in workflow
    assert "release-candidate-build-evidence" in workflow
    assert "release-candidate-evidence" in workflow
    assert "pip install -e" not in workflow
    assert "id-token" not in workflow
    assert "gh-action-pypi-publish" not in workflow
    assert "twine upload" not in workflow
    assert "repository-url" not in workflow
    assert "contents: read" in workflow
    assert "publication_authorized" in (
        ROOT / ".github" / "release" / "write_gate_manifest.py"
    ).read_text(encoding="utf-8")
    assert refs and all(re.search(r"@[0-9a-f]{40}$", ref) for ref in refs)


def test_candidate_gate_depends_on_every_required_artifact_and_matrix_job():
    workflow = _workflow("release-candidate.yml")
    gate = workflow.split("\n  candidate-gate:", 1)[1]
    needs = gate.split("\n    runs-on:", 1)[0]
    for job in (
        "policy",
        "build-candidate",
        "artifact-install",
        "base-artifact-matrix",
        "wp7c-artifact-matrix",
        "wp7d-artifact-matrix",
    ):
        assert f"- {job}" in needs


def test_publication_workflow_is_manual_no_rebuild_and_oidc_isolated():
    workflow = _workflow("publish-pypi.yml")
    refs = _action_refs(workflow)
    trigger = workflow.split("permissions:", 1)[0]
    validation = workflow.split("  validate-reviewed-artifacts:", 1)[1].split(
        "\n  publish-pypi:", 1
    )[0]
    publish = workflow.split("\n  publish-pypi:", 1)[1]

    assert "workflow_dispatch:" in trigger
    assert not any(
        forbidden in trigger
        for forbidden in ("pull_request:", "push:", "release:", "schedule:")
    )
    assert "python -m build" not in workflow
    assert "hatch build" not in workflow
    assert "pip install" not in workflow
    assert "verify_publication.py" in validation
    assert "verify_environment.py" in validation
    assert "environment:\n      name: pypi" in publish
    assert "id-token: write" not in validation
    assert publish.count("id-token: write") == 1
    assert "username:" not in publish and "password:" not in publish
    assert "TEST_PYPI" not in workflow.upper() and "test.pypi.org" not in workflow
    assert "repository-url:" not in publish
    assert "skip-existing: false" in publish
    assert "pypa/gh-action-pypi-publish@" + EXPECTED_ACTIONS["pypi_publish"] in publish
    assert refs and all(re.search(r"@[0-9a-f]{40}$", ref) for ref in refs)


def test_archive_policy_is_allowlisted_and_scans_recursive_canaries():
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    sdist = pyproject.split("[tool.hatch.build.targets.sdist]", 1)[1]
    verifier = (ROOT / ".github" / "release" / "verify_candidate.py").read_text(
        encoding="utf-8"
    )

    for required in (
        '"/src/ragleakguard"',
        '"/README.md"',
        '"/README.zh-TW.md"',
        '"/SECURITY.md"',
        '"/LICENSE"',
        '"/pyproject.toml"',
        '"/docs/releases/0.1.1.md"',
    ):
        assert required in sdist
    assert "exclude" not in sdist
    for forbidden in ('"/tests"', '"/reports"', '"/scripts"', '"/.github"'):
        assert forbidden not in sdist
    for canary in (
        "document-text-canary",
        "detected-value-canary",
        "record-id-canary",
        "tenant-canary",
        "secret-token-canary",
    ):
        assert canary in verifier
    assert "CREDENTIAL_PATTERNS" in verifier
    assert "ABSOLUTE_PATH_PATTERNS" in verifier
    assert "set(files) != expected" in verifier
    assert "Metadata.from_email(data, validate=True)" in verifier


def test_release_test_inputs_are_exact_and_python_39_compatible():
    constraints = (
        ROOT / ".github" / "release" / "test-constraints.txt"
    ).read_text(encoding="utf-8")
    requirements = {
        line.strip()
        for line in constraints.splitlines()
        if line.strip() and not line.startswith("#")
    }
    assert requirements == {
        "pip==25.2",
        "typer==0.20.0",
        "rich==14.1.0",
        "pytest==8.4.2",
        "faker==37.8.0",
        "presidio-analyzer==2.2.359",
        "presidio-anonymizer==2.2.359",
        "spacy==3.7.5",
        "numpy==1.26.4",
    }


def test_incomplete_build_evidence_cannot_emit_candidate_success(tmp_path):
    build = tmp_path / "build.json"
    output = tmp_path / "gate.json"
    build.write_text(
        json.dumps({"schema": 1, "status": "build-failed"}), encoding="utf-8"
    )
    environment = os.environ.copy()
    environment.update(
        {
            "RLG_SOURCE_SHA": "0" * 40,
            "GITHUB_RUN_ID": "123",
            "GITHUB_REPOSITORY": "Agenvana/RAGLeakGuard",
            "GITHUB_SERVER_URL": "https://github.com",
        }
    )
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / ".github" / "release" / "write_gate_manifest.py"),
            "--build-evidence",
            str(build),
            "--output",
            str(output),
        ],
        capture_output=True,
        text=True,
        env=environment,
        timeout=30,
    )

    assert result.returncode != 0
    assert not output.exists()


def test_publication_environment_must_preexist_with_required_reviewers(tmp_path):
    response = tmp_path / "environment.json"
    verifier = ROOT / ".github" / "release" / "verify_environment.py"
    response.write_text(
        json.dumps({"name": "pypi", "protection_rules": []}), encoding="utf-8"
    )
    rejected = subprocess.run(
        [sys.executable, str(verifier), "--response", str(response)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert rejected.returncode != 0

    response.write_text(
        json.dumps(
            {
                "name": "pypi",
                "protection_rules": [
                    {
                        "type": "required_reviewers",
                        "reviewers": [{"type": "User", "reviewer": {"id": 1}}],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    accepted = subprocess.run(
        [sys.executable, str(verifier), "--response", str(response)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert accepted.returncode == 0


def test_canonical_claim_surfaces_distinguish_proposed_and_published_versions():
    surfaces = (
        ROOT / "README.md",
        ROOT / "README.zh-TW.md",
        ROOT / "SECURITY.md",
        ROOT / "CONTRIBUTING.md",
        ROOT / "ROADMAP.md",
        ROOT / "docs" / "ARCHITECTURE.md",
        ROOT / "docs" / "THREAT_MODEL.md",
        ROOT / "docs" / "RELEASE_PROCESS.md",
        ROOT / "docs" / "releases" / "0.1.1.md",
    )
    combined = "\n".join(path.read_text(encoding="utf-8") for path in surfaces)

    for exact in (
        "0.1.1",
        ">=3.9,<3.13",
        "Ubuntu 24.04",
        "macOS 15",
        "Windows Server 2025",
        "protected `pypi` environment",
        "Trusted Publishing",
        "not published",
    ):
        assert exact in combined
    assert "PyPI `0.1.0`" in combined
    assert "must not be used" in combined
    assert "不得用於 Chroma 掃描" in combined
