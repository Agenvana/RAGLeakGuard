"""WP8 version, package, claim, candidate, and publication safeguards."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest
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


def _run_scripts(workflow):
    lines = workflow.splitlines()
    scripts = []
    for index, line in enumerate(lines):
        match = re.match(r"^(\s*)run:\s*(.*)$", line)
        if match is None:
            continue
        indent = len(match.group(1))
        block = [match.group(2)]
        for following in lines[index + 1 :]:
            if following.strip() and len(following) - len(following.lstrip()) <= indent:
                break
            block.append(following)
        scripts.append("\n".join(block))
    return scripts


def _dispatch_validator_code():
    workflow = _workflow("publish-pypi.yml")
    marker = "          python - <<'PY'\n"
    start = workflow.index(marker) + len(marker)
    end = workflow.index("\n          PY", start)
    return textwrap.dedent(workflow[start:end])


def _valid_dispatch_environment(output):
    commit = "a" * 40
    return {
        **os.environ,
        "GITHUB_OUTPUT": str(output),
        "RLG_INPUT_CANDIDATE_RUN_ID": "123",
        "RLG_INPUT_EXPECTED_COMMIT": commit,
        "RLG_INPUT_EXPECTED_TAG": "v0.1.1",
        "RLG_INPUT_EXPECTED_VERSION": "0.1.1",
        "RLG_INPUT_WHEEL_SHA256": "b" * 64,
        "RLG_INPUT_SDIST_SHA256": "c" * 64,
        "RLG_INPUT_CONFIRMATION": "publish-reviewed-0.1.1-artifacts",
        "RLG_EVENT_NAME": "workflow_dispatch",
        "RLG_REPOSITORY": "Agenvana/RAGLeakGuard",
        "RLG_REF": "refs/tags/v0.1.1",
        "RLG_SHA": commit,
        "RLG_WORKFLOW_REF": (
            "Agenvana/RAGLeakGuard/.github/workflows/"
            "publish-pypi.yml@refs/tags/v0.1.1"
        ),
        "RLG_WORKFLOW_SHA": commit,
    }


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
    assert POLICY["publication"] == {
        "trusted_publisher": {
            "repository": "Agenvana/RAGLeakGuard",
            "workflow": "publish-pypi.yml",
            "environment": "pypi",
        },
        "workflow_ref": "refs/tags/v0.1.1",
        "workflow_path": ".github/workflows/publish-pypi.yml",
        "deployment_branch_policy": {
            "protected_branches": False,
            "custom_branch_policies": True,
            "required_policy": {"name": "v0.1.1", "type": "tag"},
        },
        "prevent_self_review": True,
        "can_admins_bypass": False,
    }


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
    assert "deployment-branch-policies" in validation
    assert "refs/tags/v0.1.1" in validation
    assert (
        "Agenvana/RAGLeakGuard/.github/workflows/"
        "publish-pypi.yml@refs/tags/v0.1.1"
    ) in validation
    assert workflow.index("Validate dispatch inputs") < workflow.index("actions/checkout@")
    assert workflow.index("Validate dispatch inputs") < workflow.index("download-artifact@")
    assert "environment:\n      name: pypi" in publish
    assert "id-token: write" not in validation
    assert publish.count("id-token: write") == 1
    assert "username:" not in publish and "password:" not in publish
    assert "TEST_PYPI" not in workflow.upper() and "test.pypi.org" not in workflow
    assert "repository-url:" not in publish
    assert "skip-existing: false" in publish
    assert "pypa/gh-action-pypi-publish@" + EXPECTED_ACTIONS["pypi_publish"] in publish
    assert refs and all(re.search(r"@[0-9a-f]{40}$", ref) for ref in refs)


def test_dispatch_inputs_are_never_interpolated_into_run_scripts():
    workflow = _workflow("publish-pypi.yml")
    for script in _run_scripts(workflow):
        assert "${{ inputs." not in script
    input_lines = [line for line in workflow.splitlines() if "${{ inputs." in line]
    assert len(input_lines) == 7
    assert all(
        re.fullmatch(
            r"\s+RLG_INPUT_[A-Z0-9_]+: \$\{\{ inputs\.[a-z0-9_]+ \}\}",
            line,
        )
        for line in input_lines
    )
    after_validation = workflow.split(
        "      - name: Check out the exact reviewed commit and tags", 1
    )[1]
    assert "${{ inputs." not in after_validation
    assert "needs.validate-reviewed-artifacts.outputs" in workflow


def test_dispatch_validator_accepts_only_exact_safe_values(tmp_path):
    output = tmp_path / "outputs.txt"
    result = subprocess.run(
        [sys.executable, "-c", _dispatch_validator_code()],
        cwd=tmp_path,
        env=_valid_dispatch_environment(output),
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr
    assert output.read_text(encoding="utf-8").splitlines() == [
        "candidate_run_id=123",
        f"expected_commit={'a' * 40}",
        "expected_tag=v0.1.1",
        "expected_version=0.1.1",
        f"wheel_sha256={'b' * 64}",
        f"sdist_sha256={'c' * 64}",
        "workflow_ref=refs/tags/v0.1.1",
        f"workflow_sha={'a' * 40}",
    ]


@pytest.mark.parametrize(
    ("field", "malicious"),
    (
        (
            "RLG_INPUT_CONFIRMATION",
            "publish-reviewed-0.1.1-artifacts; touch rlg-injection-canary",
        ),
        ("RLG_INPUT_EXPECTED_VERSION", "0.1.1$(touch rlg-injection-canary)"),
        ("RLG_INPUT_EXPECTED_TAG", "v0.1.1; touch rlg-injection-canary"),
        ("RLG_INPUT_EXPECTED_COMMIT", "a" * 39 + ";"),
        ("RLG_INPUT_EXPECTED_COMMIT", "A" * 40),
        ("RLG_INPUT_WHEEL_SHA256", "b" * 63 + ";"),
        ("RLG_INPUT_SDIST_SHA256", "$(touch rlg-injection-canary)"),
        ("RLG_INPUT_CANDIDATE_RUN_ID", "1; touch rlg-injection-canary"),
        ("RLG_INPUT_CANDIDATE_RUN_ID", "0"),
        ("RLG_INPUT_CANDIDATE_RUN_ID", "-1"),
        ("RLG_INPUT_CANDIDATE_RUN_ID", "01"),
        ("RLG_INPUT_CANDIDATE_RUN_ID", "not-a-run"),
        ("RLG_REF", "refs/heads/arbitrary-branch"),
        ("RLG_WORKFLOW_SHA", "d" * 40),
    ),
)
def test_dispatch_validator_rejects_malformed_or_injectable_values(
    tmp_path, field, malicious
):
    output = tmp_path / "outputs.txt"
    environment = _valid_dispatch_environment(output)
    environment[field] = malicious
    result = subprocess.run(
        [sys.executable, "-c", _dispatch_validator_code()],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode != 0
    assert not (tmp_path / "rlg-injection-canary").exists()
    assert not output.exists() or output.read_text(encoding="utf-8") == ""


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


def _run_environment_verifier(tmp_path, environment, branch_policies):
    response = tmp_path / "environment.json"
    policies = tmp_path / "branch-policies.json"
    response.write_text(json.dumps(environment), encoding="utf-8")
    policies.write_text(json.dumps(branch_policies), encoding="utf-8")
    return subprocess.run(
        [
            sys.executable,
            str(ROOT / ".github" / "release" / "verify_environment.py"),
            "--response",
            str(response),
            "--branch-policies",
            str(policies),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )


def _valid_environment_evidence():
    return {
        "name": "pypi",
        "can_admins_bypass": False,
        "protection_rules": [
            {
                "type": "required_reviewers",
                "prevent_self_review": True,
                "reviewers": [
                    {"type": "User", "reviewer": {"id": 1, "login": "reviewer"}}
                ],
            },
            {"type": "branch_policy"},
        ],
        "deployment_branch_policy": {
            "protected_branches": False,
            "custom_branch_policies": True,
        },
    }, {
        "total_count": 1,
        "branch_policies": [{"name": "v0.1.1", "type": "tag"}],
    }


def test_publication_environment_requires_exact_tag_and_reviewer_separation(tmp_path):
    environment, policies = _valid_environment_evidence()
    accepted = _run_environment_verifier(tmp_path, environment, policies)
    assert accepted.returncode == 0, accepted.stderr
    assert accepted.stdout == "Exact protected pypi environment contract verified.\n"


@pytest.mark.parametrize(
    "admin_bypass",
    (
        pytest.param("missing", id="missing"),
        pytest.param(True, id="true"),
        pytest.param(None, id="null"),
        pytest.param("false", id="string"),
        pytest.param(0, id="zero"),
        pytest.param(1, id="one"),
        pytest.param([], id="list"),
        pytest.param({}, id="mapping"),
    ),
)
def test_publication_environment_rejects_admin_bypass_without_success_evidence(
    tmp_path, admin_bypass
):
    environment, policies = _valid_environment_evidence()
    if admin_bypass == "missing":
        environment.pop("can_admins_bypass")
    else:
        environment["can_admins_bypass"] = admin_bypass

    rejected = _run_environment_verifier(tmp_path, environment, policies)

    assert rejected.returncode != 0
    assert rejected.stdout == ""
    assert "verified" not in rejected.stderr.lower()
    assert {path.name for path in tmp_path.iterdir()} == {
        "environment.json",
        "branch-policies.json",
    }


@pytest.mark.parametrize(
    "mutation",
    (
        "no-reviewers",
        "self-review",
        "no-branch-rule",
        "protected-branches",
        "arbitrary-branch",
        "extra-policy",
        "missing-policy-type",
    ),
)
def test_publication_environment_rejects_incomplete_or_branch_policy(
    tmp_path, mutation
):
    environment, policies = _valid_environment_evidence()
    if mutation == "no-reviewers":
        environment["protection_rules"][0]["reviewers"] = []
    elif mutation == "self-review":
        environment["protection_rules"][0]["prevent_self_review"] = False
    elif mutation == "no-branch-rule":
        environment["protection_rules"].pop()
    elif mutation == "protected-branches":
        environment["deployment_branch_policy"] = {
            "protected_branches": True,
            "custom_branch_policies": False,
        }
    elif mutation == "arbitrary-branch":
        policies["branch_policies"][0] = {"name": "*", "type": "branch"}
    elif mutation == "extra-policy":
        policies["total_count"] = 2
        policies["branch_policies"].append({"name": "main", "type": "branch"})
    else:
        policies["branch_policies"][0].pop("type")

    rejected = _run_environment_verifier(tmp_path, environment, policies)
    assert rejected.returncode != 0


def test_canonical_release_notes_state_exact_corrective_upgrade_warnings():
    notes = (ROOT / "docs" / "releases" / "0.1.1.md").read_text(
        encoding="utf-8"
    )
    normalized = " ".join(notes.split())
    for wording in (
        "Python 3.13+ does not match `0.1.1`",
        "the unsafe `0.1.0` metadata may still match Python 3.13+ until that release is yanked",
        "Users on Python 3.13+ must not assume `pip install -U ragleakguard` installed the corrective version",
        "`pip install -U ragleakguard` installed the corrective version",
        "They must verify the installed version",
        "There is no supported corrective Chroma path on Python 3.13+",
        "The old `chroma` extra was replaced by `chroma-snapshot`",
        "Using the old extra does not install the required exact ChromaDB 1.5.9 dependency",
        "Legacy `--path` is rejected",
        "The bounded operator-snapshot invocation requires",
    ):
        assert wording in normalized
    for option in (
        "--snapshot",
        "--work-parent",
        "--source-id",
        "--acknowledge-offline-complete-snapshot",
        "--report",
    ):
        assert option in notes


def test_release_process_defines_exact_publication_trust_contract():
    process = (ROOT / "docs" / "RELEASE_PROCESS.md").read_text(encoding="utf-8")
    normalized = " ".join(process.split())
    for wording in (
        "Agenvana/RAGLeakGuard/.github/workflows/publish-pypi.yml@refs/tags/v0.1.1",
        "`protected_branches: false`",
        "`custom_branch_policies: true`",
        "`prevent_self_review: true`",
        "prevents a modified publication workflow dispatched from an arbitrary branch",
        "repository: Agenvana/RAGLeakGuard",
        "workflow: publish-pypi.yml",
        "environment: pypi",
        "publication remains blocked until a second eligible reviewer is available",
        "Allow administrators to bypass configured protection rules: disabled.",
    ):
        assert wording in normalized


def test_release_architecture_forbids_administrator_bypass():
    architecture = (ROOT / "docs" / "ARCHITECTURE.md").read_text(encoding="utf-8")
    assert (
        "Allow administrators to bypass configured protection rules: disabled."
        in " ".join(architecture.split())
    )


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
