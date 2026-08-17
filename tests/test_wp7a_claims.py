"""Package and public-claim regression tests for WP7A."""
import re
from pathlib import Path

import pytest
from click import unstyle
from typer.testing import CliRunner

from ragleakguard import cli


ROOT = Path(__file__).resolve().parents[1]
ENGLISH_CURRENT = (
    ROOT / "README.md",
    ROOT / "SECURITY.md",
    ROOT / "CONTRIBUTING.md",
    ROOT / "ROADMAP.md",
    ROOT / "docs" / "ARCHITECTURE.md",
    ROOT / "docs" / "THREAT_MODEL.md",
    ROOT / "docs" / "MONITOR_STATE.md",
    ROOT / "docs" / "RELEASE_PROCESS.md",
)


def test_package_metadata_keeps_chroma_optional_and_exact_for_snapshot_activation():
    document = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    base_dependencies = re.search(
        r"^dependencies\s*=\s*\[(.*?)\]",
        document,
        re.MULTILINE | re.DOTALL,
    ).group(1)
    optional_dependencies = re.search(
        r"^\[project\.optional-dependencies\]\s*(.*?)(?=^\[)",
        document,
        re.MULTILINE | re.DOTALL,
    ).group(1)
    description = re.search(
        r'^description\s*=\s*"([^"]+)"$', document, re.MULTILINE
    ).group(1)
    sdist = re.search(
        r"^\[tool\.hatch\.build\.targets\.sdist\]\s*(.*)",
        document,
        re.MULTILINE | re.DOTALL,
    ).group(1)
    sdist_include = re.findall(
        r'"([^"]+)"', re.search(r"include\s*=\s*\[(.*?)\]", sdist, re.DOTALL).group(1)
    )
    assert "chromadb" not in base_dependencies.lower()
    assert 'chroma-snapshot = ["chromadb==1.5.9"]' in optional_dependencies
    assert "operator-snapshot chroma" in description.lower()
    assert "scan your ai's vector database" not in description.lower()
    assert re.search(
        r'^requires-python\s*=\s*">=3\.9,<3\.13"$', document, re.MULTILINE
    )

    assert set(sdist_include) == {
        "/src/ragleakguard",
        "/README.md",
        "/README.zh-TW.md",
        "/SECURITY.md",
        "/LICENSE",
        "/pyproject.toml",
        "/docs/releases/0.1.1.md",
    }
    assert not any(
        forbidden in item
        for item in sdist_include
        for forbidden in ("tests", "reports", "scripts", ".github", ".env")
    )
    # Hatchling's standard sdist always includes the VCS ignore file; do not
    # pretend an ineffective exclusion narrows the archive.
    assert "exclude" not in sdist


@pytest.mark.parametrize("path", ENGLISH_CURRENT, ids=lambda path: path.name)
def test_current_english_claim_surfaces_record_wp7d_safety_boundary(path):
    text = path.read_text(encoding="utf-8")
    lowered = text.lower()

    assert "1.5.9" in text
    assert "operator" in lowered and "snapshot" in lowered
    assert "direct/live" in lowered and "disabled" in lowered
    assert "complete" in lowered and "quiescent" in lowered


@pytest.mark.parametrize(
    "path",
    (
        ROOT / "README.md",
        ROOT / "README.zh-TW.md",
        ROOT / "SECURITY.md",
        ROOT / "CONTRIBUTING.md",
        ROOT / "docs" / "ARCHITECTURE.md",
        ROOT / "docs" / "THREAT_MODEL.md",
        ROOT / "docs" / "RELEASE_PROCESS.md",
    ),
    ids=lambda path: path.name,
)
def test_public_claim_surfaces_warn_against_pypi_010_chroma_scanning(path):
    text = path.read_text(encoding="utf-8")
    assert "0.1.0" in text
    assert "Chroma" in text
    assert "must not be used" in text or "不得用於" in text


def test_english_and_traditional_chinese_readmes_offer_only_snapshot_quickstart():
    for name in ("README.md", "README.zh-TW.md"):
        text = (ROOT / name).read_text(encoding="utf-8")
        lowered = text.lower()
        assert "ragleakguard scan --source chroma" in lowered
        for option in (
            "--snapshot",
            "--work-parent",
            "--source-id",
            "--acknowledge-offline-complete-snapshot",
            "--report",
        ):
            assert option in lowered
        assert "ragleakguard monitor --source chroma" not in lowered
        assert "chroma-snapshot" in lowered
        assert "safe to run against production" not in lowered
        assert "read-only; safe" not in lowered


def test_traditional_chinese_readme_states_all_required_current_facts():
    text = (ROOT / "README.zh-TW.md").read_text(encoding="utf-8")

    for phrase in (
        "操作員快照",
        "直接／即時 Chroma 掃描仍停用",
        "1.5.9",
        "完整且靜止",
        "不會證明快照的來源、靜止狀態、完整性或原子一致性",
        "PyPI `0.1.0`",
        "不得用於 Chroma 掃描",
    ):
        assert phrase in text


@pytest.mark.parametrize("command", ["scan", "monitor"])
def test_cli_help_advertises_disabled_chroma_and_exit_six(command):
    result = CliRunner().invoke(cli.app, [command, "--help"])
    output = " ".join(unstyle(result.output).split())

    assert result.exit_code == 0
    assert "disabled" in output.lower()
    if command == "scan":
        assert "6 = candidate dependency or activation environment unavailable" in output
    else:
        assert "6 = direct Chroma scanning disabled" in output
    assert "pinecone" not in output.lower()
    assert "production" not in output.lower()
    if command == "monitor":
        assert "create a new baseline" not in output.lower()


def test_current_docs_never_offer_direct_path_or_monitor_chroma_commands():
    for path in ENGLISH_CURRENT + (ROOT / "README.zh-TW.md",):
        text = path.read_text(encoding="utf-8")
        assert not re.search(
            r"ragleakguard\s+scan\s+--source\s+chroma(?:(?!```)[\s\S])*?--path",
            text,
            re.I,
        )
        assert not re.search(r"ragleakguard\s+monitor\s+--source\s+chroma", text, re.I)
