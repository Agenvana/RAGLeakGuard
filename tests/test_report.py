"""Golden contract tests for the versioned identifier risk policy."""
import re
from pathlib import Path
from types import MappingProxyType

import pytest

from ragleakguard.detect import DEFAULT_ENTITIES, LOCALE_PACKS
from ragleakguard.report import build_report, recorded_policy_version
from ragleakguard.risk_policy import (
    IDENTIFIER_SEVERITY,
    POLICY_ID,
    POLICY_VERSION,
    InconsistentRiskAggregates,
    UnsupportedRiskPolicyVersion,
    assess_risk,
    severity_for,
)


EXPECTED_SEVERITY = {
    "AU_MEDICARE": "HIGH",
    "AU_TFN": "HIGH",
    "CREDIT_CARD": "HIGH",
    "CRYPTO": "HIGH",
    "IBAN_CODE": "HIGH",
    "MEDICAL_LICENSE": "HIGH",
    "NRP": "HIGH",
    "US_BANK_NUMBER": "HIGH",
    "US_DRIVER_LICENSE": "HIGH",
    "US_ITIN": "HIGH",
    "US_PASSPORT": "HIGH",
    "US_SSN": "HIGH",
    "AU_ABN": "MEDIUM",
    "AU_PHONE": "MEDIUM",
    "EMAIL_ADDRESS": "MEDIUM",
    "LOCATION": "MEDIUM",
    "PERSON": "MEDIUM",
    "PHONE_NUMBER": "MEDIUM",
    "AU_ACN": "LOW",
    "DATE_TIME": "LOW",
    "IP_ADDRESS": "LOW",
}


def _implemented_detector_types():
    implemented = set(DEFAULT_ENTITIES)
    for entities in LOCALE_PACKS.values():
        implemented.update(entities)
    return implemented


def test_policy_matrix_is_immutable_and_exhaustive_for_detector():
    assert isinstance(IDENTIFIER_SEVERITY, MappingProxyType)
    assert dict(IDENTIFIER_SEVERITY) == EXPECTED_SEVERITY
    assert set(EXPECTED_SEVERITY) == _implemented_detector_types()

    with pytest.raises(TypeError):
        IDENTIFIER_SEVERITY["EMAIL_ADDRESS"] = "LOW"


def test_documented_policy_matrix_matches_the_golden_contract():
    policy_doc = (
        Path(__file__).resolve().parents[1] / "docs" / "RISK_POLICY.md"
    ).read_text(encoding="utf-8")
    documented_rows = dict(re.findall(
        r"^\| `([^`]+)` \| `(HIGH|MEDIUM|LOW)` \|$",
        policy_doc,
        flags=re.MULTILINE,
    ))
    assert documented_rows == EXPECTED_SEVERITY


@pytest.mark.parametrize(
    ("entity_type", "expected"),
    sorted(EXPECTED_SEVERITY.items()),
)
def test_golden_severity_for_every_supported_identifier(entity_type, expected):
    assert severity_for(entity_type) == expected


@pytest.mark.parametrize(
    ("by_type", "n_records", "n_flagged", "expected_level", "expected_score"),
    [
        ({}, 0, 0, "LOW", 0),
        ({}, 10, 0, "LOW", 0),
        ({"EMAIL_ADDRESS": 49}, 100, 49, "MODERATE", 1),
        ({"EMAIL_ADDRESS": 50}, 100, 50, "ELEVATED", 2),
        ({"US_SSN": 24}, 100, 24, "ELEVATED", 2),
        ({"US_SSN": 25}, 100, 25, "HIGH", 3),
        ({"CUSTOM_SECRET": 25}, 100, 25, "HIGH", 3),
    ],
    ids=[
        "zero-records",
        "empty-input",
        "below-50-percent",
        "at-50-percent",
        "high-below-25-percent",
        "high-at-25-percent",
        "unknown-at-25-percent",
    ],
)
def test_golden_overall_risk_boundaries(
    by_type, n_records, n_flagged, expected_level, expected_score
):
    result = assess_risk(by_type, n_flagged, n_records)
    assert (result.level, result.score) == (expected_level, expected_score)


@pytest.mark.parametrize(
    ("by_type", "n_records", "n_flagged", "expected_level"),
    [
        ({"DATE_TIME": 10, "EMAIL_ADDRESS": 15}, 100, 25, "MODERATE"),
        ({"US_SSN": 1, "EMAIL_ADDRESS": 24}, 100, 25, "HIGH"),
        ({"US_SSN": 1, "DATE_TIME": 99}, 100, 50, "HIGH"),
        ({"CUSTOM_SECRET": 1, "EMAIL_ADDRESS": 23}, 100, 24, "ELEVATED"),
    ],
)
def test_golden_representative_severity_combinations(
    by_type, n_records, n_flagged, expected_level
):
    assert assess_risk(by_type, n_flagged, n_records).level == expected_level


def test_unknown_type_remains_visible_and_cannot_lower_overall_risk():
    result = assess_risk({"CUSTOM_SECRET": 1}, n_flagged=1, n_records=100)
    assert result.level == "ELEVATED"
    assert result.score == 2
    assert result.unknown_types == ("CUSTOM_SECRET",)
    assert severity_for("CUSTOM_SECRET") == "REVIEW"

    report = build_report({"CUSTOM_SECRET": 1}, n_records=100, n_flagged=1)
    assert "| CUSTOM_SECRET | 1 | REVIEW |" in report
    assert "conservatively treated as high-impact" in report


def test_unknown_type_label_cannot_change_markdown_table_structure():
    entity_type = "CUSTOM|<script>alert(1)</script>\nSECOND_ROW"
    report = build_report({entity_type: 1}, n_records=1, n_flagged=1)

    assert entity_type not in report
    assert (
        "| CUSTOM&#124;&lt;script&gt;alert(1)&lt;/script&gt;\\nSECOND_ROW | 1 | REVIEW |"
        in report
    )


@pytest.mark.parametrize(
    ("character", "visible_escape"),
    [
        pytest.param("\n", "\\n", id="line-feed"),
        pytest.param("\r", "\\r", id="carriage-return"),
        pytest.param("\t", "\\t", id="tab"),
        pytest.param("\u0000", "\\u0000", id="null"),
        pytest.param("\u000b", "\\u000B", id="vertical-tab"),
        pytest.param("\u000c", "\\u000C", id="form-feed"),
        pytest.param("\u001c", "\\u001C", id="file-separator"),
        pytest.param("\u001d", "\\u001D", id="group-separator"),
        pytest.param("\u001e", "\\u001E", id="record-separator"),
        pytest.param("\u007f", "\\u007F", id="delete"),
        pytest.param("\u0085", "\\u0085", id="next-line"),
        pytest.param("\u061c", "\\u061C", id="arabic-letter-mark"),
        pytest.param("\u200e", "\\u200E", id="left-to-right-mark"),
        pytest.param("\u200f", "\\u200F", id="right-to-left-mark"),
        pytest.param("\u2028", "\\u2028", id="line-separator"),
        pytest.param("\u2029", "\\u2029", id="paragraph-separator"),
        pytest.param("\u202d", "\\u202D", id="left-to-right-override"),
        pytest.param("\u202e", "\\u202E", id="right-to-left-override"),
        pytest.param("\u2066", "\\u2066", id="left-to-right-isolate"),
        pytest.param("\u2067", "\\u2067", id="right-to-left-isolate"),
        pytest.param("\u2068", "\\u2068", id="first-strong-isolate"),
        pytest.param("\u2069", "\\u2069", id="pop-directional-isolate"),
        pytest.param("\ud800", "\\uD800", id="surrogate"),
    ],
)
def test_custom_label_presentation_controls_are_visible_and_inert(
    character, visible_escape
):
    forged_content = "## FORGED LOW-RISK RESULT | 999 | LOW"
    entity_type = f"CUSTOM{character}{forged_content}"
    report = build_report({entity_type: 1}, n_records=100, n_flagged=1)
    baseline = build_report({"CUSTOM_SAFE": 1}, n_records=100, n_flagged=1)
    lines = report.splitlines()
    baseline_lines = baseline.splitlines()

    expected_label = (
        f"CUSTOM{visible_escape}## FORGED LOW-RISK RESULT "
        "&#124; 999 &#124; LOW"
    )
    represented_lines = [line for line in lines if "FORGED LOW-RISK RESULT" in line]

    assert represented_lines == [f"| {expected_label} | 1 | REVIEW |"]
    assert len(lines) == len(baseline_lines)
    assert [line for line in lines if line.startswith("#")] == [
        line for line in baseline_lines if line.startswith("#")
    ]
    assert sum(line.startswith("|") for line in lines) == sum(
        line.startswith("|") for line in baseline_lines
    )
    assert "- **Risk level:** **ELEVATED**" in report
    assert "- **Risk score:** **2/3**" in report
    assert "conservatively treated as high-impact" in report


@pytest.mark.parametrize(
    ("by_type", "n_records", "n_flagged"),
    [
        ({}, 1, 1),
        ({"EMAIL_ADDRESS": 1}, 1, 0),
        ({"EMAIL_ADDRESS": 1}, 1, 2),
        ({"EMAIL_ADDRESS": 1}, 3, 2),
        ({"EMAIL_ADDRESS": 0}, 1, 0),
        ({"EMAIL_ADDRESS": -1}, 1, 0),
        ({"EMAIL_ADDRESS": True}, 1, 1),
        ({"EMAIL_ADDRESS": 1}, 0, 0),
        ({"EMAIL_ADDRESS": 1}, -1, 0),
        ({"EMAIL_ADDRESS": 1}, 1, -1),
        ({"EMAIL_ADDRESS": 1}, True, 1),
        ({"EMAIL_ADDRESS": 1}, 1, True),
        ({"": 1}, 1, 1),
        ({"   ": 1}, 1, 1),
        ({1: 1}, 1, 1),
        (["EMAIL_ADDRESS"], 1, 1),
    ],
)
def test_inconsistent_aggregate_counts_fail_explicitly(by_type, n_records, n_flagged):
    with pytest.raises(InconsistentRiskAggregates):
        assess_risk(by_type, n_flagged, n_records)


def test_policy_version_is_explicit_and_unsupported_versions_fail_closed():
    result = assess_risk({}, 0, 0, policy_version=POLICY_VERSION)
    assert result.policy_id == POLICY_ID
    assert result.policy_version == POLICY_VERSION

    with pytest.raises(UnsupportedRiskPolicyVersion):
        assess_risk({}, 0, 0, policy_version="0.legacy")
    with pytest.raises(UnsupportedRiskPolicyVersion):
        build_report({}, 0, 0, policy_version="0.legacy")


def test_generated_report_records_policy_and_ordinal_score():
    report = build_report(
        {"AU_MEDICARE": 100, "EMAIL_ADDRESS": 100, "DATE_TIME": 50},
        n_records=100,
        n_flagged=100,
    )
    assert f"- **Risk policy:** `{POLICY_ID}`" in report
    assert f"- **Risk policy version:** `{POLICY_VERSION}`" in report
    assert recorded_policy_version(report) == POLICY_VERSION
    assert "- **Risk level:** **HIGH**" in report
    assert "- **Risk score:** **3/3**" in report


def test_legacy_unversioned_report_is_not_retroactively_attributed():
    legacy_report = """# RAGLeakGuard - Sensitive Data Report

- **Records scanned:** 10
- **Risk level:** **LOW**
"""
    assert recorded_policy_version(legacy_report) is None

    # The prior five-positional-argument interface remains valid, but every newly
    # generated report receives current, explicit attribution.
    regenerated = build_report({}, 10, 0, "chroma", "synthetic-store")
    assert recorded_policy_version(regenerated) == POLICY_VERSION


@pytest.mark.parametrize(
    "report",
    [
        "- **Risk policy version:**",
        "- **Risk policy version:** ``",
        "- **Risk policy version:** `1.0.0`\n- **Risk policy version:** `1.0.0`",
    ],
)
def test_malformed_or_ambiguous_policy_attribution_fails_explicitly(report):
    with pytest.raises(ValueError):
        recorded_policy_version(report)


def test_classification_and_rendering_are_deterministic_for_identical_inputs():
    first = {"DATE_TIME": 2, "US_SSN": 1, "EMAIL_ADDRESS": 2}
    second = {"EMAIL_ADDRESS": 2, "US_SSN": 1, "DATE_TIME": 2}
    expected = assess_risk(first, 5, 10, policy_version=POLICY_VERSION)

    for _ in range(10):
        assert assess_risk(second, 5, 10, policy_version=POLICY_VERSION) == expected
        assert build_report(
            second,
            10,
            5,
            source="chroma",
            path="synthetic-store",
            policy_version=POLICY_VERSION,
        ) == build_report(
            first,
            10,
            5,
            source="chroma",
            path="synthetic-store",
            policy_version=POLICY_VERSION,
        )


def test_policy_attribution_adds_no_sensitive_runtime_fields():
    report = build_report({"EMAIL_ADDRESS": 1}, n_records=1, n_flagged=1)
    for canary in (
        "raw-detected-value-canary",
        "document-text-canary",
        "span-canary",
        "record-id-canary",
        "tenant-canary",
        "secret-canary",
        "exception-text-canary",
    ):
        assert canary not in report
