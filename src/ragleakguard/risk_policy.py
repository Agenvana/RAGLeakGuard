"""Versioned identifier severity and aggregate risk policy.

The version is an explicit review boundary. Change it whenever a severity,
threshold, score, unknown-type rule, or aggregate-validation rule changes.
"""
from dataclasses import dataclass
from types import MappingProxyType
from typing import Dict, Mapping, Tuple

from ragleakguard.detect import DEFAULT_ENTITIES, LOCALE_PACKS


POLICY_ID = "RLG-ID-RISK"
POLICY_VERSION = "1.0.0"
POLICY_REFERENCE = f"{POLICY_ID}@{POLICY_VERSION}"

# This matrix is intentionally exhaustive for the detector's current default and
# locale-pack entity types. Unknown future/custom types use the separate REVIEW
# rule below; they are not silently added to this versioned matrix.
IDENTIFIER_SEVERITY = MappingProxyType({
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
})

UNKNOWN_SEVERITY = "REVIEW"

# Ordinal prioritisation only: this is not a probability, compliance measure, or
# guarantee of harm. It keeps the report's numeric score tied to its level.
LEVEL_SCORE = MappingProxyType({
    "LOW": 0,
    "MODERATE": 1,
    "ELEVATED": 2,
    "HIGH": 3,
})


class UnsupportedRiskPolicyVersion(ValueError):
    """Raised when a caller requests policy semantics this build does not implement."""


class InconsistentRiskAggregates(ValueError):
    """Raised when aggregate counts cannot describe a completed scan."""


@dataclass(frozen=True)
class RiskAssessment:
    """Deterministic result produced by one explicit policy version."""

    policy_id: str
    policy_version: str
    level: str
    score: int
    unknown_types: Tuple[str, ...]


def _implemented_entity_types():
    entities = set(DEFAULT_ENTITIES)
    for locale_entities in LOCALE_PACKS.values():
        entities.update(locale_entities)
    return frozenset(entities)


SUPPORTED_IDENTIFIER_TYPES = _implemented_entity_types()


def _validate_policy_definition() -> None:
    mapped = frozenset(IDENTIFIER_SEVERITY)
    if mapped != SUPPORTED_IDENTIFIER_TYPES:
        missing = sorted(SUPPORTED_IDENTIFIER_TYPES - mapped)
        extra = sorted(mapped - SUPPORTED_IDENTIFIER_TYPES)
        raise RuntimeError(
            f"{POLICY_REFERENCE} does not match implemented detector types "
            f"(missing={missing}, extra={extra})."
        )


_validate_policy_definition()


def _require_supported_version(policy_version: str) -> None:
    if policy_version != POLICY_VERSION:
        raise UnsupportedRiskPolicyVersion(
            f"Unsupported risk policy version; this build implements {POLICY_VERSION}."
        )


def _validate_aggregates(
    by_type: Mapping[str, int], n_flagged: int, n_records: int
) -> Dict[str, int]:
    if type(n_records) is not int or n_records < 0:
        raise InconsistentRiskAggregates("n_records must be a non-negative integer.")
    if type(n_flagged) is not int or n_flagged < 0:
        raise InconsistentRiskAggregates("n_flagged must be a non-negative integer.")
    if n_flagged > n_records:
        raise InconsistentRiskAggregates("n_flagged cannot exceed n_records.")
    if not isinstance(by_type, Mapping):
        raise InconsistentRiskAggregates("by_type must be a mapping of entity counts.")

    aggregates: Dict[str, int] = {}
    for entity_type, count in by_type.items():
        if not isinstance(entity_type, str) or not entity_type.strip():
            raise InconsistentRiskAggregates("Entity types must be non-empty strings.")
        if type(count) is not int or count <= 0:
            raise InconsistentRiskAggregates("Entity counts must be positive integers.")
        aggregates[entity_type] = count

    total_findings = sum(aggregates.values())
    if total_findings == 0 and n_flagged != 0:
        raise InconsistentRiskAggregates(
            "Flagged records require at least one aggregate finding."
        )
    if total_findings > 0 and n_flagged == 0:
        raise InconsistentRiskAggregates(
            "Aggregate findings require at least one flagged record."
        )
    if n_flagged > total_findings:
        raise InconsistentRiskAggregates(
            "Each flagged record requires at least one aggregate finding."
        )
    return aggregates


def severity_for(entity_type: str, *, policy_version: str = POLICY_VERSION) -> str:
    """Return the explicit severity, or REVIEW for a truly unknown/custom type."""
    _require_supported_version(policy_version)
    if not isinstance(entity_type, str) or not entity_type.strip():
        raise ValueError("Entity type must be a non-empty string.")
    return IDENTIFIER_SEVERITY.get(entity_type, UNKNOWN_SEVERITY)


def assess_risk(
    by_type: Mapping[str, int],
    n_flagged: int,
    n_records: int,
    *,
    policy_version: str = POLICY_VERSION,
) -> RiskAssessment:
    """Classify validated aggregate findings under one immutable policy version.

    Unknown/custom entity types stay visible as REVIEW and are conservatively
    treated as high-impact for the overall result. Exact integer comparisons
    implement the inclusive 25% and 50% boundaries without float rounding.
    """
    _require_supported_version(policy_version)
    aggregates = _validate_aggregates(by_type, n_flagged, n_records)
    unknown_types = tuple(sorted(set(aggregates) - set(IDENTIFIER_SEVERITY)))

    if not aggregates:
        level = "LOW"
    else:
        has_high_impact = bool(unknown_types) or any(
            IDENTIFIER_SEVERITY[entity_type] == "HIGH"
            for entity_type in aggregates
            if entity_type in IDENTIFIER_SEVERITY
        )
        at_least_25_percent = n_flagged * 4 >= n_records
        at_least_50_percent = n_flagged * 2 >= n_records
        if has_high_impact and at_least_25_percent:
            level = "HIGH"
        elif has_high_impact or at_least_50_percent:
            level = "ELEVATED"
        else:
            level = "MODERATE"

    return RiskAssessment(
        policy_id=POLICY_ID,
        policy_version=POLICY_VERSION,
        level=level,
        score=LEVEL_SCORE[level],
        unknown_types=unknown_types,
    )
