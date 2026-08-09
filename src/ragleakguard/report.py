"""Reporting — turn aggregate findings into a risk-scored Markdown report.

Severity weighting + regulatory framing + remediation = the security judgment
that makes a scan trustworthy, rather than a noisy entity dump.
"""
import re
from html import escape
from typing import Dict, Optional
from unicodedata import category

from ragleakguard.risk_policy import (
    IDENTIFIER_SEVERITY,
    POLICY_ID,
    POLICY_VERSION,
    UNKNOWN_SEVERITY,
    assess_risk,
    severity_for,
)


# Read-only compatibility alias for callers that inspected the old report module.
# Its semantics are now governed by POLICY_VERSION rather than a local mutable map.
SEVERITY = IDENTIFIER_SEVERITY

_POLICY_VERSION_LABEL = "- **Risk policy version:**"
_POLICY_VERSION_PATTERN = re.compile(
    r"^- \*\*Risk policy version:\*\* `([^`\r\n]+)`$"
)
_PRESENTATION_CONTROL_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Zl", "Zp"})
_VISIBLE_CONTROL_ESCAPES = {"\t": "\\t", "\n": "\\n", "\r": "\\r"}


def recorded_policy_version(markdown: str) -> Optional[str]:
    """Return a report's recorded version, or None for legacy unversioned output.

    Historical reports are never assigned the current version retroactively.
    Ambiguous or malformed version attribution fails explicitly.
    """
    matching_lines = [
        line for line in markdown.splitlines()
        if line.startswith(_POLICY_VERSION_LABEL)
    ]
    if not matching_lines:
        return None
    if len(matching_lines) != 1:
        raise ValueError("Report risk policy attribution is malformed or ambiguous.")
    match = _POLICY_VERSION_PATTERN.fullmatch(matching_lines[0])
    if match is None:
        raise ValueError("Report risk policy attribution is malformed or ambiguous.")
    return match.group(1)


def _visible_presentation_character(character: str) -> str:
    """Render presentation controls as visible, inert ASCII escape sequences."""
    if character in _VISIBLE_CONTROL_ESCAPES:
        return _VISIBLE_CONTROL_ESCAPES[character]
    if category(character) not in _PRESENTATION_CONTROL_CATEGORIES:
        return character
    codepoint = ord(character)
    if codepoint <= 0xFFFF:
        return f"\\u{codepoint:04X}"
    return f"\\U{codepoint:08X}"


def _markdown_table_cell(value: str) -> str:
    """Keep an unknown/custom identifier label visible without altering presentation."""
    visible = "".join(_visible_presentation_character(char) for char in value)
    return escape(visible, quote=True).replace("|", "&#124;")


def _risk_level(
    by_type: Dict[str, int],
    n_flagged: int,
    n_records: int,
    *,
    policy_version: str = POLICY_VERSION,
) -> str:
    """Compatibility helper returning the versioned assessment's level."""
    return assess_risk(
        by_type,
        n_flagged,
        n_records,
        policy_version=policy_version,
    ).level


def build_report(
    by_type: Dict[str, int],
    n_records: int,
    n_flagged: int,
    source: str = "chroma",
    path: str = "",
    policy_version: str = POLICY_VERSION,
) -> str:
    """Build an attributable Markdown risk report from aggregate findings."""
    aggregates = dict(by_type)
    assessment = assess_risk(
        aggregates,
        n_flagged,
        n_records,
        policy_version=policy_version,
    )
    total = sum(aggregates.values())
    pct = f"{(n_flagged / n_records * 100):.0f}%" if n_records else "0%"

    lines = [
        "# RAGLeakGuard — Sensitive Data Report",
        "",
        f"- **Source:** `{source}` {path}".rstrip(),
        f"- **Records scanned:** {n_records}",
        f"- **Records with sensitive data:** {n_flagged} ({pct})",
        f"- **Total findings:** {total}",
        f"- **Risk policy:** `{POLICY_ID}`",
        f"{_POLICY_VERSION_LABEL} `{assessment.policy_version}`",
        f"- **Risk level:** **{assessment.level}**",
        f"- **Risk score:** **{assessment.score}/3**",
        "",
        "## Findings by type",
        "",
        "| Type | Count | Severity |",
        "|------|------:|----------|",
    ]
    for entity_type, count in sorted(
        aggregates.items(), key=lambda item: (-item[1], item[0])
    ):
        severity = severity_for(entity_type, policy_version=policy_version)
        label = _markdown_table_cell(entity_type)
        lines.append(f"| {label} | {count} | {severity} |")

    if assessment.unknown_types:
        lines += [
            "",
            f"> **{UNKNOWN_SEVERITY}:** Unknown/custom identifier types remain visible and are "
            "conservatively treated as high-impact when calculating the overall risk level.",
        ]

    lines += [
        "",
        "## Why this matters",
        "- These values are **embedded** in a vector store — text can be partially "
        "**reconstructed** from the vectors (embedding inversion), so they are *not* anonymous.",
        "- They are **hard to delete**: removing them from the live index does not remove them "
        "from backups, replicas, caches, or any fine-tuned model.",
        "- Under Australia's Privacy Act (APP 11) and the GDPR, holding this without controls can "
        "create **notifiable-breach** and **right-to-erasure** exposure.",
        "",
        "## Recommended actions",
        "1. **Prevent:** redact / tokenise sensitive fields *before* embedding.",
        "2. **Remediate:** delete affected records and rebuild the index from a sanitised source.",
        "3. **Purge copies:** backups, replicas, caches, logs.",
        "4. **Prove:** keep an erasure record for compliance.",
        "",
        "---",
        "_Generated by **RAGLeakGuard** (Diagnose). Detection is best-effort — tune recognisers for "
        "your jurisdiction; absence of a finding is not proof of safety._",
    ]
    return "\n".join(lines)
