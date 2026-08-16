"""Reporting — turn aggregate findings into a risk-scored Markdown report.

Severity weighting + regulatory framing + remediation = the security judgment
that makes a scan trustworthy, rather than a noisy entity dump.
"""
import errno
import math
import os
import re
import secrets
import stat
import time
from html import escape
from pathlib import Path
from typing import Callable, Dict, Optional
from unicodedata import category

from ragleakguard import _snapshot
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
_MAX_FINAL_REPORT_BYTES = 1_048_576
_REPORT_FINALIZATION_SECONDS = 30.0
_REPORT_TEMP_PREFIX = ".rlg-report-"
_REPORT_TEMP_SUFFIX = ".tmp"
_REPORT_FAILURE = "Report finalization failed; no completed report is available."


class ReportFinalizationError(RuntimeError):
    """Static, path-free failure for bounded atomic report replacement."""

    def __init__(self) -> None:
        super().__init__(_REPORT_FAILURE)


def _scrub_report_error(
    error: Optional[ReportFinalizationError] = None,
) -> ReportFinalizationError:
    """Detach every retained exception that could carry operator-controlled data."""
    if type(error) is not ReportFinalizationError:
        error = ReportFinalizationError()
    pending = [error]
    seen = set()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        if current.__cause__ is not None:
            pending.append(current.__cause__)
        if current.__context__ is not None:
            pending.append(current.__context__)
        nested = getattr(current, "exceptions", ())
        if type(nested) is tuple:
            pending.extend(nested)
        current.__cause__ = None
        current.__context__ = None
        current.__suppress_context__ = True
    return error


def _report_now(clock: Callable[[], float]) -> float:
    failure = None
    try:
        value = clock()
    except BaseException:
        failure = ReportFinalizationError()
    if failure is not None:
        raise _scrub_report_error(failure)
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ReportFinalizationError()
    return float(value)


def _report_check(deadline: float, clock: Callable[[], float]) -> None:
    if _report_now(clock) > deadline:
        raise ReportFinalizationError()


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


def _markdown_inline_code(value: str) -> str:
    visible = "".join(_visible_presentation_character(char) for char in value)
    return escape(visible, quote=True).replace("`", "&#96;")


def _report_identity(path: Path):
    raw = os.lstat(path)
    identity = _snapshot._identity(raw)
    if (
        not stat.S_ISREG(identity.mode)
        or stat.S_ISLNK(identity.mode)
        or _snapshot._is_reparse(identity)
        or identity.links != 1
        or identity.size > _MAX_FINAL_REPORT_BYTES
        or _snapshot._windows_has_named_streams(path)
    ):
        raise ReportFinalizationError()
    return identity


def _read_existing_report(path: Path):
    failure = None
    result = None
    try:
        identity = _report_identity(path)
        flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0))
        flags |= int(getattr(os, "O_NOFOLLOW", 0))
        descriptor = os.open(path, flags)
        try:
            if not _snapshot._same_path_handle_identity(
                identity, _snapshot._identity(os.fstat(descriptor))
            ):
                raise ReportFinalizationError()
            chunks = []
            total = 0
            while total <= _MAX_FINAL_REPORT_BYTES:
                chunk = os.read(descriptor, min(65_536, _MAX_FINAL_REPORT_BYTES + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
            if total > _MAX_FINAL_REPORT_BYTES:
                raise ReportFinalizationError()
            result = (identity, b"".join(chunks))
        finally:
            os.close(descriptor)
    except ReportFinalizationError as error:
        failure = error
    except BaseException:
        failure = ReportFinalizationError()
    if failure is not None:
        raise _scrub_report_error(failure)
    return result


def _write_all(descriptor: int, encoded: bytes) -> None:
    offset = 0
    while offset < len(encoded):
        written = os.write(descriptor, encoded[offset:offset + 65_536])
        if type(written) is not int or written <= 0:
            raise OSError
        offset += written


def _new_report_temp(
    parent: Path,
    encoded: bytes,
    deadline: float,
    clock: Callable[[], float],
    token_source: Callable[[int], bytes],
):
    failure = None
    result = None
    path = None
    descriptor = None
    owned_identity = None
    failed = True
    try:
        _report_check(deadline, clock)
        try:
            token = token_source(16)
        except BaseException:
            raise ReportFinalizationError() from None
        if type(token) is not bytes or len(token) != 16:
            raise ReportFinalizationError()
        path = parent / (_REPORT_TEMP_PREFIX + token.hex() + _REPORT_TEMP_SUFFIX)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | int(
            getattr(os, "O_BINARY", 0)
        )
        flags |= int(getattr(os, "O_NOFOLLOW", 0))
        descriptor = os.open(path, flags, 0o600)
        _snapshot._harden(path, False)
        owned_identity = _snapshot._identity(os.fstat(descriptor))
        _write_all(descriptor, encoded)
        _report_check(deadline, clock)
        os.fsync(descriptor)
        _report_check(deadline, clock)
        identity = _snapshot._identity(os.fstat(descriptor))
        if identity.size != len(encoded):
            raise ReportFinalizationError()
        failed = False
        result = (path, identity)
    except ReportFinalizationError as error:
        failure = error
    except BaseException:
        failure = ReportFinalizationError()
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except BaseException:
                pass
        if failed and path is not None and owned_identity is not None:
            try:
                observed = _report_identity(path)
                if _snapshot._same_object(observed, owned_identity):
                    os.unlink(path)
            except BaseException:
                pass
    if failure is not None:
        raise _scrub_report_error(failure)
    return result


def _remove_owned_temp(path: Optional[Path], identity) -> None:
    if path is None or identity is None:
        return
    try:
        if _snapshot._same_object(_report_identity(path), identity):
            os.unlink(path)
    except BaseException:
        pass


def _sync_report_directory(parent: Path) -> bool:
    if os.name == "nt":
        return False
    flags = os.O_RDONLY | int(getattr(os, "O_DIRECTORY", 0))
    descriptor = None
    try:
        descriptor = os.open(parent, flags)
        os.fsync(descriptor)
        return True
    except OSError as error:
        if error.errno in {errno.EINVAL, errno.ENOTSUP, errno.EBADF}:
            return False
        raise
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _finalize_report(
    markdown: str,
    target: object,
    *,
    clock: Callable[[], float] = time.monotonic,
    token_source: Callable[[int], bytes] = secrets.token_bytes,
) -> None:
    """Restrictively and atomically replace one bounded same-directory report."""
    temporary = None
    temporary_identity = None
    replaced = False
    existing_identity = None
    existing_bytes = None
    target_path = None
    failure = None
    try:
        if type(markdown) is not str:
            raise ReportFinalizationError()
        encoded = markdown.encode("utf-8", errors="strict")
        if len(encoded) > _MAX_FINAL_REPORT_BYTES:
            raise ReportFinalizationError()
        start = _report_now(clock)
        deadline = start + _REPORT_FINALIZATION_SECONDS
        if not math.isfinite(deadline):
            raise ReportFinalizationError()
        target_path = Path(target)
        if not target_path.is_absolute():
            target_path = Path.cwd() / target_path
        if os.name == "nt" and ":" in target_path.name:
            raise ReportFinalizationError()
        parent = target_path.parent
        parent_raw = os.lstat(parent)
        parent_identity = _snapshot._identity(parent_raw)
        if (
            not stat.S_ISDIR(parent_identity.mode)
            or stat.S_ISLNK(parent_identity.mode)
            or _snapshot._is_reparse(parent_identity)
            or _snapshot._windows_has_named_streams(parent)
            or parent.resolve(strict=True) != parent
        ):
            raise ReportFinalizationError()
        if os.path.lexists(target_path):
            existing_identity, existing_bytes = _read_existing_report(target_path)
        _report_check(deadline, clock)
        temporary, temporary_identity = _new_report_temp(
            parent, encoded, deadline, clock, token_source
        )
        if not _snapshot._same_object(
            parent_identity, _snapshot._identity(os.lstat(parent))
        ):
            raise ReportFinalizationError()
        if existing_identity is None:
            if os.path.lexists(target_path):
                raise ReportFinalizationError()
        elif not _snapshot._same_object(_report_identity(target_path), existing_identity):
            raise ReportFinalizationError()
        if not _snapshot._same_path_handle_identity(
            _report_identity(temporary), temporary_identity
        ):
            raise ReportFinalizationError()
        os.replace(temporary, target_path)
        temporary = None
        replaced = True
        final_identity = _report_identity(target_path)
        if not _snapshot._same_object(final_identity, temporary_identity):
            raise ReportFinalizationError()
        _snapshot._assert_restrictive(target_path, False)
        _sync_report_directory(parent)
        _report_check(deadline, clock)
        if (
            not _snapshot._same_object(
                parent_identity, _snapshot._identity(os.lstat(parent))
            )
            or not _snapshot._same_object(
                _report_identity(target_path), temporary_identity
            )
        ):
            raise ReportFinalizationError()
        _snapshot._assert_restrictive(target_path, False)
    except BaseException as error:
        failure = (
            error if type(error) is ReportFinalizationError
            else ReportFinalizationError()
        )
        if replaced and target_path is not None:
            try:
                if not _snapshot._same_object(
                    _report_identity(target_path), temporary_identity
                ):
                    raise ReportFinalizationError()
                if existing_identity is None:
                    os.unlink(target_path)
                else:
                    rollback, rollback_identity = _new_report_temp(
                        target_path.parent,
                        existing_bytes,
                        float("inf"),
                        lambda: 0.0,
                        token_source,
                    )
                    try:
                        os.replace(rollback, target_path)
                        rollback = None
                    finally:
                        _remove_owned_temp(rollback, rollback_identity)
                _sync_report_directory(target_path.parent)
            except BaseException:
                pass
        _remove_owned_temp(temporary, temporary_identity)
    if failure is not None:
        raise _scrub_report_error(failure)


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
    source_line = f"- **Source:** `{_markdown_inline_code(source)}`"
    if path:
        source_line += f" `{_markdown_inline_code(path)}`"

    lines = [
        "# RAGLeakGuard — Sensitive Data Report",
        "",
        source_line,
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
